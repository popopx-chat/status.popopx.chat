#!/usr/bin/env python3
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""Audit a built POPOPX status export before it is published.

Checks every .html file in the export for:
  * subresources (script, style, image, font, iframe, ...) that point at
    another origin than the site's own -- the site must make zero requests
    to third parties;
  * inline event handlers (onclick=...) and style= attributes -- both are
    inline script/style that a strict CSP would refuse;
  * external url(...) / @import in inline <style> blocks and in .css files;
  * external <meta http-equiv="refresh"> targets and form actions.

It also collects the SHA-256 hashes of every inline <script> and <style> so
deploy_centos.sh can render a Content-Security-Policy that allows exactly the
inline assets this build contains -- no 'unsafe-inline'.

Stdlib only (Python 3.6+), like scripts/health_probe.py: the CentOS host has
python3 for dnf and must not need pip.

usage:
  scripts/site_audit.py --public public
  scripts/site_audit.py --public public --emit-csp /tmp/csp-hashes.json
  scripts/site_audit.py --public public --base https://status.popopx.chat/

exit: 0 clean, 1 policy violation, 2 usage/IO error.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

SCHEMA = "popopx.status.v1"

SUBRESOURCE_ATTRS = {
    "audio": ("src",),
    "embed": ("src",),
    "iframe": ("src",),
    "img": ("src", "srcset"),
    "input": ("src",),
    "link": ("href",),
    "object": ("data",),
    "script": ("src",),
    "source": ("src", "srcset"),
    "track": ("src",),
    "use": ("href", "xlink:href"),
    "image": ("href", "xlink:href"),
    "video": ("src", "poster"),
    "form": ("action",),
}

# rel values on <link> that the browser fetches automatically. Other rels
# (canonical, alternate feed links) are still required to be same-origin here,
# but the wording of the finding differs.
FETCHED_LINK_RELS = {
    "stylesheet", "icon", "shortcut", "apple-touch-icon", "apple-touch-icon-precomposed",
    "manifest", "preload", "prefetch", "preconnect", "dns-prefetch", "modulepreload",
}

CSS_URL_RE = re.compile(
    r"""url\(\s*(?P<quote>['"]?)(?P<url>[^'")]+)(?P=quote)\s*\)"""
    r"""|@import\s+(?:url\(\s*)?(?P<import>['"]?)(?P<import_url>[^'")\s;]+)""",
    re.IGNORECASE,
)
SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
STYLE_RE = re.compile(r"<style\b([^>]*)>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)


def sha256_token(text):
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def split_srcset(value):
    for candidate in value.split(","):
        url = candidate.strip().split()
        if url:
            yield url[0]


def port_of(parts):
    try:
        return parts.port
    except ValueError:
        return None


def effective_port(parts):
    port = port_of(parts)
    if port is not None:
        return port
    return 443 if parts.scheme == "https" else 80


class Origin:
    def __init__(self, base):
        self.base = base
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("--base must be an absolute http(s) URL: %r" % base)
        self.scheme = parts.scheme
        self.host = parts.hostname.lower()
        self.port = effective_port(parts)

    def classify(self, url, page_url):
        """Return None if same-origin, else (kind, absolute_url)."""
        value = url.strip()
        if not value or value.startswith("#") or value.startswith("data:"):
            return None
        if value.lower().startswith(("mailto:", "tel:", "javascript:")):
            return ("unsupported-scheme", value)
        absolute = urljoin(page_url, value)
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return ("unsupported-scheme", absolute)
        if parts.hostname.lower() != self.host or effective_port(parts) != self.port:
            return ("external", absolute)
        if self.scheme == "https" and parts.scheme != "https":
            return ("insecure", absolute)
        return None


class PageParser(HTMLParser):
    def __init__(self, origin, page_url, findings):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.origin = origin
        self.page_url = page_url
        self.findings = findings
        self.inline_handlers = []
        self.style_attrs = 0

    def add(self, kind, detail):
        self.findings.append({
            "page": self.page_url,
            "kind": kind,
            "detail": detail,
            "line": self.getpos()[0],
        })

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {}
        for name, value in attrs:
            name = name.lower()
            if value is None:
                value = ""
            if name in values:
                # Duplicate attributes are invalid HTML; keep the first one,
                # which is what browsers use.
                continue
            values[name] = value
            if re.match(r"^on[a-z]+$", name):
                self.inline_handlers.append("%s %s=%r" % (tag, name, value))
                self.add("inline-event-handler", "%s %s=%r" % (tag, name, value))
            if name == "style":
                self.style_attrs += 1
                self.add("inline-style-attribute", "%s style=%r" % (tag, value))

        if tag == "a" and values.get("href", "").strip().lower().startswith("javascript:"):
            self.add("inline-javascript-url", "a href=%r" % values.get("href", ""))

        for attr in SUBRESOURCE_ATTRS.get(tag, ()):
            if attr not in values:
                continue
            raw = values[attr]
            urls = split_srcset(raw) if attr == "srcset" else (raw,)
            for url in urls:
                verdict = self.origin.classify(url, self.page_url)
                if not verdict:
                    continue
                kind, absolute = verdict
                if tag == "form" and kind == "external":
                    kind = "external-form-action"
                elif tag == "link":
                    rels = set(values.get("rel", "").lower().split())
                    if rels & FETCHED_LINK_RELS:
                        kind = "external-subresource"
                    else:
                        kind = "external-link-target"
                else:
                    kind = "external-subresource"
                self.add(kind, "<%s %s> -> %s" % (tag, attr, absolute))

        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            content = values.get("content", "")
            match = re.search(r"url\s*=\s*(.+)$", content, re.IGNORECASE)
            if match:
                verdict = self.origin.classify(match.group(1).strip(" '\""), self.page_url)
                if verdict:
                    self.add("external-meta-refresh", "meta refresh -> %s" % verdict[1])

    handle_startendtag = handle_starttag


def audit_css(text, page_url, origin, findings, where):
    for match in CSS_URL_RE.finditer(text):
        url = match.group("url") or match.group("import_url") or ""
        verdict = origin.classify(url, page_url)
        if verdict:
            findings.append({
                "page": page_url,
                "kind": "external-css-resource",
                "detail": "%s -> %s" % (where, verdict[1]),
                "line": text.count("\n", 0, match.start()) + 1,
            })


def audit_page(path, public_root, origin, script_hashes, style_hashes, findings):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        html = handle.read()
    rel = os.path.relpath(path, public_root).replace(os.sep, "/")
    page_url = urljoin(origin.base.rstrip("/") + "/", rel)

    parser = PageParser(origin, page_url, findings)
    parser.feed(html)
    parser.close()

    for match in SCRIPT_RE.finditer(html):
        attrs, body = match.group(1), match.group(2)
        if re.search(r"\bsrc\s*=", attrs, re.IGNORECASE):
            continue  # an external script file; <script src> already checked
        if body.strip():
            script_hashes.add(sha256_token(body))
    for match in STYLE_RE.finditer(html):
        body = match.group(2)
        if body.strip():
            style_hashes.add(sha256_token(body))
        audit_css(body, page_url, origin, findings, "inline <style>")

    return len(html)


def audit_css_files(public_root, origin, findings):
    count = 0
    for root, dirs, files in os.walk(public_root):
        dirs.sort()
        for name in sorted(files):
            if not name.lower().endswith(".css"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, public_root).replace(os.sep, "/")
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            audit_css(text, urljoin(origin.base.rstrip("/") + "/", rel), origin, findings, "stylesheet " + rel)
            count += 1
    return count


def audit_status_json(public_root, findings):
    """The live panel is the point of the site: prove the export has its data."""
    path = os.path.join(public_root, "status.json")
    if not os.path.isfile(path):
        findings.append({
            "page": "status.json",
            "kind": "missing-status-json",
            "detail": "no status.json in the export; the live panel would sit empty (run scripts/health_probe.py)",
            "line": 0,
        })
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (ValueError, OSError) as exc:
        findings.append({
            "page": "status.json",
            "kind": "invalid-status-json",
            "detail": "cannot parse status.json: %s" % exc,
            "line": 0,
        })
        return None
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        findings.append({
            "page": "status.json",
            "kind": "invalid-status-json",
            "detail": "status.json does not declare schema %s" % SCHEMA,
            "line": 0,
        })
        return None
    summary = document.get("summary") or {}
    if not isinstance(summary.get("total"), int) or summary["total"] <= 0:
        findings.append({
            "page": "status.json",
            "kind": "invalid-status-json",
            "detail": "status.json summary.total is missing or zero",
            "line": 0,
        })
    return document


def main(argv):
    args = parse_args(argv)
    public_root = os.path.abspath(args.public)
    if not os.path.isdir(public_root):
        sys.stderr.write("site_audit: not a directory: %s\n" % public_root)
        return 2
    try:
        origin = Origin(args.base)
    except ValueError as exc:
        sys.stderr.write("site_audit: %s\n" % exc)
        return 2

    pages = []
    for root, dirs, files in os.walk(public_root):
        dirs.sort()
        for name in sorted(files):
            if name.lower().endswith((".html", ".htm")):
                pages.append(os.path.join(root, name))
    if not pages:
        sys.stderr.write("site_audit: no .html files under %s\n" % public_root)
        return 2

    findings = []
    script_hashes = set()
    style_hashes = set()
    for page in pages:
        audit_page(page, public_root, origin, script_hashes, style_hashes, findings)
    css_count = audit_css_files(public_root, origin, findings)
    document = audit_status_json(public_root, findings)

    report = {
        "base": origin.base,
        "pages": len(pages),
        "css_files": css_count,
        "script_hashes": sorted(script_hashes),
        "style_hashes": sorted(style_hashes),
        "status": {
            "schema": document.get("schema") if document else None,
            "summary": document.get("summary") if document else None,
        },
        "findings": findings,
    }
    if args.json:
        write_json(args.json, report)

    if findings:
        sys.stderr.write("site_audit: %d violation(s)\n" % len(findings))
        for item in findings:
            sys.stderr.write("  %s:%s [%s] %s\n" % (
                item["page"], item["line"], item["kind"], item["detail"]))
        sys.stderr.write("site_audit: refusing to emit CSP hashes for an artifact that "
                         "would make third-party requests or need 'unsafe-inline'\n")
        return 1

    if args.emit_csp:
        write_json(args.emit_csp, {
            "script_hashes": sorted(script_hashes),
            "style_hashes": sorted(style_hashes),
        })

    if not args.quiet:
        print("site_audit: %d page(s), %d stylesheet(s): no external subresource, "
              "no inline handler, no style attribute" % (len(pages), css_count))
        print("site_audit: inline CSP hashes: %d script, %d style" % (
            len(script_hashes), len(style_hashes)))
        for token in sorted(script_hashes):
            print("  script-src %s" % token)
        for token in sorted(style_hashes):
            print("  style-src  %s" % token)
        if report["status"]["summary"]:
            print("site_audit: status.json %s %s" % (
                report["status"]["schema"], report["status"]["summary"]))
    return 0


def write_json(path, value):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Audit a built POPOPX status export and emit its CSP hashes.")
    parser.add_argument("--public", default="public",
                        help="built export directory (default: public)")
    parser.add_argument("--base", default="https://status.popopx.chat/",
                        help="site origin (default: https://status.popopx.chat/)")
    parser.add_argument("--json", metavar="PATH",
                        help="write the full audit report as JSON")
    parser.add_argument("--emit-csp", metavar="PATH",
                        help="write {script_hashes, style_hashes} JSON for the vhost render")
    parser.add_argument("--quiet", action="store_true", help="print nothing on success")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))