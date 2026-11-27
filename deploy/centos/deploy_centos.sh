#!/usr/bin/env bash
#
# deploy_centos.sh -- publish the POPOPX infrastructure status page (a static
# Hugo build) onto a nginx web root, for RHEL-family hosts (dnf or yum: CentOS
# Stream, CentOS 8, Rocky, AlmaLinux, RHEL), and install the health probe that
# keeps status.json current.
#
# There are two ways to get the bytes onto the host:
#
#   THE WORKSTATION BUILDS (default; --source DIR)
#     workstation:  /tmp/popopx-hugo/hugo --minify --gc
#     workstation:  /opt/homebrew/bin/python3.11 scripts/health_probe.py
#     workstation:  COPYFILE_DISABLE=1 tar -czf status-popopx-dist.tgz -C public .
#     workstation:  scp status-popopx-dist.tgz HOST:/tmp/
#     host:         mkdir -p /srv/status-popopx-dist
#     host:         tar -xzf /tmp/status-popopx-dist.tgz -C /srv/status-popopx-dist
#     host:         sudo ./deploy/centos/deploy_centos.sh \
#                       --source /srv/status-popopx-dist --email you@example.com
#     (COPYFILE_DISABLE=1 matters: without it BSD tar adds AppleDouble "._name"
#      entries to the archive, and this script refuses an export that contains
#      them rather than publishing them to a public web root.)
#
#   THE HOST BUILDS (--build-on-host)
#     sudo ./deploy/centos/deploy_centos.sh --build-on-host
#     Needs `hugo` on PATH (0.120.x is what this repo is built and audited
#     with) and outbound HTTPS from the host, because the probe runs first to
#     write static/status.json before Hugo copies it into public/.
#
# What this script never does, on purpose:
#   * it never contacts the production host from a workstation: no ssh, no scp,
#     no rsync over a remote shell, no curl/wget to a server, no token, no
#     password, no credential path. The only network it uses is the one dnf,
#     yum and certbot need on the host itself.
#   * it never publishes a directory it cannot prove is this site's build.
#     scripts/site_audit.py must pass on the exact export: no third-party
#     subresource, no inline event handler, no style= attribute, and a valid
#     status.json whose schema is popopx.status.v1. The same run measures the
#     inline <script>/<style> hashes that go into the CSP.
#   * it never deletes web-root content without first writing an out-of-tree
#     tarball backup, and it never runs against a web root that contains the
#     repository this script is being read from.
#   * it never installs a vhost that the local nginx build cannot parse, and
#     never installs one that references a certificate that does not exist yet:
#     the certificate comes first. A rejected install is rolled back and the
#     rollback is re-validated with `nginx -t`.
#   * it never `restart`s nginx; it reloads, so other vhosts keep their sockets.
#   * it never enables a third-party package repository. certbot comes from the
#     enabled repos or EPEL (the same rule as the sibling node portal); the
#     status page itself needs no build toolchain on the host.
#
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only

set -euo pipefail

# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

DRY_RUN=0
SKIP_INSTALL=0
CHECK_ONLY=0
ASSUME_YES=0
SKIP_CERTBOT=0
BUILD_ON_HOST=0
WEB_ROOT_OVERRIDE=""
SOURCE_DIR="${SOURCE_DIR:-}"
CERT_EMAIL="${CERT_EMAIL:-}"
OS_RELEASE="${OS_RELEASE:-/etc/os-release}"

TLS_READY=0
BOOTSTRAP_LIVE=0
BACKUP_TAR=""
CONF_PREV_COPY=""
CONF_ORIGINAL_COPY=""
CONF_BACKUPS=""
NEEDS_YES_REASON=""
RENDERED_CONF=""
BOOTSTRAP_CONF=""
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/popopx-status-deploy.XXXXXX")"

# Nothing written by this script outside the two destination trees is meant to
# survive it, except the rendered vhost under --dry-run (it is the artifact
# worth looking at). The bootstrap ACME server is always removed.
cleanup_temp() {
  [[ -z "$BOOTSTRAP_CONF" || ! -f "$BOOTSTRAP_CONF" ]] || rm -f -- "$BOOTSTRAP_CONF"
  if [[ "$DRY_RUN" -eq 0 && "$CHECK_ONLY" -eq 0 ]]; then
    rm -rf -- "$TMP_DIR"
  fi
}
trap cleanup_temp EXIT

say()  { printf '%s\n' "$*"; }
info() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
ok()   { printf '[+] %s\n' "$*"; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

show_args() {
  local line
  line="$(printf '%q ' "$@")"
  printf '%s' "${line% }"
}

# plan: record (and show) one mutating step, then run it. The command is passed
# as argv and executed directly -- never through eval -- so a path with an
# apostrophe in its name is still exactly one path.
plan() {
  local line
  line="$(show_args "$@")"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'DRY-RUN  %s\n' "$line"
  else
    printf 'RUN      %s\n' "$line"
    "$@"
  fi
}

need() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
  done
}

file_digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "$1" 2>/dev/null | cut -c1-16
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" 2>/dev/null | cut -c1-16
  else
    printf 'no-sha256-tool'
  fi
}

install_conf() {
  local src="$1" label="$2"
  local pre_dir pre_conf
  pre_dir="$(mktemp -d)"
  pre_conf="${pre_dir}/nginx.conf"
  cat >"$pre_conf" <<PRE
pid ${pre_dir}/nginx.pid;
error_log ${pre_dir}/error.log crit;
events { worker_connections 16; }
http {
  include /etc/nginx/mime.types;
  access_log ${pre_dir}/access.log;
  client_body_temp_path ${pre_dir}/cbt;
  proxy_temp_path ${pre_dir}/pt;
  include ${src};
}
PRE
  say "--- nginx -t on ${label}, isolated from the live tree ---"
  if ! nginx -t -c "$pre_conf" -p "$pre_dir" 2>&1; then
    rm -rf -- "$pre_dir"
    die "the ${label} failed 'nginx -t' in isolation; the live config was not touched"
  fi
  rm -rf -- "$pre_dir"

  local slug="${2// /-}" CONF_BACKUP
  CONF_BACKUP="${NGINX_CONF_DST}.bak.${TS}.${slug}"
  if [[ -f "$NGINX_CONF_DST" ]]; then
    cp -a -- "$NGINX_CONF_DST" "$CONF_BACKUP"
    CONF_PREV_COPY="$CONF_BACKUP"
    CONF_BACKUPS+="$CONF_BACKUP"$'\n'
    [[ -n "$CONF_ORIGINAL_COPY" ]] || CONF_ORIGINAL_COPY="$CONF_BACKUP"
    ok "previous conf saved as $CONF_BACKUP"
  else
    CONF_PREV_COPY=""
    info "no existing $NGINX_CONF_DST (first deploy); nothing to back up"
  fi

  install -d -m 0755 /etc/nginx/conf.d
  install -m 0644 -o root -g root -- "$src" "$NGINX_CONF_DST"
  say "--- nginx -t on the full live config ---"
  if nginx -t 2>&1; then
    ok "live config valid"
  else
    if [[ -n "$CONF_PREV_COPY" && -f "$CONF_PREV_COPY" ]]; then
      cp -a -- "$CONF_PREV_COPY" "$NGINX_CONF_DST"
      if nginx -t 2>&1; then
        ok "previous conf restored and 'nginx -t' passes again"
      else
        warn "rollback copied the previous conf but 'nginx -t' still fails -- inspect $NGINX_CONF_DST by hand"
      fi
      warn "install of ${label} rejected: restored ${CONF_PREV_COPY}, nothing was reloaded"
    else
      rm -f -- "$NGINX_CONF_DST"
      if nginx -t 2>&1; then
        ok "installed file removed and 'nginx -t' passes again"
      else
        warn "removed the installed file but 'nginx -t' still fails -- inspect /etc/nginx by hand"
      fi
      warn "install of ${label} rejected: removed the file we created, nothing was reloaded"
    fi
    if [[ "$BOOTSTRAP_LIVE" -eq 1 && -n "$CONF_ORIGINAL_COPY" ]]; then
      warn "Note what is live right now: this run already reloaded the ACME-only bootstrap, so"
      warn "     $DOMAIN answers port 80 with 404 for everything except /.well-known/, and"
      warn "     there is no HTTPS block yet. Returning to the pre-run state is one command:"
      warn "       sudo cp -a $CONF_ORIGINAL_COPY $NGINX_CONF_DST && sudo nginx -t && sudo systemctl reload nginx"
    fi
    die "nginx -t failed for the ${label}"
  fi

  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx
    ok "nginx reloaded (graceful; no dropped connections)"
  else
    info "nginx is installed but not running yet; enabling and starting it once"
    systemctl enable --now nginx
    ok "nginx started"
  fi
}

# render_conf: expand the two CSP hash placeholders with the hashes measured
# from THIS export, and rewrite the root directive if --web-root moved it. Both
# rewrites are counted; nginx only ever sees the checked result, because every
# install path goes through `nginx -t` in install_conf.
render_conf() {
  RENDERED_CONF="${TMP_DIR}/vhost.rendered"
  "$PYTHON_BIN" - "$CSP_HASHES" "$CONF_SRC" "$RENDERED_CONF" "$WEB_ROOT" "$CONF_ROOT" <<'PY'
import json
import re
import sys

hashes_path, src, dst, web_root, conf_root = sys.argv[1:6]
with open(hashes_path, "r", encoding="utf-8") as handle:
    hashes = json.load(handle)
script = "".join(" '%s'" % token for token in hashes.get("script_hashes", []))
style = "".join(" '%s'" % token for token in hashes.get("style_hashes", []))
if not hashes.get("script_hashes"):
    raise SystemExit("refusing a CSP with no inline script hash")
if not hashes.get("style_hashes"):
    raise SystemExit("refusing a CSP with no inline style hash")

with open(src, "r", encoding="utf-8") as handle:
    text = handle.read()
for token in ("@CSP_SCRIPT_HASHES@", "@CSP_STYLE_HASHES@"):
    count = text.count(token)
    if count != 1:
        raise SystemExit("template has %d occurrence(s) of %s, expected exactly 1"
                         % (count, token))
text = text.replace("@CSP_SCRIPT_HASHES@", script).replace("@CSP_STYLE_HASHES@", style)
if "@CSP_" in text:
    raise SystemExit("unexpanded @CSP_ token left in the rendered vhost")

if web_root != conf_root:
    pattern = re.compile(r"(?m)^(\s*root\s+)" + re.escape(conf_root) + r"(;)")
    text, replaced = pattern.subn(lambda m: m.group(1) + web_root + m.group(2), text)
    if replaced == 0:
        raise SystemExit("no 'root %s;' directive found to rewrite" % conf_root)
    if re.search(r"(?m)^\s*root\s+" + re.escape(conf_root) + r";", text):
        raise SystemExit("a 'root %s;' directive survived the rewrite" % conf_root)
    print("root directives rewritten to %s: %d" % (web_root, replaced))

with open(dst, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
  if ! cmp -s "$CONF_SRC" "$RENDERED_CONF"; then
    info "vhost rendered: $RENDERED_CONF"
  fi
}

usage() {
  cat <<'USAGE'
usage: deploy_centos.sh [options]

  --source DIR        Publish DIR as the site. DIR must be a built Hugo export:
                      index.html with the live panel and a valid status.json.
                      Resolution order: --source, $SOURCE_DIR, <repo>/public.
  --build-on-host     Run the health probe and `hugo --minify` on this machine
                      first (needs hugo 0.120.x and outbound HTTPS here).
  --email ADDRESS     Let's Encrypt registration address. Required unless
                      --no-certbot, and only used when no certificate for this
                      name exists yet.
  --no-certbot        Do not run certbot. The files are still published, but the
                      TLS vhost is installed only if a certificate already
                      exists.
  --web-root <path>   Publish somewhere other than the root declared in
                      deploy/centos/nginx-status.popopx.chat.conf.
  --skip-install      Install no packages. nginx, rsync, python3 and (unless
                      --no-certbot) certbot must already be present.
  --check             Run the preflight (artifact audit, hashes, vhost render),
                      print the evidence, exit 0. Changes and asks nothing.
  --dry-run           Print every step that would change the system, change
                      nothing. Skips the confirmation prompt.
  --yes, -y           Skip the confirmation prompt (needed for any
                      non-interactive real run).
  -h, --help          Show this help.

Unknown arguments are a hard stop.
USAGE
}

# --------------------------------------------------------------------------
# arguments
# --------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)            DRY_RUN=1; shift ;;
    --skip-install)       SKIP_INSTALL=1; shift ;;
    --check)              CHECK_ONLY=1; shift ;;
    --yes|-y)             ASSUME_YES=1; shift ;;
    --no-certbot)         SKIP_CERTBOT=1; shift ;;
    --build-on-host)      BUILD_ON_HOST=1; shift ;;
    --email)              [[ $# -ge 2 ]] || die "--email needs a value"; CERT_EMAIL="$2"; shift 2 ;;
    --email=*)            CERT_EMAIL="${1#*=}"; shift ;;
    --source)             [[ $# -ge 2 ]] || die "--source needs a value"; SOURCE_DIR="$2"; shift 2 ;;
    --source=*)           SOURCE_DIR="${1#*=}"; shift ;;
    --web-root)           [[ $# -ge 2 ]] || die "--web-root needs a value"; WEB_ROOT_OVERRIDE="$2"; shift 2 ;;
    --web-root=*)         WEB_ROOT_OVERRIDE="${1#*=}"; shift ;;
    -h|--help)            usage; exit 0 ;;
    *)                    usage >&2; die "unknown argument: $1" ;;
  esac
done

# --------------------------------------------------------------------------
# where we are. Everything is derived from this file's own location, so no
# developer's absolute path is baked in. The domain and web root are read out
# of the conf, so the conf stays the single source of truth.
# --------------------------------------------------------------------------

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEPLOY_DIR/../.." && pwd)"
CONF_SRC="${DEPLOY_DIR}/nginx-status.popopx.chat.conf"
PROBE_SRC="${REPO_ROOT}/scripts/health_probe.py"
AUDIT_SRC="${REPO_ROOT}/scripts/site_audit.py"

[[ -f "$CONF_SRC" ]] || die "missing $CONF_SRC"
[[ -f "$PROBE_SRC" ]] || die "missing $PROBE_SRC"
[[ -f "$AUDIT_SRC" ]] || die "missing $AUDIT_SRC"
[[ -f "${REPO_ROOT}/config.yml" ]] || die "$REPO_ROOT does not look like the repo root (no config.yml)"

DOMAIN="$(awk '!/^[[:space:]]*#/ && $1=="server_name" {gsub(/;/,"",$2); print $2; exit}' "$CONF_SRC")"
[[ -n "$DOMAIN" ]] || die "could not read server_name from $CONF_SRC"

CONF_ROOT="$(awk '!/^[[:space:]]*#/ && $1=="root" {gsub(/;/,"",$2); print $2; exit}' "$CONF_SRC")"
WEB_ROOT="${WEB_ROOT_OVERRIDE:-$CONF_ROOT}"
[[ -n "$WEB_ROOT" && "${WEB_ROOT:0:1}" == "/" ]] || die "web root must be absolute (got: '$WEB_ROOT')"
WEB_ROOT="${WEB_ROOT%/}"
[[ -n "$WEB_ROOT" ]] || die "web root resolved to '/' -- refuse to continue"
[[ "$WEB_ROOT" != *" "* ]] || die "web root contains a space: '$WEB_ROOT' -- the vhost renderer does not support that"

if [[ -n "$SOURCE_DIR" ]]; then
  [[ -d "$SOURCE_DIR" ]] || die "--source is not a directory: $SOURCE_DIR"
  SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
fi

NGINX_CONF_DST="/etc/nginx/conf.d/${DOMAIN}.conf"
LIVE_CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
BACKUP_DIR="/var/backups/popopx"
TS="$(date +%Y%m%dT%H%M%S)"
BACKUP_TAR="${BACKUP_DIR}/${DOMAIN}.${TS}.tar.gz"
PROBE_BIN_DIR="/opt/popopx-status"
PROBE_DST="${PROBE_BIN_DIR}/health_probe.py"
CSP_HASHES="${TMP_DIR}/csp-hashes.json"
AUDIT_JSON="${TMP_DIR}/site-audit.json"

PYTHON_BIN="$(command -v python3 || true)"
[[ -n "$PYTHON_BIN" ]] || die "python3 is required (artifact audit, CSP hashes, health probe)"
[[ "$PYTHON_BIN" == /* ]] || PYTHON_BIN="$(cd "$(dirname "$PYTHON_BIN")" && pwd)/$(basename "$PYTHON_BIN")"

say ""
say "POPOPX infrastructure status deploy"
info "repo root      : $REPO_ROOT"
info "domain         : $DOMAIN"
info "web root       : $WEB_ROOT"
info "nginx conf dst : $NGINX_CONF_DST"
info "cert dir       : $LIVE_CERT_DIR"
info "python3        : $PYTHON_BIN ($("$PYTHON_BIN" -c 'import sys; print(sys.version.split()[0])' 2>/dev/null || echo unknown))"
say ""

# --------------------------------------------------------------------------
# 1. host sanity + package manager
# --------------------------------------------------------------------------

if [[ "$DRY_RUN" -eq 1 || "$CHECK_ONLY" -eq 1 ]]; then
  info "no-change mode (--dry-run/--check): root privileges are not required yet."
else
  [[ "$(id -u)" -eq 0 ]] || die "must run as root (or with sudo); re-run with --dry-run to see the plan"
fi

if command -v dnf >/dev/null 2>&1; then
  PM="dnf -y"
  info "package manager: dnf"
elif command -v yum >/dev/null 2>&1; then
  PM="yum -y"
  info "package manager: yum"
elif [[ "$SKIP_INSTALL" -eq 1 ]]; then
  PM=""
  info "--skip-install: no package manager needed"
else
  command -v apt-get >/dev/null 2>&1 && die "apt-get found: this script is the RHEL-family runbook (dnf/yum, SELinux, firewalld). Use a Debian-specific runbook instead, or pass --skip-install and provide nginx + rsync + certbot yourself."
  die "neither dnf nor yum found, and --skip-install is not set: this script will not guess your package manager."
fi

if [[ -r "$OS_RELEASE" ]]; then
  # shellcheck disable=SC1090
  . "$OS_RELEASE"
  info "distro         : ${PRETTY_NAME:-unknown}"
  case "${ID:-}" in
    centos|rocky|almalinux|rhel|fedora|ol|amzn) : ;;
    ubuntu|debian) die "ID='${ID}' is Debian-family; this runbook is for dnf/yum hosts (see the message above about apt)." ;;
    *) warn "ID='${ID:-unset}' is not a known RHEL-family id; continuing because dnf/yum is present." ;;
  esac
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  SYSTEMD_AVAILABLE=1
  info "init           : systemd (the probe gets a timer)"
else
  SYSTEMD_AVAILABLE=0
  info "init           : no running systemd; the probe falls back to /etc/cron.d"
fi

# --------------------------------------------------------------------------
# 2. resolve the export to publish
# --------------------------------------------------------------------------

say ""
say "=== 2. what gets published ==="

if [[ "$BUILD_ON_HOST" -eq 1 ]]; then
  if [[ -n "$SOURCE_DIR" ]]; then die "--build-on-host and --source are mutually exclusive"; fi
  command -v hugo >/dev/null 2>&1 || die "--build-on-host needs hugo on PATH (this repo is built with 0.120.4 extended). Build on the workstation instead and pass --source."
  HUGO_VERSION="$(hugo version 2>&1 | { grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true; } | head -1)"
  info "mode: the host builds (hugo ${HUGO_VERSION:-unknown})"
  if [[ "$HUGO_VERSION" != "0.120.4" ]]; then
    warn "this repo is pinned and audited with hugo 0.120.4; ${HUGO_VERSION:-another version} may render different bytes (the CSP hashes are recomputed, so the page still works -- but templates can change)."
  fi
  say "--- health probe first: static/status.json must exist before Hugo runs ---"
  plan "$PYTHON_BIN" "$PROBE_SRC" --output "${REPO_ROOT}/static/status.json" --quiet --timeout 10
  say "--- hugo build ---"
  plan hugo --minify --gc --cleanDestinationDir --source "$REPO_ROOT"
  SOURCE_DIR="${REPO_ROOT}/public"
  if [[ "$DRY_RUN" -eq 1 && ! -d "$SOURCE_DIR" ]]; then
    die "--build-on-host --dry-run needs an existing $SOURCE_DIR to audit; run a real build once, or pass --source"
  fi
else
  [[ -n "$SOURCE_DIR" ]] || SOURCE_DIR="${REPO_ROOT}/public"
  if [[ ! -d "$SOURCE_DIR" ]]; then
    die "no built export at $SOURCE_DIR.
   Either publish one you built on the workstation:
     workstation:  /tmp/popopx-hugo/hugo --minify --gc
     workstation:  /opt/homebrew/bin/python3.11 scripts/health_probe.py
     workstation:  COPYFILE_DISABLE=1 tar -czf status-popopx-dist.tgz -C public .
     host:         mkdir -p /srv/status-popopx-dist && tar -xzf /tmp/status-popopx-dist.tgz -C /srv/status-popopx-dist
     host:         sudo ./deploy/centos/deploy_centos.sh --source /srv/status-popopx-dist --email <address>
   or let this host build it (needs hugo here):  --build-on-host"
  fi
fi

info "export dir     : $SOURCE_DIR"

# --- the export gate ------------------------------------------------------
# This is the gate that keeps a broken or leaking build off the web root: the
# auditor fails on a third-party request, an inline handler/style attribute,
# a missing or malformed status.json, and emits the CSP hashes from the same
# bytes. Nothing below installs a vhost until it has passed.
INDEX_HTML="${SOURCE_DIR}/index.html"
[[ -f "$INDEX_HTML" ]] || die "$INDEX_HTML is missing -- that is not a Hugo export"

say ""
say "--- artifact audit (third-party requests, inline code, status.json) ---"
if ! "$PYTHON_BIN" "$AUDIT_SRC" --public "$SOURCE_DIR" --base "https://${DOMAIN}/" \
      --emit-csp "$CSP_HASHES" --json "$AUDIT_JSON"; then
  die "the export failed the audit above. Refusing to publish it."
fi

grep -q 'live-status' "$INDEX_HTML" || die "$INDEX_HTML has no live-status panel; that is not this site's build."
grep -q 'data-status-url' "$INDEX_HTML" || die "$INDEX_HTML does not point the live panel at status.json."
grep -q 'status.json' "$INDEX_HTML" || die "$INDEX_HTML does not reference status.json."

PROBE_ROWS="$(grep -o 'data-probe-host=' "$INDEX_HTML" | wc -l | tr -d ' ')"
STATUS_TOTAL="$("$PYTHON_BIN" - "$SOURCE_DIR/status.json" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    print(json.load(handle)["summary"]["total"])
PY
)"
[[ "$PROBE_ROWS" -eq "$STATUS_TOTAL" ]] || die "the live panel has $PROBE_ROWS row(s) but status.json monitors $STATUS_TOTAL target(s); publish a build made from the same config.yml."
ok "export accepted: $PROBE_ROWS monitored row(s), status.json schema popopx.status.v1"

if ! "$PYTHON_BIN" "$PROBE_SRC" --check-config "${REPO_ROOT}/config.yml"; then
  die "scripts/health_probe.py targets and config.yml systems disagree (see above)."
fi

HASH_COUNTS="$("$PYTHON_BIN" - "$CSP_HASHES" <<'PY'
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print(len(data.get("script_hashes", [])), len(data.get("style_hashes", [])))
PY
)"
read -r SCRIPT_HASH_COUNT STYLE_HASH_COUNT <<<"$HASH_COUNTS"
[[ "$SCRIPT_HASH_COUNT" -ge 1 ]] || die "the audit measured no inline script hash; the CSP would block this site's only script."
[[ "$STYLE_HASH_COUNT" -ge 1 ]] || die "the audit measured no inline style hash; the CSP would block the theme's only stylesheet."
ok "CSP hashes measured: $SCRIPT_HASH_COUNT script, $STYLE_HASH_COUNT style"

render_conf
grep -q 'sha256-' "$RENDERED_CONF" || die "rendered vhost has no sha256- CSP token; refusing to install it"
ok "vhost rendered with the measured hashes"

EXPORT_JUNK="$(find "$SOURCE_DIR" -maxdepth 1 \( -name '.DS_Store' -o -name '._*' -o -name '.git' -o -name 'node_modules' -o -name 'deploy' -o -name 'scripts' -o -name 'themes' \) -print 2>/dev/null | head -n3 || true)"
[[ -z "$EXPORT_JUNK" ]] || die "the export holds non-build entries:
$(printf '%s\n' "$EXPORT_JUNK")
   Repack it from public/ on the workstation with BSD tar's resource fork off:
     COPYFILE_DISABLE=1 tar -czf status-popopx-dist.tgz -C public ."

EXPORT_FILES="$(find "$SOURCE_DIR" -type f | wc -l | tr -d ' ')"

# --------------------------------------------------------------------------
# 3. refusal gate: never delete the tree we are standing in
# --------------------------------------------------------------------------

if [[ "$SOURCE_DIR" == "$WEB_ROOT" ]]; then
  die "--source and --web-root are the same directory ($WEB_ROOT). Mirroring it onto itself would erase the export while publishing it."
fi
if [[ "$REPO_ROOT" == "$WEB_ROOT" || "$REPO_ROOT" == "$WEB_ROOT"/* ]]; then
  die "this script is being run from inside the web root:
   repo root : $REPO_ROOT
   web root  : $WEB_ROOT
   Publishing mirrors the web root to the export, which would delete the
   repository (and .git, and the very file bash is reading). Move the clone out
   first, then re-run from the new location."
fi
if [[ "$SOURCE_DIR" == "$WEB_ROOT"/* ]]; then
  die "the export lives inside the web root ($SOURCE_DIR inside $WEB_ROOT). Move it out (e.g. /srv) so the mirror cannot delete its own source."
fi

WEB_ROOT_JUNK=""
if [[ -d "$WEB_ROOT" ]]; then
  WEB_ROOT_JUNK="$(find "$WEB_ROOT" -maxdepth 1 \( -name '.git' -o -name 'src' -o -name 'node_modules' -o -name 'deploy' -o -name 'public' \) -print 2>/dev/null | sort | head -n6 || true)"
  if [[ -n "$WEB_ROOT_JUNK" ]]; then
    warn "the web root is not a build output; it holds repository content:"
    printf '%s\n' "$WEB_ROOT_JUNK" | sed 's/^/      /'
    warn "it will be replaced by the export, after a tarball backup."
  fi
fi

if [[ -f "$NGINX_CONF_DST" ]] && ! cmp -s "$NGINX_CONF_DST" "$RENDERED_CONF"; then
  NEEDS_YES_REASON="the already-installed vhost at $NGINX_CONF_DST is not the file this run would install"
  warn "$NEEDS_YES_REASON."
  say "   installed sha256 $(file_digest "$NGINX_CONF_DST")  |  about to install sha256 $(file_digest "$RENDERED_CONF")"
  say "   first directives of the installed file:"
  grep -vE '^[[:space:]]*(#|$)' "$NGINX_CONF_DST" 2>/dev/null | head -n 4 | sed 's/^/      /'
fi

SHADOWS=""
if [[ -d /etc/nginx/conf.d ]]; then
  DOMAIN_RE="${DOMAIN//./\\.}"
  SHADOWS="$(grep -lE "server_name[^;]*${DOMAIN_RE}" /etc/nginx/conf.d/*.conf 2>/dev/null | grep -vF "$NGINX_CONF_DST" || true)"
fi
if [[ -n "$SHADOWS" ]]; then
  warn "another conf.d file also declares server_name $DOMAIN:"
  printf '%s\n' "$SHADOWS" | sed 's/^/      /'
  say "   nginx resolves a duplicate by include order; resolve this before the site can be trusted, or the rollback puts you back here."
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  say ""
  ok "--check: preflight finished, nothing was changed."
  say "   export     : $SOURCE_DIR ($EXPORT_FILES files, $PROBE_ROWS rows)"
  say "   web root   : $WEB_ROOT"
  say "   vhost      : $NGINX_CONF_DST"
  say "   rendered   : $RENDERED_CONF"
  if [[ -f "${LIVE_CERT_DIR}/fullchain.pem" ]]; then CERT_STATE="present"; else CERT_STATE="not present yet"; fi
  if [[ "$SYSTEMD_AVAILABLE" -eq 1 ]]; then INIT_STATE="yes"; else INIT_STATE="no (cron fallback)"; fi
  say "   certificate: $CERT_STATE"
  say "   systemd    : $INIT_STATE"
  exit 0
fi

if [[ "$DRY_RUN" -eq 0 && "$ASSUME_YES" -eq 0 ]]; then
  say ""
  if [[ -n "$NEEDS_YES_REASON" ]]; then
    printf '%s\n' "About to: back up $WEB_ROOT, mirror the export over it, obtain a certificate,"
    printf '%s\n' "replace $NGINX_CONF_DST (which is not the file this run would install), and install"
    printf '%s\n' "the health-probe timer."
  else
    printf '%s\n' "About to: back up $WEB_ROOT, mirror the export over it, obtain a certificate,"
    printf '%s\n' "install the vhost, and install the health-probe timer."
  fi
  if [[ ! -t 0 ]]; then
    die "no terminal to ask for confirmation and --yes was not passed; refusing to change this machine from a non-interactive run."
  fi
  printf 'Proceed with the steps above? [y/N] '
  read -r REPLY || REPLY=""
  case "$REPLY" in
    [yY]|[yY][eE][sS]) : ;;
    *) say "aborted by operator; nothing was changed."; exit 0 ;;
  esac
fi

# --------------------------------------------------------------------------
# 4. packages
# --------------------------------------------------------------------------

say ""
say "=== 4. packages ==="

if [[ "$SKIP_INSTALL" -eq 1 ]]; then
  MISSING=()
  for p in nginx rsync; do
    command -v "$p" >/dev/null 2>&1 || MISSING+=("$p")
  done
  if [[ "$SKIP_CERTBOT" -eq 0 ]]; then
    command -v certbot >/dev/null 2>&1 || MISSING+=("certbot")
  fi
  if [[ "${#MISSING[@]}" -gt 0 ]]; then
    warn "--skip-install set, but these are missing: ${MISSING[*]}"
    say "   install them yourself, or re-run without --skip-install."
  else
    ok "--skip-install: everything required is already present."
  fi
else
  plan $PM install nginx rsync
  if [[ "$SKIP_CERTBOT" -eq 0 ]] && ! command -v certbot >/dev/null 2>&1; then
    if $PM list available certbot >/dev/null 2>&1; then
      info "certbot is available in the enabled repos; no repository changes needed"
    else
      plan $PM install epel-release
    fi
    plan $PM install certbot
  fi
fi

if ! command -v nginx >/dev/null 2>&1; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    warn "nginx is not installed yet; this dry run assumes the package step installs it. A real run stops here if it does not."
  else
    die "nginx is required for 'nginx -t' and 'systemctl reload nginx' and is not present (it would be installed without --skip-install)."
  fi
fi
if ! command -v rsync >/dev/null 2>&1; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    warn "rsync is not installed yet; this dry run assumes the package step installs it."
  else
    die "rsync is required: this script publishes by mirroring the web root to the export, and only rsync --delete can remove the previous release. Install it (${PM%% *} install -y rsync) or drop --skip-install."
  fi
fi

if [[ "$SKIP_CERTBOT" -eq 0 ]]; then
  if command -v certbot >/dev/null 2>&1; then
    ok "certbot available: $(certbot --version 2>/dev/null || echo 'unknown version')"
  elif [[ "$DRY_RUN" -eq 1 && "$SKIP_INSTALL" -eq 0 && -n "$PM" ]]; then
    warn "certbot is not installed yet; this dry run assumes '${PM} install certbot' succeeds. A real run stops here if it does not."
  else
    die "certbot is not installed and --no-certbot was not passed. Either install it (${PM%% *} install -y certbot) or re-run with --no-certbot."
  fi
fi

# --------------------------------------------------------------------------
# 5. nginx version facts, used by the HTTP/2 gate below
# --------------------------------------------------------------------------

nginx_version() {
  local raw
  raw="$(nginx -v 2>&1 | { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || true; } | head -1)"
  [[ -n "$raw" ]] && printf '%s' "$raw" || printf '0.0.0'
}

nginx_supports_http2_on() {
  local v major minor patch
  v="$(nginx_version)"
  IFS=. read -r major minor patch <<<"$v"
  patch="${patch:-0}"
  [[ "$major" -gt 1 ]] && return 0
  [[ "$major" -eq 1 && "$minor" -gt 25 ]] && return 0
  [[ "$major" -eq 1 && "$minor" -eq 25 && "$patch" -ge 1 ]] && return 0
  return 1
}

if command -v nginx >/dev/null 2>&1; then
  info "nginx version  : $(nginx_version) ($(nginx -v 2>&1 | head -1))"
fi

# --------------------------------------------------------------------------
# 6. backup of the current web root, outside the tree
# --------------------------------------------------------------------------

say ""
say "=== 6. web root backup ==="

if [[ -d "$WEB_ROOT" && -n "$(ls -A "$WEB_ROOT" 2>/dev/null || true)" ]]; then
  info "backing up the current web root to $BACKUP_TAR (outside the web root, so the mirror cannot delete its own backup)"
  plan mkdir -p -m 0750 -- "$BACKUP_DIR"
  plan tar -czf "$BACKUP_TAR" -C "$WEB_ROOT" .
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "dry run: the tarball is not written, so the rollback command in the summary is a plan, not a recovery option"
  fi
else
  info "web root is absent or empty: nothing to back up."
  BACKUP_TAR=""
fi

# --------------------------------------------------------------------------
# 7. publish: mirror the export onto the web root
# --------------------------------------------------------------------------
# Mirroring, not copying: stale pages from an older config must not survive a
# deploy. /.well-known/ is excluded from deletion because certbot --webroot
# writes into it and a renewal must not be interrupted by a publish.
# --------------------------------------------------------------------------

say ""
say "=== 7. publish $SOURCE_DIR -> $WEB_ROOT (mirror) ==="

plan install -d -m 0755 -- "$WEB_ROOT"

if [[ -d "$WEB_ROOT" ]]; then
  PRUNE_LIST="$(find "$WEB_ROOT" -mindepth 1 -maxdepth 1 -not -name '.well-known' -exec basename {} \; 2>/dev/null | sort || true)"
  KEEP_LIST="$(find "$SOURCE_DIR" -mindepth 1 -maxdepth 1 -exec basename {} \; 2>/dev/null | sort || true)"
  TO_DELETE="$(comm -23 <(printf '%s\n' "$PRUNE_LIST") <(printf '%s\n' "$KEEP_LIST") | grep -v '^$' || true)"
  if [[ -n "$TO_DELETE" ]]; then
    if [[ -n "$(printf '%s\n' "$TO_DELETE" | sed -n 2p)" ]]; then PLURAL="ies"; else PLURAL="y"; fi
    info "the mirror will remove $(printf '%s\n' "$TO_DELETE" | wc -l | tr -d ' ') top-level entr${PLURAL}:"
    printf '%s\n' "$TO_DELETE" | sed 's/^/      /'
  else
    info "the mirror removes nothing at the top level; the web root already matches the export."
  fi
fi

plan rsync -a --delete --exclude '/.well-known/' -- "$SOURCE_DIR/" "$WEB_ROOT/"

# --------------------------------------------------------------------------
# 8. ownership and modes: readable by nginx, never world-writable
# --------------------------------------------------------------------------

say ""
say "=== 8. owner / group / mode ==="

plan chown -R root:root "$WEB_ROOT"
plan find "$WEB_ROOT" -mindepth 1 -type d -exec chmod 0755 '{}' +
plan find "$WEB_ROOT" -mindepth 1 -type f -exec chmod 0644 '{}' +
info "owner root:root, dirs 0755, files 0644: nginx may read every file, nothing is group- or world-writable"

# --------------------------------------------------------------------------
# 9. SELinux (RHEL ships enforcing; a wrong context shows up as 403)
# --------------------------------------------------------------------------

say ""
say "=== 9. SELinux ==="

SELINUX_MODE="$(getenforce 2>/dev/null || echo Unknown)"
info "getenforce: $SELINUX_MODE"

SEMANAGE_OK=0
if command -v semanage >/dev/null 2>&1; then SEMANAGE_OK=1; fi

if [[ "$SELINUX_MODE" == "Disabled" ]]; then
  info "SELinux disabled: nothing to relabel."
elif [[ "$SEMANAGE_OK" -eq 1 ]]; then
  if semanage fcontext -l 2>/dev/null | grep -qF -- "${WEB_ROOT}(/.*)?"; then
    ok "fcontext rule for $WEB_ROOT already registered"
  else
    plan semanage fcontext -a -t httpd_sys_content_t "${WEB_ROOT}(/.*)?"
  fi
  plan restorecon -Rv -- "$WEB_ROOT"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if ! semanage fcontext -l 2>/dev/null | grep -qF -- "${WEB_ROOT}(/.*)?"; then
      semanage fcontext -a -t httpd_sys_content_t "${WEB_ROOT}(/.*)?"
    fi
    restorecon -Rv "$WEB_ROOT" >/dev/null
    ok "contexts set with semanage + restorecon (survives relabel and reboot)"
  fi
else
  warn "semanage is not available (policycoreutils-python-utils not installed)."
  say "   Falling back to chcon, which is NOT persistent: a relabel or an"
  say "   autorelabel reboot will drop these contexts and nginx will 403 again."
  say "   To fix permanently: ${PM:-dnf} install -y policycoreutils-python-utils"
  say "   then: semanage fcontext -a -t httpd_sys_content_t '${WEB_ROOT}(/.*)?'"
  say "   then: restorecon -Rv '${WEB_ROOT}'"
  plan chcon -Rt httpd_sys_content_t -- "$WEB_ROOT"
fi

# --------------------------------------------------------------------------
# 10. certificate -- BEFORE any vhost that references the pem files
# --------------------------------------------------------------------------

say ""
say "=== 10. certificate ==="

if [[ -f "${LIVE_CERT_DIR}/fullchain.pem" && -f "${LIVE_CERT_DIR}/privkey.pem" ]]; then
  ok "certificate already issued for $DOMAIN; reusing it"
  TLS_READY=1
  if command -v certbot >/dev/null 2>&1; then
    info "check expiry yourself: certbot certificates   # the renewal timer is what actually keeps this alive"
  fi
elif [[ "$SKIP_CERTBOT" -eq 1 ]]; then
  TLS_READY=0
  warn "--no-certbot and no certificate at $LIVE_CERT_DIR."
  say "   The files are published, but the TLS vhost in this repository is NOT"
  say "   installed, because it references $LIVE_CERT_DIR/*.pem and installing it"
  say "   without those files would fail 'nginx -t' for every vhost on this machine."
  say "   Finish TLS later with:"
  say "     sudo certbot certonly --webroot -w $WEB_ROOT -d $DOMAIN --email <address>"
  say "     sudo ./deploy/centos/deploy_centos.sh --source <same dir> --yes"
else
  [[ -n "$CERT_EMAIL" ]] || die "no certificate for $DOMAIN yet, so an email address is required for Let's Encrypt registration: pass --email you@example.com (or --no-certbot to defer TLS)."

  BOOTSTRAP_CONF="${TMP_DIR}/acme-bootstrap.conf"
  cat >"$BOOTSTRAP_CONF" <<BOOT
# Generated by deploy_centos.sh: HTTP surface for the ACME HTTP-01 challenge
# only, installed so certbot --webroot can answer, removed once the real vhost
# is in place. Not part of the repository.
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    root ${WEB_ROOT};
    charset utf-8;
    server_tokens off;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        try_files \$uri =404;
    }

    location = /.well-known/acme-challenge/ {
        return 404;
    }

    location / {
        return 404;
    }
}
BOOT
  info "bootstrap conf written: $BOOTSTRAP_CONF (ACME only; everything else 404 for the duration of the challenge)"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'DRY-RUN  install -m 0644 %s -> %s\n' "$BOOTSTRAP_CONF" "$NGINX_CONF_DST"
    printf 'DRY-RUN  nginx -t && systemctl reload nginx   # now serving /.well-known/acme-challenge/ only\n'
    printf 'DRY-RUN  certbot certonly --webroot -w %s -d %s --cert-name %s --non-interactive --agree-tos --email %s --key-type rsa --rsa-key-size 2048\n' "$WEB_ROOT" "$DOMAIN" "$DOMAIN" "$CERT_EMAIL"
    TLS_READY=1
    info "dry run assumes the ACME challenge succeeds; if it does not, the real run stops at this step and no vhost is installed"
  else
    install_conf "$BOOTSTRAP_CONF" "bootstrap ACME server"
    BOOTSTRAP_LIVE=1

    say "--- certbot certonly --webroot for $DOMAIN ---"
    if ! certbot certonly --webroot \
        -w "$WEB_ROOT" \
        -d "$DOMAIN" \
        --cert-name "$DOMAIN" \
        --non-interactive \
        --agree-tos \
        --email "$CERT_EMAIL" \
        --key-type rsa \
        --rsa-key-size 2048 \
        --keep-until-expiring; then
      rm -f -- "$BOOTSTRAP_CONF"
      if [[ -n "$CONF_PREV_COPY" && -f "$CONF_PREV_COPY" ]]; then
        cp -a -- "$CONF_PREV_COPY" "$NGINX_CONF_DST"
      else
        rm -f -- "$NGINX_CONF_DST"
      fi
      if nginx -t 2>&1; then
        systemctl reload nginx 2>/dev/null || true
        BOOTSTRAP_LIVE=0
        warn "certbot failed: the pre-run configuration is back in place and reloaded; this host serves what it served before the run"
      else
        warn "certbot failed and the pre-run configuration no longer passes 'nginx -t' -- look at $NGINX_CONF_DST before reloading anything"
      fi
      die "certbot could not issue a certificate for $DOMAIN.
   Most common causes, in order: DNS for $DOMAIN does not point at this host;
   port 80 is not reachable from the internet (cloud security group, not just
   firewalld); the Let's Encrypt rate limit. Re-run this script once it resolves."
    fi
    rm -f -- "$BOOTSTRAP_CONF"
    [[ -f "${LIVE_CERT_DIR}/fullchain.pem" ]] || die "certbot reported success but $LIVE_CERT_DIR/fullchain.pem is not there; investigate before re-running"
    ok "certificate issued for $DOMAIN"
    TLS_READY=1
  fi
fi

# --------------------------------------------------------------------------
# 11. the production vhost
# --------------------------------------------------------------------------

say ""
say "=== 11. nginx vhost -> $NGINX_CONF_DST ==="

if [[ "$TLS_READY" -eq 0 ]]; then
  info "skipped: no certificate for $DOMAIN, so the TLS vhost is NOT installed."
  say "   The repository conf is deliberately not half-installed either: its port-80"
  say "   block only redirects to HTTPS, and a 301 to a broken origin locks every"
  say "   visitor out."
  say "   What answers $DOMAIN right now: sudo nginx -T | grep -n 'server_name $DOMAIN'"
  say "   To finish TLS: sudo certbot certonly --webroot -w $WEB_ROOT -d $DOMAIN --email <address>"
  say "   then re-run this script (same flags) and it installs the vhost."
else
  if grep -qE '^[[:space:]]*http2[[:space:]]+on;' "$RENDERED_CONF" && ! nginx_supports_http2_on; then
    die "the vhost uses 'http2 on;' but nginx $(nginx_version) predates that directive (needs >= 1.25.1). The repository conf ships the 'listen 443 ssl http2;' parameter form."
  fi
  if nginx_supports_http2_on; then
    info "nginx $(nginx_version) may print a deprecation notice for 'listen ... http2' in nginx -t; harmless, and the form still works"
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'DRY-RUN  nginx -t on %s in a throwaway prefix, then install -> %s\n' "$RENDERED_CONF" "$NGINX_CONF_DST"
    printf 'DRY-RUN  systemctl reload nginx\n'
    info "rendered vhost left in place for inspection: $RENDERED_CONF"
  else
    install_conf "$RENDERED_CONF" "production vhost"
    BOOTSTRAP_LIVE=0
  fi
fi

# --------------------------------------------------------------------------
# 12. health probe: binary + timer (or cron) + a seed run
# --------------------------------------------------------------------------
# The page fetches /status.json every 60 s; without a probe it shows "No data".
# The probe runs as root with only its output directory writable
# (ProtectSystem=strict + ReadWritePaths), writes atomically, and never
# serves anything itself. The timer keeps the file at most ~2 minutes old.
# --------------------------------------------------------------------------

say ""
say "=== 12. health probe -> $PROBE_DST ==="

plan install -d -m 0755 -- "$PROBE_BIN_DIR"
plan install -m 0755 -o root -g root -- "$PROBE_SRC" "$PROBE_DST"

if [[ "$SYSTEMD_AVAILABLE" -eq 1 ]]; then
  PROBE_SERVICE_SRC="${TMP_DIR}/popopx-status-probe.service"
  PROBE_TIMER_SRC="${TMP_DIR}/popopx-status-probe.timer"
  cat >"$PROBE_SERVICE_SRC" <<UNIT
[Unit]
Description=POPOPX infrastructure status probe
Documentation=file://${PROBE_DST}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Nice=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${WEB_ROOT}
ExecStart=${PYTHON_BIN} ${PROBE_DST} --output ${WEB_ROOT}/status.json --quiet --timeout 10
TimeoutStartSec=90
UNIT
  cat >"$PROBE_TIMER_SRC" <<UNIT
[Unit]
Description=Run the POPOPX status probe every 2 minutes

[Timer]
OnBootSec=45s
OnUnitActiveSec=2min
AccuracySec=15s
Unit=popopx-status-probe.service

[Install]
WantedBy=timers.target
UNIT
  plan install -m 0644 -o root -g root -- "$PROBE_SERVICE_SRC" /etc/systemd/system/popopx-status-probe.service
  plan install -m 0644 -o root -g root -- "$PROBE_TIMER_SRC" /etc/systemd/system/popopx-status-probe.timer
  plan systemctl daemon-reload
  plan systemctl enable --now popopx-status-probe.timer
  plan systemctl start popopx-status-probe.service
else
  PROBE_CRON_SRC="${TMP_DIR}/popopx-status-probe.cron"
  cat >"$PROBE_CRON_SRC" <<CRON
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/2 * * * * root ${PYTHON_BIN} ${PROBE_DST} --output ${WEB_ROOT}/status.json --quiet --timeout 10
CRON
  plan install -m 0644 -o root -g root -- "$PROBE_CRON_SRC" /etc/cron.d/popopx-status-probe
  plan "$PYTHON_BIN" "$PROBE_DST" --output "${WEB_ROOT}/status.json" --quiet --timeout 10
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  [[ -f "${WEB_ROOT}/status.json" ]] || die "the probe did not write ${WEB_ROOT}/status.json; the live panel would have no data."
  # Surface the one host-dependent failure mode of the SMP pin check: a Python
  # built against LibreSSL (macOS system python) has no Ed448, so the 5223
  # self-signed chain cannot be verified there. CentOS 8's python3 uses
  # OpenSSL 1.1.1 and supports it. Report, do not fail: the probe itself
  # reports the real state, and a falsely degraded row is visible on the page.
  "$PYTHON_BIN" - "${WEB_ROOT}/status.json" <<'PY' || warn "status.json is written but could not be summarized"
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    document = json.load(handle)
summary = document["summary"]
print("[+] probe: %(state)s -- %(up)d up, %(degraded)d degraded, %(down)d down, "
      "max %(max_latency_ms)s ms" % summary)
for target in document.get("targets", []):
    if target.get("state") != "up":
        print("[!] probe target %s: state=%s error=%s" % (
            target.get("host"), target.get("state"), target.get("error")))
    for extra in target.get("extra_tls") or []:
        if not extra.get("ok"):
            print("[!] %s:%s TLS pin check failed: %s" % (
                target.get("host"), extra.get("port"), extra.get("error")))
            print("[!]   if this host's python3 uses LibreSSL, it has no Ed448 and cannot "
                  "verify the SMP self-signed chain; CentOS 8's python3 (OpenSSL 1.1.1) can.")
PY
fi

# --------------------------------------------------------------------------
# 13. firewall: look first, then only add what is missing
# --------------------------------------------------------------------------

say ""
say "=== 13. firewalld ==="

if ! command -v firewall-cmd >/dev/null 2>&1; then
  info "firewall-cmd not present: no firewall change (and no cloud security group here to remind you about)."
elif ! firewall-cmd --state >/dev/null 2>&1; then
  info "firewalld not running: no firewall change. If this host sits behind a cloud security group, open 80 and 443 there."
else
  FW_SERVICES="$(firewall-cmd --list-services 2>/dev/null || echo '')"
  info "currently allowed services: ${FW_SERVICES:-none}"
  FW_CHANGED=0
  case " ${FW_SERVICES} " in
    *" http "*)  ok "service 'http' already allowed; nothing to open" ;;
    *)           plan firewall-cmd --permanent --add-service=http; FW_CHANGED=1 ;;
  esac
  case " ${FW_SERVICES} " in
    *" https "*)  ok "service 'https' already allowed; nothing to open" ;;
    *)
      if [[ "$TLS_READY" -eq 1 ]]; then
        plan firewall-cmd --permanent --add-service=https; FW_CHANGED=1
      else
        info "not opening 'https' now: no certificate is configured yet"
      fi
      ;;
  esac
  if [[ "$DRY_RUN" -eq 0 && "$FW_CHANGED" -eq 1 ]]; then
    if firewall-cmd --reload >/dev/null 2>&1; then
      ok "firewalld reloaded"
    else
      warn "firewall-cmd --reload failed: the permanent rules were written but are not active yet"
    fi
  fi
fi

# --------------------------------------------------------------------------
# 14. local verification and the operator's checklist
# --------------------------------------------------------------------------

say ""
say "=== 14. self-verification ==="

if [[ "$DRY_RUN" -eq 0 && "$TLS_READY" -eq 1 ]] && command -v curl >/dev/null 2>&1; then
  say "--- local TLS probe (--resolve 127.0.0.1, no proxy, no DNS) ---"
  if curl -s --noproxy '*' --resolve "${DOMAIN}:443:127.0.0.1" -o /dev/null -w 'entry document: %{http_code}\n' "https://${DOMAIN}/"; then :; fi
  CSP_HEADER="$(curl -sI --noproxy '*' --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/" 2>/dev/null | { grep -i '^content-security-policy:' || true; })"
  if [[ -n "$CSP_HEADER" ]]; then
    case "$CSP_HEADER" in
      *sha256-*) ok "CSP header carries the measured inline hash(es), no unsafe-inline" ;;
      *)         warn "CSP header is present but has no sha256- token; check the rendered vhost" ;;
    esac
  else
    warn "no Content-Security-Policy header on the local HTTPS response"
  fi
  STATUS_CACHE="$(curl -sI --noproxy '*' --resolve "${DOMAIN}:443:127.0.0.1" "https://${DOMAIN}/status.json" 2>/dev/null | { grep -i '^cache-control:' || true; })"
  case "$STATUS_CACHE" in
    *no-store*) ok "status.json is served with Cache-Control: no-store" ;;
    *)          warn "status.json does not carry 'no-store' (got: ${STATUS_CACHE:-no header}); the live panel may show stale rows" ;;
  esac
fi

if [[ "$SYSTEMD_AVAILABLE" -eq 1 ]]; then
  PROBE_SCHEDULE="systemd timer"
  PROBE_TIMER_CHECK="systemctl list-timers popopx-status-probe.timer"
else
  PROBE_SCHEDULE="cron"
  PROBE_TIMER_CHECK="cat /etc/cron.d/popopx-status-probe"
fi
if [[ "$TLS_READY" -eq 1 ]]; then
  TLS_SUMMARY="ready, certificate at $LIVE_CERT_DIR"
else
  TLS_SUMMARY="NOT installed on this run (see step 10)"
fi
if [[ "$DRY_RUN" -eq 1 ]]; then
  BACKUP_NOTE="  (dry run: the tarball was not written)"
else
  BACKUP_NOTE=""
fi

say ""
cat <<EOF
  # the entry document is the BUILT one, and the live panel is wired
  curl -s --noproxy '*' https://${DOMAIN}/ | grep -c 'live-status'          # expect 1
  curl -s --noproxy '*' https://${DOMAIN}/status.json | head -c 200; echo

  # zero third-party requests: the HTML must name no remote host (each link is
  # same-origin or an operator click, never a subresource; site_audit.py is the
  # gate for that distinction)
  curl -s --noproxy '*' https://${DOMAIN}/ | grep -Eo 'https?://[A-Za-z0-9.-]+' | sort -u

  # strict CSP on every response
  curl -sI --noproxy '*' https://${DOMAIN}/ | grep -i '^content-security-policy'

  # probe freshness: generated_at must move every 2 minutes
  curl -s --noproxy '*' https://${DOMAIN}/status.json | grep -o '"generated_at": *"[^"]*"'
  ${PROBE_TIMER_CHECK}

  # TLS, once the certificate is in place
  curl -sI --noproxy '*' http://${DOMAIN}/ | sed -n 1p                          # expect 301
  curl -sI --noproxy '*' https://${DOMAIN}/ | grep -i strict-transport          # expect max-age=300
  echo | openssl s_client -servername ${DOMAIN} -connect ${DOMAIN}:443 2>/dev/null | openssl x509 -noout -subject   # expect CN=${DOMAIN}
  sudo certbot renew --dry-run

  # SELinux actually enforcing, and no AVC denials for httpd
  getenforce
  sudo ausearch -m avc -ts recent | tail -n 20

  # this vhost is the one nginx loaded, and no other file claims the name
  sudo nginx -T | grep -c 'server_name  *${DOMAIN}'                         # expect 2: the :80 and the :443 block, one conf
EOF

say ""
say "=== done ==="
say "web root     : $WEB_ROOT   (mirrored from $SOURCE_DIR, $EXPORT_FILES files)"
say "conf         : $NGINX_CONF_DST"
say "probe        : $PROBE_DST, every 2 minutes ($PROBE_SCHEDULE, output $WEB_ROOT/status.json)"
say "tls          : $TLS_SUMMARY"
if [[ -n "$BACKUP_TAR" ]]; then
  say "web root backup: $BACKUP_TAR   -- contains the previous web root. Delete it once you are satisfied.$BACKUP_NOTE"
fi
if [[ -n "$CONF_BACKUPS" ]]; then
  while IFS= read -r backup; do
    [[ -n "$backup" ]] || continue
    say "conf backup  : $backup"
  done <<<"$CONF_BACKUPS"
elif [[ "$DRY_RUN" -eq 1 ]]; then
  info "no conf backup written: this is a dry run."
else
  info "no conf backup: $NGINX_CONF_DST did not exist before this run."
fi
say ""
say "redeploy after a content change:"
say "  workstation: /tmp/popopx-hugo/hugo --minify --gc && /opt/homebrew/bin/python3.11 scripts/health_probe.py"
say "  workstation: COPYFILE_DISABLE=1 tar -czf status-popopx-dist.tgz -C public . && scp status-popopx-dist.tgz HOST:/tmp/"
say "  host:        tar -xzf /tmp/status-popopx-dist.tgz -C $SOURCE_DIR && sudo $(readlink -f "$0" 2>/dev/null || printf '%s' "$0") --source $SOURCE_DIR --yes"
say ""
if [[ -z "$BACKUP_TAR" ]]; then
  say "rollback the publish: no web-root backup was taken (the directory was absent or empty)."
else
  say "rollback the publish (NOT the vhost) -- extract next to the live root, then swap:"
  say "  sudo mkdir -m 0755 -p '/var/www/${DOMAIN}.restore'"
  say "  sudo tar -xzf $BACKUP_TAR -C '/var/www/${DOMAIN}.restore'"
  say "  sudo mv $WEB_ROOT '${WEB_ROOT}.bad' && sudo mv '/var/www/${DOMAIN}.restore' $WEB_ROOT"
  say "  sudo restorecon -Rv $WEB_ROOT           # relabel whatever tar could not carry"
  say "  sudo systemctl reload nginx             # then remove '${WEB_ROOT}.bad' once the site is verified"
fi
if [[ -n "$CONF_ORIGINAL_COPY" ]]; then
  say "rollback the vhost -- the file that was installed before this run is $CONF_ORIGINAL_COPY"
  say "  sudo cp -a $CONF_ORIGINAL_COPY $NGINX_CONF_DST && sudo nginx -t && sudo systemctl reload nginx"
else
  say "rollback the vhost: $NGINX_CONF_DST did not exist before this run, so"
  say "  sudo rm -f $NGINX_CONF_DST && sudo nginx -t && sudo systemctl reload nginx"
fi
if [[ "$DRY_RUN" -eq 1 ]]; then warn "dry run: no change was made to this host."; fi
exit 0