#!/usr/bin/env python3
# Copyright (c) 2026 POPOPX (popopx.chat)
# SPDX-License-Identifier: AGPL-3.0-only
"""POPOPX infrastructure health probe.

Pure Python 3 standard library (3.6+). Probes the public POPOPX endpoints over
TCP/TLS/HTTP, measures latency, validates certificates, and writes one
same-origin JSON document that the status page fetches from /status.json.

The target list below is the monitoring matrix. It must stay in sync with the
`params.systems` list in config.yml; `--check-config` verifies that.

Usage:
    python3 scripts/health_probe.py                     # -> static/status.json
    python3 scripts/health_probe.py --output /var/www/status.popopx.chat/status.json
    python3 scripts/health_probe.py --stdout            # print instead of write
    python3 scripts/health_probe.py --check-config config.yml

Exit status:
    0  probe finished and the output was written (even if targets are down)
    1  invalid invocation or output could not be written
    2  --fail-on-down was passed and at least one target is not `up`
    3  --check-config found a mismatch between config.yml and this file
"""

from __future__ import print_function

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import math
import os
import socket
import ssl
import sys
import tempfile
import time

PROBE_VERSION = "1.0.0"
SCHEMA = "popopx.status.v1"
USER_AGENT = "POPOPX-StatusProbe/%s (+https://status.popopx.chat/)" % PROBE_VERSION
MAX_HEADER_BYTES = 16384
STATE_UP = "up"
STATE_DEGRADED = "degraded"
STATE_DOWN = "down"

TARGETS = (
    {
        "id": "smp1.popopx.im",
        "name": "SMP relay smp1",
        "host": "smp1.popopx.im",
        "port": 443,
        "path": "/",
        "kind": "relay",
        "extra_tls": (
            {
                "port": 5223,
                "pin_sha256": "b42184c92a2e5bc9e555144adfad5160608f4cae12ad11bcb83fe07418dc361c",
            },
        ),
    },
    {
        "id": "popopx.chat",
        "name": "POPOPX official website",
        "host": "popopx.chat",
        "port": 443,
        "path": "/",
        "kind": "website",
        "extra_tls": (),
    },
    {
        "id": "node.popopx.chat",
        "name": "POPOPX Mac Node portal",
        "host": "node.popopx.chat",
        "port": 443,
        "path": "/",
        "kind": "website",
        "extra_tls": (),
    },
    {
        "id": "mp.popopx.chat",
        "name": "POPOPX service suite portal",
        "host": "mp.popopx.chat",
        "port": 443,
        "path": "/",
        "kind": "website",
        "extra_tls": (),
    },
    {
        "id": "bot.popopx.chat",
        "name": "POPOPX Bot Studio portal",
        "host": "bot.popopx.chat",
        "port": 443,
        "path": "/",
        "kind": "website",
        "extra_tls": (),
    },
    {
        "id": "bpay.popopx.im",
        "name": "POPOPX BTCPay bot",
        "host": "bpay.popopx.im",
        "port": 443,
        "path": "/",
        "kind": "service",
        "extra_tls": (),
    },
)


def utc_now_iso():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def elapsed_ms(start):
    return round((time.monotonic() - start) * 1000.0, 1)


def cert_days_left(cert):
    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        return None
    try:
        expires = ssl.cert_time_to_seconds(not_after)
    except (ValueError, TypeError):
        return None
    remaining = int(math.floor((expires - time.time()) / 86400.0))
    return remaining


def read_http_status(sock):
    """Read the response head, return the integer status code."""
    buffer = b""
    while b"\r\n\r\n" not in buffer and len(buffer) < MAX_HEADER_BYTES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
    head = buffer.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    parts = head.split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ValueError("unexpected HTTP response: %r" % head[:80])
    return int(parts[1])


def probe_extra_tls(host, spec, timeout, verified_context, pinned_context):
    """Probe an additional TLS port.

    The SMP relay's native port (5223) uses a self-signed, client-pinned
    certificate chain, exactly as the SMP protocol expects. Public CA
    verification would always fail there, so those ports are checked with a
    handshake plus an explicit SHA-256 pin instead. Ports without a pin are
    verified against the system trust store.
    """
    port = int(spec["port"])
    pin = spec.get("pin_sha256")
    context = pinned_context if pin else verified_context
    started = time.monotonic()
    entry = {
        "port": port,
        "ok": False,
        "tls_version": None,
        "cert_sha256": None,
        "pin_sha256": pin,
        "pin_match": None,
        "latency_ms": None,
        "error": None,
    }
    raw = None
    tls = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        tls = context.wrap_socket(raw, server_hostname=host)
        entry["tls_version"] = tls.version()
        if pin:
            der = tls.getpeercert(binary_form=True)
            digest = hashlib.sha256(der).hexdigest() if der else None
            entry["cert_sha256"] = digest
            entry["pin_match"] = digest == pin
            entry["ok"] = bool(digest) and digest == pin
            if not entry["ok"]:
                entry["error"] = "pinned certificate mismatch"
        else:
            entry["ok"] = True
    except (OSError, ssl.SSLError) as exc:
        entry["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        entry["latency_ms"] = elapsed_ms(started)
        for sock in (tls, raw):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return entry


def probe_target(target, timeout, context, pinned_context):
    host = target["host"]
    port = target["port"]
    path = target.get("path", "/")
    started = time.monotonic()
    result = {
        "id": target["id"],
        "name": target["name"],
        "host": host,
        "port": port,
        "url": "https://%s%s" % (host, path),
        "kind": target.get("kind", "website"),
        "state": STATE_DOWN,
        "ok": False,
        "http_status": None,
        "tls": {
            "ok": False,
            "version": None,
            "cert_days_left": None,
            "cert_not_after": None,
        },
        "latency_ms": {
            "tcp": None,
            "tls": None,
            "http": None,
            "total": None,
        },
        "extra_tls": [],
        "error": None,
        "checked_at": utc_now_iso(),
    }

    raw = None
    tls = None
    try:
        connect_started = time.monotonic()
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            raw.settimeout(timeout)
            result["latency_ms"]["tcp"] = elapsed_ms(connect_started)
        except OSError as exc:
            result["error"] = "TCP connect failed: %s" % exc
            return result

        handshake_started = time.monotonic()
        try:
            tls = context.wrap_socket(raw, server_hostname=host)
            result["latency_ms"]["tls"] = elapsed_ms(handshake_started)
        except ssl.SSLError as exc:
            result["tls"]["ok"] = False
            result["error"] = "TLS handshake failed: %s" % exc
            result["state"] = STATE_DEGRADED
            return result

        cert = tls.getpeercert()
        result["tls"] = {
            "ok": True,
            "version": tls.version(),
            "cert_days_left": cert_days_left(cert),
            "cert_not_after": cert.get("notAfter") if cert else None,
        }

        request_started = time.monotonic()
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ) % (path, host, USER_AGENT)
        tls.sendall(request.encode("ascii", "replace"))
        status = read_http_status(tls)
        result["latency_ms"]["http"] = elapsed_ms(request_started)
        result["http_status"] = status
        result["latency_ms"]["total"] = elapsed_ms(started)
        result["ok"] = 200 <= status < 400
        result["state"] = STATE_UP if result["ok"] else STATE_DEGRADED
        if not result["ok"]:
            result["error"] = "HTTP status %d" % status
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["latency_ms"]["total"] = elapsed_ms(started)
        if result["tls"]["ok"]:
            result["state"] = STATE_DEGRADED
            result["error"] = "HTTP probe failed: %s" % exc
        elif result["latency_ms"]["tcp"] is not None:
            result["state"] = STATE_DEGRADED
            result["error"] = "TLS probe failed: %s" % exc
        else:
            result["state"] = STATE_DOWN
            result["error"] = str(exc)
        return result
    finally:
        for sock in (tls, raw):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    if result["latency_ms"]["total"] is None:
        result["latency_ms"]["total"] = elapsed_ms(started)

    for spec in target.get("extra_tls", ()):
        extra = probe_extra_tls(host, spec, timeout, context, pinned_context)
        result["extra_tls"].append(extra)
        if not extra["ok"] and result["state"] == STATE_UP:
            result["state"] = STATE_DEGRADED
            if not result["error"]:
                result["error"] = "TLS port %s failed: %s" % (extra["port"], extra["error"])

    result["checked_at"] = utc_now_iso()
    return result


def build_document(results, timeout):
    counts = {STATE_UP: 0, STATE_DEGRADED: 0, STATE_DOWN: 0}
    for result in results:
        counts[result["state"]] = counts.get(result["state"], 0) + 1
    if counts[STATE_DOWN]:
        overall = STATE_DOWN
    elif counts[STATE_DEGRADED]:
        overall = STATE_DEGRADED
    else:
        overall = STATE_UP
    latencies = [
        r["latency_ms"]["total"]
        for r in results
        if isinstance(r["latency_ms"].get("total"), (int, float))
    ]
    return {
        "schema": SCHEMA,
        "generated_at": utc_now_iso(),
        "probe": {
            "version": PROBE_VERSION,
            "timeout_s": timeout,
            "targets": len(results),
        },
        "summary": {
            "state": overall,
            "total": len(results),
            "up": counts[STATE_UP],
            "degraded": counts[STATE_DEGRADED],
            "down": counts[STATE_DOWN],
            "max_latency_ms": max(latencies) if latencies else None,
        },
        "targets": results,
    }


def write_atomic(path, document):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory)
    payload = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    fd, temp_path = tempfile.mkstemp(prefix=".status-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def check_config(config_path):
    """Compare the systems in config.yml with TARGETS (minimal line parser)."""
    hosts = []
    in_systems = False
    with open(config_path, "r") as handle:
        for line in handle:
            if line.strip() == "systems:" and line.startswith("  "):
                in_systems = True
                continue
            if in_systems:
                if line.startswith("    - name:"):
                    hosts.append(line.split(":", 1)[1].strip().strip("'\""))
                elif line.strip() and not line.startswith("    "):
                    break
    expected = [target["id"] for target in TARGETS]
    if hosts == expected:
        print("config.yml systems match health_probe.py targets (%d)" % len(hosts))
        return 0
    sys.stderr.write("config.yml systems do not match health_probe.py targets\n")
    sys.stderr.write("  config.yml: %s\n" % ", ".join(hosts) if hosts else "  config.yml: <none found>\n")
    sys.stderr.write("  probe     : %s\n" % ", ".join(expected))
    return 3


def main(argv=None):
    parser = argparse.ArgumentParser(description="Probe POPOPX infrastructure and write status.json")
    parser.add_argument("--output", default="static/status.json", help="output path (default: static/status.json)")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-connection timeout in seconds (default: 8)")
    parser.add_argument("--stdout", action="store_true", help="print the JSON document instead of writing a file")
    parser.add_argument("--quiet", action="store_true", help="do not print the human summary")
    parser.add_argument("--fail-on-down", action="store_true", help="exit 2 unless every target is up")
    parser.add_argument("--check-config", metavar="PATH", help="verify TARGETS against config.yml systems, then exit")
    parser.add_argument("--version", action="version", version="%(prog)s " + PROBE_VERSION)
    args = parser.parse_args(argv)

    if args.check_config:
        return check_config(args.check_config)

    if args.timeout <= 0:
        sys.stderr.write("--timeout must be positive\n")
        return 1

    context = ssl.create_default_context()
    pinned_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pinned_context.check_hostname = False
    pinned_context.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    results = []
    workers = min(8, len(TARGETS)) or 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(probe_target, target, args.timeout, context, pinned_context) for target in TARGETS]
        for future in futures:
            try:
                results.append(future.result())
            except Exception as exc:  # keep the document shape even on a bug
                results.append({
                    "id": "unknown",
                    "name": "unknown",
                    "host": "unknown",
                    "port": 0,
                    "url": "",
                    "kind": "unknown",
                    "state": STATE_DOWN,
                    "ok": False,
                    "http_status": None,
                    "tls": {"ok": False, "version": None, "cert_days_left": None, "cert_not_after": None},
                    "latency_ms": {"tcp": None, "tls": None, "http": None, "total": None},
                    "extra_tls": [],
                    "error": "probe crashed: %s" % exc,
                    "checked_at": utc_now_iso(),
                })

    document = build_document(results, args.timeout)
    if args.stdout:
        sys.stdout.write(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    else:
        write_atomic(args.output, document)

    if not args.quiet and not args.stdout:
        summary = document["summary"]
        print(
            "POPOPX status probe: %d up, %d degraded, %d down in %.2fs"
            % (summary["up"], summary["degraded"], summary["down"], time.monotonic() - started)
        )
        for result in results:
            latency = result["latency_ms"].get("total")
            latency_text = ("%6.1f ms" % latency) if isinstance(latency, (int, float)) else "     n/a"
            print("  %-6s %-18s %s" % (result["state"], result["host"], latency_text))
        if not args.stdout:
            print("written: %s" % args.output)

    if args.fail_on_down and document["summary"]["state"] != STATE_UP:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())