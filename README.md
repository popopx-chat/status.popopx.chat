# status.popopx.chat

The POPOPX infrastructure status page: a static [Hugo](https://gohugo.io/) site
that reports the operational state of POPOPX relay nodes, the official website
matrix and ecosystem services.

Live state is not hand-edited. `scripts/health_probe.py` probes every target
over TCP, TLS and HTTP, writes one same-origin JSON document, and the page's
inline script mirrors that document onto the component matrix and the live
probe table.

```
health_probe.py ──> static/status.json ──> public/status.json
                                              │
                         browser fetch (same origin, every 60 s)
                                              ▼
                                component matrix + probe table
```

## Monitored targets

| Host | Category | Check |
| --- | --- | --- |
| `smp1.popopx.im` | Core relay network | HTTPS 443 (public CA) + SMP port 5223 (SHA-256 certificate pin) |
| `popopx.chat` | Official website matrix | HTTPS 443 (public CA) |
| `node.popopx.chat` | Official website matrix | HTTPS 443 (public CA) |
| `mp.popopx.chat` | Official website matrix | HTTPS 443 (public CA) |
| `bot.popopx.chat` | Official website matrix | HTTPS 443 (public CA) |
| `bpay.popopx.im` | Ecosystem services | HTTPS 443 (public CA) |

The list lives in two places that must agree: `TARGETS` in
`scripts/health_probe.py` and `params.systems` in `config.yml`.
`health_probe.py --check-config config.yml` fails when they drift.

The SMP relay's native port presents the self-signed, client-pinned certificate
the protocol expects, so it is verified by an explicit SHA-256 pin instead of a
CA chain. Everything else is verified against the system trust store.

## Requirements

- Hugo 0.120.x extended (this tree is built and audited with 0.120.4).
- Python 3.6+ with OpenSSL 1.1.1 or newer. The SMP 5223 handshake needs Ed448
  signature support; LibreSSL builds (including macOS system Python) lack it and
  will report that port as degraded even though the relay is healthy.

## Build and verify

```sh
python3 scripts/health_probe.py                # writes static/status.json
hugo --minify --gc                             # writes public/
python3 scripts/site_audit.py --public public \
    --base https://status.popopx.chat/ --emit-csp /tmp/status-csp.json
```

`site_audit.py` is the publish gate. It fails the build when any page loads a
third-party subresource, carries an inline event handler or `style=` attribute,
references an external `url()`/`@import`, or when `status.json` is missing or
does not match schema `popopx.status.v1`. On success it prints the hashes of
the one inline `<script>` and one inline `<style>` block; those exact hashes are
what the nginx vhost puts in its CSP (`deploy/centos/deploy_centos.sh` renders
them, so nobody copies a hash by hand).

`config.yml` sets `minify.disableHTML: true` deliberately. Hugo 0.120's HTML
minifier rewrites the inline panel script into invalid scoping (it assigns a
loop variable to the function's own name), which breaks the live updates. The
page is a few KB and gzip handles it; the script stays byte-exact and is
verified by the audit instead.

## Frontend behaviour

- `#live-status` fetches `status.json?t=<timestamp>` with `cache: 'no-store'`,
  every 60 s and whenever the tab becomes visible again.
- Probe states `up`/`degraded`/`down` map to the theme's
  `ok`/`disrupted`/`down` component states; the page banner, category rollups
  and header colour follow the worst state. A target missing from the document
  is shown as unknown and degrades the overall summary.
- Data older than 10 minutes is labelled stale, and the header's "Last updated"
  relative time is driven by the probe's `generated_at`, not by page load.
- If the fetch fails, the panel and the banner say the probe data is
  unavailable instead of claiming everything is healthy.
- With JavaScript disabled the static incident view is what remains; the
  noscript notice says live probe results cannot update.

## Deploy

`deploy/centos/` holds the nginx vhost and an idempotent deploy script for
RHEL-family hosts. The normal path is: build on a workstation, copy the export
to the host, and run the script, which audits the exact bytes it is about to
publish, obtains the certificate before installing a TLS vhost that references
it, mirrors the web root with a backup, and installs the probe as a systemd
timer (or `/etc/cron.d` on hosts without systemd) that refreshes `status.json`
every two minutes.

See [`deploy/centos/README.md`](deploy/centos/README.md) for the flag list,
verification commands and rollback.

## Repository layout

```
config.yml                     Hugo config: categories, systems, outputs
content/                       incidents and pages (no incidents recorded)
themes/popopx/                 vendored, rebranded status theme
static/                        logos, favicons; status.json is generated
scripts/health_probe.py        stdlib-only connectivity/TLS probe
scripts/site_audit.py          pre-publish compliance and CSP-hash audit
deploy/centos/                 nginx vhost + deploy script + runbook
```

## Licence

The source in this repository is **AGPL-3.0-only** — see [`LICENSE`](LICENSE).
The `LICENSE` file is the licence text itself and is not modified.

`themes/popopx/` is derived from the cState status theme by Mantas Vilčinskas,
which is MIT-licensed; its licence is preserved verbatim in
[`themes/popopx/LICENSE.md`](themes/popopx/LICENSE.md).

`POPOPX` and the POPOPX logo are marks of the POPOPX Chat project. AGPL-3.0
grants no licence to them; a fork must replace the marks.