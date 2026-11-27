# Deploying status.popopx.chat

Artifacts in this directory:

| File | Purpose |
| --- | --- |
| `deploy_centos.sh` | Idempotent publisher: audit, web-root backup, rsync mirror, certbot, nginx vhost, probe timer |
| `nginx-status.popopx.chat.conf` | nginx vhost template; CSP hash placeholders are filled from the export being published |

The script targets RHEL-family hosts (dnf or yum): CentOS Stream, CentOS 8,
Rocky, AlmaLinux, RHEL. It refuses to run on a host with `apt-get`.

## Prerequisites

- DNS for `status.popopx.chat` already points at the host. Certbot's HTTP-01
  challenge cannot succeed before that; the script stops with the exact reason.
- Ports 80 and 443 reachable from the Internet.
- Python 3.6+ on the host with OpenSSL 1.1.1 or newer, so the probe can
  complete the Ed448 handshake on the SMP relay's 5223 port. The script warns
  when the host Python cannot do it instead of silently reporting the relay
  degraded.
- For the default deployment path, nothing else: nginx, rsync, certbot and
  firewalld handling are installed by the script from the host's enabled repos
  (certbot may come from EPEL; no other third-party repository is enabled).

## Build on a workstation, publish on the host

```sh
# workstation
python3 scripts/health_probe.py
hugo --minify --gc
COPYFILE_DISABLE=1 tar -czf status-popopx-dist.tgz -C public .
scp status-popopx-dist.tgz HOST:/tmp/

# host
sudo mkdir -p /srv/status-popopx-dist
sudo tar -xzf /tmp/status-popopx-dist.tgz -C /srv/status-popopx-dist
sudo ./deploy/centos/deploy_centos.sh \
    --source /srv/status-popopx-dist --email ops@popopx.chat
```

`COPYFILE_DISABLE=1` matters: BSD tar otherwise adds AppleDouble `._name`
entries, and the script refuses to publish an export containing them.

Or let the host build (needs Hugo 0.120.x and outbound HTTPS on the host):

```sh
sudo ./deploy/centos/deploy_centos.sh --build-on-host --email ops@popopx.chat
```

## Flags

```
--source DIR        Publish DIR as the site (default: <repo>/public)
--build-on-host     Probe + `hugo --minify` on this machine first
--email ADDRESS     Let's Encrypt registration address; required unless --no-certbot
--no-certbot        Publish only; install the TLS vhost only if a certificate exists
--web-root PATH     Publish somewhere other than /var/www/status.popopx.chat
--skip-install      Install no packages (nginx, rsync, python3, certbot must exist)
--check             Preflight only: audit, hashes, vhost render; changes nothing
--dry-run           Print every mutating step; changes nothing
--yes, -y           Skip the confirmation prompt (required for non-interactive runs)
-h, --help          Usage
```

Unknown arguments are a hard stop.

## What a real run does, in order

1. Resolves the export, and requires a built `index.html` with the live panel
   plus a valid `status.json` (`schema: popopx.status.v1`, `summary.total > 0`).
2. Runs `scripts/site_audit.py` on the exact export: no third-party
   subresource, no inline handler, no `style=` attribute, no external
   `url()`/`@import`. The same run measures the inline `<script>`/`<style>`
   SHA-256 hashes.
3. Checks that `health_probe.py` targets and `config.yml` systems agree, and
   that the export's status rows match the number of configured systems.
4. Renders the vhost: substitutes the measured CSP hashes and, if `--web-root`
   moved the tree, rewrites `root`. It refuses a render that has zero hashes or
   residual `@...@` placeholders.
5. Backs up the current web root to `/var/backups/popopx/<domain>.<timestamp>.tar.gz`
   (outside the tree), then mirrors the export with `rsync --delete`, excluding
   `/.well-known/` so ACME files survive.
6. Applies SELinux context (`semanage fcontext` when available, `restorecon`
   either way) and opens 80/443 in firewalld only if firewalld is running and
   the ports are missing.
7. Obtains the certificate **before** installing a vhost that references it:
   a temporary ACME-only server serves the challenge, certbot runs, and the
   temporary server is removed. If certbot fails, the previous nginx config is
   restored and re-validated.
8. Installs `/etc/nginx/conf.d/status.popopx.chat.conf` only after
   `nginx -t` passes in an isolated prefix; then validates the live config and
   reloads nginx (never restarts). A rejected config is rolled back and the
   rollback is re-validated.
9. Installs the probe to `/opt/popopx-status/health_probe.py` and schedules it
   every 2 minutes: a systemd timer (`popopx-status-probe.timer`) when systemd
   runs, otherwise `/etc/cron.d/popopx-status-probe`. The probe writes
   `status.json` atomically, so nginx never serves a half-written file.
10. Runs a local TLS check with `curl --resolve` and prints the operator
    checklist (below), the backup paths and both rollback recipes.

## Verification

```sh
curl -s https://status.popopx.chat/ | grep -c 'live-status'            # 1
curl -s https://status.popopx.chat/status.json | head -c 200; echo
curl -sI https://status.popopx.chat/ | grep -i '^content-security-policy'
curl -sI https://status.popopx.chat/status.json | grep -i '^cache-control'   # no-store
curl -s https://status.popopx.chat/status.json | grep -o '"generated_at": *"[^"]*"'
systemctl list-timers popopx-status-probe.timer        # or: cat /etc/cron.d/popopx-status-probe
sudo certbot renew --dry-run
getenforce
sudo ausearch -m avc -ts recent | tail -n 20
sudo nginx -T | grep -c 'server_name  *status.popopx.chat'               # 2 (:80 + :443)
```

`generated_at` must advance every two minutes. The HTML must name no remote
host as a subresource; `site_audit.py` is the gate that distinguishes a
same-origin reference from an operator-click link.

## Rollback

Publish only (the vhost stays):

```sh
sudo mkdir -m 0755 -p /var/www/status.popopx.chat.restore
sudo tar -xzf /var/backups/popopx/status.popopx.chat.<timestamp>.tar.gz \
    -C /var/www/status.popopx.chat.restore
sudo mv /var/www/status.popopx.chat /var/www/status.popopx.chat.bad
sudo mv /var/www/status.popopx.chat.restore /var/www/status.popopx.chat
sudo restorecon -Rv /var/www/status.popopx.chat
sudo systemctl reload nginx
```

Vhost only: restore the `*.bak.<timestamp>.*` copy the script printed, or
remove the conf if this was the first deploy, then `nginx -t` and reload.

## Notes

- The vhost is a static-file server only: no PHP/Python handler, no proxy, no
  SPA fallback, dotfiles and source-file extensions denied, `status.json`
  served `no-store`, `index.html` revalidated on every load, hashed static
  assets absent by design (all CSS/JS is inline and hashed in the CSP).
- `listen 443 ssl http2;` uses the parameter form because the production host
  runs nginx 1.14.1, where the standalone `http2 on;` directive does not exist.
  On nginx >= 1.25.1 `nginx -t` prints a harmless deprecation notice.
- The script never contacts this host from a workstation, never restarts nginx,
  never installs a vhost referencing a missing certificate, and never deletes
  the web root without writing a backup first.