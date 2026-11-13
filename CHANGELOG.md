# Changelog

Each version is a Git tag and a GitHub release. To switch to any version (to roll back or forward), run `./update.sh <version>`, e.g. `./update.sh v1.2.0`. Run `git checkout main && ./update.sh` to return to the latest version. See [Releases and rollback](README.md#releases-and-rollback).

All versions use the same database format, so you can move between them freely without losing device names, alert settings or history.

## v1.3.1 (2026-11-12)
- Releases: every version is now tagged and published as a GitHub release.
- `update.sh` can switch to any release (`./update.sh v1.2.0`) and list them (`./update.sh --list`).
- The dashboard header shows the running version.

## v1.3.0 (2026-11-12): HTTPS
- The dashboard is served over HTTPS by default on port 8443 with a self-signed certificate. The certificate is created on first start, reused, and renewed near expiry or when the host's name or IP changes.
- Plain HTTP on port 8080 redirects to HTTPS.
- Option to use your own certificate (`TLS=custom`) or turn HTTPS off (`TLS=off`).
- Certificate download and fingerprint in the dashboard header; HSTS when using a trusted certificate.
- New dependency: `cryptography` 50.0.2 (no known vulnerabilities).
- **Rolling back below this version** returns the dashboard to plain HTTP at `http://<host>:8080`.

## v1.2.0 (2026-11-12): DHCP reservations
- New **Reservations** tab: view DHCP reservations on a Linksys router, see whether each device is using its reserved IP, and add or remove reservations.
- Changes are opt-in (`LINKSYS_ALLOW_CHANGES=true`) and require a dashboard password.
- Each change is validated, backed up (`/data/router-backups`), verified, and automatically rolled back if any other router setting changed.

## v1.1.0 (2026-11-12): Linksys router integration
- Optional read-only integration with Linksys Velop/Atlas routers through their local JNAP API.
- IP map shows reserved addresses and which free addresses are outside the DHCP pool (safe for static IPs).
- Reservation descriptions and Linksys device names are used as device names, including in alerts.

## v1.0.0 (2026-11-12): First release
- ARP-based device discovery, device inventory with vendor and hostname, connection time, and IP address map.
- Per-device drop-off alerts by phone (ntfy, Pushover) and/or email (SMTP), plus optional new-device alerts.
- Activity log and REST API.
- Hardened container: runs as non-root with only the `NET_RAW` capability.
- Optional login, cross-site request protection, Host allow-list, and security headers.
- Fully pinned dependencies, audited with pip-audit (fixes for CVEs in starlette and h11, and a scapy advisory).
