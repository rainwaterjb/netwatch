# Changelog

Each version is a Git tag and a GitHub release. To switch to any version (to roll back or forward), run `./update.sh <version>`, e.g. `./update.sh v1.2.0`. Run `git checkout main && ./update.sh` to return to the latest version. See [Releases and rollback](README.md#releases-and-rollback).

All versions use the same database format, so you can move between them freely without losing device names, alert settings or history.

## v1.7.0 (2026-11-18): New Overview dashboard with a timeline, and a Top domains tab
- **New Overview tab** (now the home screen), in a darker "control room" look used across the whole dashboard:
  - A status strip: internet, devices online, services, free addresses and DNS queries.
  - **Needs attention**: services that are down, critical devices offline, chatty devices and new devices, each with a one-click action.
  - The **address map** at a glance, **service checks** with trend lines, and a **live activity** feed that can hide brief blips (a device that was back within 5 minutes).
- **Timeline** on the Overview: internet outages, failed service checks, when each device was online, and DNS lookups per hour, on one shared time axis. Choose 6 hours, 24 hours or 7 days; filter by tag, critical devices, or only devices that dropped off. Select a device to open its details.
- **New Top domains tab** (when Pi-hole is connected): the busiest allowed and blocked domains across the network, the blocked share, and which devices looked up each domain. Pick a device to see its own top domains. A chatty device's "Top domains" button jumps straight there.
- New API endpoints: `GET /api/timeline?hours=6|24|168`, `GET /api/dns/top`, `GET /api/dns/domain?name=…`.
- No database changes; rolling back to v1.6.0 is safe.

## v1.6.0 (2026-11-18): More routers (OPNsense, pfSense, UniFi, OpenWrt)
- **Router integration now supports OPNsense, pfSense, UniFi and OpenWrt** as well as Linksys. Choose one with `ROUTER_TYPE`.
  - **OPNsense:** Dnsmasq or Kea DHCP (auto-detected), via API key + secret.
  - **pfSense:** DHCP static mappings, via the pfrest REST API package.
  - **UniFi:** client fixed IPs, via API key or a local admin account (UniFi OS and self-hosted controllers).
  - **OpenWrt:** `dhcp` host entries, via ubus JSON-RPC.
- Every router gets the same features: reservations and DHCP pool on the IP map, router device names, the Reservations tab, and optional add/remove of reservations.
- The same safeguards apply to every router: validation, a backup before each change, verification afterwards, and an automatic undo if the router didn't end up as expected.
- Each router's own rules are enforced and explained, e.g. pfSense needs reservations **outside** the DHCP pool and Linksys **inside** it. The IP suggestions in the Reservations tab follow the rule.
- New settings: `ROUTER_TYPE`, `ROUTER_URL`, `ROUTER_API_KEY`, `ROUTER_API_SECRET`, `ROUTER_USERNAME`, `ROUTER_PASSWORD`, `ROUTER_VERIFY_TLS`, `ROUTER_INTERFACE`, `ROUTER_SITE`, `ROUTER_DHCP`, `ROUTER_ALLOW_CHANGES`.
- **No action needed for existing Linksys setups:** the old `LINKSYS_*` settings still work.

## v1.5.1 (2026-11-17): Fewer false "offline" events from phones and tablets
- Before marking **any** device offline (not only watched ones), NetWatch now checks it directly one more time.
- The re-check sends the request straight to the device's MAC address first. Wi-Fi access points hold direct messages for devices in power-save mode, so dozing phones, tablets and laptops answer it even when they ignore the regular broadcast scan. A broadcast is still tried last, in case the device's address changed.
- Re-checks run in parallel, so scans stay fast with many devices.
- Devices that are really gone still go offline after the usual missed scans, and alerts work as before.

## v1.5.0 (2026-11-17): Service checks, internet tracking, Pi-hole, and more
New features:
- **Service checks** (new Services tab): watch a web page (HTTP/HTTPS), a TCP port or ping, with uptime %, response times, and alerts when a service goes down or comes back. Checks can follow a device, so they survive IP changes.
- **Internet outage tracking**: NetWatch checks your connection every 30 seconds and records outages, telling apart "the internet was down" from "the router was unreachable". You get an alert with the duration once it's back. Shows 24h/7d/30d uptime.
- **Pi-hole integration** (v6+, read-only, supports several Pi-holes): DNS queries per device (24 hours and last hour), top domains, and **chatty-device** detection when a device suddenly makes far more queries than usual, with optional alerts.
- **Wake-on-LAN** button for offline devices.
- **Quiet hours**: alerts are held overnight and sent as one summary when quiet hours end. Devices marked **Critical** still alert right away.
- **Snooze** alerts for a device (1 hour to 1 week).
- **Device detail panel** (click a device): presence timeline with availability % for 24h/7d/30d, IP history, recent activity, DNS activity, linked service checks, rename, tags, snooze and more.
- **New-devices inbox**: newly seen devices are marked NEW until you mark them as known, with a banner and a "New" filter.
- **Tags**: label devices (e.g. #servers, #iot), filter by tag, and turn alerts on or off for a whole tag at once.
- **Export**: download the device list as CSV, or a full database backup, from the new Settings tab.
- Alerts are also held while the internet is down and sent once it's back.

Compatibility:
- The database gains new columns and tables. Older versions ignore them, so rolling back with `./update.sh v1.4.0` still works (tested).
- Devices that existed before upgrading are treated as already known, so the inbox starts empty.

## v1.4.0 (2026-11-13): Mobile-friendly dashboard
- Responsive layout that works on phones and tablets. On narrow screens, the device, reservation and activity tables become stacked cards, and the header stats become compact tiles.
- Larger tap targets on touch screens, a horizontally scrolling tab bar, and a sort menu on phones (where column headers are hidden).
- Tap an IP-map cell or the HTTPS badge to see its details, since touch screens have no hover.
- Form fields no longer zoom the page on iPhone when tapped.

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
