# Changelog

Each version is a Git tag and a GitHub release. To switch to any version (to roll back or forward), run `./update.sh <version>`, e.g. `./update.sh v1.2.0`. Run `git checkout main && ./update.sh` to return to the latest version. See [Releases and rollback](README.md#releases-and-rollback).

All versions use the same database format, so you can move between them freely without losing device names, alert settings or history.

## v1.15.0 (2026-11-20): Themes and your own Home page
- **11 themes** in **Settings → Appearance**: Control Room (the original), Daylight, OLED Black, Fjord, Paper, Phosphor, Ember, Synthwave, Lagoon, High Contrast and Neon Grid. All text and status colors meet WCAG AA contrast in every theme.
- **Blue and orange status colors** as an option with any theme, for red-green color blindness, and **follow the device's light or dark setting** with a chosen light and dark theme.
- **Customizable Home page** (the Overview tab is now Home): drag or use arrows to reorder, S/M/L widths, remove and add widgets. 13 widgets, including new **Internet health**, **Top domains**, **Open alerts**, **New and unrecognized**, **Pinned devices**, **Device types** and **Quick actions**. Four starting layouts: Overview, At a glance, Troubleshooting and DNS watcher.
- **Pin to Home** in each device's details (up to 12 devices).
- **Pause alerts for an hour** from Quick actions (admins). Works like quiet hours: held alerts go out as a summary afterwards; critical devices still alert. Shown in the notice bar with **Resume now**. API: `POST /api/alerts/pause`.
- Theme and layout are saved per person (viewers too, and each API token separately) via `GET/PUT/DELETE /api/prefs`, and cleaned up when an account is deleted. Settings is now visible to viewers, showing only Appearance.
- The sign-in page follows the theme you used last on that browser.
- Fonts are bundled (SIL Open Font License), so the dashboard still loads nothing from outside your network.
- Database: one new table, `user_prefs`. **Rollback-safe**: older versions ignore it and show the original look and Overview.

## v1.14.0 (2026-11-18): Secure by default
- **No password, no dashboard.** If `WEB_PASSWORD` isn't set (and there are no accounts), the dashboard and API now stay closed and show a page explaining how to set it, instead of being open to anyone on the network. Scanning, alerts and the health check keep running. Set `ALLOW_NO_LOGIN=true` to keep the old open behaviour (not recommended).
- The example Prometheus + Grafana stack no longer ships a default Grafana password: it won't start until you set `GRAFANA_PASSWORD` in its own `.env`.
- README: screenshots from a demo network.
- Security review before the public release: secret scan of the full Git history, bandit static analysis, pip-audit (no known vulnerabilities) and a browser sweep that injected HTML into every device name, vendor, model, tag, check, rule, channel and DNS domain (nothing ran).
- No database changes. **Rollback-safe**, but an older version with no `WEB_PASSWORD` is open to the network again.

## v1.13.1 (2026-11-18): Updating follows releases
- `./update.sh` now installs the **latest release** instead of whatever is on the `main` branch, so a fresh install or an update always lands on a tested, published version. `./update.sh main` is there for trying unreleased fixes.
- `./update.sh --list` says when a newer release is out.
- README: the quick start installs the latest release, a new **Updating** section, a **Releases at a glance** table with what each release added and what switches off if you roll back past it, a current architecture diagram, release/CI/license badges, and up-to-date notification, security and limitation notes.
- `.env.example` now includes the Pi-hole, internet-outage, scan-timeout and log-level settings.
- No code changes to NetWatch itself. **Rollback-safe.**

## v1.13.0 (2026-11-18): Prometheus metrics, Grafana dashboard and JSON logs
- **Prometheus metrics** at `/metrics`, scraped with a read-only API token: devices (online, type, critical, connected time), addresses, internet (up, latency, uptime, outages), service checks, DNS (with Pi-hole), open alerts, alert-channel health, activity counts and scanner health. Checked with `promtool check metrics`.
- **Grafana dashboard** (`examples/monitoring/grafana/dashboards/netwatch.json`): status tiles, a device presence timeline, internet and service status, response times, devices over time, top DNS talkers, internet uptime, offline critical devices and activity. Every query was run against a real Prometheus 3.16 scraping NetWatch.
- **Prometheus alert rules** (`examples/monitoring/netwatch.rules.yml`) and an optional **Prometheus + Grafana Docker stack** with everything provisioned.
- **JSON logs** with `LOG_FORMAT=json` for Loki (via Grafana Alloy) or Vector; `LOG_ACTIVITY=true` adds every Activity entry as a structured log line.
- `METRICS=false` turns the endpoint off. No database changes and no new dependencies. **Rollback-safe.**

## v1.12.0 (2026-11-18): Installable app and push notifications
- **Install NetWatch as an app** on iPhone/iPad (Add to Home Screen), Android, Chrome/Edge (Install app button) and Mac (Add to Dock), with its own icon.
- **Native push notifications**, no ntfy or Pushover needed: turn them on per device under **Access → Notifications on this device**. They carry everything that goes to Phone (device checkboxes, internet and chatty alerts, the quiet-hours digest) and alert rules that send to the new **NetWatch app** destination. Escalations stay on screen; tapping opens NetWatch.
- Anyone signed in, including viewers, can turn notifications on for their own devices; admins can see and remove everyone's.
- The card explains exactly what's missing when notifications can't be turned on: the iPhone home-screen step, an untrusted certificate, or notifications blocked in the browser.
- **Security:** messages are end-to-end encrypted for each device (RFC 8291; verified against the RFC's test vector) and signed with NetWatch's own VAPID key (RFC 8292), kept in the data folder with owner-only permissions and left out of backups. Only known push services over HTTPS are allowed (no SSRF). The service worker caches nothing and only opens NetWatch pages.
- The Host allow-list (`ALLOWED_HOSTS`) now also covers the sign-in page and the app files; only the health check and certificate download are exempt.
- README: getting a free, trusted Let's Encrypt certificate through Cloudflare DNS without exposing NetWatch to the internet.
- The phone header no longer squeezes its buttons.
- No new dependencies. **Rollback-safe:** one new table; older versions ignore it.

## v1.11.0 (2026-11-18): Device recognition and private Wi-Fi addresses
- **Device recognition:** each device gets a type (phone, tablet, computer, TV, streaming player, speaker, printer, camera, smart home, console, network gear, server, watch), an icon, and often its model and OS. Learned from DHCP requests (name, vendor class, fingerprint), Bonjour/mDNS (AirPlay, Google Cast, printers, HomeKit…), UPnP/SSDP descriptions, the MAC manufacturer and the hostname. Admins can set the type by hand.
- **Private Wi-Fi addresses:** devices using a randomized MAC get a badge. When one rejoins under a new address with the same name (and DHCP fingerprint) as a known device, the Overview asks "… looks like Alex's iPhone": **Same device** moves the name, tags, alert settings and service checks to the new address and hides the old record; **Not the same** is remembered. Generic names never match, and devices online at the same time are never linked. Link and unlink by hand in the details window.
- **Automatic linking** (Settings → Device recognition, off by default) links clear-cut cases straight away, so a phone with a new private address doesn't raise a "new device" alert.
- Marking a device as known (or linking it) now closes its open "new device" rule alert.
- Security: the DHCP listener uses a kernel filter so only DHCP requests are read; UPnP descriptions are fetched only from the device that answered, over http, with no redirects, a 64 KB limit and no XML entities; everything devices say is length-limited and shown as plain text.
- `DISCOVERY=false` turns recognition off. No new dependencies.
- **Rollback-safe:** new columns and tables only. Older versions show linked old addresses as separate offline devices again.

## v1.10.0 (2026-11-18): Alert rules, new channels, escalation and acknowledgement
- **Alert rules** (new Alerts tab): choose what to be told about (device offline, new device, service down, internet down, chatty device), for which devices or checks (any, critical, a tag, or chosen ones), and **only if it lasts N minutes**. Brief blips send nothing and are noted in the Activity log.
- **Channels:** Discord, Slack, Telegram, Gotify, ntfy, webhooks (Home Assistant's webhook trigger works out of the box, with optional HMAC signing) and MQTT, alongside phone and email. Each has a Send test button and shows its last result.
- **Recovery messages**, **escalation** to other channels if an alert isn't acknowledged in time, and **acknowledgement** from the Overview or the Alerts tab. Read-only viewers can acknowledge too.
- **Bursts are grouped:** four or more alerts for one rule at once go out as a single summary. Failed deliveries are retried with back-off.
- Quiet hours, snooze and critical devices apply to rules as they do to the checkboxes.
- `PUBLIC_URL` adds an "Open NetWatch" link to rule alerts.
- The per-device Phone/Email checkboxes work exactly as before.
- **Rollback-safe:** new tables only. Older versions ignore rules and channels and keep the checkbox alerts.

## v1.9.0 (2026-11-18): Single sign-on (Authentik and other OpenID Connect providers)
- **Sign in with Authentik**, Keycloak, Authelia, Google or any OpenID Connect provider. The sign-in page shows the button when `OIDC_*` is set; password sign-in keeps working alongside it.
- **Roles from groups:** `OIDC_ADMIN_GROUPS` sign in as admin and `OIDC_VIEWER_GROUPS` as viewer, refreshed at every sign-in. Others are refused unless `OIDC_DEFAULT_ROLE=viewer`. Someone removed from the groups is signed out and their tokens are revoked.
- SSO accounts appear in the Access tab with an **SSO** tag. They have no password, can't be given one, and can't take over an existing local username. Admins can still disable or delete them.
- Security: authorization code flow with PKCE, a one-time state tied to the browser, nonce, and full ID-token checks (signature from the provider's keys, issuer, audience, expiry). Only public-key signatures are accepted. `OIDC_CA_FILE` trusts a home CA without turning certificate checks off.
- New dependency: PyJWT 2.15.1 (audited).
- **Rollback-safe:** two new columns on the accounts table only. Older versions ignore SSO accounts, which can't sign in there; everyone else is unaffected.

## v1.8.0 (2026-11-18): Accounts, read-only users and API tokens
- **Sign-in page** instead of the browser's login box. Sign out from the header.
- **Accounts** (new Access tab): give each person their own sign-in, as an **admin** or a read-only **viewer**. Viewers see everything but can't change anything; the dashboard hides the buttons they can't use, and the server refuses the changes either way.
- **API tokens** for Homepage, scripts and other tools (`Authorization: Bearer nw_...`), read-only or admin, with an expiry. The Access tab shows a ready-to-paste Homepage snippet when you create one.
- **Change your own password**; admins can reset passwords, disable or delete accounts, and revoke tokens. Each of these takes effect immediately.
- Security: scrypt password hashing; sessions and tokens stored only as hashes; `HttpOnly`/`Secure`/`SameSite=Strict` cookies plus a required request header for changes; sign-in lockout after repeated wrong passwords; sign-ins and account changes in the Activity log; backups leave out sessions.
- The built-in admin from `WEB_USERNAME` / `WEB_PASSWORD` keeps working everywhere, including Basic login for tools such as Homepage and curl.
- **Rollback-safe:** only new tables were added. Accounts require `WEB_PASSWORD`, so older versions keep asking for that password; extra accounts and tokens simply stop working until you upgrade again.

## v1.7.1 (2026-11-18): Security and layout hardening
- **DNS details now require a dashboard login.** Top domains, per-device domains and "which devices looked up this domain" are only available when `WEB_PASSWORD` is set, since they show what everyone on the network browses. Query counts and chatty-device alerts still work without a password.
- The cache of Pi-hole lookups is now capped, so repeated domain lookups can't grow NetWatch's memory use.
- Device MAC addresses are now escaped everywhere they appear in the new Overview and Top domains pages (defence in depth; MACs come from the network scan).
- Very long device, service or domain names no longer stretch the page on phones. Before, a long name could push the device details window's close button off the screen.
- No database changes; rolling back to v1.7.0 or v1.6.0 is safe.

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
