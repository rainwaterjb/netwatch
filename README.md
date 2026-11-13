# NetWatch

**A lightweight, self-hosted network monitor for your home or lab LAN.**
NetWatch shows every device on your network, which IP addresses are free, how long each device has been connected, and alerts you on your phone and/or by email when a device you care about drops off.

It runs as a single Docker container. It works well on a small VM or LXC container on Proxmox, or on any Linux host that sits on the network you want to watch.

---

## Features

| | |
|---|---|
| **Device inventory** | Every device that answers on the LAN, with IP address, MAC address, manufacturer (looked up from the MAC), and hostname (via reverse DNS). Give devices friendly names from the dashboard. |
| **IP address map** | A grid of the whole subnet showing which addresses are in use, which were last used by a device that's currently offline, and which are free. One click copies the list of free addresses. |
| **Connection time** | How long each device has been connected since it last joined, plus first-seen and last-seen times. |
| **Drop-off alerts** | Per device, choose **Phone**, **Email**, or both. Optionally get a second alert when the device comes back. |
| **New-device alerts** | Optionally get notified whenever a device the tool has never seen joins your network. |
| **Activity log** | A timeline of new devices, disconnects, reconnects, and IP address changes. |
| **Router integration** *(optional)* | For Linksys Velop/Atlas routers: shows DHCP reservations and the DHCP pool on the IP map, flags which free addresses are safe for static IPs, and uses the names from your router. Optionally add and remove DHCP reservations from a **Reservations** tab. |
| **Phone notifications** | Through [ntfy](https://ntfy.sh) (free, open source, can be self-hosted) and/or [Pushover](https://pushover.net). |
| **Email notifications** | Through any SMTP server (your mail provider, Gmail with an app password, a self-hosted relay, etc.). |
| **REST API** | Everything in the dashboard is available as JSON, with interactive docs at `/docs`. |

---

## How it works

```
┌────────────────────── Docker host on your LAN ──────────────────────┐
│                                                                     │
│   Scanner thread ──ARP sweep every N seconds──►  devices on the LAN │
│        │                                                            │
│        ▼                                                            │
│   SQLite (devices + events) ◄──── FastAPI web app ◄── your browser  │
│        │                                                            │
│        └── device went offline / came back ──► ntfy / Pushover      │
│                                               SMTP email            │
└─────────────────────────────────────────────────────────────────────┘
```

1. **Discovery.** On a fixed interval, NetWatch sends an ARP "who has this IP?" request to every address in your subnet. Anything that answers is online. ARP works even on devices that block ping.
2. **Identity.** Devices are tracked by **MAC address**, not IP. A device keeps its name, history, and alert settings even if DHCP hands it a new IP.
3. **Offline detection.** A device is only marked offline after missing several sweeps in a row (configurable). Before alerting on a watched device, NetWatch sends a few extra targeted probes. This avoids false alarms from devices whose Wi-Fi briefly sleeps.
4. **Enrichment.** Manufacturer names come from the bundled IEEE OUI database, so this works offline. Hostnames come from reverse DNS, which most home routers and Pi-hole/AdGuard set up from DHCP leases.
5. **Notifications.** Alerts are sent in the background so a slow mail server never delays scanning.

Because ARP is a layer-2 protocol, NetWatch must run on the same network (or VLAN) that it monitors. That's why the container uses host networking.

---

## Quick start

**Requirements:** a Linux host (VM, LXC, or bare metal) connected to the LAN you want to monitor, with Docker and Docker Compose installed.

```bash
git clone <this-repo-url> netwatch
cd netwatch
cp .env.example .env
nano .env                    # set SUBNET, WEB_PASSWORD and your notification settings
docker compose up -d --build
```

Then open `https://<host-ip>:8443` and log in with `WEB_USERNAME` / `WEB_PASSWORD`. Your browser will warn about the certificate the first time; see [HTTPS](#https) to make that go away. `http://<host-ip>:8080` redirects to the HTTPS address.

Useful commands:

```bash
docker compose logs -f                         # watch scans and alerts
./update.sh                                    # update to the latest release (see Releases and rollback)
docker cp netwatch:/data/netwatch.db ./backup.db      # back up device names and alert settings
```

### Releases and rollback

Every version is published as a [GitHub release](../../releases) and a Git tag (`v1.0.0`, `v1.1.0`, …). See [CHANGELOG.md](CHANGELOG.md) for what changed in each. The running version is shown in the dashboard header.

```bash
./update.sh --list                    # list releases and show which one is running
./update.sh v1.2.0                    # switch to a specific release (roll back)
git checkout main && ./update.sh      # go back to the latest version
```

After rolling back to a release older than v1.3.1, that release's own `update.sh` can't switch versions. Run `git checkout main` first, as shown above; this works from any version.

Switching versions keeps your `.env` and data: device names, alert settings and history. All versions share the same database format. If a newer version needs a setting that an older one doesn't have, the older version simply ignores it.

### Running on Proxmox

Docker needs a guest to run in. Either option works:

- **VM (simplest):** a small Debian or Ubuntu VM with its network card on your LAN bridge (commonly `vmbr0`). 1 vCPU, 512 MB RAM, and a few GB of disk is plenty.
- **LXC container:** a Debian LXC on the LAN bridge with the **nesting** feature enabled (plus **keyctl** for unprivileged containers). If the image build fails at the `setcap` step, the container's storage doesn't support file capabilities; use a VM instead.

If your network uses VLANs, attach the guest to the VLAN you want to watch. Run one NetWatch instance per VLAN.

---

## HTTPS

The dashboard is served over HTTPS by default, so your login and network data are encrypted on the wire.

| `TLS` setting | What happens |
|---|---|
| `self-signed` *(default)* | NetWatch creates its own certificate on first start (stored in `/data/tls`). It is reused across restarts and only regenerated when it nears expiry or the host's name/IP changes. |
| `custom` | Uses your own certificate and key, e.g. from a home-lab CA or Let's Encrypt. |
| `off` | Plain HTTP on `PORT`. Not recommended: the login is sent unencrypted. |

The dashboard is at `https://<host-ip>:8443` (`HTTPS_PORT`). Plain HTTP on port 8080 (`PORT`) redirects there automatically. The header shows **🔒 HTTPS**; hover over it to see the certificate's SHA-256 fingerprint and expiry date.

### Removing the browser warning (self-signed)

A self-signed certificate isn't vouched for by a public authority, so browsers warn the first time. You can click through (the connection is still encrypted), or install the certificate as trusted on the devices you use. Click **certificate** in the dashboard header to download `netwatch.crt`, then:

- **macOS:** open the file in Keychain Access, double-click the certificate, expand *Trust*, and set *When using this certificate* to **Always Trust**.
- **Windows:** double-click the file → *Install Certificate* → *Local Machine* → *Place all certificates in the following store* → **Trusted Root Certification Authorities**.
- **iPhone / iPad:** open the file and install the profile in *Settings → General → VPN & Device Management*, then enable it under *Settings → General → About → Certificate Trust Settings*.
- **Android:** *Settings → Security → Encryption & credentials → Install a certificate → CA certificate*.
- **Firefox** uses its own store: *Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import*.

Before trusting it, check that the fingerprint matches the one in the container log (`docker compose logs | grep SHA-256`).

The certificate covers the host's name and LAN IP. To reach NetWatch by another name (e.g. `netwatch.lan` from your local DNS), add it to `TLS_HOSTNAMES` and restart; the certificate is regenerated, so install the new one.

### Using your own certificate

```
TLS=custom
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
```

Mount the folder in `docker-compose.yml` (`- ./certs:/certs:ro`). The key must be readable by the container user (UID 10001). With a trusted certificate, NetWatch also sends an HSTS header so browsers always use HTTPS.

---

## Setting up notifications

### Phone: ntfy (free)
1. Install the **ntfy** app (iOS / Android).
2. Make up a long, random topic name. On the public ntfy.sh server, anyone who knows a topic name can read it, so don't use something guessable.
3. Subscribe to that topic in the app.
4. In `.env`, set `NTFY_URL=https://ntfy.sh/<your-topic>`. If you self-host ntfy with access control, use your server's URL and set `NTFY_TOKEN`.

### Phone: Pushover
Create an application at pushover.net, then set `PUSHOVER_USER_KEY` and `PUSHOVER_APP_TOKEN`. If both ntfy and Pushover are configured, alerts go to both.

### Email
Fill in the `SMTP_*` settings. Most providers use port `587` with `starttls`. For Gmail, use `smtp.gmail.com` and an **App Password**, not your account password. NetWatch refuses to send SMTP credentials over an unencrypted connection.

After changing `.env`, restart with `docker compose up -d`, then click **Send test alert** in the dashboard. A notification channel's checkbox stays greyed out until that channel is configured.

### Choosing what alerts you
On the **Devices** tab, tick **Phone**, **Email**, or both for any device. Tick **+ when back** to also hear when it reconnects. Click a device's name to rename it. To be told about unknown devices joining, set `NOTIFY_NEW_DEVICES` to `phone`, `email`, or `both`.

---

## Linksys router integration (optional)

If your router is a Linksys Velop or Atlas mesh system, NetWatch can read its DHCP settings through the router's local JNAP API (the same API the Linksys web interface uses). With it enabled:

- **IP map:** reserved addresses are shown in purple, even when the device is off, so they're never mistaken for free. Free addresses *outside* the DHCP pool get a dashed outline; these are the ones safe to assign as static IPs. A **Copy static-safe IPs** button copies just those.
- **Devices:** reservation descriptions and device names from the Linksys app are used as display names, which also appear in alerts. Devices whose reservation points at a different IP than they're using get a warning badge.
- **Reservations tab:** lists every DHCP reservation on the router and whether each device is actually using its reserved address.

Enable it in `.env`:

```
LINKSYS_URL=http://192.168.1.1
LINKSYS_PASSWORD=<router admin password>
```

To check that your router supports it before enabling (the password prompt keeps it out of your shell history):

```bash
read -s -p "Router admin password: " P; echo
curl -s -X POST http://192.168.1.1/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/router/GetLANSettings" \
  -H "X-JNAP-Authorization: Basic $(printf 'admin:%s' "$P" | base64)" \
  -H "Content-Type: application/json" -d '{}'
unset P
```

A response starting with `"result": "OK"` means it's supported.

Notes:
- **Read-only unless you opt in.** By default NetWatch never changes router settings. See below to manage reservations.
- **Unofficial API.** JNAP isn't documented by Linksys, so a firmware update could change it. If a sync fails, NetWatch shows a banner and keeps working without router data.
- **Plain HTTP.** Most Linksys routers serve JNAP over unencrypted HTTP, so the admin password crosses your LAN encoded but not encrypted. Only enable this on a network you trust.

### Managing reservations from NetWatch (optional)

With `LINKSYS_ALLOW_CHANGES=true` **and** a `WEB_PASSWORD` set, the Reservations tab lets you:

- **Reserve an address:** pick a device (or enter a MAC address), choose an IP, and add a description. A **Reserve** button on the Devices tab pre-fills the form with that device's current IP.
- **Remove a reservation.**

Safeguards:

- **Validated first.** The IP must be on your network and inside the DHCP pool (a Linksys requirement). It can't be already reserved or in use by another device, and it can't be the router's own address.
- **Backed up.** The router's full LAN settings are saved to `/data/router-backups/` before every change. The last 30 backups are kept, readable only by the container user.
- **Only reservations change.** NetWatch reads the live settings, changes only the reservation list, and sends everything else back untouched.
- **Verified and rolled back.** After saving, NetWatch reads the settings again. If anything other than the reservation list changed, or the reservation didn't stick, it restores the previous settings automatically and shows an error.
- **Logged.** Every change appears in the Activity log.

A device picks up a new reservation the next time it renews its DHCP lease. Reconnect or reboot it to apply it immediately. Until then, its status shows as *Waiting*.

To view or copy a backup:

```bash
docker exec netwatch ls /data/router-backups
docker cp netwatch:/data/router-backups ./router-backups
```

---

## Configuration

All settings are environment variables in `.env`. See `.env.example` for a commented template.

| Variable | Default | Description |
|---|---|---|
| `SUBNET` | auto-detect | Network to scan, in CIDR form (e.g. `192.168.1.0/24`) |
| `INTERFACE` | auto-detect | Network interface on that LAN (e.g. `eth0`, `ens18`) |
| `SCAN_INTERVAL` | `60` | Seconds between sweeps (minimum 10) |
| `OFFLINE_AFTER_MISSED_SCANS` | `3` | Consecutive missed sweeps before a device counts as offline |
| `ARP_TIMEOUT` | `3` | Seconds to wait for replies during a sweep |
| `EVENT_RETENTION_DAYS` | `90` | How long to keep the activity log |
| `TLS` | `self-signed` | HTTPS mode: `self-signed`, `custom`, or `off` |
| `HTTPS_PORT` | `8443` | HTTPS dashboard port |
| `PORT` | `8080` | Plain-HTTP port; redirects to HTTPS (serves the dashboard when `TLS=off`) |
| `TLS_HOSTNAMES` | *(empty)* | Extra names/IPs for the self-signed certificate, comma-separated |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | *(empty)* | Certificate and key for `TLS=custom` |
| `TZ` | `UTC` | Time zone used for timestamps in alerts |
| `WEB_USERNAME` | `admin` | Dashboard login username |
| `WEB_PASSWORD` | *(empty)* | Dashboard login password. **Strongly recommended.** Empty disables login. |
| `ALLOWED_HOSTS` | *(empty)* | Comma-separated hostnames/IPs allowed to reach the dashboard |
| `NTFY_URL` / `NTFY_TOKEN` | *(empty)* | ntfy topic URL and optional access token |
| `PUSHOVER_USER_KEY` / `PUSHOVER_APP_TOKEN` | *(empty)* | Pushover credentials |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURITY` | – / `587` / `starttls` | Mail server; security is `starttls`, `ssl`, or `none` |
| `SMTP_USER` / `SMTP_PASSWORD` | *(empty)* | Mail server login |
| `SMTP_FROM` / `SMTP_TO` | *(empty)* | Sender address; comma-separated recipients |
| `LINKSYS_URL` | *(empty)* | Linksys router address, e.g. `http://192.168.1.1`. Empty disables the integration. |
| `LINKSYS_USERNAME` / `LINKSYS_PASSWORD` | `admin` / *(empty)* | Router admin login (read-only use) |
| `ROUTER_POLL_INTERVAL` | `300` | Seconds between router syncs |
| `LINKSYS_ALLOW_CHANGES` | `false` | Allow adding/removing DHCP reservations (also requires `WEB_PASSWORD`) |
| `NOTIFY_NEW_DEVICES` | `none` | Alert on never-seen devices: `none`, `phone`, `email`, `both` |

---

## Security

NetWatch is designed to run on a trusted home or lab network. It ships with these protections:

**Container hardening**
- Runs as an unprivileged user (UID 10001), not root.
- All Linux capabilities are dropped except `NET_RAW`, the one needed to send ARP packets. Promiscuous mode is disabled, so `NET_ADMIN` isn't needed.
- OS packages are upgraded at build time. Memory and process limits are set in `docker-compose.yml`.
- Secrets are read from `.env`, which is excluded from Git (`.gitignore`) and from the image (`.dockerignore`).

**Web application**
- HTTPS by default (TLS 1.2+), with HTTP redirected to HTTPS.
- Optional HTTP Basic login, with constant-time credential checks.
- Cross-site request protection: state-changing requests from other websites are rejected, using the `Sec-Fetch-Site` and `Origin` headers.
- Optional `ALLOWED_HOSTS` allow-list to block DNS-rebinding attacks.
- Strict security headers: Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, and `no-referrer`.
- Input validation on all API parameters. All SQL uses parameterized queries. All device data is HTML-escaped in the dashboard.
- Error details from mail and push servers are logged, not returned to the browser.

**Dependencies**
- All Python dependencies, including transitive ones, are pinned to exact versions in `requirements.txt`. They are audited with [`pip-audit`](https://pypi.org/project/pip-audit/) against the PyPI/OSV advisory databases.
- The pins require versions that include fixes for these advisories, which affected older releases allowed by earlier, loosely pinned requirements:

  | Package | Advisory | Issue | Fixed in |
  |---|---|---|---|
  | starlette | CVE-2024-47874 | Multipart form fields buffered without a size limit (DoS) | 0.40.0 |
  | starlette | CVE-2025-54121 | Event loop blocked while spooling large uploads (DoS) | 0.47.2 |
  | starlette | CVE-2026-48710 | Host header not validated when reconstructing URLs | 1.0.1 |
  | starlette | CVE-2026-48817 | HTTP method dispatch could reach non-handler attributes | 1.1.0 |
  | starlette | CVE-2026-48818 | `StaticFiles` UNC path handling on Windows | 1.1.0 |
  | starlette | CVE-2026-54282 | Request path not validated when rebuilding `request.url` | 1.3.0 |
  | starlette | CVE-2026-54283 | Form limits ignored for URL-encoded bodies (DoS) | 1.3.1 |
  | h11 | CVE-2025-43859 | Lenient chunked-encoding parsing (request smuggling) | 0.16.0 |
  | scapy | GHSA-cq46-m9x9-j8w2 | Unsafe deserialization of session files | 2.7.0 |

  `cryptography` (used for HTTPS certificates) was added later at 50.0.2, with no known vulnerabilities at the time.

To re-check at any time:

```bash
pip install pip-audit
pip-audit -r requirements.txt                 # Python dependencies
trivy image netwatch:latest                   # OS packages in the built image (optional)
```

**Recommendations**
- Set `WEB_PASSWORD` and `ALLOWED_HOSTS`.
- Install the self-signed certificate on your devices (or use your own), so you'd notice if a different certificate ever appeared.
- Don't port-forward the dashboard to the internet. For remote access, use a VPN (WireGuard, Tailscale) or a reverse proxy with TLS and authentication.
- Rebuild regularly with `docker compose build --pull` to pick up base-image security fixes.
- Use a long, random ntfy topic, or a self-hosted ntfy server with access tokens.

---

## Limitations and tips

- **"Free" means nothing answered right now.** A powered-off device may still hold a DHCP lease, and IPs reserved on your router may look free (unless the Linksys integration is enabled). Before assigning a static IP, pick one outside your router's DHCP pool. The amber cells show addresses recently used by known devices.
- **Randomized MAC addresses.** Modern phones and laptops often use a private MAC per Wi-Fi network; these show as "Private (randomized MAC)". The address is normally stable for a given network. If a device rotates it, it will show up as a new device.
- **Sleeping phones.** Phones can ignore ARP for several minutes while idle. If you watch a phone, raise `OFFLINE_AFTER_MISSED_SCANS` (e.g. to 10) to avoid false alarms.
- **Hostnames** depend on your router or DNS server publishing DHCP hostnames. If the column is blank, name devices in the dashboard.
- **IPv4 only.** IPv6-only devices aren't discovered.
- **Large subnets** (bigger than /22) work but scan more slowly; the map shows up to 4,096 addresses.

---

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Scanner status, subnet, counts, configured channels |
| `GET` | `/api/devices` | All known devices |
| `PATCH` | `/api/devices/{mac}` | Update `nickname`, `notify_phone`, `notify_email`, `notify_return` |
| `DELETE` | `/api/devices/{mac}` | Forget a device |
| `GET` | `/api/ips` | Every address in the subnet with its status |
| `GET` | `/api/events?limit=&mac=` | Activity log |
| `GET` | `/api/reservations` | DHCP reservations on the router, with device status |
| `POST` | `/api/reservations` | Add a reservation: `mac`, `ip`, `description` (requires `LINKSYS_ALLOW_CHANGES`) |
| `DELETE` | `/api/reservations/{mac}` | Remove a reservation (requires `LINKSYS_ALLOW_CHANGES`) |
| `POST` | `/api/scan` | Trigger a scan now |
| `POST` | `/api/test-notification` | Send a test alert |
| `GET` | `/healthz` | Unauthenticated health check (used by Docker) |
| `GET` | `/netwatch.crt` | The server's public certificate (unauthenticated) |

---

## Project layout

```
netwatch/
├── app/
│   ├── main.py          # FastAPI app and REST API
│   ├── monitor.py       # Scan loop, online/offline logic, alert triggers
│   ├── scanner.py       # ARP sweeps, probes, hostname and vendor lookup
│   ├── notifier.py      # ntfy, Pushover and SMTP delivery
│   ├── security.py      # Login, CSRF/Host checks, security headers
│   ├── serve.py         # Entry point: HTTPS server + HTTP redirect
│   ├── tls.py           # Self-signed certificate creation/renewal
│   ├── healthcheck.py   # Docker health check
│   ├── router_linksys.py  # Optional Linksys JNAP integration (reservations)
│   ├── db.py            # SQLite storage
│   ├── config.py        # Environment-variable configuration
│   └── static/index.html  # Dashboard (single page, no external assets)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt     # Fully pinned, audited dependencies
├── update.sh            # Update, or switch to any release (rollback)
├── CHANGELOG.md         # What changed in each release
├── .env.example         # Configuration template (copy to .env)
├── .gitignore
└── .dockerignore
```

## Tech stack

Python 3.13 · FastAPI · Uvicorn · Scapy · netaddr · cryptography · SQLite · vanilla HTML/JS
