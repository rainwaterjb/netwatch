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
| **Router integration** *(optional)* | For Linksys Velop/Atlas routers: shows DHCP reservations and the DHCP pool on the IP map, flags which free addresses are safe for static IPs, and uses the names from your router. Read-only. |
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

Then open `http://<host-ip>:8080` and log in with `WEB_USERNAME` / `WEB_PASSWORD`.

Useful commands:

```bash
docker compose logs -f                         # watch scans and alerts
./update.sh                                    # git pull + rebuild + restart
docker cp netwatch:/data/netwatch.db ./backup.db      # back up device names and alert settings
```

### Running on Proxmox

Docker needs a guest to run in. Either option works:

- **VM (simplest):** a small Debian or Ubuntu VM with its network card on your LAN bridge (commonly `vmbr0`). 1 vCPU, 512 MB RAM, and a few GB of disk is plenty.
- **LXC container:** a Debian LXC on the LAN bridge with the **nesting** feature enabled (plus **keyctl** for unprivileged containers). If the image build fails at the `setcap` step, the container's storage doesn't support file capabilities; use a VM instead.

If your network uses VLANs, attach the guest to the VLAN you want to watch. Run one NetWatch instance per VLAN.

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
- **Read-only by design.** NetWatch never changes router settings.
- **Unofficial API.** JNAP isn't documented by Linksys, so a firmware update could change it. If a sync fails, NetWatch shows a banner and keeps working without router data.
- **Plain HTTP.** Most Linksys routers serve JNAP over unencrypted HTTP, so the admin password crosses your LAN encoded but not encrypted. Only enable this on a network you trust.

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
| `PORT` | `8080` | Web dashboard port |
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

To re-check at any time:

```bash
pip install pip-audit
pip-audit -r requirements.txt                 # Python dependencies
trivy image netwatch:latest                   # OS packages in the built image (optional)
```

**Recommendations**
- Set `WEB_PASSWORD` and `ALLOWED_HOSTS`.
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
| `POST` | `/api/scan` | Trigger a scan now |
| `POST` | `/api/test-notification` | Send a test alert |
| `GET` | `/healthz` | Unauthenticated health check (used by Docker) |

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
│   ├── router_linksys.py  # Optional read-only Linksys JNAP integration
│   ├── db.py            # SQLite storage
│   ├── config.py        # Environment-variable configuration
│   └── static/index.html  # Dashboard (single page, no external assets)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt     # Fully pinned, audited dependencies
├── update.sh            # Pull latest code, rebuild and restart
├── .env.example         # Configuration template (copy to .env)
├── .gitignore
└── .dockerignore
```

## Tech stack

Python 3.13 · FastAPI · Uvicorn · Scapy · netaddr · SQLite · vanilla HTML/JS
