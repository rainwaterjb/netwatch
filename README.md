# NetWatch

**A lightweight, self-hosted network monitor for your home or lab LAN.**
NetWatch shows every device on your network, which IP addresses are free, how long each device has been connected, and alerts you on your phone and/or by email when a device you care about drops off.

It runs as a single Docker container. It works well on a small VM or LXC container on Proxmox, or on any Linux host that sits on the network you want to watch.

---

## Features

| | |
|---|---|
| **Overview dashboard** | One screen with the state of everything: internet, devices, services, free addresses and DNS; a **Needs attention** list; a live activity feed that can hide brief blips; the address map; and service checks with trend lines. |
| **Timeline** | Internet outages, failed service checks, when each device was online, and DNS volume, all lined up on one time axis (6 hours, 24 hours or 7 days), so you can see what happened at the same moment. Filter by tag or show only devices that dropped. |
| **Accounts and API tokens** | A sign-in page, separate accounts for each person (admin or read-only viewer), and API tokens for tools like Homepage. The built-in admin from `.env` always works. |
| **Single sign-on** *(optional)* | Sign in with Authentik, Keycloak, Authelia or any OpenID Connect provider. Admin or viewer role comes from the provider's groups. |
| **Device recognition** | Works out what each device is (phone, tablet, computer, TV, streaming player, speaker, printer, camera, smart home, console, network gear, server) and its model, from what it already announces on the network: DHCP, Bonjour/mDNS and UPnP. |
| **Private Wi-Fi addresses** | Phones and laptops change their MAC address. When one rejoins under a new private address, NetWatch recognises it and offers to link it to the device you already named, keeping its name, tags and alerts. |
| **Device inventory** | Every device that answers on the LAN, with IP address, MAC address, manufacturer (looked up from the MAC), and hostname (via reverse DNS). Give devices friendly names from the dashboard. |
| **IP address map** | A grid of the whole subnet showing which addresses are in use, which were last used by a device that's currently offline, and which are free. One click copies the list of free addresses. |
| **Connection time** | How long each device has been connected since it last joined, plus first-seen and last-seen times. |
| **Drop-off alerts** | Per device, choose **Phone**, **Email**, or both. Optionally get a second alert when the device comes back. |
| **Quiet hours & snooze** | Hold alerts overnight and get one summary in the morning. Snooze a device while you work on it. **Critical** devices always alert. |
| **Device details** | Click any device for a presence timeline with availability %, IP history, recent activity, DNS activity and its service checks. |
| **New-devices inbox** | Devices NetWatch has never seen are marked **NEW** until you review them. |
| **Tags** | Group devices (`#servers`, `#iot`…), filter by tag, and switch alerts for a whole group at once. |
| **Service checks** | Watch web pages, TCP ports and ping targets. Get uptime %, response times and down/up alerts. |
| **Internet outage tracking** | Records when your internet (or router) was down and for how long, with 24h/7d/30d uptime. |
| **Pi-hole integration** *(optional)* | DNS queries and top domains per device, a **Top domains** tab for the whole network (allowed and blocked, and which devices looked each one up), plus alerts when a device suddenly gets "chatty". |
| **Wake-on-LAN** | Wake sleeping devices from the dashboard. |
| **Export** | Device list as CSV and a full database backup, one click each. |
| **New-device alerts** | Optionally get notified whenever a device the tool has never seen joins your network. |
| **Activity log** | A timeline of new devices, disconnects, reconnects, and IP address changes. |
| **Router integration** *(optional)* | Connects to **OPNsense, pfSense, UniFi, OpenWrt or Linksys**: shows DHCP reservations and the DHCP pool on the IP map, flags which free addresses are safe for static IPs, and uses your router's device names. Optionally add and remove DHCP reservations from a **Reservations** tab. |
| **Alert rules** | "If any #iot device is offline for 10 minutes, post to Discord; if nobody acknowledges it in 30 minutes, also send to Telegram." Rules for devices, new devices, service checks, internet outages and chatty devices, with recovery messages, escalation and acknowledgement. |
| **More alert channels** | Discord, Slack, Telegram, Gotify, ntfy, webhooks (including Home Assistant) and MQTT, alongside phone and email. |
| **Installable app** | Add NetWatch to your phone's home screen or your computer's dock, and get alerts as **native push notifications**, end-to-end encrypted, without ntfy or Pushover. |
| **Phone notifications** | Through [ntfy](https://ntfy.sh) (free, open source, can be self-hosted) and/or [Pushover](https://pushover.net). |
| **Email notifications** | Through any SMTP server (your mail provider, Gmail with an app password, a self-hosted relay, etc.). |
| **Works on mobile** | The dashboard adapts to phones and tablets: tables become cards, with touch-friendly controls. |
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

Then open `https://<host-ip>:8443` and sign in with `WEB_USERNAME` / `WEB_PASSWORD`. Your browser will warn about the certificate the first time; see [HTTPS](#https) to make that go away. `http://<host-ip>:8080` redirects to the HTTPS address.

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

### A free, trusted certificate with Let's Encrypt and Cloudflare

If you own a domain on Cloudflare, you can give NetWatch a real certificate for a name like `netwatch.example.com` **without exposing anything to the internet**. Let's Encrypt checks you own the domain through a DNS record instead of connecting to NetWatch. Every device then trusts NetWatch with no warnings and nothing to install, which is also what the app and push notifications need.

1. **Name:** in your local DNS (e.g. Pi-hole → *Local DNS → DNS Records*) point `netwatch.example.com` at NetWatch's LAN IP. Nothing is added to public DNS.
2. **Cloudflare API token:** *My Profile → API Tokens → Create Token → Edit zone DNS*, limited to that one zone.
3. **Get the certificate** on the Docker host:
   ```bash
   sudo apt install certbot python3-certbot-dns-cloudflare
   sudo install -m 600 /dev/null /root/cloudflare.ini
   echo "dns_cloudflare_api_token = <token>" | sudo tee /root/cloudflare.ini
   sudo certbot certonly --dns-cloudflare --dns-cloudflare-credentials /root/cloudflare.ini -d netwatch.example.com
   ```
4. **Hand it to NetWatch** and reload it after each renewal (certbot renews automatically):
   ```bash
   sudo tee /etc/letsencrypt/renewal-hooks/deploy/netwatch.sh >/dev/null <<'HOOK'
   #!/bin/sh
   install -d -m 750 -o 10001 /opt/netwatch/certs
   install -m 640 -o 10001 /etc/letsencrypt/live/netwatch.example.com/fullchain.pem /opt/netwatch/certs/
   install -m 600 -o 10001 /etc/letsencrypt/live/netwatch.example.com/privkey.pem /opt/netwatch/certs/
   docker restart netwatch
   HOOK
   sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/netwatch.sh && sudo /etc/letsencrypt/renewal-hooks/deploy/netwatch.sh
   ```
5. In `.env`: `TLS=custom`, `TLS_CERT_FILE=/certs/fullchain.pem`, `TLS_KEY_FILE=/certs/privkey.pem`, add `netwatch.example.com` to `ALLOWED_HOSTS`, and set `PUBLIC_URL=https://netwatch.example.com:8443`. Mount `./certs:/certs:ro` in `docker-compose.yml` and run `docker compose up -d`.

Open `https://netwatch.example.com:8443`. If you use single sign-on, update the redirect URI at your provider to the new name too.

---

## The NetWatch app and push notifications

NetWatch can be installed as an app and send **native notifications** to phones, tablets and computers, with no ntfy or Pushover account needed.

**1. Make sure the device trusts NetWatch's certificate.** Browsers only run apps and notifications from a site they fully trust. Use the [Let's Encrypt route](#a-free-trusted-certificate-with-lets-encrypt-and-cloudflare), or install NetWatch's own certificate on the device ([see above](#removing-the-browser-warning-self-signed)). On iPhone, also turn it on under *Certificate Trust Settings*.

**2. Install the app.**
- **iPhone / iPad** (iOS 16.4+): open NetWatch in Safari → *Share* → **Add to Home Screen**, then open it from the home screen. Notifications on iOS only work from the home-screen app.
- **Android / Chrome / Edge:** use **Install app** in the NetWatch header, or the browser's *Install* menu item.
- **Mac (Safari 17+):** *File → Add to Dock*.

**3. Turn on notifications:** in the app, go to **Access → Notifications on this device → Turn on notifications**, then **Send a test**. If something is missing (the home-screen step, the certificate, or notifications blocked in the browser), the card says exactly what.

What arrives:
- Everything that goes to **Phone**: the device checkboxes, internet and chatty-device alerts, and the morning digest after quiet hours. This works even if ntfy/Pushover aren't set up.
- Alert rules that send to **NetWatch app** (choose it like any channel in the Alerts tab). Escalations stay on screen until you dismiss them, and tapping a notification opens NetWatch.
- Every person who turns notifications on gets them, including read-only viewers. Each person can see and remove their own devices; admins see everyone's.

How it's protected:
- Messages are **end-to-end encrypted** for each device (Web Push, RFC 8291), so Apple, Google, Mozilla or Microsoft carry them but can't read them. NetWatch signs them with its own key (VAPID, RFC 8292), created on first start in the data folder, readable only by NetWatch and left out of backups.
- NetWatch only sends to known push services over HTTPS, so a signed-in user can't use notifications to make NetWatch contact other hosts. Devices whose app was removed are forgotten automatically.
- The app files (manifest, service worker, icons) are public because browsers fetch them before you sign in; they contain no data. The service worker caches nothing and only ever opens NetWatch pages.

NetWatch needs outbound HTTPS to the push services. Set `PUSH_CONTACT` (`mailto:` or `https:`) to give push services a contact address.

---

## Accounts and API tokens

With `WEB_PASSWORD` set, the dashboard has a sign-in page. The **built-in admin** (`WEB_USERNAME` / `WEB_PASSWORD` from `.env`) always works, so you can't lock yourself out. Change its password by editing `.env` and restarting; that signs the built-in admin out everywhere.

In the **Access** tab, admins can:

- **Add accounts** for other people, as an **admin** (can change everything) or a **viewer** (can look but not change anything: no scans, alerts, reservations, settings, accounts or backups). Reset a password, disable or delete an account; each of these signs that person out straight away.
- **Create API tokens** for tools and scripts, as viewer (read-only) or admin, with an expiry. A token is shown once; NetWatch only keeps a hash of it. Tokens can't manage accounts or other tokens, and a token made by an account can never do more than that account.

Everyone can change their own password in the Access tab (the built-in admin's lives in `.env`).

Using a token, for example with Homepage's `customapi` widget:

```yaml
widget:
  type: customapi
  url: https://<netwatch-ip>:8443/api/status
  headers:
    Authorization: Bearer nw_...
```

or with curl: `curl -H "Authorization: Bearer nw_..." https://<netwatch-ip>:8443/api/status`. Basic login (`-u user:password`) keeps working too.

How it's protected:
- Passwords are hashed with scrypt. Session cookies and tokens are random 256-bit values stored only as hashes, so a copy of the database (or a backup) can't be used to sign in. Backups leave out sessions entirely.
- Session cookies are `HttpOnly`, `Secure` and `SameSite=Strict`. Changes made with a session also need NetWatch's own request header, which other websites can't send.
- After 5 wrong passwords for an account, or 10 from one address, sign-in is paused for 15 minutes. Failed and successful sign-ins and account changes appear in the Activity log.
- Sessions end after a week without use, and after 30 days at most.

**Rolling back is safe.** Accounts need `WEB_PASSWORD` to be set, and older versions (before v1.8.0) simply ignore the accounts and keep asking for `WEB_PASSWORD`. Only the extra accounts and tokens stop working until you upgrade again, so switch Homepage back to Basic login first if you roll back.

## Single sign-on (optional)

NetWatch can sign people in through **Authentik**, Keycloak, Authelia, Google or any other OpenID Connect provider. The sign-in page then shows a **Sign in with …** button above the password form. Password sign-in keeps working, so the built-in admin is always there if the provider is down.

### Setting up Authentik

1. In Authentik, go to **Applications → Applications → Create with provider** (or create an **OAuth2/OpenID Provider** and then an **Application**).
2. Provider type **OAuth2/OpenID Connect**, client type **Confidential**.
3. **Redirect URI** (strict): `https://<netwatch-address>:8443/api/auth/oidc/callback`, using the exact address you open NetWatch with.
4. **Signing key**: pick a certificate, for example *authentik Self-signed Certificate*. NetWatch only accepts tokens signed with a public/private key pair, not ones signed with the client secret.
5. Scopes: keep the defaults (`openid`, `email`, `profile`). Authentik's `profile` scope includes the user's groups.
6. Create groups such as `netwatch-admins` and `netwatch-viewers` and add people to them.
7. Copy the **Client ID**, **Client Secret** and the **OpenID Configuration Issuer** (looks like `https://auth.example.com/application/o/netwatch/`) into `.env`:

```
OIDC_ISSUER=https://auth.example.com/application/o/netwatch/
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_ADMIN_GROUPS=netwatch-admins
OIDC_VIEWER_GROUPS=netwatch-viewers
OIDC_BUTTON_LABEL=Sign in with Authentik
```

Restart (`docker compose up -d`). The **Access** tab shows the SSO settings NetWatch picked up, and anything that stops SSO from working.

### How roles and accounts work

- Members of `OIDC_ADMIN_GROUPS` sign in as **admin**, members of `OIDC_VIEWER_GROUPS` as **viewer**. Anyone else is refused, unless you set `OIDC_DEFAULT_ROLE=viewer`.
- Roles are refreshed from the groups **every time** someone signs in. Someone removed from all allowed groups is signed out, and their API tokens are revoked, the next time they try.
- The first sign-in creates a NetWatch account (shown with an **SSO** tag in the Access tab). It has no password, so it can only sign in through the provider. If the provider's username is already used by a local account, the SSO account gets `-sso` added instead of taking it over.
- Admins can still **disable** or **delete** an SSO account in NetWatch, which blocks it even if the provider allows it.
- **Sign out** signs you out of NetWatch only, not out of Authentik.

### How it's protected

The sign-in uses the authorization-code flow with **PKCE**. A one-time `state` value is tied to the browser that started the sign-in, so nobody can trick you into signing in as them, and a `nonce` is checked as well. NetWatch fetches the ID token server-to-server and checks its signature against the provider's published keys, plus its issuer, audience, expiry and nonce. Tokens from the provider are never sent to the browser.

If your provider uses a certificate from your own CA, point `OIDC_CA_FILE` at that CA certificate (mounted into the container). `OIDC_VERIFY_TLS=false` turns the check off entirely; avoid it if you can.

**Rolling back is safe.** SSO needs `WEB_PASSWORD`, and it only adds two columns to the accounts table. Older versions ignore SSO accounts: they can't sign in there, and everyone else can.

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

## Device recognition and private addresses

NetWatch works out what each device is, shown as an icon and a label ("Tablet · iPadOS", "Streaming player · Chromecast with Google TV"). It only listens to and asks for what devices already share on your LAN:

- **DHCP:** when a device joins, it broadcasts its name, a vendor class (e.g. `android-dhcp-14`, `MSFT 5.0`) and the list of settings it asks for, which works like an operating-system fingerprint. NetWatch listens with a kernel filter that only lets DHCP requests through.
- **Bonjour / mDNS:** a few questions every 15 minutes for common services (AirPlay, Google Cast, printers, HomeKit, file sharing). Answers include models such as `iPhone15,2`.
- **UPnP / SSDP:** one discovery broadcast every 15 minutes. TVs, speakers, consoles and routers answer, and NetWatch reads their description file (only from the device that answered, with size limits, no redirects and no XML entities).
- The manufacturer from the MAC address, and the hostname.

Open a device and look under **What it is** to see the type, what it was recognised from, and everything NetWatch has seen. Admins can set the type by hand; choose **Automatic** to go back.

### Private (randomized) Wi-Fi addresses

iPhones, Android phones, Windows and macOS use a **private MAC address** for each Wi-Fi network, and may change it. To NetWatch that looks like a brand-new device, and the old one seems to disappear. Those devices get a **private address** badge.

When a device with a private address appears with the **same name** as a device NetWatch already knows (for example `Alexs-iPhone`), ideally with the same DHCP fingerprint, the Overview shows **"… looks like Alex's iPhone"**:

- **Same device:** the new address takes the old one's name, tags, alert settings and service checks. The old record is kept for history, hidden from lists, and can't raise alerts. Any "new device" alert is closed.
- **Not the same:** NetWatch remembers and won't ask again.

Generic names such as `iPhone` or `android-1a2b3c` are never enough, and two devices online at the same time are never treated as one. You can also link or unlink devices by hand in the details window. To skip the question when it's clear-cut (same name **and** same DHCP fingerprint), turn on **automatic linking** under Settings → Device recognition; then a phone that rejoins with a new address doesn't trigger a "new device" alert at all.

Set `DISCOVERY=false` to turn recognition off. **Rolling back is safe:** older versions ignore the new columns and tables; linked old addresses simply show up as separate (offline) devices again.

## Alert rules and channels

The Phone/Email checkboxes on each device are the simple way to get alerts, and they keep working. **Alert rules** (Alerts tab, admins) add more control:

- **When:** a device goes offline, a new device joins, a service check fails, the internet goes down, or a device gets chatty.
- **For:** any device, critical devices, devices with a tag, or chosen devices (or any/chosen service checks).
- **Only if it lasts N minutes.** A device that comes back within that time is treated as a blip: nothing is sent, and the Activity log says so. For internet outages, the alert goes out once the connection is back, if the outage lasted at least that long.
- **Send to:** phone and email from `.env`, plus any channels you've added. Optionally also send a message when it recovers.
- **Escalation:** if nobody acknowledges the alert within M minutes, also send it somewhere else.
- **Quiet hours** hold rule alerts until morning, unless the rule says otherwise or the device is critical. Snoozed devices don't alert.

If four or more alerts for the same rule are due at once (say, a power cut takes ten devices offline), they're sent as **one summary** instead of a flood. If a channel can't be reached, NetWatch retries with increasing gaps (for example, while the internet is down) and gives up after 30 attempts.

**Open alerts** appear under **Needs attention** on the Overview and in the Alerts tab. Anyone signed in, including read-only viewers, can **acknowledge** them, which stops escalation. Admins manage rules and channels.

### Channels

| Type | What you need |
|---|---|
| Discord | A channel webhook URL (Server settings → Integrations → Webhooks). `@everyone` in a device name never pings anyone. |
| Slack | An incoming-webhook URL |
| Telegram | A bot token from @BotFather and the chat ID |
| Gotify | Server URL and an application token |
| ntfy | The topic URL, and an access token if the topic is protected |
| Webhook / Home Assistant | Any URL that accepts a JSON `POST`. For Home Assistant, make an automation with a **Webhook** trigger and paste its URL. Add a signing secret to get an `X-NetWatch-Signature: sha256=<HMAC>` header. |
| MQTT | Broker host and port, optional TLS, username and password, and a topic (default `netwatch/alerts`). Messages are JSON. |

Every channel has a **Send test** button and shows whether its last message got through. Tokens, passwords and webhook URLs are stored in NetWatch's database and are never shown again in the browser; leave a secret field blank when editing to keep it. They are included in database backups, so keep those safe.

Set `PUBLIC_URL` (e.g. `https://192.168.1.50:8443`) to add an "Open NetWatch" link to every rule alert.

**Rolling back is safe.** Rules, channels and alerts live in new tables. Older versions ignore them: rule alerts stop, and the per-device checkboxes carry on as before.

## Alerts: quiet hours, snooze and critical devices

All alerts (device drop-offs, service checks, internet outages, chatty devices, new devices) follow these rules:

- **Quiet hours** (Settings tab): alerts during the chosen hours (e.g. 22:00 to 07:00) are held, then sent as **one summary** when quiet hours end: a short list by phone and full details by email.
- **Critical devices** (device detail panel) ignore quiet hours and always alert right away. Use this for things like your NAS or Proxmox host.
- **Snooze** (device detail panel) silences a single device's alerts for 1 hour up to 1 week, e.g. while you reboot it. Skipped alerts are still listed in the Activity log.
- **While the internet is down**, alerts can't reach your phone or inbox. They're held and sent once the connection is back.

## Service checks

Being on the network doesn't mean a service is working. A server can answer ARP while its web UI has crashed. The **Services** tab lets you watch:

| Type | Up when… | Example |
|---|---|---|
| **Web page (HTTP/HTTPS)** | the page answers with any status below 500 (a login page counts as up) | Proxmox UI: device = your Proxmox host, HTTPS, port 8006, certificate check **off** |
| **Port (TCP)** | a connection to the port succeeds | SSH on 22, SMB on 445, a database port |
| **Ping** | the host replies to ping | a switch or access point |

- Link a check to a **device** and it follows that device if its IP changes, or enter a fixed host or IP.
- Choose how often to check (30 seconds to 15 minutes) and how many failures in a row count as down (default 2), so one dropped packet doesn't page you.
- Each check shows its current state, 24-hour and 7-day uptime, response time, and a strip of recent results.
- For self-signed HTTPS (Proxmox, many NAS boxes), turn off **Check certificate**.

## Internet outage tracking

Every 30 seconds NetWatch tries to connect to a few public addresses (Cloudflare, Google and Quad9 DNS by default; change with `WAN_CHECK_TARGETS`). If none answer for two checks in a row, an outage begins. NetWatch also checks your router, so each outage is recorded as either:

- **internet down (router OK)**: the problem is on your ISP's side, or
- **router unreachable**: the problem is inside your home.

Once the connection is back you get an alert with the duration (choose the channel in Settings). The Services tab shows uptime for 24 hours, 7 days and 30 days, plus a list of outages.

## Pi-hole integration (optional)

If you use Pi-hole v6 or newer as your DNS server, NetWatch can show, for each device:

- DNS queries in the last 24 hours and the last hour, with an hour-by-hour chart.
- Its usual hourly volume.
- Its top domains.

The **Top domains** tab shows the busiest allowed and blocked domains across the whole network, the blocked share, and, when you select a domain, which devices looked it up. Pick a device from the list to see its own top domains instead.

A device is flagged **chatty** when its last hour is far above normal: by default 5× its usual volume, and at least 600 queries. Both thresholds can be changed in Settings. That's often the first sign of a misbehaving IoT device, a stuck app, or malware. You can be alerted when it happens.

```
PIHOLE_URLS=http://192.168.1.2,http://192.168.1.3
PIHOLE_PASSWORD=<app password>
```

- Several Pi-holes are supported; their numbers are added together per device.
- Create an **app password** in Pi-hole under *Settings → Web interface / API* rather than using your main password. If your Pi-holes have different passwords, list them in the same order, comma-separated.
- If you use Pi-hole's default self-signed HTTPS address, set `PIHOLE_VERIFY_TLS=false`, or use its `http://` address on your LAN.
- NetWatch only reads from Pi-hole; it never changes Pi-hole settings.
- DNS details (per-device domains and the Top domains tab) need a dashboard login (`WEB_PASSWORD`), because they show what each device looks up. Query counts and chatty-device alerts work either way.
- Devices are matched by IP address, so a device that has made no DNS queries through Pi-hole shows no numbers.

## Wake-on-LAN

Offline devices have a **Wake** button (also in the detail panel). It sends a standard "magic packet" to the device's MAC address. It works only if the device supports Wake-on-LAN and has it enabled, usually in the BIOS/UEFI and the network adapter's settings. Most devices can only be woken over a wired connection.

---

## Router integration (optional)

NetWatch can connect to your router to read its DHCP settings and, if you allow it, manage DHCP reservations. Supported routers:

| Router | `ROUTER_TYPE` | Connects with | Reservations stored as | Reserved IPs must be |
|---|---|---|---|---|
| **OPNsense** | `opnsense` | API key + secret | Dnsmasq "Hosts" or Kea "Reservations" (auto-detected) | anywhere in the subnet |
| **pfSense** | `pfsense` | REST API package + API key | DHCP "Static mappings" | **outside** the DHCP pool |
| **UniFi** (UDM, UDR, UCG, Cloud Key, self-hosted) | `unifi` | API key, or a local admin account | Client "Fixed IP" | anywhere in the subnet |
| **OpenWrt** | `openwrt` | ubus JSON-RPC (root login) | `dhcp` "host" entries | anywhere in the subnet |
| **Linksys** Velop / Atlas | `linksys` | admin password (local JNAP API) | DHCP reservations | **inside** the DHCP pool |

With a router connected:

- **IP map:** reserved addresses are shown in purple, even when the device is off, so they're never mistaken for free. Free addresses *outside* the DHCP pool get a dashed outline; these are the ones safe to set as static IPs on a device itself. **Copy static-safe IPs** copies just those.
- **Devices:** reservation descriptions and router device names are used as display names, which also appear in alerts. A device whose reservation points at a different IP than it's using gets a warning badge.
- **Reservations tab:** lists every DHCP reservation on the router and whether each device is actually using its reserved address.

If a sync fails, NetWatch shows the reason in **Settings → Integrations** and keeps working without router data.

### Setting up your router

<details>
<summary><b>OPNsense</b></summary>

1. In OPNsense, go to **System → Access → Users** and create a user for NetWatch, or use an existing one.
2. Give it the privilege for your DHCP server: **Services: Dnsmasq DNS/DHCP: Settings** (Dnsmasq, the default on new installs) or the **Kea DHCP** privileges (Kea).
3. In that user's **API keys** section, create a key. OPNsense downloads a file containing the key and secret, and shows the secret only once.

```
ROUTER_TYPE=opnsense
ROUTER_URL=https://192.168.1.1
ROUTER_API_KEY=<key>
ROUTER_API_SECRET=<secret>
ROUTER_VERIFY_TLS=false      # OPNsense's default certificate is self-signed
```

NetWatch detects whether you use Dnsmasq or Kea. Set `ROUTER_DHCP=dnsmasq` or `ROUTER_DHCP=kea` to choose explicitly. The legacy ISC DHCP server has no API for reservations, so it isn't supported.
</details>

<details>
<summary><b>pfSense</b></summary>

1. Install the community REST API package (**pfSense-pkg-RESTAPI**, by pfrest) on the firewall, following its instructions.
2. Under **System → REST API → Keys**, create an API key.

```
ROUTER_TYPE=pfsense
ROUTER_URL=https://192.168.1.1
ROUTER_API_KEY=<key>
ROUTER_INTERFACE=lan         # the DHCP server's interface
ROUTER_VERIFY_TLS=false      # pfSense's default certificate is self-signed
```

pfSense requires static mappings to be **outside** the DHCP pool, and NetWatch enforces the same rule. After each change NetWatch applies the DHCP server configuration.
</details>

<details>
<summary><b>UniFi</b></summary>

Use **one** of these:

- **API key (recommended):** create one in the UniFi Network application (**Settings → Control Plane → Integrations**, or under your admin's profile on some versions).
  ```
  ROUTER_TYPE=unifi
  ROUTER_URL=https://192.168.1.1
  ROUTER_API_KEY=<key>
  ROUTER_VERIFY_TLS=false
  ```
- **Local admin account:** create a *local* (not cloud/SSO) admin in UniFi OS. Accounts that use 2FA can't log in through the API.
  ```
  ROUTER_TYPE=unifi
  ROUTER_URL=https://192.168.1.1
  ROUTER_USERNAME=netwatch
  ROUTER_PASSWORD=<password>
  ROUTER_VERIFY_TLS=false
  ```

For a site other than the default, set `ROUTER_SITE` to the site's short name (from the URL in the UniFi app). A reservation is the client's **Fixed IP** setting; the controller pushes it to the gateway automatically.
</details>

<details>
<summary><b>OpenWrt</b></summary>

OpenWrt's web interface (LuCI) includes the ubus JSON-RPC endpoint NetWatch uses.

```
ROUTER_TYPE=openwrt
ROUTER_URL=https://192.168.1.1       # or http:// if LuCI isn't on HTTPS
ROUTER_USERNAME=root
ROUTER_PASSWORD=<root password>
ROUTER_INTERFACE=lan
ROUTER_VERIFY_TLS=false              # if LuCI uses a self-signed certificate
```

A dedicated rpcd user also works if its ACL allows `uci` read/write on the `dhcp` and `network` configs. Reservations are saved as `host` entries in `/etc/config/dhcp`, and dnsmasq reloads automatically when they're committed.
</details>

<details>
<summary><b>Linksys Velop / Atlas</b></summary>

```
ROUTER_TYPE=linksys
ROUTER_URL=http://192.168.1.1
ROUTER_PASSWORD=<router admin password>
```

NetWatch uses the router's local JNAP API, the same one the Linksys web interface uses. To check that your router supports it (the password prompt keeps it out of your shell history):

```bash
read -s -p "Router admin password: " P; echo
curl -s -X POST http://192.168.1.1/JNAP/ \
  -H "X-JNAP-Action: http://linksys.com/jnap/router/GetLANSettings" \
  -H "X-JNAP-Authorization: Basic $(printf 'admin:%s' "$P" | base64)" \
  -H "Content-Type: application/json" -d '{}'
unset P
```

A response starting with `"result": "OK"` means it's supported. JNAP is undocumented, so a firmware update could change it. Most Linksys routers serve it over plain HTTP, so the admin password crosses your LAN encoded but not encrypted. Linksys requires reservations to be **inside** the DHCP pool.

Older NetWatch settings (`LINKSYS_URL`, `LINKSYS_PASSWORD`, `LINKSYS_ALLOW_CHANGES`) still work.
</details>

### Managing reservations from NetWatch (optional)

With `ROUTER_ALLOW_CHANGES=true` **and** a `WEB_PASSWORD` set, the Reservations tab lets you:

- **Reserve an address:** pick a device (or enter a MAC address), choose an IP, and add a description. A **Reserve** button on the Devices tab pre-fills the form with that device's current IP when the router allows it.
- **Remove a reservation.**

These safeguards apply to every router:

- **Validated first.** The IP must be on your network and follow your router's pool rule (see the table above). It can't be already reserved or in use by another device, and it can't be the router's own address.
- **Backed up.** The router's reservations (and, for Linksys, its full LAN settings) are saved to `/data/router-backups/` before every change. The last 30 backups are kept, readable only by the container user.
- **Verified and undone if wrong.** After saving, NetWatch reads the reservations back from the router. If the change isn't exactly as expected, or any *other* reservation changed, NetWatch undoes it and shows an error.
- **Logged.** Every change appears in the Activity log.

Give NetWatch's router account only the permissions it needs (DHCP read/write) rather than full admin where your router allows it. If you only want to *see* reservations, leave `ROUTER_ALLOW_CHANGES=false`.

A device picks up a new reservation the next time it renews its DHCP lease. Reconnect or reboot it to apply it immediately; until then its status shows as *Waiting*.

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
| `WEB_PASSWORD` | *(empty)* | Built-in admin password. **Strongly recommended.** Needed for sign-in, accounts, API tokens and DNS details. Empty disables login. |
| `ALLOWED_HOSTS` | *(empty)* | Comma-separated hostnames/IPs allowed to reach the dashboard |
| `DISCOVERY` | `true` | Recognise devices from DHCP, Bonjour/mDNS and UPnP |
| `DISCOVERY_INTERVAL` | `900` | Seconds between Bonjour/UPnP passes (min 300) |
| `PUSH_CONTACT` | `mailto:netwatch@example.org` | Contact address sent to push services (`mailto:` or `https:`) |
| `PUSH_ALLOWED_HOSTS` | *(empty)* | Extra push-service hosts to allow (only needed for unusual browsers) |
| `PUBLIC_URL` | *(empty)* | NetWatch's address, added as a link to rule alerts |
| `OIDC_ISSUER` | *(empty)* | Single sign-on provider's issuer URL. Empty turns SSO off. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | *(empty)* | Client credentials from the provider |
| `OIDC_ADMIN_GROUPS` / `OIDC_VIEWER_GROUPS` | *(empty)* | Comma-separated provider groups that sign in as admin / viewer |
| `OIDC_DEFAULT_ROLE` | `none` | Role for people in neither list: `none` (refused) or `viewer` |
| `OIDC_REDIRECT_URL` | *(auto)* | Callback URL registered at the provider, if NetWatch can't work it out (e.g. behind a reverse proxy) |
| `OIDC_SCOPES` | `openid profile email` | Scopes to request |
| `OIDC_GROUPS_CLAIM` | `groups` | ID-token claim that lists the user's groups |
| `OIDC_BUTTON_LABEL` | `Sign in with SSO` | Text of the sign-in button |
| `OIDC_CA_FILE` | *(empty)* | Extra CA certificate to trust for the provider |
| `OIDC_VERIFY_TLS` | `true` | Check the provider's HTTPS certificate |
| `NTFY_URL` / `NTFY_TOKEN` | *(empty)* | ntfy topic URL and optional access token |
| `PUSHOVER_USER_KEY` / `PUSHOVER_APP_TOKEN` | *(empty)* | Pushover credentials |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURITY` | – / `587` / `starttls` | Mail server; security is `starttls`, `ssl`, or `none` |
| `SMTP_USER` / `SMTP_PASSWORD` | *(empty)* | Mail server login |
| `SMTP_FROM` / `SMTP_TO` | *(empty)* | Sender address; comma-separated recipients |
| `ROUTER_TYPE` | *(empty)* | `opnsense`, `pfsense`, `unifi`, `openwrt` or `linksys`. Empty disables the integration. |
| `ROUTER_URL` | *(empty)* | Router address, e.g. `https://192.168.1.1` |
| `ROUTER_API_KEY` / `ROUTER_API_SECRET` | *(empty)* | API credentials (OPNsense: key + secret; pfSense and UniFi: key) |
| `ROUTER_USERNAME` / `ROUTER_PASSWORD` | *(empty)* | Login (UniFi local admin, OpenWrt, Linksys) |
| `ROUTER_VERIFY_TLS` | `true` | Set `false` for the router's self-signed HTTPS certificate |
| `ROUTER_INTERFACE` | `lan` | pfSense DHCP interface / OpenWrt interface |
| `ROUTER_SITE` | `default` | UniFi site |
| `ROUTER_DHCP` | `auto` | OPNsense DHCP server: `auto`, `dnsmasq` or `kea` |
| `ROUTER_POLL_INTERVAL` | `300` | Seconds between router syncs |
| `ROUTER_ALLOW_CHANGES` | `false` | Allow adding/removing DHCP reservations (also requires `WEB_PASSWORD`) |
| `WAN_CHECK` | `true` | Internet outage tracking on/off |
| `WAN_CHECK_INTERVAL` | `30` | Seconds between internet checks |
| `WAN_CHECK_TARGETS` | `1.1.1.1:443,8.8.8.8:443,9.9.9.9:443` | Public host:port pairs to test |
| `PIHOLE_URLS` | *(empty)* | Pi-hole addresses, comma-separated. Empty disables the integration. |
| `PIHOLE_PASSWORD` | *(empty)* | Pi-hole (app) password; comma-separated if they differ |
| `PIHOLE_VERIFY_TLS` | `true` | Set `false` for Pi-hole's self-signed HTTPS certificate |
| `PIHOLE_POLL_INTERVAL` | `300` | Seconds between Pi-hole syncs |
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
- Sign-in page, per-person accounts (admin or read-only viewer) and API tokens; see [Accounts and API tokens](#accounts-and-api-tokens). HTTP Basic login still works for tools.
- Passwords hashed with scrypt; sessions and tokens stored only as hashes; constant-time credential checks; sign-in attempts rate-limited.
- Cross-site request protection: state-changing requests from other websites are rejected, using the `Sec-Fetch-Site` and `Origin` headers.
- Optional `ALLOWED_HOSTS` allow-list to block DNS-rebinding attacks.
- Strict security headers: Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, and `no-referrer`.
- Input validation on all API parameters. All SQL uses parameterized queries. All device data, and everything read from your router and Pi-hole (device names, domain names), is HTML-escaped in the dashboard.
- DNS details (top domains, which device looked up what) show what everyone on the network browses, so they're only available when `WEB_PASSWORD` is set.
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

- **"Free" means nothing answered right now.** A powered-off device may still hold a DHCP lease, and IPs reserved on your router may look free (unless a router is connected). Before assigning a static IP, pick one outside your router's DHCP pool. The amber cells show addresses recently used by known devices.
- **Randomized MAC addresses.** Modern phones and laptops often use a private MAC per Wi-Fi network; these show as "Private (randomized MAC)". The address is normally stable for a given network. If a device rotates it, it will show up as a new device.
- **Sleeping phones.** Phones and tablets in power-save mode often ignore the regular scan. Before marking any device offline, NetWatch checks it directly at its MAC address, which most dozing devices still answer. If a device still flaps on and off, raise `OFFLINE_AFTER_MISSED_SCANS` (e.g. to 10).
- **Hostnames** depend on your router or DNS server publishing DHCP hostnames. If the column is blank, name devices in the dashboard.
- **IPv4 only.** IPv6-only devices aren't discovered.
- **Presence history** comes from the online/offline events NetWatch records, so it covers the activity-log retention period (`EVENT_RETENTION_DAYS`, default 90 days). Offline times are recorded when NetWatch notices, after the missed-scan threshold.
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
| `POST` | `/api/reservations` | Add a reservation: `mac`, `ip`, `description` (requires `ROUTER_ALLOW_CHANGES`) |
| `DELETE` | `/api/reservations/{mac}` | Remove a reservation (requires `ROUTER_ALLOW_CHANGES`) |
| `POST` | `/api/scan` | Trigger a scan now |
| `GET` | `/api/devices/{mac}/history?days=` | Presence timeline, availability, IP history, recent events |
| `GET` | `/api/devices/{mac}/dns` | Pi-hole query stats and top domains for a device |
| `POST` | `/api/devices/{mac}/wake` | Send a Wake-on-LAN packet |
| `POST` | `/api/devices/acknowledge` | Mark devices as known: `{"macs": [...]}` |
| `POST` | `/api/tags/{tag}/alerts` | Set phone/email alerts for every device with a tag |
| `GET` / `POST` / `PUT` / `DELETE` | `/api/checks[/{id}]` | List, add, edit and delete service checks |
| `POST` | `/api/checks/{id}/run` | Run a check now |
| `GET` | `/api/internet` | Internet status, uptime and outages |
| `GET` / `PUT` | `/api/settings` | Quiet hours and alert settings |
| `GET` | `/api/export/devices.csv` | Device list as CSV |
| `GET` | `/api/export/backup` | Full database backup |
| `POST` | `/api/test-notification` | Send a test alert |
| `POST` | `/api/auth/login` | Sign in: `username`, `password`; sets a session cookie |
| `POST` | `/api/auth/logout` | Sign out |
| `GET` | `/api/auth/me` | Who you're signed in as, and your role |
| `GET` | `/api/auth/options` | Whether single sign-on is available (public) |
| `GET` | `/api/auth/oidc/start`, `/api/auth/oidc/callback` | Single sign-on flow (public; used by the browser) |
| `POST` | `/api/auth/password` | Change your own password: `current`, `new` |
| `GET` / `POST` / `PATCH` / `DELETE` | `/api/users[/{id}]` | Manage accounts (admins, signed in; not with a token) |
| `GET` / `POST` / `DELETE` | `/api/tokens[/{id}]` | Manage API tokens (admins, signed in; not with a token) |
| `GET` | `/api/push/key` | NetWatch's public push key |
| `POST` | `/api/push/subscribe`, `/api/push/unsubscribe` | Turn notifications on/off for a browser |
| `POST` | `/api/push/test` | Send a test to your own devices |
| `GET` / `DELETE` | `/api/push/devices[/{id}]` | Your devices getting notifications (`?everyone=true` for admins) |
| `GET` | `/manifest.webmanifest`, `/sw.js`, `/icons/*` | App manifest, service worker and icons (public, no data) |
| `GET` | `/api/devices/{mac}/recognition` | Type, model, evidence, linked addresses and possible matches |
| `GET` | `/api/links` | "Same device?" suggestions (admins) |
| `POST` | `/api/links/{id}/confirm`, `/api/links/{id}/reject` | Accept or turn down a suggestion (admins) |
| `POST` | `/api/devices/{mac}/link`, `/api/devices/{mac}/unlink` | Link `{"other": "<older MAC>"}` by hand, or unlink an old address (admins) |
| `POST` | `/api/discover` | Run a Bonjour/UPnP pass now (admins) |
| `GET` / `POST` / `PUT` / `DELETE` | `/api/alert-rules[/{id}]` | Alert rules (admins) |
| `GET` / `POST` / `PUT` / `DELETE` | `/api/alert-channels[/{id}]` | Alert channels; secrets are never returned (admins) |
| `POST` | `/api/alert-channels/{id}/test` | Send a test message |
| `GET` | `/api/incidents?open=1` | Open and recent rule alerts |
| `POST` | `/api/incidents/{id}/ack`, `/api/incidents/ack-all` | Acknowledge (any signed-in user) |
| `GET` | `/api/timeline?hours=6\|24\|168` | Outages, failing checks, device presence and DNS volume for the timeline |
| `GET` | `/api/dns/top`, `/api/dns/domain?name=` | Network-wide top domains; which devices looked up a domain |
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
│   ├── security.py      # Who's asking, roles, CSRF/Host checks, security headers
│   ├── auth.py          # Accounts, sessions, API tokens, password hashing, sign-in limits
│   ├── sso.py           # Single sign-on (OpenID Connect)
│   ├── serve.py         # Entry point: HTTPS server + HTTP redirect
│   ├── tls.py           # Self-signed certificate creation/renewal
│   ├── healthcheck.py   # Docker health check
│   ├── routers/         # Router drivers: OPNsense, pfSense, UniFi, OpenWrt (+ shared base)
│   ├── router_linksys.py  # Linksys JNAP driver
│   ├── alerts.py        # Central alert path: quiet hours, snooze, held alerts
│   ├── rules.py         # Alert rules, delays, grouping, escalation, acknowledgement
│   ├── alert_channels.py  # Discord, Slack, Telegram, Gotify, ntfy, webhook, MQTT
│   ├── services.py      # Service checks (HTTP, TCP, ping)
│   ├── wan.py           # Internet outage tracking
│   ├── pihole.py        # Optional Pi-hole v6 integration
│   ├── history.py       # Device presence timeline
│   ├── recognize.py     # Device recognition (DHCP, mDNS, SSDP) and private-address linking
│   ├── push.py          # Web Push: encryption (RFC 8291), VAPID (RFC 8292), subscriptions
│   ├── timeline.py      # Overview timeline (outages, checks, presence, DNS)
│   ├── wol.py           # Wake-on-LAN
│   ├── db.py            # SQLite storage
│   ├── config.py        # Environment-variable configuration
│   ├── static/index.html  # Dashboard (single page, no external assets)
│   ├── static/login.html  # Sign-in page
│   ├── static/sw.js     # Service worker: shows notifications (caches nothing)
│   └── static/manifest.webmanifest, static/icons/  # Installable app
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
