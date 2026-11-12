"""Integration with Linksys Velop/Atlas routers via their local JNAP API.

Reads the DHCP pool, DHCP reservations and device names. Optionally (only
when LINKSYS_ALLOW_CHANGES=true) adds and removes DHCP reservations. Every
change is backed up first, verified afterwards, and rolled back if anything
other than the reservation list changed.
"""
import base64
import copy
import ipaddress
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("netwatch.router")
JNAP_PREFIX = "http://linksys.com/jnap/"
GENERIC_NAMES = {"", "network device", "unknown"}
# Fields of GetLANSettings that SetLANSettings accepts back.
SETTABLE_KEYS = ("ipAddress", "networkPrefixLength", "hostName", "isDHCPEnabled", "dhcpSettings")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
DESC_RE = re.compile(r"^[\w .\-()']*$")
MAX_BACKUPS = 30


class RouterError(Exception):
    pass


class LinksysRouter:
    def __init__(self, cfg):
        self.url = (cfg.linksys_url or "").rstrip("/")
        self.username = cfg.linksys_username or "admin"
        self.password = cfg.linksys_password
        self.interval = cfg.router_poll_interval
        self.allow_changes = cfg.linksys_allow_changes
        self.backup_dir = cfg.router_backup_dir
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self._stop = threading.Event()
        self.state = {
            "reservations": {},      # mac -> {"ip", "description"}
            "reserved_ips": {},      # ip  -> {"mac", "description"}
            "names": {},             # mac -> name from the router's device list
            "dhcp_first": None, "dhcp_last": None,
            "router_ip": None, "prefix": None, "max_desc": 63,
            "last_sync": None, "error": None,
        }

    @property
    def enabled(self):
        return bool(self.url and self.password)

    # JNAP
    def _call(self, action, body=None):
        creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        req = urllib.request.Request(
            f"{self.url}/JNAP/", data=json.dumps(body or {}).encode(), method="POST",
            headers={
                "Content-Type": "application/json",
                "X-JNAP-Action": JNAP_PREFIX + action,
                "X-JNAP-Authorization": f"Basic {creds}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.URLError as e:
            raise RouterError(f"cannot reach router at {self.url}: {getattr(e, 'reason', e)}") from None
        except (ValueError, OSError) as e:
            raise RouterError(f"bad response from router: {e.__class__.__name__}") from None
        result = data.get("result")
        if result != "OK":
            if result == "_ErrorUnauthorized":
                raise RouterError("router rejected the admin password (check LINKSYS_PASSWORD)")
            raise RouterError(f"{action} failed: {result}")
        return data.get("output") or {}

    # Sync
    def sync(self):
        lan = self._call("router/GetLANSettings")
        self._apply_lan(lan)

    def _apply_lan(self, lan):
        dhcp = lan.get("dhcpSettings") or {}
        reservations, reserved_ips = {}, {}
        for r in dhcp.get("reservations") or []:
            mac = (r.get("macAddress") or "").lower()
            ip = r.get("ipAddress")
            if not mac or not ip:
                continue
            desc = (r.get("description") or "").strip() or None
            reservations[mac] = {"ip": ip, "description": desc}
            reserved_ips[ip] = {"mac": mac, "description": desc}

        names = None
        try:
            names = self._device_names()
        except RouterError as e:
            log.debug("Device names unavailable: %s", e)

        with self.lock:
            if names is None:
                names = self.state["names"]
            self.state.update(
                reservations=reservations, reserved_ips=reserved_ips, names=names,
                prefix=lan.get("networkPrefixLength"),
                max_desc=lan.get("maxDHCPReservationDescriptionLength") or 63,
                dhcp_first=dhcp.get("firstClientIPAddress") if lan.get("isDHCPEnabled", True) else None,
                dhcp_last=dhcp.get("lastClientIPAddress") if lan.get("isDHCPEnabled", True) else None,
                router_ip=lan.get("ipAddress"), last_sync=time.time(), error=None,
            )
        log.info("Router sync: %d reservations, %d named devices, DHCP pool %s-%s",
                 len(reservations), len(names), dhcp.get("firstClientIPAddress"),
                 dhcp.get("lastClientIPAddress"))

    def _device_names(self):
        """Names you've given devices in the Linksys app (best effort)."""
        out = None
        for action in ("devicelist/GetDevices3", "devicelist/GetDevices"):
            try:
                out = self._call(action)
                break
            except RouterError:
                continue
        if out is None:
            raise RouterError("device list not supported")
        names = {}
        for d in out.get("devices") or []:
            props = {p.get("name"): p.get("value") for p in d.get("properties") or []
                     if isinstance(p, dict)}
            name = (props.get("userDeviceName") or d.get("friendlyName") or "").strip()
            if name.lower() in GENERIC_NAMES:
                continue
            macs = list(d.get("knownMACAddresses") or [])
            macs += [c.get("macAddress") for c in d.get("connections") or [] if isinstance(c, dict)]
            for mac in macs:
                if mac:
                    names[mac.lower()] = name[:64]
        return names

    def start(self):
        if self.enabled:
            threading.Thread(target=self._run, name="router-sync", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.sync()
            except RouterError as e:
                log.warning("Router sync failed: %s", e)
                with self.lock:
                    self.state["error"] = str(e)
            except Exception:
                log.exception("Router sync failed")
                with self.lock:
                    self.state["error"] = "unexpected error (see container logs)"
            self._stop.wait(self.interval)

    # Queries
    def snapshot(self):
        with self.lock:
            return {k: (dict(v) if isinstance(v, dict) else v) for k, v in self.state.items()}

    def in_dhcp_pool(self, ip, snap=None):
        s = snap or self.snapshot()
        if not (s["dhcp_first"] and s["dhcp_last"]):
            return None
        try:
            a = ipaddress.IPv4Address(ip)
            return ipaddress.IPv4Address(s["dhcp_first"]) <= a <= ipaddress.IPv4Address(s["dhcp_last"])
        except ValueError:
            return None

    def name_for(self, mac):
        with self.lock:
            r = self.state["reservations"].get(mac)
            return (r and r["description"]) or self.state["names"].get(mac)

    # Changes (opt-in)
    def validate_new(self, mac, ip, description):
        """Return normalized (mac, ip, description) or raise ValueError with a friendly message."""
        s = self.snapshot()
        mac = (mac or "").strip().lower().replace("-", ":")
        if not MAC_RE.match(mac):
            raise ValueError("MAC address must look like aa:bb:cc:dd:ee:ff")
        try:
            addr = ipaddress.IPv4Address((ip or "").strip())
        except ValueError:
            raise ValueError("Enter a valid IPv4 address") from None
        ip = str(addr)
        if s["router_ip"] and s["prefix"]:
            net = ipaddress.IPv4Network(f"{s['router_ip']}/{s['prefix']}", strict=False)
            if addr not in net or addr in (net.network_address, net.broadcast_address):
                raise ValueError(f"{ip} is not a usable address on the router's network ({net})")
        if ip == s["router_ip"]:
            raise ValueError("That is the router's own address")
        if self.in_dhcp_pool(ip, s) is False:
            raise ValueError(f"Linksys only allows reservations inside the DHCP pool "
                             f"({s['dhcp_first']} - {s['dhcp_last']})")
        if mac in s["reservations"]:
            raise ValueError(f"This device already has a reservation ({s['reservations'][mac]['ip']}). "
                             "Remove it first to change it.")
        if ip in s["reserved_ips"]:
            other = s["reserved_ips"][ip]
            raise ValueError(f"{ip} is already reserved for {other['description'] or other['mac']}")
        description = " ".join((description or "").split())
        if len(description) > s["max_desc"]:
            raise ValueError(f"Description must be {s['max_desc']} characters or fewer")
        if not DESC_RE.match(description):
            raise ValueError("Description may contain letters, numbers, spaces and . - ( ) ' _")
        return mac, ip, description

    def add_reservation(self, mac, ip, description):
        mac, ip, description = self.validate_new(mac, ip, description)
        entry = {"macAddress": mac.upper(), "ipAddress": ip, "description": description}
        return self._change_reservations(lambda res: res + [entry], f"add {ip}")

    def remove_reservation(self, mac):
        mac = (mac or "").strip().lower()
        if mac not in self.snapshot()["reservations"]:
            raise ValueError("No reservation for that device")
        return self._change_reservations(
            lambda res: [r for r in res if (r.get("macAddress") or "").lower() != mac], f"remove {mac}")

    def _change_reservations(self, transform, what):
        if not (self.enabled and self.allow_changes):
            raise RouterError("Router changes are disabled (set LINKSYS_ALLOW_CHANGES=true)")
        with self.write_lock:
            before = self._call("router/GetLANSettings")       # always start from live settings
            self._backup(before, what)
            request = {k: copy.deepcopy(before[k]) for k in SETTABLE_KEYS if k in before}
            dhcp = request.setdefault("dhcpSettings", {})
            dhcp["reservations"] = transform(list(dhcp.get("reservations") or []))
            want = _res_key(dhcp["reservations"])

            self._call("router/SetLANSettings", request)
            after = self._call("router/GetLANSettings")

            problems = self._diff(before, after, want)
            if problems:
                log.error("Router change '%s' did not verify (%s); restoring previous settings",
                          what, "; ".join(problems))
                original = {k: before[k] for k in SETTABLE_KEYS if k in before}
                try:
                    self._call("router/SetLANSettings", original)
                    restored = self._call("router/GetLANSettings")
                    ok = not self._diff(before, restored, _res_key(before["dhcpSettings"].get("reservations")))
                except RouterError:
                    ok = False
                self._apply_lan(self._call("router/GetLANSettings"))
                raise RouterError("The router didn't apply the change as expected, so it was rolled back"
                                  if ok else "The change didn't verify and automatic rollback failed. "
                                  "Check the router's DHCP settings; a backup is in the router-backups folder.")
            log.info("Router change applied: %s", what)
            self._apply_lan(after)
            return self.snapshot()

    @staticmethod
    def _diff(before, after, want_reservations):
        problems = []
        if _res_key((after.get("dhcpSettings") or {}).get("reservations")) != want_reservations:
            problems.append("reservation list differs")
        for k in SETTABLE_KEYS:
            if k == "dhcpSettings":
                b = {x: y for x, y in (before.get(k) or {}).items() if x != "reservations"}
                a = {x: y for x, y in (after.get(k) or {}).items() if x != "reservations"}
                if a != b:
                    problems.append("other DHCP settings changed")
            elif before.get(k) != after.get(k):
                problems.append(f"{k} changed")
        return problems

    def _backup(self, lan, what):
        try:
            os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)
            name = time.strftime("lan-%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}.json"
            path = os.path.join(self.backup_dir, name)
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump({"reason": what, "saved": time.time(), "lan_settings": lan}, f, indent=2)
            files = sorted(f for f in os.listdir(self.backup_dir) if f.startswith("lan-"))
            for old in files[:-MAX_BACKUPS]:
                os.remove(os.path.join(self.backup_dir, old))
        except OSError as e:
            raise RouterError(f"Could not save a backup before changing the router ({e.strerror}); "
                              "no change was made") from None


def _res_key(reservations):
    return sorted(((r.get("macAddress") or "").lower(), r.get("ipAddress"), (r.get("description") or ""))
                  for r in reservations or [])
