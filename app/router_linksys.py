"""Read-only integration with Linksys Velop/Atlas routers via their local JNAP API.

JNAP is undocumented; this module only *reads* settings (DHCP pool, DHCP
reservations, device names) and never changes anything on the router.
"""
import base64
import ipaddress
import json
import logging
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("netwatch.router")
JNAP_PREFIX = "http://linksys.com/jnap/"
GENERIC_NAMES = {"", "network device", "unknown"}


class RouterError(Exception):
    pass


class LinksysRouter:
    def __init__(self, cfg):
        self.url = (cfg.linksys_url or "").rstrip("/")
        self.username = cfg.linksys_username or "admin"
        self.password = cfg.linksys_password
        self.interval = cfg.router_poll_interval
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.state = {
            "reservations": {},      # mac -> {"ip", "description"}
            "reserved_ips": {},      # ip  -> {"mac", "description"}
            "names": {},             # mac -> name from the router's device list
            "dhcp_first": None, "dhcp_last": None,
            "router_ip": None, "last_sync": None, "error": None,
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

        names = {}
        try:
            names = self._device_names()
        except RouterError as e:
            log.debug("Device names unavailable: %s", e)

        with self.lock:
            self.state.update(
                reservations=reservations, reserved_ips=reserved_ips, names=names,
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
