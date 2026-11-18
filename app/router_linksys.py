"""Linksys Velop / Atlas mesh routers, via their local JNAP API.

Reads the DHCP pool, DHCP reservations and device names. Optionally adds and
removes DHCP reservations. Linksys stores reservations inside the LAN
settings, so a change rewrites that whole block: NetWatch sends back exactly
what it read with only the reservation list changed, verifies the result,
and restores the previous settings if anything else changed.
"""
import base64
import copy
import json
import logging
import urllib.error
import urllib.request

from .routers.base import RouterBase, RouterError, norm_mac

log = logging.getLogger("netwatch.router")
JNAP_PREFIX = "http://linksys.com/jnap/"
GENERIC_NAMES = {"", "network device", "unknown"}
# Fields of GetLANSettings that SetLANSettings accepts back.
SETTABLE_KEYS = ("ipAddress", "networkPrefixLength", "hostName", "isDHCPEnabled", "dhcpSettings")

__all__ = ["LinksysRouter", "RouterError"]


class LinksysRouter(RouterBase):
    brand = "Linksys"
    pool_rule = "inside"
    needs = ("url", "password")

    def __init__(self, cfg):
        super().__init__(cfg)
        # Older .env files used LINKSYS_* names.
        self.url = (self.url or getattr(cfg, "linksys_url", "") or "").rstrip("/")
        self.username = self.username or getattr(cfg, "linksys_username", "") or "admin"
        self.password = self.password or getattr(cfg, "linksys_password", "")
        self.allow_changes = self.allow_changes or getattr(cfg, "linksys_allow_changes", False)

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
    def fetch(self):
        return self._info(self._call("router/GetLANSettings"), with_names=True)

    def _info(self, lan, with_names=False):
        dhcp = lan.get("dhcpSettings") or {}
        names = None
        if with_names:
            try:
                names = self._device_names()
            except RouterError as e:
                log.debug("Device names unavailable: %s", e)
        on = lan.get("isDHCPEnabled", True)
        pool = (dhcp.get("firstClientIPAddress"), dhcp.get("lastClientIPAddress")) if on else None
        return {
            "reservations": [{"mac": norm_mac(r.get("macAddress")), "ip": r.get("ipAddress"),
                              "description": r.get("description") or ""}
                             for r in dhcp.get("reservations") or []],
            "pool": pool, "router_ip": lan.get("ipAddress"), "prefix": lan.get("networkPrefixLength"),
            "names": names, "max_desc": lan.get("maxDHCPReservationDescriptionLength") or 63, "raw": lan,
        }

    def _apply_lan(self, lan):
        self._store(self._info(lan))

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

    # Changes (opt-in): Linksys rewrites the whole LAN settings block
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
        self._require_changes()
        with self.write_lock:
            before = self._call("router/GetLANSettings")       # always start from live settings
            self._backup({"reservations": self._info(before)["reservations"], "raw": before}, what)
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


def _res_key(reservations):
    return sorted(((r.get("macAddress") or "").lower(), r.get("ipAddress"), (r.get("description") or ""))
                  for r in reservations or [])
