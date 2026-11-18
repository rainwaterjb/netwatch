"""OPNsense, via its REST API (API key + secret, HTTP Basic auth).

Supports both modern DHCP servers:
  - Dnsmasq (default on new installs): reservations are "Hosts" entries
    (fields host, ip, hwaddr, descr); pools are "DHCP ranges".
  - Kea DHCPv4: reservations (subnet, ip_address, hw_address, hostname,
    description); pools come from the subnet definitions.
ISC DHCP (legacy) has no API for static mappings, so it isn't supported.

Create the key under System > Access > Users > (user) > API keys. The user
needs the privilege for the DHCP server in use (e.g. "Services: Dnsmasq
DNS/DHCP: Settings" or the Kea equivalents).
"""
import base64
import ipaddress
import re

from .base import RouterBase, RouterError, first_ipv4, hostify, norm_mac


def _rows(data):
    return (data or {}).get("rows") or []


def _parse_pools(text):
    """Kea pools: "192.168.1.100 - 192.168.1.200" or CIDR, one per line/comma."""
    out = []
    for part in re.split(r"[\n,]+", str(text or "")):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = (x.strip() for x in part.split("-", 1))
            try:
                out.append((str(ipaddress.IPv4Address(a)), str(ipaddress.IPv4Address(b))))
            except ValueError:
                continue
        else:
            try:
                n = ipaddress.IPv4Network(part, strict=False)
                out.append((str(n[0]), str(n[-1])))
            except ValueError:
                continue
    return out


class OpnsenseRouter(RouterBase):
    brand = "OPNsense"
    pool_rule = "any"
    needs = ("url", "api_key", "api_secret")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.backend = (cfg.router_dhcp or "auto").lower()      # auto | dnsmasq | kea

    def _call(self, method, path, body=None):
        auth = base64.b64encode(f"{self.api_key}:{self.api_secret}".encode()).decode()
        status, data, _ = self._http(method, f"{self.url}/api/{path}", body=body,
                                     headers={"Authorization": f"Basic {auth}"})
        if status in (401, 403):
            raise _AuthError("OPNsense rejected the API key (check ROUTER_API_KEY / ROUTER_API_SECRET "
                              "and the user's privileges)")
        if status == 404:
            raise RouterError(f"OPNsense has no /api/{path} (is that DHCP server installed?)")
        if status >= 400:
            raise RouterError(f"OPNsense /api/{path} failed (HTTP {status})")
        if isinstance(data, dict) and data.get("result") == "failed":
            v = data.get("validations") or {}
            raise RouterError("OPNsense refused the change: " + ("; ".join(f"{k}: {m}" for k, m in v.items())
                                                                  or "validation failed"))
        return data

    def _search(self, path):
        return _rows(self._call("POST", path, {"current": 1, "rowCount": -1, "searchPhrase": ""}))

    def _detect(self):
        if self.backend in ("dnsmasq", "kea"):
            return self.backend
        for backend, path in (("dnsmasq", "dnsmasq/settings/search_range"), ("kea", "kea/dhcpv4/search_subnet")):
            try:
                if self._search(path):
                    return backend
            except _AuthError:
                raise                      # a wrong key must not look like "no DHCP server"
            except RouterError:
                continue
        raise RouterError("No Dnsmasq DHCP ranges or Kea subnets found on OPNsense. NetWatch supports "
                          "Dnsmasq and Kea (ISC DHCP has no API for reservations).")

    def fetch(self):
        backend = self._detect()
        return self._fetch_dnsmasq() if backend == "dnsmasq" else self._fetch_kea()

    def _fetch_dnsmasq(self):
        ranges = []
        for r in self._search("dnsmasq/settings/search_range"):
            a, b = first_ipv4(r.get("start_addr")), first_ipv4(r.get("end_addr"))
            if a and b:
                net = ipaddress.IPv4Network(f"{a}/24", strict=False)   # refined below by the LAN hint
                ranges.append((net, (a, b)))
        net, pool = self.pick(ranges)
        hint = self.network_hint()
        if hint is not None and pool and ipaddress.IPv4Address(pool[0]) in hint:
            net = hint
        reservations = []
        for h in self._search("dnsmasq/settings/search_host"):
            ip = first_ipv4(h.get("ip"))
            for mac in re.split(r"[,\s]+", str(h.get("hwaddr") or "")):
                mac = norm_mac(mac)
                if ip and mac:
                    reservations.append({"mac": mac, "ip": ip,
                                         "description": h.get("descr") or h.get("host") or "",
                                         "ref": h.get("uuid")})
        return {"reservations": reservations, "pool": pool, "router_ip": self.guess_router_ip(net),
                "prefix": net.prefixlen if net else None, "names": {}, "max_desc": 63,
                "raw": {"backend": "dnsmasq"}, "backend": "dnsmasq"}

    def _fetch_kea(self):
        subnets = []
        for s in self._search("kea/dhcpv4/search_subnet"):
            try:
                net = ipaddress.IPv4Network(str(s.get("subnet")).strip(), strict=False)
            except ValueError:
                continue
            subnets.append((net, s))
        net, sub = self.pick(subnets)
        pools = _parse_pools((sub or {}).get("pools"))
        pool = (pools[0][0], pools[-1][1]) if pools else None
        reservations = []
        for r in self._search("kea/dhcpv4/search_reservation"):
            ip, mac = first_ipv4(r.get("ip_address")), norm_mac(r.get("hw_address"))
            if ip and mac:
                reservations.append({"mac": mac, "ip": ip,
                                     "description": r.get("description") or r.get("hostname") or "",
                                     "ref": r.get("uuid")})
        return {"reservations": reservations, "pool": pool, "router_ip": self.guess_router_ip(net),
                "prefix": net.prefixlen if net else None, "names": {}, "max_desc": 63,
                "raw": {"backend": "kea"}, "backend": "kea",
                "subnets": [(n, s.get("uuid")) for n, s in subnets]}

    def _add(self, mac, ip, description, info):
        if info["backend"] == "dnsmasq":
            self._call("POST", "dnsmasq/settings/add_host", {"host": {
                "host": hostify(description, mac), "ip": ip, "hwaddr": mac, "descr": description}})
        else:
            uuid = next((u for n, u in info["subnets"] if ipaddress.IPv4Address(ip) in n), None)
            if not uuid:
                raise RouterError(f"No Kea subnet on OPNsense contains {ip}")
            self._call("POST", "kea/dhcpv4/add_reservation", {"reservation": {
                "subnet": uuid, "ip_address": ip, "hw_address": mac,
                "hostname": hostify(description, mac), "description": description}})
        self._backend_used = info["backend"]

    def _remove(self, entry, info):
        if not entry.get("ref"):
            raise RouterError("OPNsense entry has no id")
        if info["backend"] == "dnsmasq":
            self._call("POST", f"dnsmasq/settings/del_host/{entry['ref']}", {})
        else:
            self._call("POST", f"kea/dhcpv4/del_reservation/{entry['ref']}", {})
        self._backend_used = info["backend"]

    def _apply(self):
        backend = getattr(self, "_backend_used", None) or self._detect()
        self._call("POST", f"{'dnsmasq' if backend == 'dnsmasq' else 'kea'}/service/reconfigure", {})


class _AuthError(RouterError):
    pass
