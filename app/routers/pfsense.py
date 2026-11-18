"""pfSense, via the community REST API package (pfrest, v2 API).

Install "pfSense-pkg-RESTAPI" on the firewall, create an API key under
System > REST API > Keys, and set ROUTER_API_KEY. NetWatch reads and edits
the DHCP server's static mappings on one interface (ROUTER_INTERFACE,
default "lan"), then applies the DHCP server.

pfSense requires static mappings to be OUTSIDE the DHCP pool.
"""
import ipaddress

from .base import RouterBase, RouterError, first_ipv4, hostify, norm_mac


class PfsenseRouter(RouterBase):
    brand = "pfSense"
    pool_rule = "outside"
    needs = ("url", "api_key")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.iface = cfg.router_interface or "lan"

    def _call(self, method, path, body=None, params=None):
        status, data, _ = self._http(method, f"{self.url}/api/v2/{path}", body=body, params=params,
                                     headers={"X-API-Key": self.api_key})
        if status in (401, 403):
            raise RouterError("pfSense rejected the API key (check ROUTER_API_KEY and the key's privileges)")
        if status == 404 and not isinstance(data, dict):
            raise RouterError("pfSense REST API not found (is the pfSense-pkg-RESTAPI package installed?)")
        if status >= 400:
            msg = (data or {}).get("message") if isinstance(data, dict) else None
            raise RouterError(f"pfSense {path} failed (HTTP {status}{': ' + msg if msg else ''})")
        return (data or {}).get("data") if isinstance(data, dict) else None

    def fetch(self):
        server = self._call("GET", "services/dhcp_server", params={"id": self.iface}) or {}
        if isinstance(server, list):
            server = next((s for s in server if s.get("id") == self.iface), server[0] if server else {})
        a, b = first_ipv4(server.get("range_from")), first_ipv4(server.get("range_to"))
        pool = (a, b) if a and b else None
        hint = self.network_hint()
        net = hint if hint is not None and pool and ipaddress.IPv4Address(pool[0]) in hint else (
            ipaddress.IPv4Network(f"{a}/24", strict=False) if a else None)
        maps = self._call("GET", "services/dhcp_server/static_mappings", params={"parent_id": self.iface}) or []
        reservations = []
        for m in maps:
            if m.get("parent_id") not in (None, self.iface):
                continue
            ip, mac = first_ipv4(m.get("ipaddr")), norm_mac(m.get("mac"))
            if ip and mac:
                reservations.append({"mac": mac, "ip": ip,
                                     "description": m.get("descr") or m.get("hostname") or "",
                                     "ref": m.get("id")})
        return {"reservations": reservations, "pool": pool, "router_ip": self.guess_router_ip(net),
                "prefix": net.prefixlen if net else None, "names": {}, "max_desc": 63,
                "raw": {"interface": self.iface, "server": {k: server.get(k) for k in ("range_from", "range_to")},
                        "static_mappings": maps}}

    def _add(self, mac, ip, description, info):
        self._call("POST", "services/dhcp_server/static_mapping", {
            "parent_id": self.iface, "mac": mac, "ipaddr": ip,
            "hostname": hostify(description, mac), "descr": description})

    def _remove(self, entry, info):
        if entry.get("ref") is None:
            raise RouterError("pfSense static mapping has no id")
        self._call("DELETE", "services/dhcp_server/static_mapping",
                   params={"parent_id": self.iface, "id": entry["ref"]})

    def _apply(self):
        self._call("POST", "services/dhcp_server/apply", {})
