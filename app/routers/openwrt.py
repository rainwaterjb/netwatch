"""OpenWrt, via the ubus JSON-RPC interface (rpcd, served at /ubus).

Reservations are "host" sections in /etc/config/dhcp (name, mac, ip). The DHCP
pool comes from the interface's dhcp section (start + limit, offsets from the
interface's network address). Committing the dhcp config makes procd reload
dnsmasq automatically.

Log in with ROUTER_USERNAME (default root) / ROUTER_PASSWORD. A dedicated rpcd
user also works if it has read/write ACLs for "uci" on the dhcp and network
configs.
"""
import ipaddress
import re

from .base import RouterBase, RouterError, first_ipv4, hostify, norm_mac

NULL_SESSION = "0" * 32
ACCESS_DENIED = (6, -32002)          # ubus permission denied / JSON-RPC access denied


class OpenwrtRouter(RouterBase):
    brand = "OpenWrt"
    pool_rule = "any"
    needs = ("url", "password")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.username = cfg.router_username or "root"
        self.iface = cfg.router_interface or "lan"
        self.session = None
        self._id = 0

    def _rpc(self, session, obj, method, args):
        self._id += 1
        status, data, _ = self._http("POST", f"{self.url}/ubus", {
            "jsonrpc": "2.0", "id": self._id, "method": "call", "params": [session, obj, method, args or {}]})
        if status == 404:
            raise RouterError("OpenWrt /ubus not found (install uhttpd-mod-ubus / luci, check ROUTER_URL)")
        if status >= 400 or not isinstance(data, dict):
            raise RouterError(f"OpenWrt ubus call failed (HTTP {status})")
        if data.get("error"):
            code = data["error"].get("code")
            raise RouterError(f"OpenWrt {obj}.{method}: {data['error'].get('message')}", ) if code not in ACCESS_DENIED \
                else _Denied()
        result = data.get("result") or [None]
        if result[0] not in (0, None):
            if result[0] in ACCESS_DENIED:
                raise _Denied()
            raise RouterError(f"OpenWrt {obj}.{method} failed (ubus status {result[0]})")
        return result[1] if len(result) > 1 else {}

    def _login(self):
        try:
            out = self._rpc(NULL_SESSION, "session", "login",
                            {"username": self.username, "password": self.password})
        except _Denied:
            raise RouterError("OpenWrt rejected the login (check ROUTER_USERNAME / ROUTER_PASSWORD)") from None
        self.session = (out or {}).get("ubus_rpc_session")
        if not self.session:
            raise RouterError("OpenWrt login returned no session")

    def _call(self, obj, method, args=None):
        if not self.session:
            self._login()
        try:
            return self._rpc(self.session, obj, method, args)
        except _Denied:
            self._login()                    # session expired: log in again once
            try:
                return self._rpc(self.session, obj, method, args)
            except _Denied:
                raise RouterError(f"OpenWrt user '{self.username}' isn't allowed to call {obj}.{method}") from None

    def _uci_get(self, config, section=None, type_=None):
        args = {"config": config}
        if section:
            args["section"] = section
        if type_:
            args["type"] = type_
        return (self._call("uci", "get", args) or {}).get("values") or {}

    def fetch(self):
        net_sec = self._uci_get("network", self.iface)
        ipaddr, mask = net_sec.get("ipaddr"), net_sec.get("netmask")
        if isinstance(ipaddr, list):
            ipaddr = ipaddr[0] if ipaddr else None
        net = router_ip = None
        if ipaddr:
            router_ip = first_ipv4(ipaddr)
            try:
                net = ipaddress.IPv4Network(ipaddr if "/" in str(ipaddr) else f"{router_ip}/{mask or '255.255.255.0'}",
                                            strict=False)
            except ValueError:
                net = None
        pool = None
        dhcp_sec = self._uci_get("dhcp", self.iface)
        if net is not None and dhcp_sec and str(dhcp_sec.get("ignore", "0")) != "1":
            start, limit = int(dhcp_sec.get("start", 100)), int(dhcp_sec.get("limit", 150))
            first = net.network_address + start
            last = min(net.network_address + start + limit - 1, net.broadcast_address - 1)
            pool = (str(first), str(last))
        reservations, names = [], {}
        for sec_name, sec in self._uci_get("dhcp", type_="host").items():
            ip = first_ipv4(sec.get("ip"))
            macs = sec.get("mac") or []
            macs = macs if isinstance(macs, list) else re.split(r"[\s,]+", str(macs))
            for mac in macs:
                mac = norm_mac(mac)
                if not mac:
                    continue
                if sec.get("name"):
                    names[mac] = str(sec["name"])[:64]
                if ip:
                    reservations.append({"mac": mac, "ip": ip, "description": sec.get("name") or "",
                                         "ref": sec.get(".name") or sec_name})
        return {"reservations": reservations, "pool": pool, "router_ip": router_ip,
                "prefix": net.prefixlen if net else None, "names": names, "max_desc": 63,
                "raw": {"interface": self.iface, "hosts": reservations}}

    def _add(self, mac, ip, description, info):
        self._call("uci", "add", {"config": "dhcp", "type": "host",
                                  "values": {"name": hostify(description, mac), "mac": mac, "ip": ip, "dns": "1"}})
        self._call("uci", "commit", {"config": "dhcp"})

    def _remove(self, entry, info):
        if not entry.get("ref"):
            raise RouterError("OpenWrt host section has no name")
        self._call("uci", "delete", {"config": "dhcp", "section": entry["ref"]})
        self._call("uci", "commit", {"config": "dhcp"})


class _Denied(Exception):
    pass
