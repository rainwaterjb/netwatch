"""UniFi (UniFi OS consoles: UDM, UDR, UCG, Cloud Key Gen2+; and legacy
self-hosted Network controllers).

Authentication, either:
  - ROUTER_API_KEY: an API key from the Network app (Settings > Control Plane
    > Integrations, or Admins > API key), sent as X-API-KEY; or
  - ROUTER_USERNAME / ROUTER_PASSWORD: a *local* admin account (cloud/SSO
    accounts with 2FA can't log in through the API).

A reservation is a client with "Fixed IP" set (use_fixedip + fixed_ip on the
client record). The controller pushes changes to the gateway by itself.
"""
import ipaddress

from .base import RouterBase, RouterError, first_ipv4, norm_mac


class UnifiRouter(RouterBase):
    brand = "UniFi"
    pool_rule = "any"
    needs = ("url",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.site = cfg.router_site or "default"
        self.prefix_path = None          # "/proxy/network" on UniFi OS, "" on legacy controllers
        self.csrf = None
        self._logged_in = False

    @property
    def enabled(self):
        return bool(self.url and (self.api_key or (self.username and self.password)))

    def _login(self):
        if self.api_key:
            self.prefix_path = "/proxy/network" if self.prefix_path is None else self.prefix_path
            self._logged_in = True
            return
        for path, prefix in (("/api/auth/login", "/proxy/network"), ("/api/login", "")):
            status, _, headers = self._http("POST", self.url + path,
                                            {"username": self.username, "password": self.password,
                                             "remember": False})
            if status == 404:
                continue
            if status in (400, 401, 403):
                raise RouterError("UniFi rejected the login (use a local admin account; "
                                  "check ROUTER_USERNAME / ROUTER_PASSWORD)")
            if status >= 400:
                raise RouterError(f"UniFi login failed (HTTP {status})")
            self.prefix_path = prefix
            self.csrf = headers.get("X-CSRF-Token") or headers.get("x-csrf-token") or self.csrf
            self._logged_in = True
            return
        raise RouterError("UniFi login endpoint not found (check ROUTER_URL)")

    def _call(self, method, path, body=None, retry=True):
        if not self._logged_in:
            self._login()
        headers = {}
        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        url = f"{self.url}{self.prefix_path}/api/s/{self.site}/{path}"
        status, data, rh = self._http(method, url, body=body, headers=headers)
        new_csrf = rh.get("X-Updated-CSRF-Token") or rh.get("x-updated-csrf-token") if rh else None
        if new_csrf:
            self.csrf = new_csrf
        if status == 401 and retry and not self.api_key:
            self._logged_in = False
            return self._call(method, path, body, retry=False)
        if status in (401, 403):
            raise RouterError("UniFi refused the request (check the API key / account permissions)")
        meta = (data or {}).get("meta") if isinstance(data, dict) else None
        if status >= 400 or (meta and meta.get("rc") == "error"):
            msg = (meta or {}).get("msg") or f"HTTP {status}"
            raise RouterError(f"UniFi {path} failed: {msg}")
        return (data or {}).get("data") or [] if isinstance(data, dict) else []

    def fetch(self):
        nets = []
        for n in self._call("GET", "rest/networkconf"):
            if not n.get("ip_subnet"):
                continue
            try:
                net = ipaddress.IPv4Network(n["ip_subnet"], strict=False)
            except ValueError:
                continue
            nets.append((net, n))
        net, conf = self.pick(nets)
        conf = conf or {}
        pool = None
        if conf.get("dhcpd_enabled", True) and conf.get("dhcpd_start") and conf.get("dhcpd_stop"):
            pool = (first_ipv4(conf["dhcpd_start"]), first_ipv4(conf["dhcpd_stop"]))
        router_ip = first_ipv4(str(conf.get("ip_subnet", "")).split("/")[0]) if conf else None
        reservations, names, users = [], {}, {}
        for u in self._call("GET", "rest/user"):
            mac = norm_mac(u.get("mac"))
            if not mac:
                continue
            users[mac] = u
            name = (u.get("name") or u.get("hostname") or "").strip()
            if name:
                names[mac] = name[:64]
            if u.get("use_fixedip") and u.get("fixed_ip"):
                reservations.append({"mac": mac, "ip": first_ipv4(u["fixed_ip"]),
                                     "description": u.get("name") or u.get("hostname") or "",
                                     "ref": u.get("_id")})
        return {"reservations": reservations, "pool": pool, "router_ip": router_ip,
                "prefix": net.prefixlen if net else None, "names": names, "max_desc": 63,
                "raw": {"network_id": conf.get("_id"), "network": conf.get("name"),
                        "fixed": [{k: users[r["mac"]].get(k) for k in ("_id", "mac", "name", "fixed_ip", "network_id")}
                                  for r in reservations]},
                "network_id": conf.get("_id"), "users": users}

    def _add(self, mac, ip, description, info):
        if not info.get("network_id"):
            raise RouterError("Couldn't find the UniFi network for this subnet")
        body = {"use_fixedip": True, "fixed_ip": ip, "network_id": info["network_id"]}
        if description:
            body["name"] = description
        existing = info["users"].get(mac)
        if existing and existing.get("_id"):
            self._call("PUT", f"rest/user/{existing['_id']}", body)
        else:
            self._call("POST", "rest/user", {"mac": mac, **body})

    def _remove(self, entry, info):
        if not entry.get("ref"):
            raise RouterError("UniFi client record has no id")
        self._call("PUT", f"rest/user/{entry['ref']}", {"use_fixedip": False})
