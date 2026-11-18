"""Shared router integration logic.

A router driver only has to:
  - fetch()   read DHCP pool, reservations and (optionally) device names
  - _add()    create one reservation
  - _remove() delete one reservation
  - _apply()  activate pending changes (if the router needs it)

Everything else is shared, so every router behaves the same in NetWatch:
validation, a backup before each change, verification afterwards, and an
automatic undo if the router didn't end up in the expected state.
"""
import http.cookiejar
import ipaddress
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("netwatch.router")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
DESC_RE = re.compile(r"^[\w .\-()']*$")
MAX_BACKUPS = 30
POOL_RULES = {
    "inside": "only allows reservations inside the DHCP pool",
    "outside": "only allows reservations outside the DHCP pool",
    "any": "allows reservations anywhere in the subnet",
}


class RouterError(Exception):
    pass


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


def hostify(text, mac):
    """A DHCP-safe hostname from a description (routers that require one)."""
    h = re.sub(r"[^a-z0-9-]+", "-", (text or "").lower()).strip("-")[:63].strip("-")
    return h or "netwatch-" + mac.replace(":", "")[-6:]


def first_ipv4(value):
    for part in re.split(r"[,\s]+", str(value or "")):
        try:
            return str(ipaddress.IPv4Address(part.split("/")[0]))
        except ValueError:
            continue
    return None


class RouterBase:
    brand = "Router"
    pool_rule = "any"
    needs = ("url",)              # config keys that must be set for the driver to be enabled

    def __init__(self, cfg):
        self.cfg = cfg
        self.url = (cfg.router_url or "").rstrip("/")
        self.username = cfg.router_username
        self.password = cfg.router_password
        self.api_key = cfg.router_api_key
        self.api_secret = cfg.router_api_secret
        self.verify_tls = cfg.router_verify_tls
        self.allow_changes = cfg.router_allow_changes
        self.backup_dir = cfg.router_backup_dir
        self.interval = cfg.router_poll_interval
        self.network_hint = lambda: (ipaddress.IPv4Network(cfg.subnet, strict=False) if cfg.subnet else None)
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self._stop = threading.Event()
        self._opener = None
        self.state = {
            "reservations": {}, "reserved_ips": {}, "names": {},
            "dhcp_first": None, "dhcp_last": None, "router_ip": None, "prefix": None,
            "max_desc": 63, "last_sync": None, "error": None,
        }

    # ---------- configuration ----------
    @property
    def enabled(self):
        return all(getattr(self, k) for k in self.needs)

    @property
    def pool_rule_text(self):
        return f"{self.brand} {POOL_RULES[self.pool_rule]}"

    # ---------- HTTP helper ----------
    def _http(self, method, url, body=None, headers=None, params=None, form=False, timeout=15):
        """Returns (status, parsed JSON or None, response headers)."""
        if self._opener is None:
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        h = {"Accept": "application/json", **(headers or {})}
        data = None
        if body is not None:
            if form:
                data = urllib.parse.urlencode(body).encode()
                h["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                data = json.dumps(body).encode()
                h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw, status, rh = resp.read(), resp.status, resp.headers
        except urllib.error.HTTPError as e:
            raw, status, rh = e.read(), e.code, e.headers
        except ssl.SSLCertVerificationError:
            raise RouterError(f"{self.brand}'s HTTPS certificate isn't trusted "
                              "(set ROUTER_VERIFY_TLS=false for a self-signed certificate)") from None
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise RouterError(f"{self.brand}'s HTTPS certificate isn't trusted "
                                  "(set ROUTER_VERIFY_TLS=false for a self-signed certificate)") from None
            raise RouterError(f"cannot reach {self.brand} at {self.url}: {reason}") from None
        except (OSError, ValueError) as e:
            raise RouterError(f"bad response from {self.brand}: {e.__class__.__name__}") from None
        try:
            parsed = json.loads(raw.decode() or "null") if raw else None
        except ValueError:
            parsed = None
        return status, parsed, rh

    # ---------- driver hooks ----------
    def fetch(self):
        """Return {"reservations": [{"mac", "ip", "description", "ref"}], "pool": (first, last) or None,
        "router_ip", "prefix", "names": {mac: name}, "max_desc", "raw": <anything for backups>}."""
        raise NotImplementedError

    def _add(self, mac, ip, description, info):
        raise NotImplementedError

    def _remove(self, entry, info):
        raise NotImplementedError

    def _apply(self):
        pass

    # ---------- shared helpers for drivers ----------
    def pick(self, candidates):
        """From [(network, payload)], choose the one matching NetWatch's LAN (or the first)."""
        hint = self.network_hint()
        for net, payload in candidates:
            if net is not None and hint is not None and net.overlaps(hint):
                return net, payload
        return candidates[0] if candidates else (None, None)

    def guess_router_ip(self, net):
        host = urllib.parse.urlsplit(self.url).hostname
        try:
            ip = ipaddress.IPv4Address(host)
            return str(ip) if net is None or ip in net else None
        except (ValueError, TypeError):
            return None

    # ---------- sync ----------
    def sync(self):
        self._store(self.fetch())

    def _store(self, info):
        reservations, reserved_ips = {}, {}
        for r in info.get("reservations") or []:
            mac, ip = norm_mac(r.get("mac")), r.get("ip")
            if not MAC_RE.match(mac) or not ip:
                continue
            desc = (r.get("description") or "").strip() or None
            reservations[mac] = {"ip": ip, "description": desc}
            reserved_ips[ip] = {"mac": mac, "description": desc}
        pool = info.get("pool") or (None, None)
        with self.lock:
            names = info.get("names")
            self.state.update(
                reservations=reservations, reserved_ips=reserved_ips,
                names=names if names is not None else self.state["names"],
                dhcp_first=pool[0], dhcp_last=pool[1], router_ip=info.get("router_ip"),
                prefix=info.get("prefix"), max_desc=info.get("max_desc") or 63,
                last_sync=time.time(), error=None)
        log.info("%s sync: %d reservations, DHCP pool %s-%s", self.brand, len(reservations), pool[0], pool[1])

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
                log.warning("%s sync failed: %s", self.brand, e)
                with self.lock:
                    self.state["error"] = str(e)
            except Exception:
                log.exception("%s sync failed", self.brand)
                with self.lock:
                    self.state["error"] = "unexpected error (see container logs)"
            self._stop.wait(self.interval)

    # ---------- queries ----------
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

    def static_ok(self, ip, snap=None):
        """Can a reservation use this IP under the router's pool rule? None = unknown."""
        inside = self.in_dhcp_pool(ip, snap)
        if inside is None or self.pool_rule == "any":
            return None if inside is None else True
        return inside if self.pool_rule == "inside" else not inside

    def name_for(self, mac):
        with self.lock:
            r = self.state["reservations"].get(mac)
            return (r and r["description"]) or self.state["names"].get(mac)

    # ---------- changes ----------
    def validate_new(self, mac, ip, description):
        """Return normalized (mac, ip, description) or raise ValueError with a friendly message."""
        s = self.snapshot()
        mac = norm_mac(mac)
        if not MAC_RE.match(mac):
            raise ValueError("MAC address must look like aa:bb:cc:dd:ee:ff")
        try:
            addr = ipaddress.IPv4Address((ip or "").strip())
        except ValueError:
            raise ValueError("Enter a valid IPv4 address") from None
        ip = str(addr)
        net = None
        if s["router_ip"] and s["prefix"]:
            net = ipaddress.IPv4Network(f"{s['router_ip']}/{s['prefix']}", strict=False)
        elif self.network_hint() is not None:
            net = self.network_hint()
        if net is not None and (addr not in net or addr in (net.network_address, net.broadcast_address)):
            raise ValueError(f"{ip} is not a usable address on the router's network ({net})")
        if ip == s["router_ip"]:
            raise ValueError("That is the router's own address")
        if self.static_ok(ip, s) is False:
            raise ValueError(f"{self.pool_rule_text} ({s['dhcp_first']} - {s['dhcp_last']})")
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

    def _require_changes(self):
        if not (self.enabled and self.allow_changes):
            raise RouterError("Router changes are disabled (set ROUTER_ALLOW_CHANGES=true)")

    def add_reservation(self, mac, ip, description):
        mac, ip, description = self.validate_new(mac, ip, description)
        self._require_changes()
        with self.write_lock:
            before = self.fetch()
            if any(norm_mac(r["mac"]) == mac for r in before["reservations"]):
                raise ValueError("This device already has a reservation on the router")
            self._backup(before, f"add {ip} for {mac}")
            self._add(mac, ip, description, before)
            self._apply()
            after = self.fetch()
            want = _keys(before["reservations"]) | {(mac, ip)}
            if _keys(after["reservations"]) != want:
                log.error("%s: adding %s did not verify; undoing", self.brand, ip)
                self._undo_add(mac, after)
                raise RouterError(f"{self.brand} didn't save the reservation as expected, so it was undone")
            self._store(after)
            log.info("%s: reserved %s for %s", self.brand, ip, mac)
            return self.snapshot()

    def remove_reservation(self, mac):
        mac = norm_mac(mac)
        if mac not in self.snapshot()["reservations"]:
            raise ValueError("No reservation for that device")
        self._require_changes()
        with self.write_lock:
            before = self.fetch()
            entry = next((r for r in before["reservations"] if norm_mac(r["mac"]) == mac), None)
            if entry is None:
                self._store(before)
                raise ValueError("That reservation no longer exists on the router")
            self._backup(before, f"remove {entry['ip']} for {mac}")
            self._remove(entry, before)
            self._apply()
            after = self.fetch()
            want = _keys(before["reservations"]) - {(mac, entry["ip"])}
            if _keys(after["reservations"]) != want:
                log.error("%s: removing %s did not verify; restoring", self.brand, mac)
                self._undo_remove(entry, after)
                raise RouterError(f"{self.brand} didn't remove the reservation as expected, so it was restored")
            self._store(after)
            log.info("%s: removed reservation for %s", self.brand, mac)
            return self.snapshot()

    def _undo_add(self, mac, info):
        try:
            for r in info["reservations"]:
                if norm_mac(r["mac"]) == mac:
                    self._remove(r, info)
            self._apply()
            self._store(self.fetch())
        except RouterError:
            log.exception("%s: undo failed", self.brand)

    def _undo_remove(self, entry, info):
        try:
            if not any(norm_mac(r["mac"]) == norm_mac(entry["mac"]) for r in info["reservations"]):
                self._add(norm_mac(entry["mac"]), entry["ip"], entry.get("description") or "", info)
                self._apply()
            self._store(self.fetch())
        except RouterError:
            log.exception("%s: undo failed", self.brand)

    def _backup(self, info, what):
        try:
            os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)
            name = time.strftime("lan-%Y%m%d-%H%M%S") + f"-{int(time.time() * 1000) % 1000:03d}.json"
            path = os.path.join(self.backup_dir, name)
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump({"router": self.brand, "reason": what, "saved": time.time(),
                           "reservations": info.get("reservations"), "raw": info.get("raw")},
                          f, indent=2, default=str)
            files = sorted(f for f in os.listdir(self.backup_dir) if f.startswith("lan-"))
            for old in files[:-MAX_BACKUPS]:
                os.remove(os.path.join(self.backup_dir, old))
        except OSError as e:
            raise RouterError(f"Could not save a backup before changing the router ({e.strerror}); "
                              "no change was made") from None


def _keys(reservations):
    return {(norm_mac(r["mac"]), r["ip"]) for r in reservations}
