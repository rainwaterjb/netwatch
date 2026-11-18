"""Pi-hole v6 integration (read-only).

For each device (matched by IP): DNS queries in the last 24 hours, queries in
the last hour, its usual hourly volume, and top domains. A device is flagged
"chatty" when its last hour is far above its usual volume.

Uses the Pi-hole v6 REST API: POST /api/auth for a session, then requests
with the X-FTL-SID header. Several Pi-holes can be listed; their numbers are
added together.
"""
import json
import logging
import ssl
import statistics
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict

from .alerts import channels
from .monitor import display_name

log = logging.getLogger("netwatch.pihole")
CHATTY_REALERT_SECONDS = 6 * 3600


class PiholeError(Exception):
    pass


class PiholeClient:
    def __init__(self, url, password, verify_tls=True):
        self.url = url.rstrip("/")
        self.password = password
        self.sid = None
        self.lock = threading.Lock()
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=ctx))

    @property
    def host(self):
        return urllib.parse.urlsplit(self.url).hostname or self.url

    def _request(self, method, path, body=None, params=None, auth=True):
        url = f"{self.url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth and self.sid:
            headers["X-FTL-SID"] = self.sid
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                payload = json.loads(e.read().decode() or "{}")
            except ValueError:
                payload = {}
            return e.code, payload
        except urllib.error.URLError as e:
            raise PiholeError(f"cannot reach {self.host}: {getattr(e, 'reason', e)}") from None
        except (ValueError, OSError) as e:
            raise PiholeError(f"bad response from {self.host}: {e.__class__.__name__}") from None

    def _login(self):
        status, data = self._request("POST", "/api/auth", {"password": self.password}, auth=False)
        session = data.get("session") or {}
        if status == 401 or not session.get("valid"):
            raise PiholeError(f"{self.host} rejected the password (check PIHOLE_PASSWORD; "
                              "an app password from Settings > Web interface / API works)")
        if status >= 400:
            raise PiholeError(f"{self.host} login failed (HTTP {status})")
        self.sid = session.get("sid")          # None when the Pi-hole has no password

    def get(self, path, params=None):
        with self.lock:
            if self.sid is None and self.password:
                self._login()
            status, data = self._request("GET", path, params=params)
            if status == 401:
                self._login()
                status, data = self._request("GET", path, params=params)
            if status == 404:
                raise PiholeError(f"{self.host} doesn't have {path} (Pi-hole v6 or newer is required)")
            if status >= 400:
                raise PiholeError(f"{self.host} {path} failed (HTTP {status})")
            return data

    def history_by_client(self):
        """{ip: [(timestamp, count), ...]} for the last 24 hours (10-minute buckets)."""
        data = self.get("/api/history/clients", {"N": 0})
        clients = data.get("clients") or []
        if isinstance(clients, dict):              # tolerate {ip: {...}} shape
            clients = [{"ip": k, **(v if isinstance(v, dict) else {})} for k, v in clients.items()]
        ips = [c.get("ip") for c in clients]
        out = defaultdict(list)
        for entry in data.get("history") or []:
            ts = entry.get("timestamp")
            values = entry.get("data")
            if ts is None or values is None:
                continue
            if isinstance(values, dict):
                pairs = values.items()
            else:
                pairs = zip(ips, values)
            for ip, count in pairs:
                if ip and isinstance(count, (int, float)):
                    out[ip].append((float(ts), int(count)))
        return out

    def network_top(self, blocked, count):
        """Pi-hole's own top-domain list (its in-memory window, normally 24 hours)."""
        data = self.get("/api/stats/top_domains", {"count": count, "blocked": "true" if blocked else "false"})
        out = Counter()
        for d in data.get("domains") or []:
            if d.get("domain") and isinstance(d.get("count"), (int, float)):
                out[d["domain"]] += int(d["count"])
        return out, int(data.get("total_queries") or 0), int(data.get("blocked_queries") or 0)

    def domain_clients(self, domain, since, length=5000):
        data = self.get("/api/queries", {"domain": domain, "from": int(since), "length": length})
        counts = Counter()
        for q in data.get("queries") or []:
            if q.get("domain") and q["domain"] != domain:     # in case the filter isn't supported
                continue
            client = q.get("client")
            ip = client.get("ip") if isinstance(client, dict) else client
            if ip:
                counts[ip] += 1
        return counts

    def top_domains(self, ip, since, length=2000):
        data = self.get("/api/queries", {"client_ip": ip, "from": int(since), "length": length})
        counts = Counter()
        for q in data.get("queries") or []:
            client = q.get("client")
            client_ip = client.get("ip") if isinstance(client, dict) else client
            if client_ip and client_ip != ip:      # in case the filter isn't supported
                continue
            if q.get("domain"):
                counts[q["domain"]] += 1
        return counts


class PiholeIntegration:
    def __init__(self, cfg, store, alerts, router=None):
        self.store = store
        self.alerts = alerts
        self.router = router
        self.interval = cfg.pihole_poll_interval
        passwords = cfg.pihole_passwords or [""]
        self.clients = [
            PiholeClient(url, passwords[i] if i < len(passwords) else passwords[-1], cfg.pihole_verify_tls)
            for i, url in enumerate(cfg.pihole_urls)
        ]
        self.lock = threading.Lock()
        self.stats = {}             # ip -> {...}
        self.errors = {}            # host -> message
        self.last_sync = None
        self._alerted = {}          # ip -> ts of last chatty alert
        self._domain_cache = {}
        self._stop = threading.Event()

    @property
    def enabled(self):
        return bool(self.clients)

    def sync(self, now=None):
        now = now or time.time()
        merged = defaultdict(lambda: defaultdict(int))     # ip -> bucket ts -> count
        errors = {}
        for c in self.clients:
            try:
                for ip, series in c.history_by_client().items():
                    for ts, count in series:
                        merged[ip][ts] += count
            except PiholeError as e:
                errors[c.host] = str(e)
                log.warning("Pi-hole sync: %s", e)
        settings = self.alerts.settings()
        factor = float(settings.get("chatty_factor") or 5)
        minimum = int(settings.get("chatty_min_per_hour") or 600)
        stats = {}
        for ip, buckets in merged.items():
            series = sorted(buckets.items())
            last_hour = sum(c for ts, c in series if ts >= now - 3600)
            day = sum(c for ts, c in series if ts >= now - 86400)
            hourly = defaultdict(int)
            for ts, c in series:
                if now - 86400 <= ts < now - 3600:
                    hourly[int((now - ts) // 3600)] += c
            baseline = statistics.median(hourly.values()) if len(hourly) >= 6 else None
            chatty = bool(baseline is not None and last_hour >= minimum
                          and last_hour >= factor * max(baseline, 1))
            stats[ip] = {"queries_24h": day, "queries_1h": last_hour,
                         "baseline_per_hour": round(baseline) if baseline is not None else None,
                         "chatty": chatty,
                         "hourly": [hourly.get(h, 0) for h in range(23, 0, -1)] + [last_hour]}
        with self.lock:
            previous = self.stats
            self.stats, self.errors, self.last_sync = stats, errors, now
        if len(errors) < len(self.clients):
            self._chatty_transitions(previous, stats, settings, now)

    def _chatty_transitions(self, previous, stats, settings, now):
        devices = {d["ip"]: d for d in self.store.all_devices() if d.get("ip")}
        for ip, s in stats.items():
            was = (previous.get(ip) or {}).get("chatty", False)
            dev = devices.get(ip)
            if s["chatty"] and not was:
                name = display_name(dev, self.router) if dev else ip
                detail = (f"Unusually many DNS queries: {s['queries_1h']} in the last hour "
                          f"(usually about {s['baseline_per_hour']}/hour)")
                self.store.add_event("chatty", dev["mac"] if dev else None, ip, detail, ts=now)
                phone, email = channels(settings.get("chatty_alerts", "none"))
                if (phone or email) and now - self._alerted.get(ip, 0) > CHATTY_REALERT_SECONDS:
                    self._alerted[ip] = now
                    self.alerts.send(f"Chatty device: {name}", f"{name} ({ip}): {detail}.",
                                     phone=phone, email=email, tags=["loudspeaker"], device=dev, now=now)
            elif was and not s["chatty"]:
                self.store.add_event("chatty_end", dev["mac"] if dev else None, ip,
                                     "DNS query volume back to normal", ts=now)

    def stats_for(self, ip):
        with self.lock:
            return self.stats.get(ip)

    def network_top(self, count=50):
        """Top allowed and blocked domains across every Pi-hole, cached for a minute."""
        key = ("net", count)
        cached = self._domain_cache.get(key)
        if cached and time.time() - cached[0] < 60:
            return cached[1]
        allowed, blocked, errors = Counter(), Counter(), []
        total = blocked_total = 0
        for c in self.clients:
            try:
                a, t, b = c.network_top(False, count)
                bl, _, _ = c.network_top(True, count)
                allowed.update(a); blocked.update(bl); total += t; blocked_total += b
            except PiholeError as e:
                errors.append(str(e))
        result = {"allowed": [{"domain": d, "count": n} for d, n in allowed.most_common(count)],
                  "blocked": [{"domain": d, "count": n} for d, n in blocked.most_common(count)],
                  "total_queries": total, "blocked_queries": blocked_total,
                  "servers": [c.host for c in self.clients], "errors": errors, "fetched": time.time()}
        self._remember(key, result)
        return result

    def domain_clients(self, domain, hours=24):
        key = ("domain", domain, hours)
        cached = self._domain_cache.get(key)
        if cached and time.time() - cached[0] < 60:
            return cached[1]
        counts, errors = Counter(), []
        since = time.time() - hours * 3600
        for c in self.clients:
            try:
                counts.update(c.domain_clients(domain, since))
            except PiholeError as e:
                errors.append(str(e))
        result = {"clients": [{"ip": ip, "count": n} for ip, n in counts.most_common(25)],
                  "sampled": sum(counts.values()), "errors": errors}
        self._remember(key, result)
        return result

    def _remember(self, key, result, limit=300):
        """Cache a Pi-hole answer briefly; keep the cache small whatever is asked for."""
        now = time.time()
        if len(self._domain_cache) >= limit:
            for k in [k for k, (t, _) in self._domain_cache.items() if now - t >= 120]:
                del self._domain_cache[k]
            while len(self._domain_cache) >= limit:
                del self._domain_cache[next(iter(self._domain_cache))]
        self._domain_cache[key] = (now, result)

    def total_hourly(self):
        """DNS queries per hour across every client for the last 24h, oldest first."""
        with self.lock:
            series = [s["hourly"] for s in self.stats.values() if s.get("hourly")]
        if not series:
            return None
        return [sum(col) for col in zip(*series)]

    def top_domains(self, ip, hours=24, limit=15):
        key = (ip, hours)
        cached = self._domain_cache.get(key)
        if cached and time.time() - cached[0] < 120:
            return cached[1]
        counts, errors = Counter(), []
        since = time.time() - hours * 3600
        for c in self.clients:
            try:
                counts.update(c.top_domains(ip, since))
            except PiholeError as e:
                errors.append(str(e))
        result = {"domains": [{"domain": d, "count": n} for d, n in counts.most_common(limit)],
                  "sampled": sum(counts.values()), "errors": errors}
        self._remember(key, result)
        return result

    def status(self):
        with self.lock:
            return {"enabled": self.enabled, "last_sync": self.last_sync,
                    "servers": [c.host for c in self.clients],
                    "errors": dict(self.errors),
                    "chatty": sum(1 for s in self.stats.values() if s["chatty"])}

    def start(self):
        if self.enabled:
            threading.Thread(target=self._run, name="pihole-sync", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.sync()
            except Exception:
                log.exception("Pi-hole sync failed")
            self._stop.wait(self.interval)
