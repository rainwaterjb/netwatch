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
        self._domain_cache[key] = (time.time(), result)
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
