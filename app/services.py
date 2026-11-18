"""Service checks: is a port / web page / host actually responding?

Kinds:
  tcp   - a TCP connection to host:port succeeds
  http  - an HTTP(S) request gets a response below 500 (a login page or a
          redirect still means the service is running)
  ping  - ICMP echo reply (uses the NET_RAW capability the container already has)

A check can follow a device (by MAC), so it keeps working when DHCP gives the
device a new IP.
"""
import logging
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .monitor import display_name, fmt_duration

log = logging.getLogger("netwatch.services")
KINDS = ("tcp", "http", "ping")
RESULT_RETENTION_DAYS = 8


class _LimitedRedirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 3


def _http_opener(verify_tls):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),                  # never route LAN checks through a proxy
        urllib.request.HTTPSHandler(context=ctx),
        _LimitedRedirects(),
    )


def probe(kind, host, port=None, path=None, https=False, verify_tls=True, timeout=5.0):
    """Run one probe. Returns (ok, latency_ms, error_message)."""
    start = time.perf_counter()
    try:
        if kind == "tcp":
            with socket.create_connection((host, int(port)), timeout=timeout):
                pass
        elif kind == "http":
            scheme = "https" if https else "http"
            port_part = f":{int(port)}" if port else ""
            url = f"{scheme}://{host}{port_part}{path or '/'}"
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "NetWatch service check"})
            try:
                with _http_opener(verify_tls).open(req, timeout=timeout) as resp:
                    resp.read(512)
                    status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            if status >= 500:
                return False, None, f"HTTP {status}"
        elif kind == "ping":
            from scapy.all import ICMP, IP, sr1
            reply = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=False)
            if reply is None:
                return False, None, "no ping reply"
        else:
            return False, None, f"unknown check type {kind}"
    except ssl.SSLCertVerificationError:
        return False, None, "TLS certificate not trusted (turn off certificate checking for self-signed)"
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        return False, None, _short(reason)
    except (OSError, ValueError) as e:
        return False, None, _short(e)
    return True, round((time.perf_counter() - start) * 1000, 1), None


def _short(err):
    if isinstance(err, socket.timeout) or "timed out" in str(err):
        return "timed out"
    if isinstance(err, ConnectionRefusedError) or "refused" in str(err).lower():
        return "connection refused"
    text = str(err) or err.__class__.__name__
    return text[:120]


class ServiceChecker:
    def __init__(self, store, alerts, router=None):
        self.store = store
        self.alerts = alerts
        self.router = router
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="check")
        self._running = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._last_prune = 0

    def target_for(self, check):
        if check.get("mac"):
            dev = self.store.get_device(check["mac"])
            if not dev or not dev.get("ip"):
                return None, None
            return dev["ip"], dev
        return check.get("host"), None

    def run_check(self, check, now=None):
        """Probe once, record the result and handle up/down transitions."""
        now = now or time.time()
        host, dev = self.target_for(check)
        if not host:
            ok, latency, err = False, None, "device has no known IP yet"
        else:
            ok, latency, err = probe(check["kind"], host, check.get("port"), check.get("path"),
                                     bool(check.get("https")), bool(check.get("verify_tls")),
                                     float(check.get("timeout") or 5))
        self.store.add_check_result(check["id"], now, ok, latency)
        updates = {"last_check": now, "last_latency_ms": latency, "last_error": err}
        state = check.get("state") or "unknown"
        if ok:
            updates["fails"] = 0
            if state != "up":
                updates.update(state="up", since=now)
                if state == "down":
                    down_for = now - (check.get("since") or now)
                    self._notify(check, dev, f"Service back up: {check['name']}",
                                 f"{check['name']} ({self._where(check, host, dev)}) is responding again "
                                 f"after {fmt_duration(down_for)}.", "service_up",
                                 f"Back up after {fmt_duration(down_for)}", now, ["white_check_mark"])
        else:
            fails = (check.get("fails") or 0) + 1
            updates["fails"] = fails
            if fails >= (check.get("fail_after") or 2) and state != "down":
                updates.update(state="down", since=now)
                self._notify(check, dev, f"Service down: {check['name']}",
                             f"{check['name']} ({self._where(check, host, dev)}) is not responding: {err}.\n"
                             f"Failed {fails} checks in a row.", "service_down", f"Down: {err}", now,
                             ["rotating_light"])
        self.store.update_check(check["id"], **updates)
        return {"ok": ok, "latency_ms": latency, "error": err, "host": host}

    def _where(self, check, host, dev):
        kind = check["kind"]
        if kind == "http":
            scheme = "https" if check.get("https") else "http"
            port = f":{check['port']}" if check.get("port") else ""
            return f"{scheme}://{host}{port}{check.get('path') or '/'}"
        if kind == "tcp":
            return f"{host}:{check['port']}"
        return host or "?"

    def _notify(self, check, dev, title, message, event_kind, detail, now, tags):
        self.store.add_event(event_kind, check.get("mac"), dev["ip"] if dev else check.get("host"),
                             f"{check['name']}: {detail}", ts=now)
        if check.get("notify_phone") or check.get("notify_email"):
            self.alerts.send(title, message, phone=bool(check.get("notify_phone")),
                             email=bool(check.get("notify_email")), tags=tags, device=dev, now=now)

    def start(self):
        threading.Thread(target=self._run, name="service-checks", daemon=True).start()

    def stop(self):
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _run(self):
        while not self._stop.wait(5):
            now = time.time()
            try:
                for check in self.store.checks():
                    if not check["enabled"] or check["id"] in self._running:
                        continue
                    if check["last_check"] and now - check["last_check"] < check["interval"]:
                        continue
                    with self._lock:
                        self._running.add(check["id"])
                    self._pool.submit(self._run_one, check)
                if now - self._last_prune > 86400:
                    self.store.prune_check_results(now - RESULT_RETENTION_DAYS * 86400)
                    self._last_prune = now
            except Exception:
                log.exception("Service check loop failed")

    def _run_one(self, check):
        try:
            self.run_check(check)
        except Exception:
            log.exception("Check %s failed to run", check.get("name"))
        finally:
            with self._lock:
                self._running.discard(check["id"])

    def summary(self, check, now=None):
        """Uptime % and recent results for the dashboard."""
        now = now or time.time()
        day = self.store.check_results(check["id"], now - 86400)
        week = self.store.check_results(check["id"], now - 7 * 86400)
        pct = lambda rows: round(100 * sum(r["ok"] for r in rows) / len(rows), 2) if rows else None
        lat = [r["latency_ms"] for r in day if r["ok"] and r["latency_ms"] is not None]
        return {
            "uptime_24h": pct(day), "uptime_7d": pct(week),
            "avg_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
            "recent": [r["ok"] for r in day[-40:]],
        }
