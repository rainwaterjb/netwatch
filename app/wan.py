"""Internet (WAN) monitoring.

Every WAN_CHECK_INTERVAL seconds, try a TCP connection to a few well-known
public addresses. If none answer for two checks in a row, an outage starts.
The router is checked at the same time, so the outage is recorded either as
"internet" (router fine, ISP side down) or "router" (router unreachable).
Alerts can't go out while the internet is down, so you're told when it comes
back, with how long it was down.
"""
import logging
import socket
import struct
import threading
import time

from .alerts import channels
from .monitor import fmt_duration, fmt_time

log = logging.getLogger("netwatch.wan")
FAILS_BEFORE_OUTAGE = 2


def default_gateway():
    """The host's default gateway from /proc/net/route (works with host networking)."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000" and int(parts[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
    except (OSError, ValueError):
        pass
    return None


def tcp_ok(host, port, timeout=3.0):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.perf_counter() - start) * 1000, 1)
    except OSError:
        return None


class WanMonitor:
    def __init__(self, cfg, store, alerts, monitor=None):
        self.cfg = cfg
        self.store = store
        self.alerts = alerts
        self.monitor = monitor
        self.targets = cfg.wan_targets
        self.interval = cfg.wan_check_interval
        self.fails = 0
        self.state = "unknown"          # up | down | unknown
        self.last_check = None
        self.latency_ms = None
        self.gateway = None
        self._stop = threading.Event()
        alerts.wan_down = self.is_down

    @property
    def enabled(self):
        return self.cfg.wan_check_enabled and bool(self.targets)

    def is_down(self):
        return self.state == "down"

    def _router_ok(self):
        gw = self.gateway = default_gateway()
        if not gw:
            return None
        if self.monitor is not None and self.monitor.iface:
            try:
                return bool(self.monitor.scanner.probe(gw, self.monitor.iface, timeout=1.5, attempts=2))
            except Exception:
                pass
        return any(tcp_ok(gw, p, 1.5) is not None for p in (80, 443, 53))

    def check_once(self, now=None):
        now = now or time.time()
        latency = None
        for host, port in self.targets:
            latency = tcp_ok(host, port)
            if latency is not None:
                break
        self.last_check, self.latency_ms = now, latency
        if latency is not None:
            self.fails = 0
            if self.state == "down":
                self._recovered(now)
            self.state = "up"
            return True
        self.fails += 1
        if self.fails >= FAILS_BEFORE_OUTAGE and self.state != "down":
            router_ok = self._router_ok()
            cause = "router" if router_ok is False else "internet"
            detail = ("Router not reachable" if cause == "router"
                      else "Router reachable, internet not")
            # The outage started at the first failed check.
            start = now - self.interval * (self.fails - 1)
            self.store.open_outage(start, cause, detail)
            self.store.add_event("internet_down", None, self.gateway, detail, ts=start)
            self.state = "down"
            log.warning("Internet outage started (%s)", detail)
        return False

    def _recovered(self, now):
        outage = self.store.current_outage()
        if not outage:
            return
        self.store.close_outage(outage["id"], now)
        dur = fmt_duration(now - outage["start"])
        what = "Router was unreachable" if outage["cause"] == "router" else "Internet was down"
        self.store.add_event("internet_up", None, self.gateway, f"{what} for {dur}", ts=now)
        log.info("Internet back after %s", dur)
        self.state = "up"                          # so the alert isn't held as "internet down"
        phone, email = channels(self.alerts.settings().get("wan_alerts", "phone"))
        self.alerts.send(f"{what} for {dur}",
                         f"{what} from {fmt_time(outage['start'])} to {fmt_time(now)} ({dur}).\n"
                         f"{outage.get('detail') or ''}",
                         phone=phone, email=email, tags=["globe_with_meridians"], now=now)

    def start(self):
        if not self.enabled:
            return
        leftover = self.store.current_outage()
        if leftover:                       # NetWatch restarted mid-outage; we can't know when it ended
            self.store.close_outage(leftover["id"], time.time())
        threading.Thread(target=self._run, name="wan-monitor", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                self.check_once()
            except Exception:
                log.exception("WAN check failed")
            self._stop.wait(self.interval)

    def status(self, now=None):
        now = now or time.time()
        if not self.enabled:
            return {"enabled": False}
        def uptime(window):
            since = now - window
            down = 0.0
            for o in self.store.outages(limit=1000, since=since):
                down += max(0, min(o["end"] or now, now) - max(o["start"], since))
            return round(100 * (1 - down / window), 3)
        cur = self.store.current_outage()
        return {
            "enabled": True, "state": self.state, "last_check": self.last_check,
            "latency_ms": self.latency_ms, "gateway": self.gateway or default_gateway(),
            "outage_since": cur["start"] if cur else None,
            "uptime_24h": uptime(86400), "uptime_7d": uptime(7 * 86400),
            "uptime_30d": uptime(30 * 86400),
        }
