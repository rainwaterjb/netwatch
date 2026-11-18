"""Scan loop: reconciles each ARP sweep with stored devices and raises alerts."""
import ipaddress
import logging
import threading
import time

from . import scanner as default_scanner
from .alerts import AlertManager

log = logging.getLogger("netwatch.monitor")


def fmt_duration(seconds):
    seconds = int(max(0, seconds or 0))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m"
    return f"{s}s"


def fmt_time(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def display_name(dev, router=None):
    hint = router.name_for(dev["mac"]) if router is not None and router.enabled else None
    return (dev.get("nickname") or hint or dev.get("hostname")
            or dev.get("vendor") or dev["mac"])


def label(dev, router=None):
    return f"{display_name(dev, router)} ({dev.get('ip')})"


def is_watched(dev):
    return bool(dev.get("notify_phone") or dev.get("notify_email"))


class Monitor:
    def __init__(self, cfg, store, notifier, scanner=default_scanner, router=None, alerts=None):
        self.cfg = cfg
        self.router = router
        self.store = store
        self.notifier = notifier
        self.alerts = alerts or AlertManager(store, notifier)
        self.scanner = scanner
        self.iface = None
        self.network = None
        self.last_scan = None
        self.last_scan_duration = None
        self.last_error = None
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._scan_lock = threading.Lock()
        self._last_prune = 0

    # Lifecycle
    def setup(self):
        iface, net = self.scanner.detect_network(self.cfg.iface)
        if self.cfg.subnet:
            net = ipaddress.IPv4Network(self.cfg.subnet, strict=False)
        if net is None:
            raise RuntimeError("Could not detect the LAN subnet; set SUBNET (e.g. 192.168.1.0/24)")
        if net.num_addresses > 4096:
            log.warning("Subnet %s is large (%d addresses); scans will be slow", net, net.num_addresses)
        self.iface, self.network = iface, net
        log.info("Monitoring %s on interface %s every %ss", net, iface, self.cfg.scan_interval)

    def start(self):
        threading.Thread(target=self._run, name="scanner", daemon=True).start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def trigger(self):
        self._wake.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                if self.network is None:
                    self.setup()
                self.scan_once()
                self.last_error = None
            except Exception as e:
                log.exception("Scan failed")
                self.last_error = str(e)
            self._wake.wait(self.cfg.scan_interval)
            self._wake.clear()

    # One scan
    def scan_once(self, now=None):
        with self._scan_lock:
            start = time.time()
            now = now or start
            found = self.scanner.arp_scan(self.network, self.iface, timeout=self.cfg.arp_timeout)

            own_ip, own_mac = self.scanner.own_address(self.iface)
            if own_ip and own_mac:
                try:
                    if ipaddress.IPv4Address(own_ip) in self.network:
                        found.setdefault(own_ip, own_mac)
                except ValueError:
                    pass

            seen = {}
            for ip, mac in sorted(found.items(), key=lambda kv: ipaddress.IPv4Address(kv[0])):
                seen.setdefault(mac, ip)

            for mac, ip in seen.items():
                self._handle_seen(mac, ip, now)

            for dev in self.store.online_devices():
                if dev["mac"] not in seen:
                    self._handle_missing(dev, now)

            if now - self._last_prune > 86400:
                self.store.prune_events(now - self.cfg.event_retention_days * 86400)
                self._last_prune = now

            self.last_scan = now
            self.last_scan_duration = time.time() - start
            return seen

    def _handle_seen(self, mac, ip, now):
        dev = self.store.get_device(mac)
        if dev is None:
            hostname = self.scanner.resolve_hostname(ip)
            vendor = self.scanner.vendor_for(mac)
            self.store.insert_device(
                mac, ip=ip, hostname=hostname, vendor=vendor, first_seen=now,
                last_seen=now, online=1, online_since=now, missed_scans=0, acknowledged=0,
            )
            self.store.add_event("new", mac, ip, f"New device: {hostname or vendor or mac}", ts=now)
            mode = self.cfg.notify_new_devices
            if mode in ("phone", "email", "both"):
                self.alerts.send(
                    "New device on network",
                    f"{hostname or vendor or 'Unknown device'} joined at {ip} (MAC {mac}).\n"
                    "Review it in NetWatch under Devices > New.",
                    phone=mode in ("phone", "both"), email=mode in ("email", "both"),
                    tags=["new"], now=now,
                )
            return

        updates = {"last_seen": now, "missed_scans": 0, "online": 1}
        if dev["ip"] != ip:
            self.store.add_event("ip_change", mac, ip, f"IP changed {dev['ip']} -> {ip}", ts=now)
            updates["ip"] = ip
            updates["hostname"] = self.scanner.resolve_hostname(ip) or dev["hostname"]

        if not dev["online"]:
            offline_for = now - (dev["last_seen"] or now)
            updates["online_since"] = now
            self.store.add_event("online", mac, ip,
                                 f"Back online after {fmt_duration(offline_for)}", ts=now)
            if is_watched(dev) and dev["notify_return"]:
                d = {**dev, "ip": ip}
                self.alerts.send(
                    f"Back online: {display_name(d, self.router)}",
                    f"{label(d, self.router)} is back on the network after being offline for "
                    f"{fmt_duration(offline_for)}.",
                    phone=bool(dev["notify_phone"]), email=bool(dev["notify_email"]),
                    tags=["white_check_mark"], device=d, now=now,
                )
        self.store.update_device(mac, **updates)

    def _handle_missing(self, dev, now):
        mac = dev["mac"]
        missed = dev["missed_scans"] + 1
        if missed < self.cfg.offline_after:
            self.store.update_device(mac, missed_scans=missed)
            return

        # Before alerting, give a watched device one more targeted chance
        # (sleeping phones often miss a broadcast sweep).
        if is_watched(dev) and dev["ip"]:
            try:
                if self.scanner.probe(dev["ip"], self.iface) == mac:
                    self.store.update_device(mac, missed_scans=0, last_seen=now)
                    return
            except Exception:
                log.exception("Re-probe of %s failed", dev["ip"])

        self.store.update_device(mac, online=0, missed_scans=missed)
        connected_for = (dev["last_seen"] or now) - (dev["online_since"] or dev["last_seen"] or now)
        self.store.add_event("offline", mac, dev["ip"],
                             f"Dropped off after {fmt_duration(connected_for)} connected", ts=now)
        if is_watched(dev):
            self.alerts.send(
                f"Offline: {display_name(dev, self.router)}",
                f"{label(dev, self.router)} dropped off the network.\n"
                f"Last seen: {fmt_time(dev['last_seen'])}\n"
                f"It had been connected for {fmt_duration(connected_for)}.\n"
                f"MAC: {mac}",
                phone=bool(dev["notify_phone"]), email=bool(dev["notify_email"]),
                tags=["warning"], device=dev, now=now,
            )
