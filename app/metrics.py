"""Prometheus metrics at /metrics (text exposition format 0.0.4).

Scrape it with an API token (Access tab, read-only "viewer" is enough):
    authorization:
      credentials: nw_...

Everything is read from data NetWatch already keeps, so a scrape is cheap and
nothing new is stored. Series are bounded: one per device, service check or
alert channel, never one per event.
"""
import time

from .recognize import is_private_mac


def _esc(v):
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')[:200]


class _Out:
    def __init__(self):
        self.lines = []
        self.declared = set()

    def metric(self, name, mtype, help_, value, labels=None):
        if value is None:
            return
        if name not in self.declared:
            self.declared.add(name)
            self.lines.append(f"# HELP {name} {help_}")
            self.lines.append(f"# TYPE {name} {mtype}")
        lab = ""
        if labels:
            lab = "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items() if v is not None) + "}"
        if isinstance(value, bool):
            value = int(value)
        self.lines.append(f"{name}{lab} {value:.6g}" if isinstance(value, float) else f"{name}{lab} {value}")

    def text(self):
        return "\n".join(self.lines) + "\n"


def render(store, monitor, checker, wan, pihole, rules, pusher, router, version, display_name, now=None):
    now = now or time.time()
    o = _Out()
    o.metric("netwatch_info", "gauge", "NetWatch version (always 1).", 1, {"version": version})

    # ---- scanning ----
    o.metric("netwatch_last_scan_timestamp_seconds", "gauge", "When the last network scan finished.", monitor.last_scan)
    o.metric("netwatch_scan_duration_seconds", "gauge", "How long the last network scan took.", monitor.last_scan_duration)
    o.metric("netwatch_scan_error", "gauge", "1 if the last scan failed.", bool(monitor.last_error))

    # ---- devices ----
    devices = [d for d in store.all_devices() if not d.get("same_as")]
    o.metric("netwatch_devices_known", "gauge", "Devices NetWatch knows about.", len(devices))
    o.metric("netwatch_devices_online", "gauge", "Devices online now.", sum(1 for d in devices if d["online"]))
    o.metric("netwatch_devices_new", "gauge", "New devices not yet marked as known.", sum(1 for d in devices if not d.get("acknowledged", 1)))
    for d in sorted(devices, key=lambda d: d["mac"]):
        labels = {"mac": d["mac"], "name": display_name(d, router), "ip": d.get("ip") or "",
                  "type": d.get("device_type") or "unknown", "critical": "true" if d.get("critical") else "false"}
        o.metric("netwatch_device_up", "gauge", "1 if the device is online.", bool(d["online"]), labels)
    for d in sorted(devices, key=lambda d: d["mac"]):
        if d["online"] and d.get("online_since"):
            o.metric("netwatch_device_connected_seconds", "gauge", "How long the device has been online without a break.",
                     round(now - d["online_since"]), {"mac": d["mac"]})
    for d in sorted(devices, key=lambda d: d["mac"]):
        o.metric("netwatch_device_last_seen_timestamp_seconds", "gauge", "When the device was last seen.", d.get("last_seen"), {"mac": d["mac"]})
    o.metric("netwatch_devices_private_address", "gauge", "Devices using a private (randomized) Wi-Fi address.",
             sum(1 for d in devices if is_private_mac(d["mac"])))

    # ---- addresses ----
    try:
        net = monitor.network
        if net is not None:
            hosts = max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
            used = {d["ip"] for d in devices if d.get("ip")}
            reserved = {r["ip"] for r in (router.snapshot()["reservations"] if router.enabled else []) if r.get("ip")}
            online = {d["ip"] for d in devices if d["online"] and d.get("ip")}
            o.metric("netwatch_ip_addresses", "gauge", "Addresses in the monitored subnet, by state.", len(online), {"state": "online"})
            o.metric("netwatch_ip_addresses", "gauge", "", len(used - online), {"state": "offline"})
            o.metric("netwatch_ip_addresses", "gauge", "", len(reserved - used), {"state": "reserved"})
            o.metric("netwatch_ip_addresses", "gauge", "", max(0, hosts - len(used | reserved)), {"state": "free"})
    except Exception:
        pass

    # ---- internet ----
    w = wan.status()
    if w.get("enabled"):
        o.metric("netwatch_internet_up", "gauge", "1 if the internet connection is up.", w.get("state") == "up")
        for window in ("24h", "7d", "30d"):
            v = w.get(f"uptime_{window}")
            o.metric("netwatch_internet_uptime_ratio", "gauge", "Share of time the internet was up.",
                     round(v / 100, 6) if v is not None else None, {"window": window})
        o.metric("netwatch_internet_outages_30d", "gauge", "Internet outages in the last 30 days.",
                 len(store.outages(limit=1000, since=now - 30 * 86400)))
        if w.get("latency_ms") is not None:
            o.metric("netwatch_internet_latency_seconds", "gauge", "Latest internet round-trip time.", round(w["latency_ms"] / 1000, 6))

    # ---- service checks ----
    checks = [c for c in store.checks() if c["enabled"]]
    summaries = {c["id"]: checker.summary(c, now) for c in checks}
    o.metric("netwatch_services_down", "gauge", "Service checks failing now.", sum(1 for c in checks if c["state"] == "down"))
    for c in checks:
        o.metric("netwatch_service_up", "gauge", "1 if the service check passes (absent until it has run).",
                 None if c["state"] not in ("up", "down") else c["state"] == "up",
                 {"check": str(c["id"]), "name": c["name"], "kind": c["kind"]})
    for c in checks:
        u = summaries[c["id"]]["uptime_24h"]
        o.metric("netwatch_service_uptime_ratio", "gauge", "Share of passing checks in the last 24 hours.",
                 round(u / 100, 6) if u is not None else None, {"check": str(c["id"]), "window": "24h"})
    for c in checks:
        ms = summaries[c["id"]]["avg_latency_ms"]
        o.metric("netwatch_service_latency_seconds", "gauge", "Average response time of passing checks, last 24 hours.",
                 round(ms / 1000, 6) if ms is not None else None, {"check": str(c["id"])})

    # ---- DNS (Pi-hole) ----
    if pihole.enabled:
        o.metric("netwatch_pihole_up", "gauge", "1 if NetWatch can read Pi-hole.", not pihole.status().get("error"))
        with pihole.lock:
            by_ip = dict(pihole.stats)
        q24 = sum((by_ip.get(d.get("ip")) or {}).get("queries_24h", 0) for d in devices)
        o.metric("netwatch_dns_queries_24h", "gauge", "DNS lookups by known devices in the last 24 hours.", q24)
        o.metric("netwatch_dns_chatty_devices", "gauge", "Devices making unusually many DNS lookups.",
                 sum(1 for s in by_ip.values() if s.get("chatty")))
        for d in sorted(devices, key=lambda d: d["mac"]):
            s = by_ip.get(d.get("ip"))
            if s and s.get("queries_1h") is not None:
                o.metric("netwatch_device_dns_queries_1h", "gauge", "DNS lookups by the device in the last hour.",
                         s["queries_1h"], {"mac": d["mac"]})

    # ---- alerts ----
    inc = store._query("SELECT state, acked_at, escalated_at, resolved_at FROM alert_incidents "
                       "WHERE state IN ('pending', 'sent') AND resolved_at IS NULL")
    o.metric("netwatch_alerts_open", "gauge", "Open rule alerts, by state.", sum(1 for i in inc if i["state"] == "pending"), {"state": "waiting"})
    o.metric("netwatch_alerts_open", "gauge", "", sum(1 for i in inc if i["state"] == "sent" and not i["acked_at"] and not i["escalated_at"]), {"state": "unacknowledged"})
    o.metric("netwatch_alerts_open", "gauge", "", sum(1 for i in inc if i["state"] == "sent" and not i["acked_at"] and i["escalated_at"]), {"state": "escalated"})
    o.metric("netwatch_alerts_open", "gauge", "", sum(1 for i in inc if i["acked_at"]), {"state": "acknowledged"})
    o.metric("netwatch_alerts_held", "gauge", "Checkbox alerts held for quiet hours or an internet outage.", store.count_pending())
    for c in rules.channels():
        if c["last_result"]:
            o.metric("netwatch_alert_channel_ok", "gauge", "1 if the channel's last message was delivered.",
                     c["last_result"] == "ok", {"channel": c["name"], "kind": c["kind"]})
    o.metric("netwatch_push_devices", "gauge", "Devices with NetWatch app notifications turned on.", pusher.count())

    # ---- activity (last 24 hours) ----
    counts = store._query("SELECT kind, COUNT(*) n FROM events WHERE ts > ? GROUP BY kind ORDER BY kind", (now - 86400,))
    for r in counts:
        o.metric("netwatch_events_24h", "gauge", "Activity log entries in the last 24 hours, by kind.", r["n"], {"kind": r["kind"]})
    return o.text()
