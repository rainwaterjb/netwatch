"""Everything the dashboard timeline needs, on one shared time axis.

All spans are [start, end] in epoch seconds, clipped to the requested window.
"""
from . import history as dev_history
from .monitor import display_name

RANGES = (6, 24, 168)        # hours the dashboard offers
MAX_DEVICES = 120


def _clip(start, end, since, until):
    start, end = max(start, since), min(end if end is not None else until, until)
    return [start, end] if end > start else None


def _tags(value):
    if isinstance(value, list):
        return value
    return [t for t in (value or "").split(",") if t]


def check_down_spans(results, since, until):
    """Turn a run of check results into the spans where the check was failing."""
    spans, down_from = [], None
    for r in results:
        if not r["ok"] and down_from is None:
            down_from = r["ts"]
        elif r["ok"] and down_from is not None:
            spans.append([down_from, r["ts"]])
            down_from = None
    if down_from is not None:
        spans.append([down_from, until])
    return [s for s in (_clip(a, b, since, until) for a, b in spans) if s]


def build(store, router, pihole, hours, now, internet_enabled=True):
    since, until = now - hours * 3600, now

    outages = []
    for o in store.outages(limit=500, since=since):
        span = _clip(o["start"], o["end"], since, until)
        if span:
            outages.append({"span": span, "cause": o["cause"], "ongoing": o["end"] is None})
    outages.sort(key=lambda o: o["span"][0])

    services = []
    for c in store.checks():
        if not c["enabled"]:
            continue
        rows = store.check_results(c["id"], since)
        services.append({"id": c["id"], "name": c["name"], "kind": c["kind"], "state": c["state"],
                         "checked": bool(rows), "down": check_down_spans(rows, since, until)})

    devices = []
    for d in store.all_devices():
        if d.get("first_seen") and d["first_seen"] > until or d.get("same_as"):
            continue
        p = dev_history.presence(store, d, since, until)
        online = [[s["start"], s["end"]] for s in p["segments"] if s["state"] == "online"]
        if not online and not d.get("critical"):
            continue                       # never here during this window: leave it off the chart
        drops = sum(1 for s in p["segments"] if s["state"] == "offline" and s["start"] > since)
        devices.append({
            "mac": d["mac"], "name": display_name(d, router), "ip": d.get("ip"), "device_type": d.get("device_type"),
            "online": bool(d.get("online")), "critical": bool(d.get("critical")),
            "new": not d.get("acknowledged", 1),
            "tags": _tags(d.get("tags")),
            "drops": drops, "availability": p["availability"], "segments": online,
        })
    devices.sort(key=lambda d: (-d["critical"], -d["drops"], d["name"].lower()))
    truncated = len(devices) > MAX_DEVICES

    dns = None
    if pihole.enabled and hours <= 24:
        hourly = pihole.total_hourly()          # 24 values, oldest first; last = past hour
        if hourly:
            dns = {"hourly": hourly[-hours:], "bucket_hours": 1}

    return {"now": now, "since": since, "until": until, "hours": hours,
            "internet": outages if internet_enabled else None, "services": services,
            "devices": devices[:MAX_DEVICES], "devices_truncated": truncated, "dns": dns}
