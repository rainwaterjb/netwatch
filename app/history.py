"""Device presence history, rebuilt from the online/offline events already logged."""

KINDS = ("new", "online", "offline")


def presence(store, dev, since, until):
    """Return {"segments": [{"start", "end", "state"}], "availability": pct or None}.

    state is "online", "offline" or "unseen" (before NetWatch first saw it).
    """
    mac = dev["mac"]
    prev = store.last_event_before(mac, since, KINDS)
    events = store.events_between(mac, since, until, KINDS)

    if prev:
        state = "online" if prev["kind"] in ("new", "online") else "offline"
    elif events:
        first = events[0]["kind"]
        state = "unseen" if first == "new" else ("offline" if first == "online" else "online")
    else:
        state = "online" if dev.get("online") else "offline"
    if dev.get("first_seen") and dev["first_seen"] > since and not prev and \
            not (events and events[0]["kind"] == "new"):
        # Seen for the first time inside the window, but its "new" event was pruned.
        state = "unseen"

    segments, cursor = [], since
    for e in events:
        new_state = "online" if e["kind"] in ("new", "online") else "offline"
        if e["ts"] > cursor:
            segments.append({"start": cursor, "end": e["ts"], "state": state})
        cursor, state = max(cursor, e["ts"]), new_state
    if until > cursor:
        segments.append({"start": cursor, "end": until, "state": state})

    merged = []
    for seg in segments:
        if merged and merged[-1]["state"] == seg["state"]:
            merged[-1]["end"] = seg["end"]
        else:
            merged.append(dict(seg))

    on = sum(s["end"] - s["start"] for s in merged if s["state"] == "online")
    off = sum(s["end"] - s["start"] for s in merged if s["state"] == "offline")
    return {"segments": merged,
            "availability": round(100 * on / (on + off), 2) if on + off > 0 else None}


def ip_history(store, mac, limit=500):
    out = []
    for e in reversed(store.events(limit=limit, mac=mac)):
        if e["kind"] == "new":
            ip = e["ip"]
        elif e["kind"] == "ip_change":
            ip = e["ip"]
        else:
            continue
        if not out or out[-1]["ip"] != ip:
            out.append({"ts": e["ts"], "ip": ip})
    return list(reversed(out))
