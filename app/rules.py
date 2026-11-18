"""Alert rules: "when <event> happens to <these devices/services> for <N minutes>,
tell <these channels>; if nobody acknowledges it in <M minutes>, also tell <others>".

Each match becomes an *incident*:
  pending  -> waiting out the rule's delay (a device that comes back first is a blip: nothing is sent)
  sent     -> delivered; open until acknowledged or resolved
  resolved -> the device/service/internet came back (optionally announced)
  cancelled-> came back during the delay, snoozed, or couldn't be delivered

Rules run next to the per-device Phone/Email checkboxes, which keep working.
"""
import json
import logging
import threading
import time

from . import alert_channels as ch
from .alerts import in_quiet_hours
from .monitor import display_name, fmt_duration, fmt_time

log = logging.getLogger("netwatch.rules")

EVENTS = {   # what a rule can watch for -> (label, the event that ends it, what it applies to)
    "device_offline": ("A device goes offline", "device_online", "device"),
    "device_new":     ("A new device joins", "device_acknowledged", "device"),
    "service_down":   ("A service check fails", "service_up", "check"),
    "internet_down":  ("The internet goes down", "internet_up", None),
    "chatty":         ("A device gets chatty (DNS)", "chatty_end", "device"),
}
ENDS = {end: start for start, (_l, end, _a) in EVENTS.items() if end}
BUILTIN_TARGETS = ("phone", "email")
GROUP_AT = 4            # this many alerts for one rule at once are sent as one summary
MAX_ATTEMPTS = 30


class RuleError(Exception):
    pass


def _j(value, default):
    try:
        return json.loads(value) if value else default
    except ValueError:
        return default


class RuleEngine:
    def __init__(self, store, alerts, notifier, router=None, cfg=None):
        self.store = store
        self.alerts = alerts
        self.notifier = notifier
        self.router = router
        self.public_url = (getattr(cfg, "public_url", "") or "").rstrip("/")
        self.lock = threading.RLock()
        self._wake = threading.Event()
        self._stop = threading.Event()

    # ---------- rules & channels (storage) ----------
    def rules(self, enabled_only=False):
        rows = self.store._query("SELECT * FROM alert_rules" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id")
        for r in rows:
            r["scope"] = _j(r["scope"], {})
            r["channels"] = _j(r["channels"], [])
            r["escalate_channels"] = _j(r["escalate_channels"], [])
        return rows

    def get_rule(self, rule_id):
        return next((r for r in self.rules() if r["id"] == rule_id), None)

    def channels(self):
        rows = self.store._query("SELECT * FROM alert_channels ORDER BY id")
        for c in rows:
            c["config"] = _j(c["config"], {})
        return rows

    def _get_channel(self, cid):
        return next((c for c in self.channels() if c["id"] == cid), None)

    def public_channel(self, c):
        cfg, secrets_set = ch.public_config(c["kind"], c["config"])
        return {"id": c["id"], "name": c["name"], "kind": c["kind"], "enabled": bool(c["enabled"]), "config": cfg,
                "secrets_set": secrets_set, "last_sent": c["last_sent"], "last_result": c["last_result"]}

    def _clean_targets(self, targets, what):
        if not isinstance(targets, list) or len(targets) > 20:
            raise RuleError(f"{what}: choose up to 20 places to send to")
        ids = {c["id"] for c in self.channels()}
        out = []
        for t in targets:
            if t in BUILTIN_TARGETS or (isinstance(t, int) and not isinstance(t, bool) and t in ids):
                if t not in out:
                    out.append(t)
            else:
                raise RuleError(f"{what}: unknown channel {str(t)[:20]}")
        return out

    def clean_rule(self, body):
        name = str(body.get("name") or "").strip()
        if not 1 <= len(name) <= 60:
            raise RuleError("Give the rule a name (up to 60 characters)")
        event = body.get("event")
        if event not in EVENTS:
            raise RuleError("Choose what the rule watches for")
        applies = EVENTS[event][2]
        scope = body.get("scope") or {}
        if applies == "device":
            target = scope.get("target", "any")
            if target not in ("any", "critical", "tag", "devices"):
                raise RuleError("Choose which devices the rule covers")
            scope = {"target": target}
            if target == "tag":
                tag = str((body.get("scope") or {}).get("tag") or "").strip().lower()
                if not 1 <= len(tag) <= 24:
                    raise RuleError("Choose a tag")
                scope["tag"] = tag
            if target == "devices":
                macs = [str(m).lower() for m in (body.get("scope") or {}).get("macs") or []]
                if not macs or len(macs) > 200 or not all(self.store.get_device(m) for m in macs):
                    raise RuleError("Choose one or more known devices")
                scope["macs"] = macs
        elif applies == "check":
            target = scope.get("target", "any")
            if target not in ("any", "checks"):
                raise RuleError("Choose which service checks the rule covers")
            scope = {"target": target}
            if target == "checks":
                known = {c["id"] for c in self.store.checks()}
                ids = [int(i) for i in (body.get("scope") or {}).get("checks") or [] if str(i).isdigit()]
                if not ids or not set(ids) <= known:
                    raise RuleError("Choose one or more service checks")
                scope["checks"] = ids
        else:
            scope = {}
        try:
            delay = int(body.get("delay_min") or 0)
            esc = int(body.get("escalate_min") or 0)
        except (TypeError, ValueError):
            raise RuleError("Minutes must be whole numbers") from None
        if not 0 <= delay <= 1440 or not 0 <= esc <= 1440:
            raise RuleError("Minutes must be between 0 and 1440 (24 hours)")
        channels = self._clean_targets(body.get("channels") or [], "Send to")
        if not channels:
            raise RuleError("Choose at least one place to send the alert")
        esc_channels = self._clean_targets(body.get("escalate_channels") or [], "Escalate to") if esc else []
        if esc and not esc_channels:
            raise RuleError("Choose where to escalate to, or set escalation to 0 minutes")
        return {"name": name, "enabled": int(body.get("enabled", True) is not False), "event": event,
                "scope": json.dumps(scope), "delay_min": delay, "channels": json.dumps(channels),
                "notify_resolved": int(bool(body.get("notify_resolved"))), "ignore_quiet": int(bool(body.get("ignore_quiet"))),
                "escalate_min": esc, "escalate_channels": json.dumps(esc_channels)}

    def save_rule(self, body, rule_id=None):
        f = self.clean_rule(body)
        with self.store.lock:
            if rule_id is None:
                if self.store._query("SELECT COUNT(*) n FROM alert_rules")[0]["n"] >= 100:
                    raise RuleError("At most 100 rules")
                cur = self.store.conn.execute(
                    f"INSERT INTO alert_rules ({', '.join(f)}, created) VALUES ({', '.join('?' * len(f))}, ?)",
                    (*f.values(), time.time()))
                rule_id = cur.lastrowid
            else:
                if not self.get_rule(rule_id):
                    raise RuleError("Unknown rule")
                self.store.conn.execute(f"UPDATE alert_rules SET {', '.join(k + ' = ?' for k in f)} WHERE id = ?",
                                        (*f.values(), rule_id))
                if not f["enabled"]:                 # turning a rule off drops what it was waiting to send
                    self.store.conn.execute("UPDATE alert_incidents SET state = 'cancelled', result = 'rule turned off' "
                                            "WHERE rule_id = ? AND state = 'pending'", (rule_id,))
            self.store.conn.commit()
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id):
        if not self.get_rule(rule_id):
            raise RuleError("Unknown rule")
        self.store._exec("UPDATE alert_incidents SET state = 'cancelled', result = 'rule deleted' "
                         "WHERE rule_id = ? AND state IN ('pending', 'sent')", (rule_id,))
        self.store._exec("DELETE FROM alert_rules WHERE id = ?", (rule_id,))

    def save_channel(self, body, channel_id=None):
        name = str(body.get("name") or "").strip()
        if not 1 <= len(name) <= 40:
            raise RuleError("Give the channel a name (up to 40 characters)")
        old = self._get_channel(channel_id) if channel_id else None
        if channel_id and not old:
            raise RuleError("Unknown channel")
        kind = old["kind"] if old else body.get("kind")
        try:
            config = ch.validate(kind, body.get("config") or {}, old["config"] if old else None)
        except ch.ChannelError as e:
            raise RuleError(str(e)) from None
        enabled = int(body.get("enabled", True) is not False)
        with self.store.lock:
            if old:
                self.store.conn.execute("UPDATE alert_channels SET name = ?, config = ?, enabled = ? WHERE id = ?",
                                        (name, json.dumps(config), enabled, channel_id))
            else:
                if len(self.channels()) >= 30:
                    raise RuleError("At most 30 channels")
                cur = self.store.conn.execute(
                    "INSERT INTO alert_channels (name, kind, config, enabled, created) VALUES (?, ?, ?, ?, ?)",
                    (name, kind, json.dumps(config), enabled, time.time()))
                channel_id = cur.lastrowid
            self.store.conn.commit()
        return self.public_channel(self._get_channel(channel_id))

    def delete_channel(self, channel_id):
        if not self._get_channel(channel_id):
            raise RuleError("Unknown channel")
        used = [r["name"] for r in self.rules() if channel_id in r["channels"] or channel_id in r["escalate_channels"]]
        if used:
            raise RuleError(f"Still used by: {', '.join(used[:5])}. Remove it from those rules first.")
        self.store._exec("DELETE FROM alert_channels WHERE id = ?", (channel_id,))

    def test_channel(self, channel_id):
        c = self._get_channel(channel_id)
        if not c:
            raise RuleError("Unknown channel")
        msg = self._msg("NetWatch test alert", "If you can read this, the channel works.", "test", "test")
        return self._send_one(c, msg)

    # ---------- incoming events ----------
    def event(self, kind, now=None, device=None, check=None, detail=None, outage=None):
        now = now or time.time()
        try:
            with self.lock:
                if kind in EVENTS:
                    self._open(kind, now, device, check, detail)
                elif kind in ENDS:
                    self._close(ENDS[kind], now, device, check, outage)
        except Exception:
            log.exception("Alert rules: handling %s failed", kind)
        self._wake.set()

    @staticmethod
    def _subject(kind, device, check):
        applies = EVENTS[kind][2]
        if applies == "device":
            return device["mac"]
        if applies == "check":
            return f"check:{check['id']}"
        return "internet"

    def _matches(self, rule, device, check):
        scope, applies = rule["scope"], EVENTS[rule["event"]][2]
        target = scope.get("target", "any")
        if applies == "device":
            if target == "critical":
                return bool(device.get("critical"))
            if target == "tag":
                tags = device.get("tags") or ""
                tags = tags if isinstance(tags, list) else [t for t in tags.split(",") if t]
                return scope.get("tag") in tags
            if target == "devices":
                return device["mac"] in scope.get("macs", [])
        if applies == "check" and target == "checks":
            return check["id"] in scope.get("checks", [])
        return True

    def _open(self, kind, now, device, check, detail):
        if device and device.get("same_as"):
            return                                              # an old, linked address: not a device of its own
        subject = self._subject(kind, device, check)
        for rule in self.rules(enabled_only=True):
            if rule["event"] != kind or not self._matches(rule, device, check):
                continue
            if self.store._query("SELECT 1 FROM alert_incidents WHERE rule_id = ? AND subject = ? "
                                 "AND state IN ('pending', 'sent') AND resolved_at IS NULL", (rule["id"], subject)):
                continue                                        # already open for this rule
            title, message = self._describe(kind, now, device, check, detail)
            due = None if kind == "internet_down" else now + rule["delay_min"] * 60
            critical = bool(device and device.get("critical"))
            self.store._exec(
                "INSERT INTO alert_incidents (rule_id, event, subject, mac, title, message, critical, created, due, state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (rule["id"], kind, subject, device["mac"] if device else None, title, message, int(critical), now, due))

    def _close(self, kind, now, device, check, outage):
        subject = self._subject(kind, device, check)
        for inc in self.store._query("SELECT * FROM alert_incidents WHERE event = ? AND subject = ? "
                                     "AND state IN ('pending', 'sent') AND resolved_at IS NULL", (kind, subject)):
            rule = self.get_rule(inc["rule_id"])
            lasted = now - inc["created"]
            if kind == "internet_down":
                # Outage alerts go out once the connection is back, if it lasted long enough.
                start = outage["start"] if outage else inc["created"]
                lasted = now - start
                if rule and lasted >= rule["delay_min"] * 60:
                    what = "Router was unreachable" if outage and outage.get("cause") == "router" else "Internet was down"
                    self.store._exec("UPDATE alert_incidents SET title = ?, message = ?, due = ?, resolved_at = ? WHERE id = ?",
                                     (f"{what} for {fmt_duration(lasted)}",
                                      f"{what} from {fmt_time(start)} to {fmt_time(now)} ({fmt_duration(lasted)}).",
                                      now, now, inc["id"]))
                else:
                    self._cancel(inc, now, f"outage under {rule['delay_min'] if rule else 0} min")
                continue
            if inc["state"] == "pending":
                self._cancel(inc, now, f"back after {fmt_duration(lasted)}, within the rule's wait")
                if inc["mac"]:
                    self.store.add_event("suppressed", inc["mac"], None,
                                         f"No alert: back within {rule['delay_min'] if rule else 0} min ({rule['name'] if rule else 'rule'})", ts=now)
                continue
            self.store._exec("UPDATE alert_incidents SET state = 'resolved', resolved_at = ? WHERE id = ?", (now, inc["id"]))
            if rule and rule["notify_resolved"]:
                if rule["ignore_quiet"] or inc["critical"] or not in_quiet_hours(self.alerts.settings(), now):
                    end_title = {"device_offline": "Back online", "service_down": "Back up",
                                 "chatty": "Back to normal", "device_new": "Reviewed"}.get(kind, "Resolved")
                    name = inc["title"].split(": ", 1)[-1]
                    self._deliver(rule["channels"], self._msg(
                        f"{end_title}: {name}", f"{name} recovered after {fmt_duration(lasted)}.", "resolved", kind, inc))

    def _cancel(self, inc, now, why):
        self.store._exec("UPDATE alert_incidents SET state = 'cancelled', resolved_at = ?, result = ? WHERE id = ?",
                         (now, why, inc["id"]))

    def _describe(self, kind, now, device, check, detail):
        if device:
            name = display_name(device, self.router)
            where = f"{name} ({device.get('ip') or 'no IP'}, MAC {device['mac']})"
        if kind == "device_offline":
            return f"Offline: {name}", f"{where} dropped off the network.\nLast seen: {fmt_time(device.get('last_seen') or now)}"
        if kind == "device_new":
            return f"New device: {name}", f"{where} joined the network. Review it in NetWatch under Devices > New."
        if kind == "chatty":
            return f"Chatty device: {name}", f"{where}: {detail or 'unusually many DNS lookups'}."
        if kind == "service_down":
            return f"Down: {check['name']}", f"{check['name']} stopped answering. {detail or ''}".strip()
        return "Internet is down", f"The internet connection went down at {fmt_time(now)}."

    # ---------- delivery ----------
    def _msg(self, title, message, severity, event, inc=None):
        return {"title": title, "message": message, "severity": severity, "event": event,
                "incident_id": inc["id"] if inc else None, "mac": inc["mac"] if inc else None,
                "ts": time.time(), "url": self.public_url or None}

    def _send_one(self, c, msg):
        try:
            ch.send(c["kind"], c["config"], msg)
            result = "ok"
        except ch.ChannelError as e:
            result = f"failed: {e}"[:200]
        except Exception as e:                                # never let a channel break the engine
            log.exception("Channel %s failed", c["name"])
            result = f"failed: {e.__class__.__name__}"
        if result != "ok":
            log.warning("Alert channel %s: %s", c["name"], result)
        self.store._exec("UPDATE alert_channels SET last_sent = ?, last_result = ? WHERE id = ?",
                         (time.time(), result, c["id"]))
        return result

    def _deliver(self, targets, msg):
        """Send to each target; returns (number that worked, summary)."""
        ok, parts = 0, []
        builtin = [t for t in targets if t in BUILTIN_TARGETS]
        if builtin:
            res = self.notifier.send_now(msg["title"], msg["message"] + (f"\n\nOpen NetWatch: {msg['url']}" if msg.get("url") else ""),
                                         phone="phone" in builtin, email="email" in builtin,
                                         tags={"resolved": ["white_check_mark"], "escalation": ["rotating_light"]}.get(msg["severity"], ["warning"]))
            for k, v in res.items():
                parts.append(f"{k}: {v}")
                ok += v == "ok"
        chans = {c["id"]: c for c in self.channels()}
        for t in targets:
            c = chans.get(t)
            if c and c["enabled"]:
                r = self._send_one(c, msg)
                parts.append(f"{c['name']}: {r}")
                ok += r == "ok"
        return ok, "; ".join(parts)[:500]

    def tick(self, now=None):
        """Send what's due, group bursts, escalate unacknowledged alerts."""
        now = now or time.time()
        settings = self.alerts.settings()
        quiet = in_quiet_hours(settings, now)
        rules = {r["id"]: r for r in self.rules()}
        due = self.store._query("SELECT * FROM alert_incidents WHERE state = 'pending' AND due IS NOT NULL AND due <= ? "
                                "ORDER BY created", (now,))
        by_rule = {}
        for inc in due:
            rule = rules.get(inc["rule_id"])
            if not rule or not rule["enabled"]:
                self._cancel(inc, now, "rule removed or off")
                continue
            if inc["mac"] and inc["event"] != "device_new":
                dev = self.store.get_device(inc["mac"])
                if dev and (dev.get("snooze_until") or 0) > now:
                    self._cancel(inc, now, "device snoozed")
                    self.store.add_event("suppressed", inc["mac"], dev.get("ip"), f"Alert skipped (snoozed): {inc['title']}", ts=now)
                    continue
                if inc["event"] == "device_offline" and dev and dev["online"]:
                    self._cancel(inc, now, "back online")
                    continue
            if quiet and not rule["ignore_quiet"] and not inc["critical"]:
                continue                                        # wait for quiet hours to end
            by_rule.setdefault(rule["id"], []).append(inc)
        for rule_id, incs in by_rule.items():
            rule = rules[rule_id]
            if len(incs) >= GROUP_AT:
                names = [i["title"].split(": ", 1)[-1] for i in incs]
                msg = self._msg(f"{len(incs)} alerts: {EVENTS[rule['event']][0].lower()}",
                                f"Rule \"{rule['name']}\":\n" + "\n".join(f"• {n}" for n in names[:25])
                                + (f"\n…and {len(names) - 25} more" if len(names) > 25 else ""), "alert", rule["event"])
                self._finish(incs, *self._deliver(rule["channels"], msg), now)
            else:
                for inc in incs:
                    msg = self._msg(inc["title"], inc["message"], "alert", inc["event"], inc)
                    self._finish([inc], *self._deliver(rule["channels"], msg), now)
        # escalation
        for inc in self.store._query("SELECT * FROM alert_incidents WHERE state = 'sent' AND acked_at IS NULL "
                                     "AND resolved_at IS NULL AND escalated_at IS NULL"):
            rule = rules.get(inc["rule_id"])
            if not rule or not rule["escalate_min"] or now < inc["sent_at"] + rule["escalate_min"] * 60:
                continue
            ok, summary = self._deliver(rule["escalate_channels"], self._msg(
                f"Not acknowledged after {rule['escalate_min']} min: {inc['title']}", inc["message"], "escalation", inc["event"], inc))
            self.store._exec("UPDATE alert_incidents SET escalated_at = ?, result = ? WHERE id = ?",
                             (now, f"escalated: {summary}", inc["id"]))
            self.store.add_event("escalated", inc["mac"], None, f"Escalated (not acknowledged): {inc['title']}", ts=now)

    def _finish(self, incs, ok, summary, now):
        for inc in incs:
            if ok:
                state = "resolved" if inc["resolved_at"] else "sent"
                self.store._exec("UPDATE alert_incidents SET state = ?, sent_at = ?, result = ?, attempts = attempts + 1 "
                                 "WHERE id = ?", (state, now, summary, inc["id"]))
            else:
                attempts = inc["attempts"] + 1
                if attempts >= MAX_ATTEMPTS or not summary:
                    self.store._exec("UPDATE alert_incidents SET state = 'cancelled', attempts = ?, result = ? WHERE id = ?",
                                     (attempts, f"not delivered: {summary or 'no working channel'}", inc["id"]))
                else:                                           # retry with back-off (e.g. internet still down)
                    self.store._exec("UPDATE alert_incidents SET attempts = ?, due = ?, result = ? WHERE id = ?",
                                     (attempts, now + min(60 * attempts, 900), summary, inc["id"]))

    # ---------- acknowledging ----------
    def incidents(self, open_only=False, limit=100):
        q = "SELECT * FROM alert_incidents"
        if open_only:
            q += " WHERE state IN ('pending', 'sent') AND resolved_at IS NULL"
        rows = self.store._query(q + " ORDER BY created DESC LIMIT ?", (limit,))
        names = {r["id"]: r["name"] for r in self.rules()}
        for r in rows:
            r["rule_name"] = names.get(r["rule_id"])
        return rows

    def ack(self, incident_id, by, now=None):
        now = now or time.time()
        rows = self.store._query("SELECT * FROM alert_incidents WHERE id = ?", (incident_id,))
        if not rows:
            raise RuleError("Unknown alert")
        inc = rows[0]
        if inc["acked_at"]:
            return inc
        self.store._exec("UPDATE alert_incidents SET acked_at = ?, acked_by = ? WHERE id = ?", (now, by[:64], incident_id))
        self.store.add_event("ack", inc["mac"], None, f"{by[:32]} acknowledged: {inc['title']}", ts=now)
        return self.store._query("SELECT * FROM alert_incidents WHERE id = ?", (incident_id,))[0]

    # ---------- background loop ----------
    def start(self):
        threading.Thread(target=self._run, name="alert-rules", daemon=True).start()

    def stop(self):
        self._stop.set()
        self._wake.set()

    def _run(self):
        while not self._stop.is_set():
            self._wake.wait(15)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                with self.lock:
                    self.tick()
            except Exception:
                log.exception("Alert rules tick failed")
