"""Central alert path: every notification goes through AlertManager.send().

- Snoozed devices: alert is skipped (and logged).
- Quiet hours: non-critical alerts are held and sent as one digest when quiet
  hours end.
- Internet down: alerts can't reach ntfy/Pushover/email, so they're held and
  sent once the connection is back.
"""
import logging
import threading
import time

log = logging.getLogger("netwatch.alerts")

DEFAULT_SETTINGS = {
    "quiet_enabled": False,
    "quiet_start": "22:00",
    "quiet_end": "07:00",
    "wan_alerts": "phone",          # none | phone | email | both
    "chatty_alerts": "none",        # none | phone | email | both
    "chatty_factor": 5,             # x normal hourly volume
    "chatty_min_per_hour": 600,     # ignore devices quieter than this
    "auto_link_private": False,     # link private-address devices to known ones without asking
    "paused_until": 0,              # alerts paused (held like quiet hours) until this time
}
CHANNEL_CHOICES = ("none", "phone", "email", "both")


def channels(choice):
    return choice in ("phone", "both"), choice in ("email", "both")


def _minutes(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def validate_time(value):
    try:
        h, m = str(value).split(":")
        if 0 <= int(h) <= 23 and 0 <= int(m) <= 59 and len(m) == 2:
            return f"{int(h):02d}:{m}"
    except (ValueError, AttributeError):
        pass
    raise ValueError("Times must look like 22:00")


def in_quiet_hours(settings, now=None):
    """Quiet hours, or a pause someone started from the dashboard: hold non-critical alerts."""
    if (settings.get("paused_until") or 0) > (now or time.time()):
        return True
    if not settings.get("quiet_enabled"):
        return False
    lt = time.localtime(now or time.time())
    cur = lt.tm_hour * 60 + lt.tm_min
    start, end = _minutes(settings["quiet_start"]), _minutes(settings["quiet_end"])
    if start == end:
        return False
    if start < end:
        return start <= cur < end
    return cur >= start or cur < end            # spans midnight


class AlertManager:
    def __init__(self, store, notifier):
        self.store = store
        self.notifier = notifier
        self.wan_down = lambda: False           # replaced by the WAN monitor
        self.rules = None                       # alert rules engine (rules.py), if running
        self.pusher = None                      # NetWatch app notifications (push.py)
        self._stop = threading.Event()

    def settings(self):
        return {**DEFAULT_SETTINGS, **self.store.get_settings()}

    def send(self, title, message, phone=False, email=False, tags=None, device=None,
             urgent=False, now=None):
        """Returns 'sent', 'held', 'snoozed' or 'skipped'."""
        now = now or time.time()
        if not ((phone and self.phone_ready) or (email and self.notifier.email_enabled)):
            return "skipped"
        if device and (device.get("snooze_until") or 0) > now:
            self.store.add_event("suppressed", device["mac"], device.get("ip"),
                                 f"Alert skipped (snoozed): {title}", ts=now)
            return "snoozed"
        critical = urgent or bool(device and device.get("critical"))
        reason = None
        if self.wan_down():
            reason = "internet down"
        elif not critical and in_quiet_hours(self.settings(), now):
            reason = "quiet hours"
        if reason:
            self.store.add_pending(title, message, phone, email, reason, ts=now)
            return "held"
        self.notifier.notify(title, message, phone=phone, email=email, tags=tags)
        if phone:
            self.push(title, message, tag=device["mac"] if device else None)
        return "sent"

    @property
    def phone_ready(self):
        """Phone alerts can go somewhere: ntfy/Pushover, or the NetWatch app."""
        return self.notifier.phone_enabled or bool(self.pusher and self.pusher.count())

    def push(self, title, message, tag=None, severity="alert"):
        if self.pusher is not None:
            try:
                self.pusher.send(title, message, tag=tag, severity=severity)
            except Exception:
                log.exception("Push notification failed")

    def event(self, kind, **details):
        """Tell the alert rules something happened. Never raises."""
        if self.rules is not None:
            self.rules.event(kind, **details)

    def flush(self, now=None):
        """Send held alerts as a digest once quiet hours are over and the internet is up."""
        now = now or time.time()
        if self.wan_down() or in_quiet_hours(self.settings(), now) or not self.store.count_pending():
            return 0
        items = self.store.take_pending()
        for channel in ("phone", "email"):
            chosen = [i for i in items if i[channel]]
            if not chosen:
                continue
            reasons = sorted({i["reason"] for i in chosen if i["reason"]})
            title = f"{len(chosen)} alert{'s' if len(chosen) != 1 else ''} while " + " / ".join(reasons or ["held"])
            if channel == "phone":
                body = "\n".join(f"{time.strftime('%H:%M', time.localtime(i['ts']))}  {i['title']}"
                                 for i in chosen[-20:])
                if len(chosen) > 20:
                    body = f"(showing last 20 of {len(chosen)})\n" + body
            else:
                body = "\n\n".join(
                    f"[{time.strftime('%Y-%m-%d %H:%M', time.localtime(i['ts']))}] {i['title']}\n{i['message']}"
                    for i in chosen)
            self.notifier.notify(title, body, phone=channel == "phone", email=channel == "email",
                                 tags=["inbox_tray"])
            if channel == "phone":
                self.push(title, body, tag="digest", severity="digest")
        log.info("Sent digest of %d held alert(s)", len(items))
        return len(items)

    def start(self):
        threading.Thread(target=self._run, name="alert-digest", daemon=True).start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(60):
            try:
                self.flush()
            except Exception:
                log.exception("Digest failed")
