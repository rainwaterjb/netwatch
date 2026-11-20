"""Per-person preferences: theme, status colors and the Home page layout.

Each signed-in person (and the built-in admin) keeps their own. Everything is
checked against fixed lists here, so stored preferences can only ever name a
known theme, widget or size.
"""
import re

# id -> light or dark. The colors themselves live in the dashboard (static/themes.js).
THEMES = {
    "control-room": "dark", "daylight": "light", "oled": "dark", "fjord": "dark",
    "paper": "light", "phosphor": "dark", "ember": "dark", "synthwave": "dark",
    "lagoon": "light", "contrast": "dark", "neon-grid": "dark",
}
STATUS_COLORS = ("standard", "colorblind")

# widget id -> sizes it can take (S = 1 column, M = 2, L = full width)
WIDGETS = {
    "status": ("M", "L"), "attention": ("S", "M", "L"), "activity": ("S", "M", "L"),
    "timeline": ("M", "L"), "ips": ("S", "M", "L"), "services": ("S", "M", "L"),
    "internet": ("S", "M"), "domains": ("S", "M", "L"), "alerts": ("S", "M", "L"),
    "newdev": ("S", "M", "L"), "pinned": ("S", "M", "L"), "types": ("S", "M"),
    "actions": ("S", "M"),
}
DEFAULT_HOME = [
    {"id": "status", "size": "L"}, {"id": "attention", "size": "M"}, {"id": "activity", "size": "M"},
    {"id": "timeline", "size": "L"}, {"id": "ips", "size": "M"}, {"id": "services", "size": "M"},
]
DEFAULTS = {
    "theme": "control-room", "status_colors": "standard", "follow_system": False,
    "light_theme": "daylight", "dark_theme": "control-room",
    "home": DEFAULT_HOME, "pinned": [],
}
MAX_PINNED = 12
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def owner_key(who):
    """Whose preferences: a person (accounts, built-in admin = user 0) or the shared open dashboard."""
    if who and who.get("user_id") is not None:
        return f"user:{int(who['user_id'])}"
    if who and who.get("token_id") is not None:
        return f"token:{int(who['token_id'])}"
    return "open"


def merged(stored):
    """Stored preferences on top of the defaults, dropping anything no longer known."""
    out = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULTS.items()}
    if isinstance(stored, dict):
        for k, v in stored.items():
            if k in DEFAULTS:
                try:
                    out.update(normalize({k: v}))
                except ValueError:
                    pass                        # e.g. a theme removed in a later version
    return out


def normalize(body):
    """Validate a partial update. Returns only the keys given, cleaned. Raises ValueError."""
    if not isinstance(body, dict):
        raise ValueError("Expected an object")
    unknown = set(body) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Unknown setting: {sorted(unknown)[0]}")
    out = {}
    for k in ("theme", "light_theme", "dark_theme"):
        if k in body:
            v = body[k]
            if v not in THEMES:
                raise ValueError(f"Unknown theme: {str(v)[:40]}")
            if k == "light_theme" and THEMES[v] != "light":
                raise ValueError("light_theme must be a light theme")
            if k == "dark_theme" and THEMES[v] != "dark":
                raise ValueError("dark_theme must be a dark theme")
            out[k] = v
    if "status_colors" in body:
        if body["status_colors"] not in STATUS_COLORS:
            raise ValueError("status_colors must be standard or colorblind")
        out["status_colors"] = body["status_colors"]
    if "follow_system" in body:
        if not isinstance(body["follow_system"], bool):
            raise ValueError("follow_system must be true or false")
        out["follow_system"] = body["follow_system"]
    if "home" in body:
        home = body["home"]
        if not isinstance(home, list) or len(home) > len(WIDGETS):
            raise ValueError("home must be a list of widgets")
        seen, clean = set(), []
        for w in home:
            if not isinstance(w, dict) or w.get("id") not in WIDGETS:
                raise ValueError("Unknown widget")
            if w["id"] in seen:
                raise ValueError(f"Widget listed twice: {w['id']}")
            if w.get("size") not in WIDGETS[w["id"]]:
                raise ValueError(f"{w['id']} can't be size {str(w.get('size'))[:4]}")
            seen.add(w["id"])
            clean.append({"id": w["id"], "size": w["size"]})
        out["home"] = clean
    if "pinned" in body:
        pinned = body["pinned"]
        if not isinstance(pinned, list) or len(pinned) > MAX_PINNED:
            raise ValueError(f"pinned holds up to {MAX_PINNED} devices")
        clean = []
        for mac in pinned:
            mac = str(mac).lower()
            if not MAC_RE.match(mac):
                raise ValueError("pinned must hold MAC addresses")
            if mac not in clean:
                clean.append(mac)
        out["pinned"] = clean
    return out
