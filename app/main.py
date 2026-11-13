"""NetWatch web app: REST API + dashboard."""
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path as FsPath

from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .config import Config
from .db import Store
from .monitor import Monitor
from .notifier import Notifier
from .router_linksys import LinksysRouter, RouterError
from .security import SecurityMiddleware
from . import tls

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

cfg = Config.from_env()
store = Store(cfg.db_path)
notifier = Notifier(cfg)
router = LinksysRouter(cfg)
monitor = Monitor(cfg, store, notifier, router=router)
STATIC = FsPath(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_app):
    if os.getenv("NETWATCH_DISABLE_SCANNER") != "1":
        monitor.start()
        router.start()
    yield
    monitor.stop()
    router.stop()


app = FastAPI(title="NetWatch", lifespan=lifespan)
app.add_middleware(SecurityMiddleware, cfg=cfg)

MAC_PATTERN = r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _cert_path():
    if cfg.tls_mode == "custom":
        return cfg.tls_cert_file
    if cfg.tls_mode == "self-signed":
        return os.path.join(cfg.tls_dir, "netwatch.crt")
    return None


@app.get("/netwatch.crt")
def certificate():
    """Public certificate, so you can install it as trusted on your devices."""
    path = _cert_path()
    if not path or not os.path.exists(path):
        raise HTTPException(404, "No certificate (HTTPS is off)")
    return FileResponse(path, media_type="application/x-x509-ca-cert", filename="netwatch.crt")


_tls_cache = {}


def _tls_status():
    path = _cert_path()
    if not path or not os.path.exists(path):
        return {"mode": cfg.tls_mode}
    mtime = os.path.getmtime(path)
    if _tls_cache.get("mtime") != mtime:
        try:
            _tls_cache.update(mtime=mtime, info=tls.describe(path))
        except Exception:
            _tls_cache.update(mtime=mtime, info={})
    return {"mode": cfg.tls_mode, **_tls_cache["info"]}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/status")
def status():
    devices = store.all_devices()
    return {
        "now": time.time(),
        "subnet": str(monitor.network) if monitor.network else cfg.subnet,
        "interface": monitor.iface,
        "scan_interval": cfg.scan_interval,
        "offline_after": cfg.offline_after,
        "last_scan": monitor.last_scan,
        "last_scan_duration": monitor.last_scan_duration,
        "last_error": monitor.last_error,
        "online": sum(1 for d in devices if d["online"]),
        "known": len(devices),
        "phone_enabled": notifier.phone_enabled,
        "email_enabled": notifier.email_enabled,
        "router": _router_status(),
        "tls": _tls_status(),
    }


def _router_status():
    if not router.enabled:
        return {"enabled": False}
    s = router.snapshot()
    can_change, reason = _change_permission()
    return {
        "enabled": True, "last_sync": s["last_sync"], "error": s["error"],
        "dhcp_first": s["dhcp_first"], "dhcp_last": s["dhcp_last"],
        "reservations": len(s["reservations"]), "max_desc": s["max_desc"],
        "can_change": can_change, "change_disabled_reason": reason,
    }


def _change_permission():
    if not router.enabled:
        return False, "Linksys integration is not configured"
    if not cfg.linksys_allow_changes:
        return False, "Set LINKSYS_ALLOW_CHANGES=true in .env to manage reservations here"
    if not cfg.web_password:
        return False, "Set WEB_PASSWORD in .env first: router changes require a dashboard login"
    return True, None


@app.get("/api/reservations")
def reservations():
    if not router.enabled:
        raise HTTPException(404, "Linksys integration is not configured")
    snap = router.snapshot()
    devices = {d["mac"]: d for d in store.all_devices()}
    out = []
    for mac, r in snap["reservations"].items():
        d = devices.get(mac)
        if d is None:
            state = "never_seen"
        elif not d["online"]:
            state = "offline"
        elif d["ip"] == r["ip"]:
            state = "active"
        else:
            state = "pending"           # online, but hasn't picked up the reserved IP yet
        out.append({
            "mac": mac, "ip": r["ip"], "description": r["description"], "state": state,
            "current_ip": d["ip"] if d else None,
            "device_name": (d and (d["nickname"] or d["hostname"] or d["vendor"])) or snap["names"].get(mac),
            "last_seen": d["last_seen"] if d else None,
        })
    out.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))
    return {"reservations": out, "router": _router_status()}


class NewReservation(BaseModel):
    mac: str = Field(max_length=17)
    ip: str = Field(max_length=15)
    description: str = Field(default="", max_length=63)


def _require_change_permission():
    ok, reason = _change_permission()
    if not ok:
        raise HTTPException(403, reason)


@app.post("/api/reservations")
def add_reservation(body: NewReservation):
    _require_change_permission()
    try:
        mac, ip, _ = router.validate_new(body.mac, body.ip, body.description)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    clash = next((d for d in store.all_devices()
                  if d["online"] and d["ip"] == ip and d["mac"] != mac), None)
    if clash:
        raise HTTPException(409, f"{ip} is currently in use by "
                                 f"{clash['nickname'] or clash['hostname'] or clash['mac']}. Pick a free address.")
    try:
        router.add_reservation(mac, ip, body.description)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    except RouterError as e:
        raise HTTPException(502, str(e)) from None
    store.add_event("reservation", mac, ip, f"Reserved {ip}" + (f" ({body.description.strip()})" if body.description.strip() else ""))
    return {"ok": True}


@app.delete("/api/reservations/{mac}")
def remove_reservation(mac: str = Path(pattern=MAC_PATTERN)):
    _require_change_permission()
    snap = router.snapshot()
    r = snap["reservations"].get(mac.lower())
    try:
        router.remove_reservation(mac)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    except RouterError as e:
        raise HTTPException(502, str(e)) from None
    store.add_event("reservation", mac.lower(), r["ip"] if r else None, "Reservation removed")
    return {"ok": True}


@app.get("/api/devices")
def devices():
    snap = router.snapshot() if router.enabled else None
    out = []
    for d in store.all_devices():
        if snap:
            r = snap["reservations"].get(d["mac"])
            d["reserved_ip"] = r["ip"] if r else None
            d["router_name"] = (r and r["description"]) or snap["names"].get(d["mac"])
        out.append(d)
    return {"now": time.time(), "devices": out}


class DeviceUpdate(BaseModel):
    nickname: str | None = Field(default=None, max_length=64)
    notify_phone: bool | None = None
    notify_email: bool | None = None
    notify_return: bool | None = None


@app.patch("/api/devices/{mac}")
def update_device(body: DeviceUpdate, mac: str = Path(pattern=MAC_PATTERN)):
    mac = mac.lower()
    if not store.get_device(mac):
        raise HTTPException(404, "Unknown device")
    fields = body.model_dump(exclude_none=True)
    if "nickname" in fields:
        fields["nickname"] = fields["nickname"].strip() or None
    for k in ("notify_phone", "notify_email", "notify_return"):
        if k in fields:
            fields[k] = int(fields[k])
    store.update_device(mac, **fields)
    return store.get_device(mac)


@app.delete("/api/devices/{mac}")
def forget_device(mac: str = Path(pattern=MAC_PATTERN)):
    if not store.delete_device(mac.lower()):
        raise HTTPException(404, "Unknown device")
    return {"ok": True}


@app.get("/api/ips")
def ip_map():
    net = monitor.network or (ipaddress.IPv4Network(cfg.subnet, strict=False) if cfg.subnet else None)
    if net is None:
        return {"subnet": None, "ips": []}
    snap = router.snapshot() if router.enabled else None
    reserved = snap["reserved_ips"] if snap else {}
    by_ip = {}
    for d in sorted(store.all_devices(), key=lambda d: (d["online"], d["last_seen"] or 0)):
        if d["ip"]:
            by_ip[d["ip"]] = d          # online / most recent wins
    out = []
    for i, host in enumerate(net.hosts()):
        if i >= 4096:
            break
        ip = str(host)
        d = by_ip.get(ip)
        res = reserved.get(ip)
        entry = {"ip": ip, "in_pool": router.in_dhcp_pool(ip, snap) if snap else None,
                 "reserved": bool(res), "reservation": res["description"] if res else None}
        if d is not None:
            entry.update(status="online" if d["online"] else "offline", mac=d["mac"],
                         name=d["nickname"] or (res and res["description"]) or d["hostname"] or d["vendor"],
                         last_seen=d["last_seen"])
        elif res:
            entry.update(status="reserved", mac=res["mac"], name=res["description"])
        elif snap and snap["router_ip"] == ip:
            entry.update(status="online", name="Router")
        else:
            entry["status"] = "free"
        out.append(entry)
    return {"subnet": str(net), "ips": out}


@app.get("/api/events")
def events(limit: int = Query(200, ge=1, le=2000),
           mac: str | None = Query(None, pattern=MAC_PATTERN)):
    return {"events": store.events(limit, mac.lower() if mac else None)}


@app.post("/api/scan")
def scan_now():
    monitor.trigger()
    return {"ok": True}


class TestNotification(BaseModel):
    phone: bool = True
    email: bool = True


@app.post("/api/test-notification")
def test_notification(body: TestNotification):
    return notifier.send_now(
        "Test notification",
        "If you can read this, NetWatch alerts are working.",
        phone=body.phone, email=body.email, tags=["bell"],
    )
