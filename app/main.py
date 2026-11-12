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
from .router_linksys import LinksysRouter
from .security import SecurityMiddleware

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
    }


def _router_status():
    if not router.enabled:
        return {"enabled": False}
    s = router.snapshot()
    return {
        "enabled": True, "last_sync": s["last_sync"], "error": s["error"],
        "dhcp_first": s["dhcp_first"], "dhcp_last": s["dhcp_last"],
        "reservations": len(s["reservations"]),
    }


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
