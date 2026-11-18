"""Device recognition and private (randomized) MAC address linking.

NetWatch learns what each device is from what it already says on the LAN:

- DHCP: when a device joins it broadcasts a request with its hostname, a
  vendor class ("android-dhcp-14", "MSFT 5.0") and a list of options it wants
  (a fingerprint of its operating system). Listened to with a kernel filter
  that only lets DHCP requests through.
- mDNS / Bonjour: a few queries for common services (AirPlay, Chromecast,
  printers, HomeKit, ...). Answers carry models like "iPhone15,2" or "Chromecast".
- SSDP / UPnP: one discovery broadcast; TVs, speakers, routers and consoles answer,
  and their description file names the make and model.
- The manufacturer from the MAC address, and the hostname.

Phones, tablets and laptops now use a private MAC address per network, which
can change. When a device with a private address shows up and has the same
non-generic name (and DHCP fingerprint) as a device NetWatch already knows,
NetWatch suggests they're the same device. Linking keeps the old record for
history (hidden from lists) and moves names, tags and alert settings to the new
address. Nothing is merged without your OK unless you turn on automatic linking.
"""
import ctypes
import ipaddress
import logging
import re
import socket
import struct
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .monitor import display_name

log = logging.getLogger("netwatch.recognize")

TYPES = {
    "phone": "Phone", "tablet": "Tablet", "computer": "Computer", "tv": "TV", "streaming": "Streaming player",
    "speaker": "Speaker", "printer": "Printer", "camera": "Camera", "smart_home": "Smart home",
    "console": "Game console", "network": "Network gear", "server": "Server / NAS", "watch": "Watch",
}
MDNS_ADDR, SSDP_ADDR = ("224.0.0.251", 5353), ("239.255.255.250", 1900)
SERVICES = ["_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp",
            "_pdl-datastream._tcp", "_scanner._tcp", "_hap._tcp", "_companion-link._tcp", "_device-info._tcp",
            "_sonos._tcp", "_spotify-connect._tcp", "_amzn-wplay._tcp", "_smb._tcp", "_afpovertcp._tcp",
            "_ssh._tcp", "_workstation._tcp", "_homekit._tcp", "_matter._tcp", "_http._tcp"]
MAX_VALUE = 200
MAX_KEYS_PER_DEVICE = 80
GENERIC_NAMES = re.compile(r"^(iphone|ipad|android|android-[0-9a-f]{6,}|localhost|phone|unknown|galaxy|"
                           r"espressif|esp|esp32|esp8266|host|client|device|dhcp|\d+|[0-9a-f]{12,}|"
                           r"(macbook|imac)(-(pro|air))?)$")
HAP_CATEGORIES = {2: "smart_home", 5: "smart_home", 6: "smart_home", 7: "smart_home", 8: "smart_home",
                  9: "smart_home", 10: "smart_home", 17: "camera", 31: "tv", 32: "speaker", 36: "tv"}

# Classic BPF for "IPv4 UDP to port 67" (as produced by `tcpdump -dd udp dst port 67`):
# only DHCP requests reach NetWatch, never other traffic.
DHCP_BPF = [(0x28, 0, 0, 0x0000000c), (0x15, 0, 8, 0x00000800), (0x30, 0, 0, 0x00000017),
            (0x15, 0, 6, 0x00000011), (0x28, 0, 0, 0x00000014), (0x45, 4, 0, 0x00001fff),
            (0xb1, 0, 0, 0x0000000e), (0x48, 0, 0, 0x00000010), (0x15, 0, 1, 0x00000043),
            (0x06, 0, 0, 0x00040000), (0x06, 0, 0, 0x00000000)]
SO_ATTACH_FILTER = 26


def is_private_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError):
        return False


def _clean(v):
    v = "".join(ch for ch in str(v) if ch.isprintable())
    return v.strip()[:MAX_VALUE]


def norm_name(name):
    """'Alexs-iPhone.local.' -> 'alexs-iphone'; None for generic or empty names."""
    if not name:
        return None
    n = str(name).strip().lower().rstrip(".")
    for suffix in (".local", ".lan", ".home", ".localdomain", ".home.arpa"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    n = n.split(".")[0].replace(" ", "-").replace("’", "").replace("'", "")
    if len(n) < 3 or GENERIC_NAMES.match(n):
        return None
    return n


# ---------- DHCP ----------
def parse_dhcp(frame):
    """Ethernet frame -> {mac, msg, hostname, vendor, params, requested_ip} for a client request, else None."""
    try:
        if len(frame) < 14 + 20 + 8 + 240 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
            return None
        ihl = (frame[14] & 0x0F) * 4
        udp = 14 + ihl
        bootp = udp + 8
        if frame[bootp] != 1:                              # BOOTREQUEST only
            return None
        mac = ":".join(f"{b:02x}" for b in frame[bootp + 28: bootp + 34])
        if frame[bootp + 236: bootp + 240] != b"\x63\x82\x53\x63":
            return None
        out, i, end = {"mac": mac}, bootp + 240, len(frame)
        while i < end:
            code = frame[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 1 >= end:
                break
            ln = frame[i + 1]
            val = frame[i + 2: i + 2 + ln]
            i += 2 + ln
            if code == 53 and val:
                out["msg"] = {1: "discover", 3: "request", 8: "inform"}.get(val[0], str(val[0]))
            elif code == 12:
                out["hostname"] = _clean(val.decode("utf-8", "replace"))
            elif code == 60:
                out["vendor"] = _clean(val.decode("latin-1"))
            elif code == 55:
                out["params"] = ",".join(str(b) for b in val)
            elif code == 50 and len(val) == 4:
                out["requested_ip"] = ".".join(str(b) for b in val)
            elif code == 81 and len(val) > 3 and "hostname" not in out:
                out["hostname"] = _clean(val[3:].decode("utf-8", "replace"))
        return out if "msg" in out else None
    except (IndexError, struct.error):
        return None


def open_dhcp_socket(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    prog = b"".join(struct.pack("HBBI", *ins) for ins in DHCP_BPF)
    buf = ctypes.create_string_buffer(prog)
    fprog = struct.pack("HL", len(DHCP_BPF), ctypes.addressof(buf))
    s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)   # the kernel copies the program here
    if iface:
        s.bind((iface, 0))
    s.settimeout(1.0)
    return s


# ---------- mDNS ----------
def _name(data, i, depth=0):
    labels, jumped, end = [], False, None
    while True:
        if i >= len(data) or depth > 20:
            raise ValueError("bad name")
        ln = data[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[i + 1]
            if not jumped:
                end = i + 2
            jumped, i, depth = True, ptr, depth + 1
            continue
        labels.append(data[i + 1: i + 1 + ln].decode("utf-8", "replace"))
        i += 1 + ln
    return ".".join(labels), (end if jumped else i)


def mdns_query(names):
    qd = b""
    for n in names:
        qd += b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00" + struct.pack("!HH", 12, 1)
    return struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0) + qd


def parse_mdns(data):
    """DNS message -> list of (name, type, value)."""
    out = []
    qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    i = 12
    for _ in range(qd):
        _n, i = _name(data, i)
        i += 4
    for _ in range(min(an + ns + ar, 200)):
        name, i = _name(data, i)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        rd = data[i:i + rdlen]
        if rtype == 12:
            out.append((name, "PTR", _name(data, i)[0]))
        elif rtype == 33 and rdlen > 6:
            out.append((name, "SRV", _name(data, i + 6)[0]))
        elif rtype == 16:
            kv, j = {}, 0
            while j < len(rd):
                ln = rd[j]
                item = rd[j + 1:j + 1 + ln].decode("utf-8", "replace")
                j += 1 + ln
                if "=" in item:
                    k, v = item.split("=", 1)
                    kv[k.lower()[:30]] = _clean(v)
            out.append((name, "TXT", kv))
        elif rtype == 1 and rdlen == 4:
            out.append((name, "A", ".".join(str(b) for b in rd)))
        i += rdlen
    return out


def mdns_browse(timeout=3.0, target=MDNS_ADDR, bind_ip=None):
    """Ask for common services; returns {ip: {"services": set, "txt": {}, "names": set, "hostname": str}}."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        if bind_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        s.bind(("", 0))
        names = [f"{x}.local" for x in SERVICES]
        for k in range(0, len(names), 8):              # a few small packets rather than one large one
            s.sendto(mdns_query(names[k:k + 8]), target)
        s.settimeout(0.3)
        found, deadline = {}, time.time() + timeout
        while time.time() < deadline:
            try:
                data, (ip, _port) = s.recvfrom(9000)
            except socket.timeout:
                continue
            try:
                records = parse_mdns(data)
            except (ValueError, IndexError, struct.error):
                continue
            d = found.setdefault(ip, {"services": set(), "txt": {}, "names": set(), "hostname": None})
            for name, rtype, value in records:
                if rtype == "PTR" and name.endswith("._tcp.local"):
                    d["services"].add(name.rsplit(".local", 1)[0])
                    inst = value.split("._", 1)[0]
                    if inst and len(d["names"]) < 10:
                        d["names"].add(_clean(inst))
                elif rtype == "SRV":
                    d["hostname"] = _clean(value)
                elif rtype == "TXT":
                    svc = next((x for x in SERVICES if f".{x}.local" in name or name.startswith(x)), "")
                    for k, v in value.items():
                        if len(d["txt"]) < 40:
                            d["txt"][f"{svc}:{k}" if svc else k] = v
                elif rtype == "A" and value == ip and name.endswith(".local"):
                    d["hostname"] = d["hostname"] or _clean(name)
        return found
    finally:
        s.close()


# ---------- SSDP / UPnP ----------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def ssdp_search(timeout=3.0, target=SSDP_ADDR, bind_ip=None):
    """M-SEARCH ssdp:all; returns {ip: {"server", "st": set, "location"}}."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        s.bind(("", 0))
        msg = (f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               f"MX: 2\r\nST: ssdp:all\r\nUSER-AGENT: NetWatch\r\n\r\n").encode()
        s.sendto(msg, target)
        s.settimeout(0.3)
        found, deadline = {}, time.time() + timeout
        while time.time() < deadline:
            try:
                data, (ip, _port) = s.recvfrom(4096)
            except socket.timeout:
                continue
            headers = {}
            for line in data.decode("latin-1").split("\r\n")[1:]:
                k, sep, v = line.partition(":")
                if sep:
                    headers[k.strip().lower()] = v.strip()
            d = found.setdefault(ip, {"server": None, "st": set(), "location": None})
            d["server"] = d["server"] or _clean(headers.get("server", "")) or None
            if headers.get("st") and len(d["st"]) < 15:
                d["st"].add(_clean(headers["st"]))
            if not d["location"] and headers.get("location"):
                d["location"] = headers["location"][:300]
        return found
    finally:
        s.close()


def fetch_description(location, responder_ip):
    """Read a UPnP device description, only from the device that answered, with tight limits."""
    try:
        u = urllib.parse.urlsplit(location)
        if u.scheme != "http" or u.hostname != responder_ip:
            return {}
        with _opener.open(urllib.request.Request(location, headers={"User-Agent": "NetWatch"}), timeout=3) as r:
            body = r.read(65536)
        if b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
            return {}
        root = ET.fromstring(body)
        out = {}
        for el in root.iter():
            tag = el.tag.split("}")[-1]
            if tag in ("friendlyName", "manufacturer", "modelName", "modelDescription", "deviceType") and tag not in out and el.text:
                out[tag] = _clean(el.text)
        return out
    except Exception:
        return {}


# ---------- deciding what a device is ----------
APPLE_MODELS = [("iphone", "phone", "iOS"), ("ipad", "tablet", "iPadOS"), ("macbook", "computer", "macOS"),
                ("imac", "computer", "macOS"), ("macmini", "computer", "macOS"), ("macpro", "computer", "macOS"),
                ("mac1", "computer", "macOS"), ("mac", "computer", "macOS"), ("appletv", "streaming", "tvOS"),
                ("audioaccessory", "speaker", "HomePod"), ("homepod", "speaker", "HomePod"), ("watch", "watch", "watchOS")]
NAME_RULES = [
    (r"iphone", "phone", "iOS"), (r"ipad", "tablet", "iPadOS"), (r"macbook|imac|mac-?mini|mac-?studio|mac-?pro", "computer", "macOS"),
    (r"galaxy-?tab|lenovo-?tab|-tab-|fire-?hd|kindle", "tablet", "Android"),
    (r"galaxy|pixel|oneplus|moto-?g|redmi|xiaomi|^android-", "phone", "Android"),
    (r"^desktop-|^laptop-|^win-|windows", "computer", "Windows"), (r"raspberrypi|^rpi|ubuntu|debian|fedora", "computer", "Linux"),
    (r"chromecast|google-?tv", "streaming", None), (r"roku", "streaming", None), (r"fire-?tv|aftmm|aftt", "streaming", "Fire OS"),
    (r"apple-?tv", "streaming", "tvOS"), (r"lgwebostv|webos|bravia|samsung.*tv|tv-|-tv$|^tv$|vizio|hisense|tcl", "tv", None),
    (r"^echo|alexa|amazon-|google-?home|nest-?(mini|audio|hub)|sonos|homepod", "speaker", None),
    (r"nintendo|switch|playstation|^ps[345]|xbox", "console", None),
    (r"printer|^hp[0-9a-f]{6}|epson|^brw|brother|canon|laserjet|officejet", "printer", None),
    (r"^esp[-_]|esp32|esp8266|tasmota|shelly|tuya|sonoff|wled|hue|ecobee|thermostat|plug|bulb|switch-|smartthings", "smart_home", None),
    (r"cam|reolink|wyze|hikvision|doorbell|ring-", "camera", None),
    (r"proxmox|truenas|unraid|synology|diskstation|qnap|^nas|nas$|server", "server", "Linux"),
    (r"router|gateway|^ap-|unifi|opnsense|pfsense|openwrt|switch$|mikrotik|eero|orbi|deco", "network", None),
]
VENDOR_RULES = [
    (r"espressif|tuya|shelly|sonoff|itead|signify|philips lighting|ecobee|lifx|wiz|meross|govee", "smart_home"),
    (r"ring llc|arlo|reolink|hikvision|dahua|axis comm|wyze", "camera"),
    (r"raspberry pi", "computer"), (r"synology|qnap|proxmox", "server"),
    (r"ubiquiti|netgear|mikrotik|aruba|ruckus|cisco|juniper|eero|linksys|tp-link systems|zyxel", "network"),
    (r"sonos", "speaker"), (r"roku", "streaming"), (r"nintendo|sony interactive|microsoft.*xbox", "console"),
    (r"brother|seiko epson|canon|lexmark|xerox|kyocera", "printer"),
]


def classify(dev, ev):
    """(type, model, os, how) from the evidence; type None if unknown."""
    model = ev.get("mdns:model") or ev.get("ssdp:modelName") or None
    # 1. Explicit model identifiers (Apple, Chromecast, HomeKit)
    for key in ("mdns:_device-info._tcp:model", "mdns:_companion-link._tcp:rpmd", "mdns:_airplay._tcp:model",
                "mdns:_raop._tcp:am", "mdns:_airplay._tcp:am"):
        v = (ev.get(key) or "").lower()
        if v:
            for prefix, typ, os_ in APPLE_MODELS:
                if v.replace(" ", "").startswith(prefix):
                    return typ, ev.get(key), os_, f"Bonjour model {ev.get(key)}"
    services = set((ev.get("mdns:services") or "").split(","))
    if "_googlecast._tcp" in services:
        md = ev.get("mdns:_googlecast._tcp:md", "")
        low = md.lower()
        typ = "speaker" if re.search(r"home|nest (mini|audio)|speaker|audio", low) and "hub" not in low else \
              "tv" if re.search(r"tv|bravia|shield|vizio|hisense|tcl", low) and "chromecast" not in low else "streaming"
        return typ, md or "Chromecast", "Cast", f"Google Cast ({md or 'device'})"
    if services & {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"}:
        m = ev.get("mdns:_ipp._tcp:ty") or ev.get("mdns:_ipp._tcp:usb_mdl") or ev.get("mdns:_printer._tcp:ty")
        return "printer", m, None, "Printer service (IPP)"
    if "_hap._tcp" in services:
        try:
            cat = int(ev.get("mdns:_hap._tcp:ci", "0"))
        except ValueError:
            cat = 0
        return HAP_CATEGORIES.get(cat, "smart_home"), ev.get("mdns:_hap._tcp:md"), None, "HomeKit accessory"
    if "_amzn-wplay._tcp" in services:
        return "streaming", model, "Fire OS", "Amazon Fire TV service"
    # 2. UPnP descriptions
    dtype = (ev.get("ssdp:deviceType") or "").lower()
    upnp = " ".join(ev.get(k, "") for k in ("ssdp:friendlyName", "ssdp:manufacturer", "ssdp:modelName", "ssdp:modelDescription", "ssdp:server")).lower()
    if "internetgatewaydevice" in dtype or "wandevice" in dtype:
        return "network", model, None, "UPnP internet gateway"
    if upnp:
        for pat, typ in [(r"roku", "streaming"), (r"xbox|playstation|nintendo", "console"), (r"sonos|denon|yamaha|bose|heos", "speaker"),
                         (r"diskstation|synology|qnap|truenas", "server"), (r"hue bridge|philips hue|smartthings", "smart_home"),
                         (r"camera|ipcam|nvr", "camera"), (r"printer", "printer"),
                         (r"\btv\b|bravia|webos|tizen|vizio|hisense|smart tv", "tv")]:
            if re.search(pat, upnp):
                return typ, model, None, f"UPnP ({ev.get('ssdp:friendlyName') or ev.get('ssdp:manufacturer') or 'device'})"
        if "mediarenderer" in dtype:
            return "speaker", model, None, "UPnP media renderer"
    # 3. Names and the DHCP vendor class
    vendor_class = (ev.get("dhcp:vendor") or "").lower()
    names = [ev.get("dhcp:hostname"), ev.get("mdns:hostname"), dev.get("hostname")]
    for n in names:
        low = (n or "").lower()
        if not low:
            continue
        for pat, typ, os_ in NAME_RULES:
            if re.search(pat, low):
                if typ == "phone" and "android" in vendor_class and re.search(r"tab", low):
                    typ = "tablet"
                return typ, model, os_, f"name '{n}'"
    if vendor_class.startswith("android-dhcp"):
        return "phone", model, "Android", f"DHCP ({ev.get('dhcp:vendor')})"
    if vendor_class.startswith("msft"):
        return "computer", model, "Windows", "DHCP (Windows)"
    if services & {"_smb._tcp", "_afpovertcp._tcp"}:
        return "server", model, None, "file sharing service"
    if services & {"_workstation._tcp", "_ssh._tcp"}:
        return "computer", model, "Linux", "Bonjour workstation"
    if services & {"_sonos._tcp", "_spotify-connect._tcp", "_raop._tcp"}:
        return "speaker", model, None, "audio streaming service"
    # 4. Manufacturer
    vendor = (dev.get("vendor") or "").lower()
    for pat, typ in VENDOR_RULES:
        if re.search(pat, vendor):
            return typ, model, None, f"maker ({dev.get('vendor')})"
    os_ = "Android" if vendor_class.startswith("android") else "Linux" if "dhcpcd" in vendor_class or "udhcp" in vendor_class else None
    return None, model, os_, None


class Recognizer:
    def __init__(self, cfg, store, monitor, alerts, router=None):
        self.cfg = cfg
        self.store = store
        self.monitor = monitor
        self.alerts = alerts
        self.router = router
        self.interval = max(300, int(getattr(cfg, "discovery_interval", 900) or 900))
        self.enabled = getattr(cfg, "discovery", True)
        self.last_discovery = None
        self.dhcp_status = "off"
        self._stop = threading.Event()
        self._kick = threading.Event()
        self.lock = threading.RLock()

    # ---------- evidence ----------
    def evidence(self, mac):
        return {r["key"]: r["value"] for r in self.store._query("SELECT key, value FROM fingerprints WHERE mac = ?", (mac,))}

    def evidence_rows(self, mac):
        return self.store._query("SELECT key, value, first_seen, last_seen FROM fingerprints WHERE mac = ? ORDER BY key", (mac,))

    def record(self, mac, values, now=None):
        now = now or time.time()
        mac = mac.lower()
        have = {r["key"] for r in self.store._query("SELECT key FROM fingerprints WHERE mac = ?", (mac,))}
        with self.store.lock:
            for k, v in values.items():
                if v in (None, "", set()):
                    continue
                if isinstance(v, (set, list)):
                    v = ",".join(sorted(v))[:MAX_VALUE * 3]
                k = str(k)[:60]
                if k not in have and len(have) >= MAX_KEYS_PER_DEVICE:
                    continue
                have.add(k)
                self.store.conn.execute(
                    "INSERT INTO fingerprints (mac, key, value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(mac, key) DO UPDATE SET value = excluded.value, last_seen = excluded.last_seen",
                    (mac, k, _clean(v) if not k.endswith("services") else str(v)[:MAX_VALUE * 3], now, now))
            self.store.conn.commit()

    # ---------- classification ----------
    def reclassify(self, mac):
        dev = self.store.get_device(mac)
        if not dev:
            return None
        typ, model, os_, how = classify(dev, self.evidence(mac))
        if dev.get("type_manual"):
            self.store.update_device(mac, model=model or dev.get("model"), os=os_ or dev.get("os"))
        else:
            self.store.update_device(mac, device_type=typ, model=model, os=os_, type_source=how)
        return typ

    # ---------- discovery passes ----------
    def handle_dhcp(self, info, now=None):
        now = now or time.time()
        self.record(info["mac"], {"dhcp:hostname": info.get("hostname"), "dhcp:vendor": info.get("vendor"),
                                  "dhcp:params": info.get("params"), "dhcp:requested_ip": info.get("requested_ip")}, now)
        if self.store.get_device(info["mac"]):
            self.reclassify(info["mac"])
            self.consider_link(info["mac"])

    def discover(self, now=None, mdns_target=MDNS_ADDR, ssdp_target=SSDP_ADDR):
        """One mDNS + SSDP pass; matches answers to known devices by IP."""
        now = now or time.time()
        own_ip = None
        try:
            own_ip = self.monitor.scanner.own_address(self.monitor.iface)[0] if self.monitor.iface else None
        except Exception:
            pass
        by_ip = {d["ip"]: d for d in sorted(self.store.all_devices(), key=lambda d: (d["online"], d["last_seen"] or 0)) if d["ip"]}
        net = self.monitor.network
        def ours(ip):
            try:
                return ip in by_ip and (net is None or ipaddress.IPv4Address(ip) in net)
            except ValueError:
                return False
        touched = set()
        try:
            for ip, d in mdns_browse(bind_ip=own_ip, target=mdns_target).items():
                if not ours(ip):
                    continue
                mac = by_ip[ip]["mac"]
                vals = {"mdns:services": d["services"], "mdns:hostname": d["hostname"],
                        "mdns:names": d["names"]}
                vals.update({f"mdns:{k}": v for k, v in d["txt"].items()})
                self.record(mac, vals, now)
                touched.add(mac)
        except OSError as e:
            log.info("mDNS discovery unavailable: %s", e)
        try:
            for ip, d in ssdp_search(bind_ip=own_ip, target=ssdp_target).items():
                if not ours(ip):
                    continue
                mac = by_ip[ip]["mac"]
                vals = {"ssdp:server": d["server"], "ssdp:st": d["st"]}
                if d["location"]:
                    vals.update({f"ssdp:{k}": v for k, v in fetch_description(d["location"], ip).items()})
                self.record(mac, vals, now)
                touched.add(mac)
        except OSError as e:
            log.info("SSDP discovery unavailable: %s", e)
        for d in self.store.all_devices():
            if d["mac"] in touched or not d.get("device_type") or not d.get("type_source"):
                self.reclassify(d["mac"])
        for mac in touched:
            self.consider_link(mac)
        self.last_discovery = now
        return touched

    # ---------- private address linking ----------
    def names_for(self, mac, dev=None):
        dev = dev or self.store.get_device(mac) or {}
        ev = self.evidence(mac)
        out = set()
        for n in (ev.get("dhcp:hostname"), ev.get("mdns:hostname"), dev.get("hostname")):
            k = norm_name(n)
            if k:
                out.add(k)
        return out, ev

    def candidates(self, mac):
        """Known devices that look like the same physical device as `mac`."""
        dev = self.store.get_device(mac)
        if not dev or not is_private_mac(mac) or dev.get("same_as"):
            return []
        names, ev = self.names_for(mac, dev)
        if not names:
            return []
        rejected = {r["other"] for r in self.store._query(
            "SELECT other FROM identity_links WHERE mac = ? AND state = 'rejected'", (mac,))}
        out = []
        for other in self.store.all_devices():
            if other["mac"] == mac or other.get("same_as") or other["mac"] in rejected:
                continue
            if other["first_seen"] and dev["first_seen"] and other["first_seen"] > dev["first_seen"]:
                continue                                    # link newer -> older only
            onames, oev = self.names_for(other["mac"], other)
            shared = names & onames
            if not shared:
                continue
            score, why = 80, [f"same name '{sorted(shared)[0]}'"]
            if ev.get("dhcp:params") and ev.get("dhcp:params") == oev.get("dhcp:params"):
                score += 15; why.append("same DHCP fingerprint")
            if ev.get("dhcp:vendor") and ev.get("dhcp:vendor") == oev.get("dhcp:vendor"):
                score += 3
            if other.get("online") and other.get("last_seen") and dev.get("last_seen") and abs(other["last_seen"] - dev["last_seen"]) < 60 \
                    and other["mac"] != mac:
                score -= 40; why.append("but both are online now")
            out.append({"mac": other["mac"], "score": score, "why": ", ".join(why)})
        return sorted(out, key=lambda c: -c["score"])

    def consider_link(self, mac, now=None):
        """Suggest (or, if allowed, make) a link for a device with a private address. Returns 'linked', 'suggested' or None."""
        now = now or time.time()
        with self.lock:
            cands = [c for c in self.candidates(mac) if c["score"] >= 80]
            if not cands:
                return None
            best = cands[0]
            existing = self.store._query("SELECT * FROM identity_links WHERE mac = ? AND other = ?", (mac, best["mac"]))
            auto = bool(self.alerts.settings().get("auto_link_private")) and best["score"] >= 95
            if existing and existing[0]["state"] != "suggested":
                return None
            if not existing:
                self.store._exec("INSERT INTO identity_links (mac, other, state, score, reason, created) VALUES (?, ?, 'suggested', ?, ?, ?)",
                                 (mac, best["mac"], best["score"], best["why"], now))
            if auto:
                self.link(mac, best["mac"], by="automatic", now=now)
                return "linked"
            return "suggested"

    def suggestions(self):
        rows = self.store._query("SELECT * FROM identity_links WHERE state = 'suggested' ORDER BY created DESC LIMIT 50")
        out = []
        for r in rows:
            new, old = self.store.get_device(r["mac"]), self.store.get_device(r["other"])
            if not new or not old or new.get("same_as") or old.get("same_as"):
                continue
            out.append({**r, "new": _summary(new, self.router), "old": _summary(old, self.router)})
        return out

    def link(self, new_mac, old_mac, by="admin", now=None):
        """Treat new_mac as the current address of old_mac's device."""
        now = now or time.time()
        new, old = self.store.get_device(new_mac), self.store.get_device(old_mac)
        if not new or not old or new_mac == old_mac:
            raise ValueError("Unknown device")
        if new.get("same_as") or old.get("same_as"):
            raise ValueError("One of these is already linked")
        tags = sorted(set(t for t in (old.get("tags") or "").split(",") + (new.get("tags") or "").split(",") if t))
        old_name = display_name(old, self.router)
        keep_name = new.get("nickname") or old.get("nickname") or (old_name if old_name != old_mac else None)
        self.store.update_device(new_mac, nickname=keep_name, tags=",".join(tags[:10]),
                                 notify_phone=old["notify_phone"] or new["notify_phone"],
                                 notify_email=old["notify_email"] or new["notify_email"],
                                 notify_return=old["notify_return"] or new["notify_return"],
                                 critical=old.get("critical") or new.get("critical"), acknowledged=1,
                                 **({"device_type": old["device_type"], "type_manual": 1} if old.get("type_manual") else {}))
        # The old address goes quiet: hidden from lists, no alerts for it.
        self.store.update_device(old_mac, same_as=new_mac, notify_phone=0, notify_email=0, notify_return=0, critical=0)
        self.store._exec("UPDATE devices SET same_as = ? WHERE same_as = ?", (new_mac, old_mac))
        self.store._exec("UPDATE checks SET mac = ? WHERE mac = ?", (new_mac, old_mac))
        self.store._exec("UPDATE identity_links SET state = 'confirmed', decided = ?, decided_by = ? WHERE mac = ? AND other = ?",
                         (now, by[:64], new_mac, old_mac))
        if not self.store._query("SELECT 1 FROM identity_links WHERE mac = ? AND other = ?", (new_mac, old_mac)):
            self.store._exec("INSERT INTO identity_links (mac, other, state, score, reason, created, decided, decided_by) "
                             "VALUES (?, ?, 'confirmed', 100, 'linked by hand', ?, ?, ?)", (new_mac, old_mac, now, now, by[:64]))
        self.store._exec("UPDATE identity_links SET state = 'rejected', decided = ?, decided_by = 'superseded' "
                         "WHERE mac = ? AND state = 'suggested'", (now, new_mac))
        name = display_name(self.store.get_device(new_mac), self.router)
        self.store.add_event("linked", new_mac, new.get("ip"), f"Same device as {old_mac} (private address); linked by {by}", ts=now)
        self.alerts.event("device_acknowledged", now=now, device=self.store.get_device(new_mac))
        return name

    def reject(self, link_id, by, now=None):
        rows = self.store._query("SELECT * FROM identity_links WHERE id = ?", (link_id,))
        if not rows or rows[0]["state"] != "suggested":
            raise ValueError("Unknown suggestion")
        self.store._exec("UPDATE identity_links SET state = 'rejected', decided = ?, decided_by = ? WHERE id = ?",
                         (now or time.time(), by[:64], link_id))

    def unlink(self, old_mac, by="admin", now=None):
        old = self.store.get_device(old_mac)
        if not old or not old.get("same_as"):
            raise ValueError("That address isn't linked")
        self.store.update_device(old_mac, same_as=None)
        self.store._exec("UPDATE identity_links SET state = 'rejected', decided = ?, decided_by = ? WHERE other = ? AND state = 'confirmed'",
                         (now or time.time(), f"unlinked by {by}"[:64], old_mac))
        self.store.add_event("linked", old_mac, old.get("ip"), f"Unlinked from {old['same_as']} by {by}", ts=now)

    def aliases(self, mac):
        return [_summary(d, self.router) for d in self.store.all_devices() if d.get("same_as") == mac]

    # ---------- background ----------
    def start(self):
        if not self.enabled:
            return
        threading.Thread(target=self._dhcp_loop, name="dhcp-listen", daemon=True).start()
        threading.Thread(target=self._discovery_loop, name="discovery", daemon=True).start()

    def stop(self):
        self._stop.set()
        self._kick.set()

    def kick(self):
        self._kick.set()

    def _discovery_loop(self):
        self._stop.wait(30)                                 # let the first scan finish
        while not self._stop.is_set():
            try:
                if self.monitor.network is not None:
                    self.discover()
            except Exception:
                log.exception("Discovery pass failed")
            self._kick.wait(self.interval)
            self._kick.clear()

    def _dhcp_loop(self):
        while not self._stop.is_set() and self.monitor.iface is None:
            self._stop.wait(5)
        try:
            sock = open_dhcp_socket(self.monitor.iface)
        except OSError as e:
            self.dhcp_status = f"unavailable ({e.strerror or e})"
            log.info("DHCP listening unavailable: %s", e)
            return
        self.dhcp_status = "listening"
        with sock:
            while not self._stop.is_set():
                try:
                    frame = sock.recv(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                info = parse_dhcp(frame)
                if info:
                    try:
                        self.handle_dhcp(info)
                    except Exception:
                        log.exception("DHCP fingerprint failed")

    def status(self):
        return {"enabled": self.enabled, "dhcp": self.dhcp_status, "last_discovery": self.last_discovery,
                "suggestions": len(self.suggestions()) if self.enabled else 0}


def _summary(d, router=None):
    return {"mac": d["mac"], "ip": d.get("ip"), "name": display_name(d, router), "online": bool(d.get("online")),
            "last_seen": d.get("last_seen"), "first_seen": d.get("first_seen"), "device_type": d.get("device_type"),
            "private": is_private_mac(d["mac"])}

