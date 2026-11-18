"""Low-level network discovery: ARP sweeps, single-host probes, name/vendor lookup."""
import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("netwatch.scanner")
_executor = ThreadPoolExecutor(max_workers=8)


def _scapy():
    from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp
    # ARP replies are unicast to us; promiscuous mode isn't needed and would
    # require the extra NET_ADMIN capability.
    conf.sniff_promisc = False
    return ARP, Ether, conf, get_if_addr, get_if_hwaddr, srp


def detect_network(iface=None):
    """Return (iface, IPv4Network) for the given or default interface."""
    _, _, conf, _, _, _ = _scapy()
    iface = iface or str(conf.iface)
    best = None
    for route in conf.route.routes:
        net, mask, gw, ifc, addr = route[:5]
        if str(ifc) != iface or gw != "0.0.0.0" or mask in (0, 0xFFFFFFFF):
            continue
        n = ipaddress.IPv4Network((net, bin(mask).count("1")), strict=False)
        if n.is_loopback or n.is_link_local:
            continue
        try:
            if ipaddress.IPv4Address(addr) in n and (best is None or n.prefixlen < best.prefixlen):
                best = n
        except ValueError:
            continue
    return iface, best


def own_address(iface):
    """IP and MAC of this host on iface (it never answers its own ARP)."""
    _, _, _, get_if_addr, get_if_hwaddr, _ = _scapy()
    try:
        return get_if_addr(iface), get_if_hwaddr(iface).lower()
    except Exception:
        return None, None


def arp_scan(network, iface, timeout=3.0, retry=1):
    """Broadcast ARP to every address in network. Returns {ip: mac}."""
    ARP, Ether, _, _, _, srp = _scapy()
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        iface=iface, timeout=timeout, retry=retry, verbose=False,
    )
    return {r[ARP].psrc: r[ARP].hwsrc.lower() for _, r in ans}


def probe(ip, iface, timeout=2.0, attempts=3, mac=None):
    """Targeted ARP to one IP. Returns the MAC that answered, or None.

    When the device's MAC is known, the request is sent straight to it
    (unicast) first. Wi-Fi access points buffer unicast frames for clients in
    power-save mode and deliver them when the client wakes for the next
    beacon, while broadcasts are often missed by dozing phones and tablets.
    The last attempt is a broadcast in case the device's MAC changed.
    """
    ARP, Ether, _, _, _, srp = _scapy()
    for i in range(attempts):
        unicast = bool(mac) and i < attempts - 1
        dst = mac if unicast else "ff:ff:ff:ff:ff:ff"
        ans, _ = srp(Ether(dst=dst) / ARP(pdst=ip), iface=iface, timeout=timeout, verbose=False)
        for _, r in ans:
            return r[ARP].hwsrc.lower()
    return None


def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def resolve_hostname(ip, timeout=2.0):
    """Reverse DNS (your router/Pi-hole usually knows DHCP hostnames)."""
    try:
        return _executor.submit(_rdns, ip).result(timeout=timeout)
    except Exception:
        return None


def is_randomized_mac(mac):
    return bool(int(mac.split(":")[0], 16) & 0x02)


def vendor_for(mac):
    if is_randomized_mac(mac):
        return "Private (randomized MAC)"
    try:
        from netaddr import EUI
        return EUI(mac).oui.registration().org
    except Exception:
        return None
