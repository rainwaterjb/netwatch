"""Wake-on-LAN: send a "magic packet" to wake a sleeping device.

The device must support Wake-on-LAN and have it enabled (usually in its
BIOS/UEFI and network adapter settings). It must also be on the same network.
"""
import re
import socket

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def magic_packet(mac):
    mac = mac.lower().replace("-", ":")
    if not MAC_RE.match(mac):
        raise ValueError("Invalid MAC address")
    return b"\xff" * 6 + bytes.fromhex(mac.replace(":", "")) * 16


def send(mac, broadcast="255.255.255.255", repeats=3):
    """Send the magic packet to the subnet broadcast on UDP ports 9 and 7."""
    packet = magic_packet(mac)
    targets = {broadcast, "255.255.255.255"}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(repeats):
            for addr in targets:
                for port in (9, 7):
                    s.sendto(packet, (addr, port))
    return sorted(targets)
