"""Minimal, allocation-light Ethernet/IPv4/TCP/UDP/ARP decoder.

Works on raw frame bytes so the same code path serves live capture and PCAP
import, and so protocol dissectors never depend on scapy objects.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_VLAN = (0x8100, 0x88A8, 0x9100)


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


@dataclass
class Frame:
    ts: float
    size: int
    src_mac: str
    dst_mac: str
    ethertype: int
    vlan: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    transport: str = ""  # "TCP", "UDP", "ARP", "IP/<n>" or "" for pure L2
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: int = 0
    payload: bytes = field(default=b"", repr=False)  # L4 payload, or L2 payload for non-IP
    arp_op: int | None = None


def decode(data: bytes, ts: float) -> Frame | None:
    if len(data) < 14:
        return None
    dst_mac, src_mac = mac_str(data[0:6]), mac_str(data[6:12])
    (ethertype,) = struct.unpack_from("!H", data, 12)
    offset = 14
    vlan = None
    while ethertype in ETH_P_VLAN and len(data) >= offset + 4:
        tci, ethertype = struct.unpack_from("!HH", data, offset)
        vlan = tci & 0x0FFF
        offset += 4

    frame = Frame(ts=ts, size=len(data), src_mac=src_mac, dst_mac=dst_mac,
                  ethertype=ethertype, vlan=vlan)

    if ethertype == ETH_P_ARP:
        if len(data) < offset + 28:
            return None
        op = struct.unpack_from("!H", data, offset + 6)[0]
        frame.transport = "ARP"
        frame.arp_op = op
        frame.src_mac = mac_str(data[offset + 8:offset + 14])
        frame.src_ip = ip_str(data[offset + 14:offset + 18])
        frame.dst_mac = mac_str(data[offset + 18:offset + 24])
        frame.dst_ip = ip_str(data[offset + 24:offset + 28])
        return frame

    if ethertype != ETH_P_IP:
        frame.payload = data[offset:]
        return frame

    if len(data) < offset + 20:
        return None
    ver_ihl = data[offset]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack_from("!H", data, offset + 2)[0]
    frag = struct.unpack_from("!H", data, offset + 6)[0]
    proto = data[offset + 9]
    frame.src_ip = ip_str(data[offset + 12:offset + 16])
    frame.dst_ip = ip_str(data[offset + 16:offset + 20])
    ip_end = min(len(data), offset + total_len) if total_len else len(data)
    l4 = offset + ihl
    if frag & 0x1FFF:  # non-first fragment: no L4 header
        frame.transport = f"IP/{proto}"
        return frame

    if proto == 6 and ip_end >= l4 + 20:
        sport, dport = struct.unpack_from("!HH", data, l4)
        data_off = (data[l4 + 12] >> 4) * 4
        frame.transport = "TCP"
        frame.src_port, frame.dst_port = sport, dport
        frame.tcp_flags = data[l4 + 13]
        frame.payload = data[l4 + data_off:ip_end]
    elif proto == 17 and ip_end >= l4 + 8:
        sport, dport = struct.unpack_from("!HH", data, l4)
        frame.transport = "UDP"
        frame.src_port, frame.dst_port = sport, dport
        frame.payload = data[l4 + 8:ip_end]
    elif proto == 1:
        frame.transport = "ICMP"
    else:
        frame.transport = f"IP/{proto}"
    return frame
