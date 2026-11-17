"""Mitsubishi SLMP/MC, CC-Link IE Field Basic, OPC UA, BACnet and port-only signatures."""

from __future__ import annotations

import struct

from backend.dissectors.base import (
    CONFIG, CONTROL, DISCOVERY, MONITOR, READ, SESSION, WRITE, Finding,
)

SLMP_COMMANDS = {
    0x0401: ("Batch Read", READ), 0x1401: ("Batch Write", WRITE),
    0x0403: ("Random Read", READ), 0x1402: ("Random Write", WRITE),
    0x0406: ("Multiple Block Batch Read", READ), 0x1406: ("Multiple Block Batch Write", WRITE),
    0x0101: ("Read CPU Model", DISCOVERY),
    0x1001: ("Remote RUN", CONTROL), 0x1002: ("Remote STOP", CONTROL),
    0x1003: ("Remote PAUSE", CONTROL), 0x1005: ("Remote Latch Clear", CONTROL),
    0x1006: ("Remote RESET", CONTROL), 0x1630: ("Remote Password Unlock", SESSION),
    0x1631: ("Remote Password Lock", SESSION),
}
SLMP_ALERTS = {0x1001: "critical", 0x1002: "critical", 0x1003: "critical",
               0x1005: "critical", 0x1006: "critical", 0x1630: "medium"}


def dissect_slmp(payload: bytes, to_server: bool) -> list[Finding]:
    """SLMP / MC protocol 3E binary frame, detected by content on any port."""
    if len(payload) < 11 or payload[0:2] not in (b"\x50\x00", b"\xd0\x00"):
        return []
    if payload[3] != 0xFF or struct.unpack_from("<H", payload, 4)[0] != 0x03FF:
        return []
    data_len = struct.unpack_from("<H", payload, 7)[0]
    if 9 + data_len != len(payload):
        return []
    is_request = payload[0] == 0x50
    finding = Finding(protocol="Mitsubishi SLMP/MC", is_request=is_request,
                      roles={"src": "SLMP client", "dst": "SLMP server (MELSEC)"} if is_request
                      else {"src": "SLMP server (MELSEC)", "dst": "SLMP client"},
                      device_hint=("PLC (Mitsubishi MELSEC)", 0.85),
                      identity_of="dst" if is_request else "src",
                      identity={"vendor": "Mitsubishi Electric"})
    if is_request and len(payload) >= 15:
        command, sub = struct.unpack_from("<HH", payload, 11)
        name, category = SLMP_COMMANDS.get(command, (f"Command 0x{command:04X}", MONITOR))
        finding.function_code = command
        finding.operation, finding.category = name, category
        finding.details["subcommand"] = f"0x{sub:04X}"
        if command in SLMP_ALERTS:
            finding.alert = (SLMP_ALERTS[command], f"MELSEC PLC {name} 명령")
    else:
        end_code = struct.unpack_from("<H", payload, 9)[0]
        finding.operation = "Response" if end_code == 0 else f"Error Response 0x{end_code:04X}"
        finding.category = MONITOR
        body = payload[11:]
        # Read CPU Model response: 16-byte ASCII model + 2-byte model code.
        if end_code == 0 and len(body) == 18 and all(32 <= b < 127 for b in body[:16].rstrip(b" \x00")):
            model = body[:16].decode("ascii").strip(" \x00")
            if model:
                finding.identity["model"] = model
                finding.operation = "Read CPU Model (Response)"
    return [finding]


def dissect_opcua(payload: bytes, to_server: bool) -> list[Finding]:
    if len(payload) < 8 or payload[0:3] not in (b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR"):
        return []
    if payload[3:4] not in (b"F", b"C", b"A"):
        return []
    kind = payload[0:3].decode()
    names = {"HEL": "Hello", "ACK": "Acknowledge", "OPN": "Open Secure Channel",
             "MSG": "Message", "CLO": "Close Secure Channel", "ERR": "Error"}
    finding = Finding(protocol="OPC UA", operation=names[kind],
                      category=MONITOR if kind == "MSG" else SESSION, is_request=to_server,
                      roles={"src": "OPC UA client", "dst": "OPC UA server"} if to_server
                      else {"src": "OPC UA server", "dst": "OPC UA client"},
                      device_hint=("OT server/gateway (OPC UA)", 0.7))
    if kind == "OPN" and len(payload) > 16:
        uri_len = struct.unpack_from("<i", payload, 12)[0]
        if 0 < uri_len < 200:
            policy = payload[16:16 + uri_len].decode("latin-1", "replace")
            finding.details["security_policy"] = policy.rsplit("#", 1)[-1]
            if policy.endswith("#None"):
                finding.alert = ("low", "OPC UA 보안 정책 None(암호화 없음) 사용")
    return [finding]


def dissect_bacnet(payload: bytes, to_server: bool) -> list[Finding]:
    if len(payload) < 4 or payload[0] != 0x81:
        return []
    return [Finding(protocol="BACnet/IP", operation="BVLC", category=MONITOR,
                    device_hint=("Building automation device", 0.7))]


def port_only(protocol: str, hint: str, confidence: float = 0.55):
    def _dissect(payload: bytes, to_server: bool) -> list[Finding]:
        return [Finding(protocol=protocol, operation=protocol, category=MONITOR, is_request=to_server,
                        device_hint=(hint, confidence))]
    return _dissect


# (transport, port) -> dissector for port-only signatures.
PORT_SIGNATURES = {
    ("UDP", 61450): port_only("CC-Link IE Field Basic", "CC-Link IE Field Basic station", 0.7),
    ("UDP", 61451): port_only("CC-Link IE Field Basic", "CC-Link IE Field Basic station", 0.7),
    ("UDP", 9600): port_only("Omron FINS", "PLC (Omron)", 0.7),
    ("TCP", 9600): port_only("Omron FINS", "PLC (Omron)", 0.7),
    ("TCP", 5094): port_only("HART-IP", "HART-IP gateway", 0.65),
    ("UDP", 5094): port_only("HART-IP", "HART-IP gateway", 0.65),
    ("TCP", 1217): port_only("CODESYS", "PLC (CODESYS runtime)", 0.6),
    ("TCP", 2455): port_only("CODESYS", "PLC (CODESYS runtime)", 0.6),
    ("TCP", 18245): port_only("GE SRTP", "PLC (GE)", 0.65),
    ("TCP", 1962): port_only("PCWorx", "PLC (Phoenix Contact)", 0.65),
    ("TCP", 20547): port_only("ProConOS", "PLC (ProConOS)", 0.6),
    ("UDP", 34964): port_only("PROFINET CM", "PROFINET device", 0.6),
    ("TCP", 1911): port_only("Niagara Fox", "Building automation controller", 0.6),
    ("TCP", 4911): port_only("Niagara Fox (TLS)", "Building automation controller", 0.6),
}
