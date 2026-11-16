"""Modbus/TCP (MBAP) including MEI device identification and Schneider UMAS."""

from __future__ import annotations

import struct

from backend.dissectors.base import (
    COMMAND, CONFIG, CONTROL, DIAGNOSTIC, DISCOVERY, PROGRAM, READ, WRITE, Finding,
)

PORT = 502

FUNCTIONS = {
    1: ("Read Coils", READ),
    2: ("Read Discrete Inputs", READ),
    3: ("Read Holding Registers", READ),
    4: ("Read Input Registers", READ),
    5: ("Write Single Coil", COMMAND),
    6: ("Write Single Register", WRITE),
    7: ("Read Exception Status", DIAGNOSTIC),
    8: ("Diagnostics", DIAGNOSTIC),
    11: ("Get Comm Event Counter", DIAGNOSTIC),
    12: ("Get Comm Event Log", DIAGNOSTIC),
    15: ("Write Multiple Coils", COMMAND),
    16: ("Write Multiple Registers", WRITE),
    17: ("Report Server ID", DISCOVERY),
    20: ("Read File Record", READ),
    21: ("Write File Record", WRITE),
    22: ("Mask Write Register", WRITE),
    23: ("Read/Write Multiple Registers", WRITE),
    24: ("Read FIFO Queue", READ),
    43: ("Encapsulated Interface Transport", DISCOVERY),
    90: ("Schneider UMAS", DIAGNOSTIC),
}

DIAG_SUBFUNCTIONS = {
    0x0001: ("Restart Communications Option", CONTROL, "high"),
    0x0004: ("Force Listen Only Mode", CONTROL, "high"),
    0x000A: ("Clear Counters and Diagnostic Register", CONFIG, "medium"),
}

UMAS_FUNCTIONS = {
    0x01: ("UMAS Init Comm", "session"),
    0x02: ("UMAS Read ID", DISCOVERY),
    0x03: ("UMAS Read Project Info", DISCOVERY),
    0x04: ("UMAS Read PLC Info", DISCOVERY),
    0x10: ("UMAS Take PLC Reservation", "session"),
    0x11: ("UMAS Release PLC Reservation", "session"),
    0x12: ("UMAS Keep Alive", "session"),
    0x20: ("UMAS Read Memory Block", READ),
    0x22: ("UMAS Read Variables", READ),
    0x23: ("UMAS Write Variables", WRITE),
    0x30: ("UMAS Initialize Download", PROGRAM),
    0x31: ("UMAS Download Block", PROGRAM),
    0x32: ("UMAS End Download", PROGRAM),
    0x33: ("UMAS Initialize Upload", PROGRAM),
    0x34: ("UMAS Upload Block", PROGRAM),
    0x35: ("UMAS End Upload", PROGRAM),
    0x40: ("UMAS Start PLC", CONTROL),
    0x41: ("UMAS Stop PLC", CONTROL),
}

MEI_OBJECTS = {0: "vendor", 1: "product_code", 2: "firmware", 4: "product_name", 5: "model"}

EXCEPTIONS = {
    1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value",
    4: "Server Device Failure", 6: "Server Device Busy", 0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Failed to Respond",
}


def _parse_mei_identity(pdu: bytes) -> dict[str, str]:
    # pdu: fc(43) mei(0x0E) code conformity more next count {id len value}*
    identity: dict[str, str] = {}
    if len(pdu) < 7:
        return identity
    count = pdu[6]
    offset = 7
    for _ in range(count):
        if offset + 2 > len(pdu):
            break
        obj_id, length = pdu[offset], pdu[offset + 1]
        value = pdu[offset + 2:offset + 2 + length].decode("latin-1", "replace").strip()
        offset += 2 + length
        key = MEI_OBJECTS.get(obj_id)
        if key and value:
            identity[key] = value
    return identity


def dissect(payload: bytes, to_server: bool) -> list[Finding]:
    findings: list[Finding] = []
    offset = 0
    # A TCP segment may carry several pipelined ADUs.
    while offset + 8 <= len(payload):
        _tid, proto_id, length = struct.unpack_from("!HHH", payload, offset)
        if proto_id != 0 or length < 2 or length > 254:
            break
        unit = payload[offset + 6]
        pdu = payload[offset + 7:offset + 6 + length]
        offset += 6 + length
        if not pdu:
            break
        findings.append(_dissect_pdu(pdu, unit, to_server))
    return findings


def _dissect_pdu(pdu: bytes, unit: int, to_server: bool) -> Finding:
    fc = pdu[0]
    roles = {"src": "Modbus client", "dst": "Modbus server"} if to_server else \
            {"src": "Modbus server", "dst": "Modbus client"}
    finding = Finding(protocol="Modbus/TCP", is_request=to_server, function_code=fc & 0x7F,
                      roles=roles, device_hint=("PLC", 0.75), details={"unit_id": unit})

    if not to_server and fc & 0x80:
        name = FUNCTIONS.get(fc & 0x7F, (f"Function {fc & 0x7F}", ""))[0]
        code = pdu[1] if len(pdu) > 1 else 0
        finding.operation = f"Exception: {name} ({EXCEPTIONS.get(code, code)})"
        finding.category = DIAGNOSTIC
        finding.details["exception"] = code
        return finding

    name, category = FUNCTIONS.get(fc, (f"Function {fc}", ""))
    finding.operation, finding.category = name, category

    if fc == 8 and len(pdu) >= 3:
        sub = struct.unpack_from("!H", pdu, 1)[0]
        if sub in DIAG_SUBFUNCTIONS:
            sub_name, sub_category, severity = DIAG_SUBFUNCTIONS[sub]
            finding.operation, finding.category = f"Diagnostics: {sub_name}", sub_category
            if to_server:
                finding.alert = (severity, f"Modbus 진단 명령: {sub_name}")
    elif fc == 43 and len(pdu) >= 2 and pdu[1] == 0x0E:
        finding.operation = "Read Device Identification"
        if not to_server:
            finding.identity = _parse_mei_identity(pdu)
            finding.identity_of = "src"
    elif fc == 90 and len(pdu) >= 3:
        umas_name, umas_category = UMAS_FUNCTIONS.get(pdu[2], (f"UMAS 0x{pdu[2]:02X}", DIAGNOSTIC))
        finding.protocol = "Modbus/UMAS"
        finding.operation, finding.category = umas_name, umas_category
        finding.details["umas_function"] = pdu[2]
        if to_server and umas_category == CONTROL:
            finding.alert = ("critical", f"Schneider PLC 운전 상태 변경: {umas_name}")
        elif to_server and pdu[2] in (0x30, 0x31, 0x32):
            finding.alert = ("critical", f"Schneider PLC 프로그램 다운로드: {umas_name}")
        elif to_server and pdu[2] in (0x33, 0x34, 0x35):
            finding.alert = ("high", f"Schneider PLC 프로그램 업로드: {umas_name}")
    elif to_server and len(pdu) >= 3 and fc in (5, 6, 15, 16, 22, 23):
        finding.details["address"] = struct.unpack_from("!H", pdu, 1)[0]
    return finding
