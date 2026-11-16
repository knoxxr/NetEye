"""EtherNet/IP encapsulation (TCP/UDP 44818) and CIP explicit messaging."""

from __future__ import annotations

import struct

from backend.dissectors.base import (
    CONFIG, CONTROL, DIAGNOSTIC, DISCOVERY, READ, SESSION, WRITE, Finding,
)

PORT = 44818
IO_PORT = 2222

COMMANDS = {
    0x0004: ("List Services", DISCOVERY),
    0x0063: ("List Identity", DISCOVERY),
    0x0064: ("List Interfaces", DISCOVERY),
    0x0065: ("Register Session", SESSION),
    0x0066: ("Unregister Session", SESSION),
    0x006F: ("SendRRData", ""),
    0x0070: ("SendUnitData", ""),
}

# Common services (0x01-0x1C) are object-independent.
CIP_SERVICES = {
    0x01: ("Get Attributes All", READ),
    0x02: ("Set Attributes All", CONFIG),
    0x03: ("Get Attribute List", READ),
    0x04: ("Set Attribute List", CONFIG),
    0x05: ("Reset", CONTROL),
    0x06: ("Start", CONTROL),
    0x07: ("Stop", CONTROL),
    0x08: ("Create", CONFIG),
    0x09: ("Delete", CONFIG),
    0x0A: ("Multiple Service Packet", ""),
    0x0D: ("Apply Attributes", CONFIG),
    0x0E: ("Get Attribute Single", READ),
    0x10: ("Set Attribute Single", CONFIG),
    0x15: ("Restore", CONFIG),
    0x16: ("Save", CONFIG),
}
# Object-specific services we care about.
CONNECTION_MANAGER = {0x52: ("Unconnected Send", ""), 0x54: ("Forward Open", SESSION),
                      0x5B: ("Large Forward Open", SESSION), 0x4E: ("Forward Close", SESSION)}
LOGIX_SERVICES = {0x4C: ("Read Tag", READ), 0x4D: ("Write Tag", WRITE),
                  0x4E: ("Read Modify Write Tag", WRITE), 0x52: ("Read Tag Fragmented", READ),
                  0x53: ("Write Tag Fragmented", WRITE), 0x55: ("Get Instance Attribute List", READ)}

CIP_CLASSES = {0x01: "Identity", 0x02: "Message Router", 0x04: "Assembly", 0x06: "Connection Manager",
               0x64: "Program", 0x6B: "Symbol", 0x6C: "Template", 0x8E: "Controller", 0xF5: "TCP/IP",
               0xF6: "Ethernet Link"}

VENDORS = {1: "Rockwell Automation/Allen-Bradley"}

DEVICE_TYPES = {
    0x00: "Generic Device", 0x02: "AC Drive", 0x07: "General Purpose Discrete I/O",
    0x0C: "Communications Adapter", 0x0E: "PLC", 0x18: "HMI", 0x2B: "Generic Device",
}


def _parse_identity_item(item: bytes) -> dict[str, str]:
    """CIP Identity item (type 0x0C) as returned by ListIdentity."""
    if len(item) < 33:
        return {}
    vendor, dev_type, product_code = struct.unpack_from("<HHH", item, 18)
    major, minor = item[24], item[25]
    serial = struct.unpack_from("<I", item, 28)[0]
    name_len = item[32]
    name = item[33:33 + name_len].decode("latin-1", "replace").strip()
    ip = ".".join(str(b) for b in item[6:10])
    identity = {
        "vendor": VENDORS.get(vendor, f"CIP Vendor {vendor}"),
        "device_class": DEVICE_TYPES.get(dev_type, f"CIP Device Type 0x{dev_type:02X}"),
        "product_code": str(product_code),
        "firmware": f"{major}.{minor:03d}",
        "serial": f"0x{serial:08X}",
        "model": name,
    }
    if ip != "0.0.0.0":
        identity["_ip"] = ip
    return identity


def _parse_identity_attributes(data: bytes) -> dict[str, str]:
    """Identity object Get_Attributes_All reply; recognised by its self-consistent layout."""
    if len(data) < 15:
        return {}
    name_len = data[14]
    name = data[15:15 + name_len]
    if not name_len or len(name) != name_len or len(data) > 15 + name_len + 16:
        return {}
    if not all(32 <= b < 127 for b in name):
        return {}
    vendor, dev_type, product_code = struct.unpack_from("<HHH", data, 0)
    serial = struct.unpack_from("<I", data, 10)[0]
    return {
        "vendor": VENDORS.get(vendor, f"CIP Vendor {vendor}"),
        "device_class": DEVICE_TYPES.get(dev_type, f"CIP Device Type 0x{dev_type:02X}"),
        "product_code": str(product_code),
        "firmware": f"{data[6]}.{data[7]:03d}",
        "serial": f"0x{serial:08X}",
        "model": name.decode("ascii").strip(),
    }


def _parse_path(path: bytes) -> dict[str, object]:
    result: dict[str, object] = {}
    i = 0
    while i < len(path):
        seg = path[i]
        if seg == 0x20 and i + 1 < len(path):
            result["class"] = path[i + 1]; i += 2
        elif seg == 0x21 and i + 3 < len(path):
            result["class"] = struct.unpack_from("<H", path, i + 2)[0]; i += 4
        elif seg == 0x24 and i + 1 < len(path):
            result["instance"] = path[i + 1]; i += 2
        elif seg == 0x25 and i + 3 < len(path):
            result["instance"] = struct.unpack_from("<H", path, i + 2)[0]; i += 4
        elif seg == 0x30 and i + 1 < len(path):
            result["attribute"] = path[i + 1]; i += 2
        elif seg == 0x91 and i + 1 < len(path):
            n = path[i + 1]
            result["tag"] = path[i + 2:i + 2 + n].decode("latin-1", "replace")
            i += 2 + n + (n % 2)
        else:
            break
    return result


def _cip(message: bytes, to_server: bool, finding: Finding) -> None:
    if not message:
        return
    service = message[0]
    if service & 0x80:  # response
        code = service & 0x7F
        name = (CIP_SERVICES.get(code) or LOGIX_SERVICES.get(code) or CONNECTION_MANAGER.get(code)
                or (f"Service 0x{code:02X}",))[0]
        finding.operation = f"CIP {name} (Response)"
        finding.category = finding.category or READ
        if code == 0x01 and len(message) >= 4 and message[2] == 0:
            identity = _parse_identity_attributes(message[4 + message[3] * 2:])
            if identity:
                finding.identity = identity
                finding.identity_of = "src"
                device_class = identity.get("device_class", "")
                finding.device_hint = ("PLC", 0.95) if device_class == "PLC" else (device_class, 0.9)
        return
    if len(message) < 2:
        return
    path_words = message[1]
    path = _parse_path(message[2:2 + path_words * 2])
    request_data = message[2 + path_words * 2:]
    cls = path.get("class")
    finding.function_code = service
    finding.details["cip_service"] = f"0x{service:02X}"
    if cls is not None:
        finding.details["cip_class"] = CIP_CLASSES.get(cls, f"0x{cls:02X}")
    if "tag" in path:
        finding.details["tag"] = path["tag"]

    if cls == 0x06 and service in CONNECTION_MANAGER:
        name, category = CONNECTION_MANAGER[service]
        if service == 0x52 and len(request_data) >= 4:
            size = struct.unpack_from("<H", request_data, 2)[0]
            _cip(request_data[4:4 + size], to_server, finding)
            return
    elif service in CIP_SERVICES:
        name, category = CIP_SERVICES[service]
    elif service in LOGIX_SERVICES:
        name, category = LOGIX_SERVICES[service]
    else:
        name, category = f"Service 0x{service:02X}", DIAGNOSTIC

    target = CIP_CLASSES.get(cls, "") if isinstance(cls, int) else ""
    finding.operation = f"CIP {name}" + (f" [{target}]" if target else "")
    finding.category = category
    if to_server:
        if service == 0x05 and cls in (0x01, None):
            finding.alert = ("critical", "CIP Identity Reset (장비 재시작) 명령")
        elif service in (0x06, 0x07):
            finding.alert = ("critical", f"CIP {name} 명령" + (f" [{target}]" if target else ""))
        elif cls in (0x64, 0x8E) and category in (CONFIG, WRITE):
            finding.alert = ("high", f"Logix 컨트롤러/프로그램 객체 변경: {name}")
        elif cls == 0xF5 and category == CONFIG:
            finding.alert = ("high", "CIP TCP/IP 설정 변경")


def dissect(payload: bytes, to_server: bool) -> list[Finding]:
    if len(payload) < 24:
        return []
    command, length = struct.unpack_from("<HH", payload, 0)
    status = struct.unpack_from("<I", payload, 8)[0]
    if command not in COMMANDS:
        return []
    name, category = COMMANDS[command]
    finding = Finding(protocol="EtherNet/IP", operation=name, category=category,
                      is_request=to_server, function_code=command,
                      roles={"src": "EtherNet/IP scanner", "dst": "EtherNet/IP adapter"} if to_server
                      else {"src": "EtherNet/IP adapter", "dst": "EtherNet/IP scanner"},
                      device_hint=("Industrial device (CIP)", 0.7),
                      identity_of="src")
    body = payload[24:24 + length]
    if status:
        finding.details["status"] = status

    if command == 0x0063 and not to_server and len(body) >= 6:
        item_type, item_len = struct.unpack_from("<HH", body, 2)
        if item_type == 0x0C:
            identity = _parse_identity_item(body[6:6 + item_len])
            identity.pop("_ip", None)
            finding.identity = identity
            device_class = identity.get("device_class", "")
            if device_class == "PLC":
                finding.device_hint = ("PLC", 0.95)
            elif device_class:
                finding.device_hint = (device_class, 0.9)
    elif command in (0x006F, 0x0070) and len(body) >= 8:
        count = struct.unpack_from("<H", body, 6)[0]
        offset = 8
        for _ in range(count):
            if offset + 4 > len(body):
                break
            item_type, item_len = struct.unpack_from("<HH", body, offset)
            item = body[offset + 4:offset + 4 + item_len]
            offset += 4 + item_len
            if item_type == 0x00B2:
                _cip(item, to_server, finding)
            elif item_type == 0x00B1 and len(item) > 2:
                _cip(item[2:], to_server, finding)
        if not finding.operation:
            finding.operation = name
    return [finding]


def dissect_io(payload: bytes) -> list[Finding]:
    """UDP 2222 implicit (Class 1) I/O: cyclic process data."""
    return [Finding(protocol="EtherNet/IP I/O", operation="Implicit I/O (Class 1)",
                    category="monitor", device_hint=("Industrial device (CIP)", 0.6))]
