"""Layer-2 industrial protocols: IEC 61850 GOOSE/SV, PROFINET (DCP/RT), CC-Link IE, LLDP."""

from __future__ import annotations

import struct

from backend.dissectors.base import CONFIG, CONTROL, DISCOVERY, MONITOR, Finding

ETH_GOOSE = 0x88B8
ETH_SV = 0x88BA
ETH_PROFINET = 0x8892
ETH_CCLINK_IE = 0x890F
ETH_LLDP = 0x88CC
ETH_ETHERCAT = 0x88A4
ETH_POWERLINK = 0x88AB

PROFINET_VENDORS = {0x002A: "Siemens", 0x0019: "Phoenix Contact", 0x011E: "Mitsubishi Electric"}


def _ber_items(data: bytes):
    i = 0
    while i + 2 <= len(data):
        tag = data[i]
        length = data[i + 1]
        i += 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        yield tag, data[i:i + length]
        i += length


def dissect_goose(payload: bytes) -> list[Finding]:
    finding = Finding(protocol="IEC 61850 GOOSE", operation="GOOSE Publish", category=MONITOR,
                      roles={"src": "GOOSE publisher"}, device_hint=("IED (IEC 61850)", 0.85))
    if len(payload) < 10:
        return [finding]
    appid = struct.unpack_from("!H", payload, 0)[0]
    finding.details["appid"] = f"0x{appid:04X}"
    for tag, value in _ber_items(payload[8:]):
        if tag != 0x61:
            continue
        for inner_tag, inner in _ber_items(value):
            if inner_tag == 0x80:
                finding.details["gocbRef"] = inner.decode("latin-1", "replace")
            elif inner_tag == 0x83:
                finding.details["goID"] = inner.decode("latin-1", "replace")
            elif inner_tag == 0x85:
                finding.details["stNum"] = int.from_bytes(inner, "big")
            elif inner_tag == 0x86:
                finding.details["sqNum"] = int.from_bytes(inner, "big")
            elif inner_tag == 0x87 and inner and inner[0]:
                finding.details["simulation"] = True
                finding.alert = ("medium", "GOOSE 시뮬레이션/테스트 플래그가 설정된 메시지")
            elif inner_tag == 0x88:
                finding.details["confRev"] = int.from_bytes(inner, "big")
    if "gocbRef" in finding.details:
        # IED name is the logical-device prefix of the control block reference.
        finding.identity = {"name": finding.details["gocbRef"].split("/")[0]}
    return [finding]


def dissect_sv(payload: bytes) -> list[Finding]:
    appid = struct.unpack_from("!H", payload, 0)[0] if len(payload) >= 2 else 0
    return [Finding(protocol="IEC 61850 Sampled Values", operation="SV Publish", category=MONITOR,
                    roles={"src": "SV publisher (Merging Unit)"},
                    device_hint=("Merging Unit (IEC 61850-9-2)", 0.85),
                    details={"appid": f"0x{appid:04X}"})]


DCP_SERVICES = {3: "Get", 4: "Set", 5: "Identify", 6: "Hello"}


def dissect_profinet(payload: bytes) -> list[Finding]:
    if len(payload) < 2:
        return []
    frame_id = struct.unpack_from("!H", payload, 0)[0]
    if 0x8000 <= frame_id <= 0xBFFF or 0xC000 <= frame_id <= 0xFBFF:
        return [Finding(protocol="PROFINET RT", operation="Cyclic I/O", category=MONITOR,
                        device_hint=("PROFINET device", 0.6))]
    if frame_id in (0xFC01, 0xFE01):
        return [Finding(protocol="PROFINET RT", operation="Alarm", category=MONITOR)]
    if not 0xFEFC <= frame_id <= 0xFEFF or len(payload) < 12:
        return [Finding(protocol="PROFINET", operation=f"Frame 0x{frame_id:04X}", category=MONITOR)]

    service_id, service_type = payload[2], payload[3]
    data_len = struct.unpack_from("!H", payload, 10)[0]
    is_response = service_type & 0x01 == 1
    service = DCP_SERVICES.get(service_id, f"Service {service_id}")
    finding = Finding(protocol="PROFINET DCP", category=DISCOVERY, is_request=not is_response,
                      operation=f"DCP {service} {'Response' if is_response else 'Request'}")
    blocks = payload[12:12 + data_len]
    i = 0
    set_targets: list[str] = []
    while i + 4 <= len(blocks):
        option, sub = blocks[i], blocks[i + 1]
        blen = struct.unpack_from("!H", blocks, i + 2)[0]
        value = blocks[i + 4:i + 4 + blen]
        i += 4 + blen + (blen % 2)
        if is_response or service_id == 6:
            value = value[2:]  # BlockInfo
        elif service_id == 4:
            value = value[2:]  # BlockQualifier
        if service_id == 4 and not is_response:
            set_targets.append({(1, 2): "IP 주소", (2, 2): "Station Name", (5, 3): "LED 점멸(Signal)",
                                (5, 4): "Response Delay", (5, 6): "공장 초기화(Reset to Factory)"}
                               .get((option, sub), f"Option {option}.{sub}"))
            continue
        if option == 2 and sub == 1:
            finding.identity["model"] = value.decode("latin-1", "replace").strip(" \x00")
        elif option == 2 and sub == 2:
            finding.identity["name"] = value.decode("latin-1", "replace").strip(" \x00")
        elif option == 2 and sub == 3 and len(value) >= 4:
            vendor_id, device_id = struct.unpack_from("!HH", value, 0)
            finding.identity["vendor"] = PROFINET_VENDORS.get(vendor_id, f"PROFINET Vendor 0x{vendor_id:04X}")
            finding.details["device_id"] = f"0x{device_id:04X}"
        elif option == 1 and sub == 2 and len(value) >= 12:
            ip = ".".join(str(b) for b in value[0:4])
            if ip != "0.0.0.0":
                finding.announced_ip = ip
    if is_response and finding.identity:
        finding.roles = {"src": "PROFINET device"}
        finding.device_hint = ("PROFINET device", 0.85)
        model = finding.identity.get("model", "")
        if any(token in model.upper() for token in ("S7-", "CPU", "PLC")):
            finding.device_hint = ("PLC (PROFINET)", 0.9)
    if service_id == 4 and not is_response:
        finding.category = CONFIG
        finding.operation = "DCP Set: " + ", ".join(set_targets or ["unknown"])
        severity = "critical" if any("초기화" in t for t in set_targets) else "high"
        finding.alert = (severity, f"PROFINET DCP 설정 변경: {', '.join(set_targets)}")
        finding.identity_of = "dst"
    return [finding]


def dissect_cclink_ie(payload: bytes) -> list[Finding]:
    return [Finding(protocol="CC-Link IE", operation="CC-Link IE frame", category=MONITOR,
                    roles={"src": "CC-Link IE station"},
                    device_hint=("CC-Link IE station (Mitsubishi ecosystem)", 0.6))]


def dissect_simple_l2(name: str, hint: str):
    def _dissect(payload: bytes) -> list[Finding]:
        return [Finding(protocol=name, operation=f"{name} frame", category=MONITOR,
                        roles={"src": f"{name} node"}, device_hint=(hint, 0.55))]
    return _dissect


def dissect_lldp(payload: bytes) -> list[Finding]:
    finding = Finding(protocol="LLDP", operation="LLDP Advertisement", category=DISCOVERY)
    i = 0
    while i + 2 <= len(payload):
        header = struct.unpack_from("!H", payload, i)[0]
        tlv_type, length = header >> 9, header & 0x01FF
        value = payload[i + 2:i + 2 + length]
        i += 2 + length
        if tlv_type == 0:
            break
        if tlv_type == 5:
            finding.identity["name"] = value.decode("utf-8", "replace").strip()
        elif tlv_type == 6:
            finding.identity["description"] = value.decode("utf-8", "replace").strip()[:200]
        elif tlv_type == 4:
            finding.details["port"] = value.decode("utf-8", "replace").strip()
        elif tlv_type == 8 and len(value) >= 6 and value[1] == 1 and value[0] == 5:
            finding.announced_ip = ".".join(str(b) for b in value[2:6])
    return [finding]


ETHERTYPE_DISSECTORS = {
    ETH_GOOSE: dissect_goose,
    ETH_SV: dissect_sv,
    ETH_PROFINET: dissect_profinet,
    ETH_CCLINK_IE: dissect_cclink_ie,
    ETH_LLDP: dissect_lldp,
    ETH_ETHERCAT: dissect_simple_l2("EtherCAT", "EtherCAT device"),
    ETH_POWERLINK: dissect_simple_l2("POWERLINK", "POWERLINK device"),
}
