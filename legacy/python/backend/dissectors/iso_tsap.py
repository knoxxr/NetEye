"""ISO-on-TCP (TPKT/COTP, TCP 102): Siemens S7comm, S7comm-plus, and MMS (IEC 61850/ICCP)."""

from __future__ import annotations

import struct

from backend.dissectors.base import (
    CONTROL, DIAGNOSTIC, DISCOVERY, MONITOR, PROGRAM, READ, SESSION, WRITE, Finding,
)

PORT = 102

S7_JOB_FUNCTIONS = {
    0x00: ("CPU Services", DIAGNOSTIC),
    0xF0: ("Setup Communication", SESSION),
    0x04: ("Read Var", READ),
    0x05: ("Write Var", WRITE),
    0x1A: ("Request Download", PROGRAM),
    0x1B: ("Download Block", PROGRAM),
    0x1C: ("Download Ended", PROGRAM),
    0x1D: ("Start Upload", PROGRAM),
    0x1E: ("Upload", PROGRAM),
    0x1F: ("End Upload", PROGRAM),
    0x28: ("PI Service", CONTROL),
    0x29: ("PLC Stop", CONTROL),
}

PI_SERVICES = {
    b"P_PROGRAM": ("PLC Start/Restart (P_PROGRAM)", "critical"),
    b"_INSE": ("Activate Block (_INSE)", "critical"),
    b"_DELE": ("Delete Block (_DELE)", "critical"),
    b"_GARB": ("Compress Memory (_GARB)", "high"),
    b"_MODU": ("Copy RAM to ROM (_MODU)", "high"),
}

USERDATA_GROUPS = {
    0: "Mode Transition", 1: "Programmer Commands", 2: "Cyclic Data",
    3: "Block Functions", 4: "CPU Functions", 5: "Security", 7: "Time Functions",
}

S7PLUS_FUNCTIONS = {
    0x04BB: "Explore", 0x04CA: "CreateObject", 0x04D4: "DeleteObject",
    0x04F2: "SetVariable", 0x0524: "GetLink", 0x0542: "SetMultiVariables",
    0x054C: "GetMultiVariables", 0x0556: "BeginSequence", 0x0560: "EndSequence",
    0x056B: "Invoke", 0x0586: "GetVarSubStreamed",
}

COTP_TYPES = {0xE0: "Connect Request", 0xD0: "Connect Confirm", 0x80: "Disconnect Request",
              0xC0: "Disconnect Confirm", 0xF0: "Data"}


def _roles(to_server: bool, client: str, server: str) -> dict[str, str]:
    return {"src": client, "dst": server} if to_server else {"src": server, "dst": client}


def dissect(payload: bytes, to_server: bool) -> list[Finding]:
    findings: list[Finding] = []
    offset = 0
    while offset + 7 <= len(payload) and payload[offset] == 0x03 and payload[offset + 1] == 0x00:
        tpkt_len = struct.unpack_from("!H", payload, offset + 2)[0]
        if tpkt_len < 7:
            break
        segment = payload[offset:offset + tpkt_len]
        offset += tpkt_len
        finding = _dissect_tpkt(segment, to_server)
        if finding:
            findings.append(finding)
    return findings


def _dissect_tpkt(segment: bytes, to_server: bool) -> Finding | None:
    li = segment[4]
    pdu_type = segment[5] & 0xF0
    data = segment[5 + li:]

    if pdu_type in (0xE0, 0xD0):
        finding = Finding(protocol="ISO-TSAP", operation=f"COTP {COTP_TYPES[pdu_type]}",
                          category=SESSION, is_request=pdu_type == 0xE0)
        # Parameters follow LI, type, dst-ref(2), src-ref(2), class(1)
        p = 11
        end = 5 + li
        while p + 2 <= end and p + 2 <= len(segment):
            code, length = segment[p], segment[p + 1]
            value = segment[p + 2:p + 2 + length]
            if code == 0xC2 and len(value) == 2:
                finding.details["dst_tsap"] = value.hex()
                if value[0] in (0x01, 0x02, 0x03):
                    finding.details["rack"] = value[1] >> 5
                    finding.details["slot"] = value[1] & 0x1F
            elif code == 0xC1:
                finding.details["src_tsap"] = value.hex()
            p += 2 + length
        return finding

    if pdu_type != 0xF0 or not data:
        return None

    if data[0] == 0x32:
        return _dissect_s7(data, to_server)
    if data[0] == 0x72:
        return _dissect_s7plus(data, to_server)
    # Anything else on ISO-TSAP is an ISO session (MMS / IEC 61850 / ICCP).
    spdu = {0x0D: "Session Connect", 0x0E: "Session Accept", 0x01: "Data Transfer",
            0x09: "Session Finish", 0x0A: "Session Disconnect", 0x19: "Session Abort"}
    return Finding(
        protocol="MMS (IEC 61850)",
        operation=spdu.get(data[0], f"SPDU 0x{data[0]:02X}"),
        category=SESSION if data[0] != 0x01 else MONITOR,
        is_request=to_server,
        roles=_roles(to_server, "MMS client", "MMS server"),
        device_hint=("IED (IEC 61850)", 0.65),
    )


def _dissect_s7(data: bytes, to_server: bool) -> Finding | None:
    if len(data) < 10:
        return None
    rosctr = data[1]
    param_len, data_len = struct.unpack_from("!HH", data, 6)
    header_len = 12 if rosctr in (2, 3) else 10
    params = data[header_len:header_len + param_len]
    body = data[header_len + param_len:header_len + param_len + data_len]
    # Direction from content: Job / userdata request come from the client.
    # During a download the PLC issues the Download Block/Ended jobs, so those are inverted.
    plc_initiated = bool(params) and params[0] in (0x1B, 0x1C)
    if rosctr == 1:
        to_server = not plc_initiated
    elif rosctr in (2, 3):
        to_server = plc_initiated
    elif rosctr == 7 and len(params) >= 6:
        to_server = (params[5] >> 4) == 0x4  # type nibble: 4 = request, 8 = response

    finding = Finding(protocol="S7comm", is_request=to_server,
                      roles=_roles(to_server, "S7 client", "S7 server"),
                      device_hint=("PLC (Siemens S7)", 0.85),
                      identity_of="dst" if to_server else "src")
    finding.identity["vendor"] = "Siemens"

    if rosctr in (1, 3) and params:
        fc = params[0]
        name, category = S7_JOB_FUNCTIONS.get(fc, (f"Function 0x{fc:02X}", DIAGNOSTIC))
        finding.function_code = fc
        finding.category = category
        if fc == 0x28:
            for marker, (pi_name, severity) in PI_SERVICES.items():
                if marker in params:
                    name = f"PI Service: {pi_name}"
                    if rosctr == 1:
                        finding.alert = (severity, f"S7 PLC {pi_name}")
                    break
        finding.operation = name if rosctr == 1 else f"{name} (Ack)"
        if rosctr == 1 and fc in (0x1B, 0x1C):
            finding.alert = ("critical", f"S7 프로그램 다운로드: {name}")
        elif rosctr == 1:
            if fc == 0x29:
                finding.alert = ("critical", "S7 PLC Stop 명령")
            elif fc in (0x1A, 0x1B, 0x1C):
                finding.alert = ("critical", f"S7 프로그램 다운로드: {name}")
            elif fc in (0x1D, 0x1E, 0x1F):
                finding.alert = ("high", f"S7 프로그램 업로드: {name}")
        return finding

    if rosctr == 7 and len(params) >= 8 and params[0:3] == b"\x00\x01\x12":
        type_group = params[5]
        group = type_group & 0x0F
        is_response = (type_group >> 4) == 0x8
        sub = params[6]
        finding.category = DIAGNOSTIC
        finding.operation = f"Userdata: {USERDATA_GROUPS.get(group, f'Group {group}')}"
        if group == 4 and sub == 0x01:
            finding.operation = "Read SZL"
            finding.category = DISCOVERY
            if len(body) >= 8:
                szl_id, szl_index = struct.unpack_from("!HH", body, 4)
                finding.details["szl_id"] = f"0x{szl_id:04X}"
                if is_response:
                    finding.identity.update(_parse_szl(body))
        elif group == 5:
            finding.operation = "Security: PLC Password"
            finding.category = SESSION
            if not is_response:
                finding.alert = ("medium", "S7 PLC 보호 암호 전송")
        elif group == 3:
            finding.operation = "Block Functions"
            finding.category = DISCOVERY
        return finding

    if rosctr == 2:
        finding.operation = "Ack"
        finding.category = SESSION
        return finding
    return None


def _parse_szl(body: bytes) -> dict[str, str]:
    """Parse SZL 0x0011 (module identification) records for order number and firmware."""
    identity: dict[str, str] = {}
    if len(body) < 12 or body[0] != 0xFF:
        return identity
    szl_id, _index, rec_len, count = struct.unpack_from("!HHHH", body, 4)
    if (szl_id & 0x00FF) != 0x11 or rec_len < 28:
        return identity
    offset = 12
    for _ in range(count):
        record = body[offset:offset + rec_len]
        offset += rec_len
        if len(record) < 28:
            break
        index = struct.unpack_from("!H", record, 0)[0]
        mlfb = record[2:22].decode("latin-1", "replace").strip(" \x00")
        ausbg, ausbe = struct.unpack_from("!HH", record, 24)
        if index == 0x0001 and mlfb:
            identity["model"] = mlfb
        elif index == 0x0007 and (ausbg >> 8) == ord("V"):
            identity["firmware"] = f"V{ausbg & 0xFF}.{ausbe >> 8}.{ausbe & 0xFF}"
    return identity


def _dissect_s7plus(data: bytes, to_server: bool) -> Finding:
    version = data[1] if len(data) > 1 else 0
    if version in (1, 2) and len(data) > 4 and data[4] in (0x31, 0x32):
        to_server = data[4] == 0x31
    finding = Finding(protocol="S7comm-plus", is_request=to_server, category=SESSION,
                      roles=_roles(to_server, "S7 client", "S7 server"),
                      device_hint=("PLC (Siemens S7-1200/1500)", 0.85),
                      identity_of="dst" if to_server else "src",
                      details={"version": version})
    finding.identity["vendor"] = "Siemens"
    finding.operation = f"S7comm-plus V{version}"
    # V1/V2 carry an unencrypted opcode/function right after the 4-byte header.
    if version in (1, 2) and len(data) >= 9:
        opcode = data[4]
        function = struct.unpack_from("!H", data, 7)[0]
        if opcode in (0x31, 0x32):
            name = S7PLUS_FUNCTIONS.get(function, f"0x{function:04X}")
            finding.operation = f"{'Request' if opcode == 0x31 else 'Response'}: {name}"
            finding.function_code = function
            if name in ("SetVariable", "SetMultiVariables"):
                finding.category = WRITE
            elif name in ("GetMultiVariables", "GetVarSubStreamed"):
                finding.category = READ
            elif name in ("CreateObject", "DeleteObject"):
                finding.category = SESSION
    return finding
