"""Utility protocols: DNP3 (TCP/UDP 20000) and IEC 60870-5-104 (TCP 2404)."""

from __future__ import annotations

import struct

from backend.dissectors.base import (
    COMMAND, CONFIG, CONTROL, DIAGNOSTIC, MONITOR, PROGRAM, READ, SESSION, WRITE, Finding,
)

DNP3_PORT = 20000
IEC104_PORT = 2404

DNP3_FUNCTIONS = {
    0: ("Confirm", SESSION), 1: ("Read", READ), 2: ("Write", WRITE),
    3: ("Select", COMMAND), 4: ("Operate", COMMAND), 5: ("Direct Operate", COMMAND),
    6: ("Direct Operate No Ack", COMMAND), 7: ("Immediate Freeze", COMMAND),
    8: ("Immediate Freeze No Ack", COMMAND), 9: ("Freeze Clear", COMMAND),
    10: ("Freeze Clear No Ack", COMMAND), 13: ("Cold Restart", CONTROL),
    14: ("Warm Restart", CONTROL), 15: ("Initialize Data", CONTROL),
    16: ("Initialize Application", CONTROL), 17: ("Start Application", CONTROL),
    18: ("Stop Application", CONTROL), 19: ("Save Configuration", CONFIG),
    20: ("Enable Unsolicited", CONFIG), 21: ("Disable Unsolicited", CONFIG),
    22: ("Assign Class", CONFIG), 23: ("Delay Measurement", SESSION),
    24: ("Record Current Time", SESSION), 25: ("Open File", PROGRAM),
    26: ("Close File", PROGRAM), 27: ("Delete File", PROGRAM),
    28: ("Get File Info", READ), 29: ("Authenticate File", PROGRAM),
    30: ("Abort File", PROGRAM), 129: ("Response", MONITOR),
    130: ("Unsolicited Response", MONITOR), 131: ("Authentication Response", SESSION),
}
DNP3_ALERTS = {
    13: "critical", 14: "critical", 15: "high", 16: "high", 17: "high", 18: "critical",
    19: "high", 21: "medium", 27: "high", 25: "medium",
}

IEC104_U = {0x07: "STARTDT act", 0x0B: "STARTDT con", 0x13: "STOPDT act",
            0x23: "STOPDT con", 0x43: "TESTFR act", 0x83: "TESTFR con"}

IEC104_TYPES = {
    1: "M_SP_NA_1 Single-point", 3: "M_DP_NA_1 Double-point", 5: "M_ST_NA_1 Step position",
    7: "M_BO_NA_1 Bitstring", 9: "M_ME_NA_1 Measured normalized", 11: "M_ME_NB_1 Measured scaled",
    13: "M_ME_NC_1 Measured float", 15: "M_IT_NA_1 Integrated totals", 30: "M_SP_TB_1 Single-point w/time",
    31: "M_DP_TB_1 Double-point w/time", 36: "M_ME_TF_1 Measured float w/time",
    45: "C_SC_NA_1 Single command", 46: "C_DC_NA_1 Double command", 47: "C_RC_NA_1 Regulating step",
    48: "C_SE_NA_1 Setpoint normalized", 49: "C_SE_NB_1 Setpoint scaled", 50: "C_SE_NC_1 Setpoint float",
    51: "C_BO_NA_1 Bitstring command", 58: "C_SC_TA_1 Single command w/time",
    59: "C_DC_TA_1 Double command w/time", 60: "C_RC_TA_1 Regulating step w/time",
    61: "C_SE_TA_1 Setpoint normalized w/time", 62: "C_SE_TB_1 Setpoint scaled w/time",
    63: "C_SE_TC_1 Setpoint float w/time", 64: "C_BO_TA_1 Bitstring w/time",
    70: "M_EI_NA_1 End of initialization", 100: "C_IC_NA_1 Interrogation",
    101: "C_CI_NA_1 Counter interrogation", 102: "C_RD_NA_1 Read", 103: "C_CS_NA_1 Clock sync",
    104: "C_TS_NA_1 Test", 105: "C_RP_NA_1 Reset process", 107: "C_TS_TA_1 Test w/time",
    110: "P_ME_NA_1 Parameter normalized", 111: "P_ME_NB_1 Parameter scaled",
    112: "P_ME_NC_1 Parameter float", 113: "P_AC_NA_1 Parameter activation",
    120: "F_FR_NA_1 File ready", 122: "F_SC_NA_1 Call directory/select file",
}

COT_NAMES = {1: "periodic", 2: "background", 3: "spontaneous", 4: "initialized", 5: "request",
             6: "activation", 7: "activation con", 8: "deactivation", 9: "deactivation con",
             10: "activation termination", 20: "interrogated", 44: "unknown type",
             45: "unknown cause", 46: "unknown ASDU address", 47: "unknown IOA"}


def dissect_dnp3(payload: bytes, to_server: bool) -> list[Finding]:
    if len(payload) < 13 or payload[0:2] != b"\x05\x64":
        return []
    length, control = payload[2], payload[3]
    dest, src = struct.unpack_from("<HH", payload, 4)
    primary = bool(control & 0x40)
    master = bool(control & 0x80)  # DIR bit: 1 = from master
    finding = Finding(protocol="DNP3", is_request=master,
                      roles={"src": "DNP3 master", "dst": "DNP3 outstation"} if master
                      else {"src": "DNP3 outstation", "dst": "DNP3 master"},
                      device_hint=("RTU/IED (DNP3 outstation)", 0.8),
                      details={"dnp3_src": src, "dnp3_dst": dest})
    link_fc = control & 0x0F
    if not (primary and link_fc in (3, 4)) or length < 8:
        finding.operation = "Link Layer"
        finding.category = SESSION
        return [finding]
    # First user-data block starts at 10: transport(1), app control(1), app fc(1)
    app_fc = payload[12]
    name, category = DNP3_FUNCTIONS.get(app_fc, (f"Function {app_fc}", DIAGNOSTIC))
    finding.function_code = app_fc
    finding.operation, finding.category = name, category
    if app_fc >= 129 and len(payload) >= 15:
        iin = struct.unpack_from(">H", payload, 13)[0]
        finding.details["iin"] = f"0x{iin:04X}"
    if master and app_fc in DNP3_ALERTS:
        finding.alert = (DNP3_ALERTS[app_fc], f"DNP3 {name} 명령")
    return [finding]


def dissect_iec104(payload: bytes, to_server: bool) -> list[Finding]:
    findings: list[Finding] = []
    offset = 0
    while offset + 6 <= len(payload) and payload[offset] == 0x68:
        apdu_len = payload[offset + 1]
        apdu = payload[offset + 2:offset + 2 + apdu_len]
        offset += 2 + apdu_len
        if len(apdu) < 4:
            break
        finding = Finding(protocol="IEC 60870-5-104", is_request=to_server,
                          roles={"src": "IEC 104 controlling station", "dst": "IEC 104 controlled station"}
                          if to_server else
                          {"src": "IEC 104 controlled station", "dst": "IEC 104 controlling station"},
                          device_hint=("RTU/IED (IEC 104)", 0.8))
        c1 = apdu[0]
        if c1 & 0x01 == 0:  # I-format
            if len(apdu) < 10:
                findings.append(finding)
                continue
            type_id, cot = apdu[4], apdu[6] & 0x3F
            negative, test = bool(apdu[6] & 0x40), bool(apdu[6] & 0x80)
            common_addr = struct.unpack_from("<H", apdu, 8)[0]
            name = IEC104_TYPES.get(type_id, f"Type {type_id}")
            finding.function_code = type_id
            finding.operation = f"{name} ({COT_NAMES.get(cot, f'cot {cot}')})"
            finding.details.update({"asdu": common_addr, "cot": cot})
            if negative:
                finding.details["negative"] = True
            if test:
                finding.details["test"] = True
            if 45 <= type_id <= 69:
                finding.category = COMMAND
                if cot == 6:
                    finding.alert = ("high", f"IEC 104 원격 제어 명령: {name}")
            elif type_id == 105:
                finding.category = CONTROL
                if cot == 6:
                    finding.alert = ("critical", "IEC 104 Reset Process 명령")
            elif 110 <= type_id <= 113:
                finding.category = CONFIG
                if cot == 6:
                    finding.alert = ("medium", f"IEC 104 파라미터 변경: {name}")
            elif type_id in (100, 101, 102):
                finding.category = READ
            elif type_id in (103, 104, 107):
                finding.category = SESSION
            elif type_id >= 120:
                finding.category = PROGRAM
            else:
                finding.category = MONITOR
        elif c1 & 0x03 == 0x01:
            finding.operation, finding.category = "S-format (ack)", SESSION
        else:
            finding.operation = IEC104_U.get(c1, f"U-format 0x{c1:02X}")
            finding.category = SESSION
        findings.append(finding)
    return findings
