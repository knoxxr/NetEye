//! Utility protocols: DNP3 (TCP/UDP 20000) and IEC 60870-5-104 (TCP 2404).

use super::base::*;
use crate::decode::{be16, le16};
use std::borrow::Cow;

pub const DNP3_PORT: u16 = 20000;
pub const IEC104_PORT: u16 = 2404;

fn dnp3_function(fc: u8) -> Option<(&'static str, &'static str)> {
    Some(match fc {
        0 => ("Confirm", SESSION), 1 => ("Read", READ), 2 => ("Write", WRITE),
        3 => ("Select", COMMAND), 4 => ("Operate", COMMAND), 5 => ("Direct Operate", COMMAND),
        6 => ("Direct Operate No Ack", COMMAND), 7 => ("Immediate Freeze", COMMAND),
        8 => ("Immediate Freeze No Ack", COMMAND), 9 => ("Freeze Clear", COMMAND),
        10 => ("Freeze Clear No Ack", COMMAND), 13 => ("Cold Restart", CONTROL),
        14 => ("Warm Restart", CONTROL), 15 => ("Initialize Data", CONTROL),
        16 => ("Initialize Application", CONTROL), 17 => ("Start Application", CONTROL),
        18 => ("Stop Application", CONTROL), 19 => ("Save Configuration", CONFIG),
        20 => ("Enable Unsolicited", CONFIG), 21 => ("Disable Unsolicited", CONFIG),
        22 => ("Assign Class", CONFIG), 23 => ("Delay Measurement", SESSION),
        24 => ("Record Current Time", SESSION), 25 => ("Open File", PROGRAM),
        26 => ("Close File", PROGRAM), 27 => ("Delete File", PROGRAM),
        28 => ("Get File Info", READ), 29 => ("Authenticate File", PROGRAM),
        30 => ("Abort File", PROGRAM), 129 => ("Response", MONITOR),
        130 => ("Unsolicited Response", MONITOR), 131 => ("Authentication Response", SESSION),
        _ => return None,
    })
}

fn dnp3_alert(fc: u8) -> Option<&'static str> {
    Some(match fc {
        13 | 14 | 18 => "critical",
        15 | 16 | 17 | 19 | 27 => "high",
        21 | 25 => "medium",
        _ => return None,
    })
}

pub fn dissect_dnp3(payload: &[u8], _to_server: bool, out: &mut Vec<Finding>) {
    if payload.len() < 13 || payload[0..2] != [0x05, 0x64] {
        return;
    }
    let (length, control) = (payload[2], payload[3]);
    let dest = le16(payload, 4).unwrap_or(0);
    let src = le16(payload, 6).unwrap_or(0);
    let primary = control & 0x40 != 0;
    let master = control & 0x80 != 0; // DIR bit: 1 = from master
    let mut f = Finding::new("DNP3")
        .req(Some(master))
        .roles(master, "DNP3 master", "DNP3 outstation")
        .hint("RTU/IED (DNP3 outstation)", 0.8);
    f.detail("dnp3_src", Detail::Int(src as i64));
    f.detail("dnp3_dst", Detail::Int(dest as i64));
    let link_fc = control & 0x0F;
    if !(primary && matches!(link_fc, 3 | 4)) || length < 8 {
        f.operation = "Link Layer".into();
        f.category = SESSION;
        out.push(f);
        return;
    }
    let app_fc = payload[12];
    let (name, category): (Str, &str) = match dnp3_function(app_fc) {
        Some((n, c)) => (n.into(), c),
        None => (format!("Function {app_fc}").into(), DIAGNOSTIC),
    };
    f.function_code = Some(app_fc as u32);
    if app_fc >= 129 && payload.len() >= 15 {
        f.detail("iin", Detail::Hex(be16(payload, 13).unwrap_or(0) as u32, 4));
    }
    if master
        && let Some(severity) = dnp3_alert(app_fc) {
            f.alert = Some((severity, format!("DNP3 {name} 명령").into()));
        }
    f.operation = name;
    f.category = category;
    out.push(f);
}

fn iec104_type(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "M_SP_NA_1 Single-point", 3 => "M_DP_NA_1 Double-point", 5 => "M_ST_NA_1 Step position",
        7 => "M_BO_NA_1 Bitstring", 9 => "M_ME_NA_1 Measured normalized", 11 => "M_ME_NB_1 Measured scaled",
        13 => "M_ME_NC_1 Measured float", 15 => "M_IT_NA_1 Integrated totals",
        30 => "M_SP_TB_1 Single-point w/time", 31 => "M_DP_TB_1 Double-point w/time",
        36 => "M_ME_TF_1 Measured float w/time", 45 => "C_SC_NA_1 Single command",
        46 => "C_DC_NA_1 Double command", 47 => "C_RC_NA_1 Regulating step",
        48 => "C_SE_NA_1 Setpoint normalized", 49 => "C_SE_NB_1 Setpoint scaled",
        50 => "C_SE_NC_1 Setpoint float", 51 => "C_BO_NA_1 Bitstring command",
        58 => "C_SC_TA_1 Single command w/time", 59 => "C_DC_TA_1 Double command w/time",
        60 => "C_RC_TA_1 Regulating step w/time", 61 => "C_SE_TA_1 Setpoint normalized w/time",
        62 => "C_SE_TB_1 Setpoint scaled w/time", 63 => "C_SE_TC_1 Setpoint float w/time",
        64 => "C_BO_TA_1 Bitstring w/time", 70 => "M_EI_NA_1 End of initialization",
        100 => "C_IC_NA_1 Interrogation", 101 => "C_CI_NA_1 Counter interrogation",
        102 => "C_RD_NA_1 Read", 103 => "C_CS_NA_1 Clock sync", 104 => "C_TS_NA_1 Test",
        105 => "C_RP_NA_1 Reset process", 107 => "C_TS_TA_1 Test w/time",
        110 => "P_ME_NA_1 Parameter normalized", 111 => "P_ME_NB_1 Parameter scaled",
        112 => "P_ME_NC_1 Parameter float", 113 => "P_AC_NA_1 Parameter activation",
        120 => "F_FR_NA_1 File ready", 122 => "F_SC_NA_1 Call directory/select file",
        _ => return None,
    })
}

fn cot_name(cot: u8) -> Str {
    Cow::Borrowed(match cot {
        1 => "periodic", 2 => "background", 3 => "spontaneous", 4 => "initialized", 5 => "request",
        6 => "activation", 7 => "activation con", 8 => "deactivation", 9 => "deactivation con",
        10 => "activation termination", 20 => "interrogated", 44 => "unknown type",
        45 => "unknown cause", 46 => "unknown ASDU address", 47 => "unknown IOA",
        _ => return Cow::Owned(format!("cot {cot}")),
    })
}

/// Monitored values (single/double points, normalized/scaled/float measurements, with or without
/// CP56 time). Handles both addressing modes of the variable structure qualifier.
fn iec104_measurements(apdu: &[u8], type_id: u8, f: &mut Finding) {
    let (Some(&vsq), Some(ca)) = (apdu.get(5), le16(apdu, 8)) else { return };
    let (count, sequence) = ((vsq & 0x7F) as usize, vsq & 0x80 != 0);
    let (kind, size) = match type_id {
        1 | 30 => ("M_SP", 1), 3 | 31 => ("M_DP", 1), 9 | 34 => ("M_ME_NA", 3),
        11 | 35 => ("M_ME_NB", 3), _ => ("M_ME_NC", 5),
    };
    let element = size + if type_id >= 30 { 7 } else { 0 }; // CP56Time2a
    let ioa_at = |o: usize| apdu.get(o..o + 3).map(|b| b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16);
    let mut offset = 10;
    let first = if sequence { let a = ioa_at(offset); offset += 3; a } else { None };
    for i in 0..count.min(MAX_VALUES_PER_PDU) {
        let ioa = match first {
            Some(base) => base + i as u32,
            None => {
                let Some(a) = ioa_at(offset) else { return };
                offset += 3;
                a
            }
        };
        let Some(e) = apdu.get(offset..offset + element) else { return };
        offset += element;
        let (value, discrete) = match type_id {
            1 | 30 => ((e[0] & 0x01) as f64, true),
            3 | 31 => ((e[0] & 0x03) as f64, true),
            9 | 34 => (i16::from_le_bytes([e[0], e[1]]) as f64 / 32768.0, false),
            11 | 35 => (i16::from_le_bytes([e[0], e[1]]) as f64, false),
            _ => (f32::from_le_bytes([e[0], e[1], e[2], e[3]]) as f64, false),
        };
        f.measure(PointId::Iec104 { ca, ioa, kind }, value, discrete);
    }
}

/// Value of the first information object of a command/setpoint ASDU (activation).
/// Point: `CA<common address> IOA<object address>`.
fn iec104_values(apdu: &[u8], type_id: u8, f: &mut Finding) {
    let (Some(ca), Some(object)) = (le16(apdu, 8), apdu.get(10..)) else { return };
    let Some(ioa) = object.get(0..3).map(|b| b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16) else { return };
    let element = &object[3..];
    let int16 = || element.get(0..2).map(|b| i16::from_le_bytes([b[0], b[1]]) as f64);
    let (value, discrete) = match type_id {
        45 | 58 => (element.first().map(|b| (b & 0x01) as f64), true),        // single command SCO
        46 | 59 | 47 | 60 => (element.first().map(|b| (b & 0x03) as f64), true), // double command / step
        48 | 61 => (int16().map(|v| v / 32768.0), false),                       // normalized setpoint
        49 | 62 => (int16(), false),                                            // scaled setpoint
        50 | 63 => (element.get(0..4).map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64), false),
        _ => (None, false),
    };
    // The command type is part of the point: an object may take both commands and setpoints.
    let kind = match type_id {
        45 | 58 => "C_SC", 46 | 59 => "C_DC", 47 | 60 => "C_RC",
        48 | 61 => "C_SE_NA", 49 | 62 => "C_SE_NB", _ => "C_SE_NC",
    };
    if let Some(value) = value {
        f.value(PointId::Iec104 { ca, ioa, kind }, value, discrete);
    }
}

pub fn dissect_iec104(payload: &[u8], to_server: bool, out: &mut Vec<Finding>) {
    let mut off = 0;
    while off + 6 <= payload.len() && payload[off] == 0x68 {
        let apdu_len = payload[off + 1] as usize;
        let apdu = &payload[(off + 2).min(payload.len())..(off + 2 + apdu_len).min(payload.len())];
        off += 2 + apdu_len;
        if apdu.len() < 4 {
            break;
        }
        let mut f = Finding::new("IEC 60870-5-104")
            .req(Some(to_server))
            .roles(to_server, "IEC 104 controlling station", "IEC 104 controlled station")
            .hint("RTU/IED (IEC 104)", 0.8);
        let c1 = apdu[0];
        if c1 & 0x01 == 0 {
            if apdu.len() < 10 {
                out.push(f);
                continue;
            }
            let (type_id, cot) = (apdu[4], apdu[6] & 0x3F);
            let name: Str = iec104_type(type_id).map(Cow::Borrowed).unwrap_or_else(|| format!("Type {type_id}").into());
            f.function_code = Some(type_id as u32);
            f.operation = format!("{name} ({})", cot_name(cot)).into();
            f.detail("asdu", Detail::Int(le16(apdu, 8).unwrap_or(0) as i64));
            f.detail("cot", Detail::Int(cot as i64));
            if apdu[6] & 0x40 != 0 {
                f.detail("negative", Detail::Bool(true));
            }
            if apdu[6] & 0x80 != 0 {
                f.detail("test", Detail::Bool(true));
            }
            if matches!(type_id, 1 | 3 | 9 | 11 | 13 | 30 | 31 | 34 | 35 | 36) {
                iec104_measurements(apdu, type_id, &mut f);
            }
            f.category = match type_id {
                45..=69 => {
                    if cot == 6 {
                        f.alert = Some(("high", format!("IEC 104 원격 제어 명령: {name}").into()));
                        iec104_values(apdu, type_id, &mut f);
                    }
                    COMMAND
                }
                105 => {
                    if cot == 6 {
                        f.alert = Some(("critical", "IEC 104 Reset Process 명령".into()));
                    }
                    CONTROL
                }
                110..=113 => {
                    if cot == 6 {
                        f.alert = Some(("medium", format!("IEC 104 파라미터 변경: {name}").into()));
                    }
                    CONFIG
                }
                100..=102 => READ,
                103 | 104 | 107 => SESSION,
                120.. => PROGRAM,
                _ => MONITOR,
            };
        } else if c1 & 0x03 == 0x01 {
            f.operation = "S-format (ack)".into();
            f.category = SESSION;
        } else {
            f.operation = match c1 {
                0x07 => "STARTDT act".into(), 0x0B => "STARTDT con".into(), 0x13 => "STOPDT act".into(),
                0x23 => "STOPDT con".into(), 0x43 => "TESTFR act".into(), 0x83 => "TESTFR con".into(),
                other => format!("U-format 0x{other:02X}").into(),
            };
            f.category = SESSION;
        }
        out.push(f);
    }
}
