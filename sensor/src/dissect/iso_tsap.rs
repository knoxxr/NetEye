//! ISO-on-TCP (TPKT/COTP, TCP 102): Siemens S7comm, S7comm-plus, and MMS (IEC 61850/ICCP).

use super::base::*;
use crate::decode::be16;
use std::borrow::Cow;

pub const PORT: u16 = 102;

fn s7_job(fc: u8) -> Option<(&'static str, &'static str)> {
    Some(match fc {
        0x00 => ("CPU Services", DIAGNOSTIC),
        0xF0 => ("Setup Communication", SESSION),
        0x04 => ("Read Var", READ),
        0x05 => ("Write Var", WRITE),
        0x1A => ("Request Download", PROGRAM),
        0x1B => ("Download Block", PROGRAM),
        0x1C => ("Download Ended", PROGRAM),
        0x1D => ("Start Upload", PROGRAM),
        0x1E => ("Upload", PROGRAM),
        0x1F => ("End Upload", PROGRAM),
        0x28 => ("PI Service", CONTROL),
        0x29 => ("PLC Stop", CONTROL),
        _ => return None,
    })
}

const PI_SERVICES: [(&[u8], &str, &str); 5] = [
    (b"P_PROGRAM", "PLC Start/Restart (P_PROGRAM)", "critical"),
    (b"_INSE", "Activate Block (_INSE)", "critical"),
    (b"_DELE", "Delete Block (_DELE)", "critical"),
    (b"_GARB", "Compress Memory (_GARB)", "high"),
    (b"_MODU", "Copy RAM to ROM (_MODU)", "high"),
];

fn userdata_group(group: u8) -> Str {
    Cow::Borrowed(match group {
        0 => "Mode Transition",
        1 => "Programmer Commands",
        2 => "Cyclic Data",
        3 => "Block Functions",
        4 => "CPU Functions",
        5 => "Security",
        7 => "Time Functions",
        _ => return Cow::Owned(format!("Group {group}")),
    })
}

fn s7plus_function(code: u16) -> Option<&'static str> {
    Some(match code {
        0x04BB => "Explore",
        0x04CA => "CreateObject",
        0x04D4 => "DeleteObject",
        0x04F2 => "SetVariable",
        0x0524 => "GetLink",
        0x0542 => "SetMultiVariables",
        0x054C => "GetMultiVariables",
        0x0556 => "BeginSequence",
        0x0560 => "EndSequence",
        0x056B => "Invoke",
        0x0586 => "GetVarSubStreamed",
        _ => return None,
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub fn dissect(payload: &[u8], to_server: bool, out: &mut Vec<Finding>) {
    let mut off = 0;
    while off + 7 <= payload.len() && payload[off] == 0x03 && payload[off + 1] == 0x00 {
        let tpkt_len = be16(payload, off + 2).unwrap_or(0) as usize;
        if tpkt_len < 7 {
            break;
        }
        let segment = &payload[off..(off + tpkt_len).min(payload.len())];
        off += tpkt_len;
        if let Some(f) = dissect_tpkt(segment, to_server) {
            out.push(f);
        }
    }
}

fn dissect_tpkt(segment: &[u8], to_server: bool) -> Option<Finding> {
    let li = segment[4] as usize;
    let pdu_type = segment[5] & 0xF0;
    let data = segment.get(5 + li..).unwrap_or(&[]);

    if pdu_type == 0xE0 || pdu_type == 0xD0 {
        let name = if pdu_type == 0xE0 { "COTP Connect Request" } else { "COTP Connect Confirm" };
        let mut f = Finding::new("ISO-TSAP").op(name, SESSION).req(Some(pdu_type == 0xE0));
        let end = 5 + li;
        let mut p = 11;
        while p + 2 <= end && p + 2 <= segment.len() {
            let (code, len) = (segment[p], segment[p + 1] as usize);
            let value = &segment[(p + 2).min(segment.len())..(p + 2 + len).min(segment.len())];
            if code == 0xC2 && value.len() == 2 {
                f.detail("dst_tsap", Detail::Str(format!("{:02x}{:02x}", value[0], value[1])));
                if matches!(value[0], 0x01..=0x03) {
                    f.detail("rack", Detail::Int((value[1] >> 5) as i64));
                    f.detail("slot", Detail::Int((value[1] & 0x1F) as i64));
                }
            } else if code == 0xC1 {
                f.detail("src_tsap", Detail::Str(value.iter().map(|b| format!("{b:02x}")).collect()));
            }
            p += 2 + len;
        }
        return Some(f);
    }
    if pdu_type != 0xF0 || data.is_empty() {
        return None;
    }
    match data[0] {
        0x32 => dissect_s7(data, to_server),
        0x72 => Some(dissect_s7plus(data, to_server)),
        spdu => {
            let name: Str = match spdu {
                0x0D => "Session Connect".into(),
                0x0E => "Session Accept".into(),
                0x01 => "Data Transfer".into(),
                0x09 => "Session Finish".into(),
                0x0A => "Session Disconnect".into(),
                0x19 => "Session Abort".into(),
                other => format!("SPDU 0x{other:02X}").into(),
            };
            Some(Finding::new("MMS (IEC 61850)")
                .op(name, if spdu != 0x01 { SESSION } else { MONITOR })
                .req(Some(to_server))
                .roles(to_server, "MMS client", "MMS server")
                .hint("IED (IEC 61850)", 0.65))
        }
    }
}

fn dissect_s7(data: &[u8], mut to_server: bool) -> Option<Finding> {
    if data.len() < 10 {
        return None;
    }
    let rosctr = data[1];
    let param_len = be16(data, 6)? as usize;
    let data_len = be16(data, 8)? as usize;
    let header_len = if matches!(rosctr, 2 | 3) { 12 } else { 10 };
    let slice = |a: usize, b: usize| data.get(a.min(data.len())..b.min(data.len())).unwrap_or(&[]);
    let params = slice(header_len, header_len + param_len);
    let body = slice(header_len + param_len, header_len + param_len + data_len);

    // Direction from content; during a download the PLC issues Download Block/Ended jobs.
    let plc_initiated = matches!(params.first(), Some(0x1B | 0x1C));
    match rosctr {
        1 => to_server = !plc_initiated,
        2 | 3 => to_server = plc_initiated,
        7 if params.len() >= 6 => to_server = params[5] >> 4 == 0x4,
        _ => {}
    }

    let mut f = Finding::new("S7comm")
        .req(Some(to_server))
        .roles(to_server, "S7 client", "S7 server")
        .hint("PLC (Siemens S7)", 0.85);
    f.identity_of_dst = to_server;
    f.identity.vendor = Some(Cow::Borrowed("Siemens"));

    if matches!(rosctr, 1 | 3) && !params.is_empty() {
        let fc = params[0];
        if rosctr == 1 && fc == 0x05 {
            s7_write_values(params, body, &mut f);
        }
        let pdu_ref = be16(data, 4).unwrap_or(0) as u32;
        if fc == 0x04 && rosctr == 1 {
            f.read_request = Some((pdu_ref, param_items(params)));
        } else if fc == 0x04 && rosctr == 3 {
            let count = params.get(1).copied().unwrap_or(0) as usize;
            f.read_response = Some((pdu_ref, ReadData::S7 { items: data_items(body, count) }));
        }
        let (mut name, category): (Str, &str) = match s7_job(fc) {
            Some((n, c)) => (n.into(), c),
            None => (format!("Function 0x{fc:02X}").into(), DIAGNOSTIC),
        };
        f.function_code = Some(fc as u32);
        f.category = category;
        if fc == 0x28
            && let Some((_, pi_name, severity)) = PI_SERVICES.iter().find(|(m, _, _)| contains(params, m)) {
                name = format!("PI Service: {pi_name}").into();
                if rosctr == 1 {
                    f.alert = Some((severity, format!("S7 PLC {pi_name}").into()));
                }
            }
        f.operation = if rosctr == 1 { name.clone() } else { format!("{name} (Ack)").into() };
        if rosctr == 1 {
            match fc {
                0x29 => f.alert = Some(("critical", "S7 PLC Stop 명령".into())),
                0x1A..=0x1C => f.alert = Some(("critical", format!("S7 프로그램 다운로드: {name}").into())),
                0x1D..=0x1F => f.alert = Some(("high", format!("S7 프로그램 업로드: {name}").into())),
                _ => {}
            }
        }
        return Some(f);
    }

    if rosctr == 7 && params.len() >= 8 && params[0..3] == [0x00, 0x01, 0x12] {
        let type_group = params[5];
        let group = type_group & 0x0F;
        let is_response = type_group >> 4 == 0x8;
        let sub = params[6];
        f.category = DIAGNOSTIC;
        f.operation = format!("Userdata: {}", userdata_group(group)).into();
        if group == 4 && sub == 0x01 {
            f.operation = "Read SZL".into();
            f.category = DISCOVERY;
            if body.len() >= 8 {
                let szl_id = be16(body, 4)?;
                f.detail("szl_id", Detail::Hex(szl_id as u32, 4));
                if is_response {
                    parse_szl(body, &mut f.identity);
                }
            }
        } else if group == 5 {
            f.operation = "Security: PLC Password".into();
            f.category = SESSION;
            if !is_response {
                f.alert = Some(("medium", "S7 PLC 보호 암호 전송".into()));
            }
        } else if group == 3 {
            f.operation = "Block Functions".into();
            f.category = DISCOVERY;
        }
        return Some(f);
    }
    if rosctr == 2 {
        f.operation = "Ack".into();
        f.category = SESSION;
        return Some(f);
    }
    None
}

/// Parameter item of Read/Write Var ("any pointer"): type, count, DB, area, bit address.
fn any_item(item: &[u8]) -> Option<ReadItem> {
    if item.len() < 12 || item[0] != 0x12 || item[2] != 0x10 {
        return None;
    }
    Some(ReadItem::S7 {
        tsize: item[3],
        count: be16(item, 4)?,
        db: be16(item, 6)?,
        area: item[8],
        bit_address: ((item[9] as u32) << 16) | ((item[10] as u32) << 8) | item[11] as u32,
    })
}

/// Data items follow the parameter items: return code, transport size, length, data, pad byte.
fn data_items(data: &[u8], count: usize) -> Vec<Option<Vec<u8>>> {
    let mut out = Vec::with_capacity(count);
    let mut d = 0usize;
    for i in 0..count {
        let (Some(header), Some(len)) = (data.get(d..d + 4), be16(data, d + 2)) else { break };
        let bytes = if matches!(header[1], 0x03..=0x05) { (len as usize).div_ceil(8) } else { len as usize };
        let Some(payload) = data.get(d + 4..d + 4 + bytes) else { break };
        // In a response 0xFF means success; in a write request the byte is reserved (0x00).
        out.push((header[0] == 0xFF || header[0] == 0x00).then(|| payload.to_vec()));
        d += 4 + bytes + if bytes % 2 == 1 && i + 1 < count { 1 } else { 0 };
    }
    out
}

/// Decode the elements of one item; points use STEP 7 notation (DB10.DBW4, MW10, DB1.DBX0.3, Q0.0).
fn s7_values(item: &ReadItem, payload: &[u8], measured: bool, f: &mut Finding) {
    let ReadItem::S7 { area, db, tsize, bit_address, count } = *item else { return };
    if !matches!(area, 0x81..=0x84) {
        return;
    }
    let (size, letter) = match tsize {
        0x01 => (0, 'X'),
        0x02 | 0x03 => (1, 'B'),
        0x04 | 0x05 => (2, 'W'),
        0x06..=0x08 => (4, 'D'),
        _ => return,
    };
    let byte = bit_address >> 3;
    let emit = |f: &mut Finding, point: PointId, value: f64, discrete: bool| {
        if measured { f.measure(point, value, discrete) } else { f.value(point, value, discrete) }
    };
    if size == 0 {
        let point = PointId::S7 { area, db, letter, byte, bit: Some((bit_address & 7) as u8) };
        emit(f, point, (payload.first().copied().unwrap_or(0) & 1) as f64, true);
        return;
    }
    for e in 0..(count as usize).min(MAX_VALUES_PER_PDU) {
        let Some(raw) = payload.get(e * size..e * size + size) else { break };
        let value = match tsize {
            0x02 | 0x03 => raw[0] as f64,
            0x04 => u16::from_be_bytes([raw[0], raw[1]]) as f64,
            0x05 => i16::from_be_bytes([raw[0], raw[1]]) as f64,
            0x06 => u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as f64,
            0x07 => i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as f64,
            _ => f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as f64, // REAL
        };
        let point = PointId::S7 { area, db, letter, byte: byte + (e * size) as u32, bit: None };
        emit(f, point, value, false);
    }
}

fn param_items(params: &[u8]) -> Vec<ReadItem> {
    let count = params.get(1).copied().unwrap_or(0) as usize;
    (0..count).map_while(|i| params.get(2 + i * 12..2 + i * 12 + 12).and_then(any_item)).collect()
}

/// S7 "Write Var" job: parameter items paired with the data items that follow them.
fn s7_write_values(params: &[u8], data: &[u8], f: &mut Finding) {
    let items = param_items(params);
    for (item, payload) in items.iter().zip(data_items(data, items.len())) {
        if let Some(payload) = payload {
            s7_values(item, &payload, false, f);
        }
    }
}

/// Values of a Read Var response item, addressed by the request item it answers.
pub fn decode_read(item: &ReadItem, payload: &[u8], out: &mut Finding) {
    s7_values(item, payload, true, out);
}

/// SZL 0x0011 (module identification): order number and firmware.
fn parse_szl(body: &[u8], identity: &mut Identity) {
    if body.len() < 12 || body[0] != 0xFF {
        return;
    }
    let (Some(szl_id), Some(rec_len), Some(count)) = (be16(body, 4), be16(body, 8), be16(body, 10)) else { return };
    let rec_len = rec_len as usize;
    if szl_id & 0x00FF != 0x11 || rec_len < 28 {
        return;
    }
    let mut off = 12;
    for _ in 0..count {
        let Some(record) = body.get(off..off + rec_len) else { break };
        off += rec_len;
        let index = be16(record, 0).unwrap_or(0);
        let mlfb = latin1(&record[2..22]);
        let mlfb = strip_chars(&mlfb, &[' ', '\0']);
        let ausbg = be16(record, 24).unwrap_or(0);
        let ausbe = be16(record, 26).unwrap_or(0);
        if index == 0x0001 && !mlfb.is_empty() {
            identity.model = Some(mlfb.to_string().into());
        } else if index == 0x0007 && ausbg >> 8 == b'V' as u16 {
            identity.firmware = Some(format!("V{}.{}.{}", ausbg & 0xFF, ausbe >> 8, ausbe & 0xFF).into());
        }
    }
}

fn dissect_s7plus(data: &[u8], mut to_server: bool) -> Finding {
    let version = data.get(1).copied().unwrap_or(0);
    if matches!(version, 1 | 2) && data.len() > 4 && matches!(data[4], 0x31 | 0x32) {
        to_server = data[4] == 0x31;
    }
    let mut f = Finding::new("S7comm-plus")
        .op(format!("S7comm-plus V{version}"), SESSION)
        .req(Some(to_server))
        .roles(to_server, "S7 client", "S7 server")
        .hint("PLC (Siemens S7-1200/1500)", 0.85);
    f.identity_of_dst = to_server;
    f.detail("version", Detail::Int(version as i64));
    f.identity.vendor = Some(Cow::Borrowed("Siemens"));
    if matches!(version, 1 | 2) && data.len() >= 9 {
        let opcode = data[4];
        let function = be16(data, 7).unwrap_or(0);
        if matches!(opcode, 0x31 | 0x32) {
            let name: Str = s7plus_function(function).map(Cow::Borrowed)
                .unwrap_or_else(|| format!("0x{function:04X}").into());
            f.function_code = Some(function as u32);
            f.category = match name.as_ref() {
                "SetVariable" | "SetMultiVariables" => WRITE,
                "GetMultiVariables" | "GetVarSubStreamed" => READ,
                "CreateObject" | "DeleteObject" => SESSION,
                _ => f.category,
            };
            f.operation = format!("{}: {name}", if opcode == 0x31 { "Request" } else { "Response" }).into();
        }
    }
    f
}
