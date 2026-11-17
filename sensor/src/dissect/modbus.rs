//! Modbus/TCP (MBAP) including MEI device identification and Schneider UMAS.

use super::base::*;
use crate::decode::be16;
use std::borrow::Cow;

pub const PORT: u16 = 502;

fn function(fc: u8) -> Option<(&'static str, &'static str)> {
    Some(match fc {
        1 => ("Read Coils", READ),
        2 => ("Read Discrete Inputs", READ),
        3 => ("Read Holding Registers", READ),
        4 => ("Read Input Registers", READ),
        5 => ("Write Single Coil", COMMAND),
        6 => ("Write Single Register", WRITE),
        7 => ("Read Exception Status", DIAGNOSTIC),
        8 => ("Diagnostics", DIAGNOSTIC),
        11 => ("Get Comm Event Counter", DIAGNOSTIC),
        12 => ("Get Comm Event Log", DIAGNOSTIC),
        15 => ("Write Multiple Coils", COMMAND),
        16 => ("Write Multiple Registers", WRITE),
        17 => ("Report Server ID", DISCOVERY),
        20 => ("Read File Record", READ),
        21 => ("Write File Record", WRITE),
        22 => ("Mask Write Register", WRITE),
        23 => ("Read/Write Multiple Registers", WRITE),
        24 => ("Read FIFO Queue", READ),
        43 => ("Encapsulated Interface Transport", DISCOVERY),
        90 => ("Schneider UMAS", DIAGNOSTIC),
        _ => return None,
    })
}

fn function_name(fc: u8) -> Str {
    function(fc).map(|f| Cow::Borrowed(f.0)).unwrap_or_else(|| Cow::Owned(format!("Function {fc}")))
}

fn umas(code: u8) -> Option<(&'static str, &'static str)> {
    Some(match code {
        0x01 => ("UMAS Init Comm", SESSION),
        0x02 => ("UMAS Read ID", DISCOVERY),
        0x03 => ("UMAS Read Project Info", DISCOVERY),
        0x04 => ("UMAS Read PLC Info", DISCOVERY),
        0x10 => ("UMAS Take PLC Reservation", SESSION),
        0x11 => ("UMAS Release PLC Reservation", SESSION),
        0x12 => ("UMAS Keep Alive", SESSION),
        0x20 => ("UMAS Read Memory Block", READ),
        0x22 => ("UMAS Read Variables", READ),
        0x23 => ("UMAS Write Variables", WRITE),
        0x30 => ("UMAS Initialize Download", PROGRAM),
        0x31 => ("UMAS Download Block", PROGRAM),
        0x32 => ("UMAS End Download", PROGRAM),
        0x33 => ("UMAS Initialize Upload", PROGRAM),
        0x34 => ("UMAS Upload Block", PROGRAM),
        0x35 => ("UMAS End Upload", PROGRAM),
        0x40 => ("UMAS Start PLC", CONTROL),
        0x41 => ("UMAS Stop PLC", CONTROL),
        _ => return None,
    })
}

fn exception_name(code: u8) -> Str {
    Cow::Borrowed(match code {
        1 => "Illegal Function",
        2 => "Illegal Data Address",
        3 => "Illegal Data Value",
        4 => "Server Device Failure",
        6 => "Server Device Busy",
        0x0A => "Gateway Path Unavailable",
        0x0B => "Gateway Target Failed to Respond",
        _ => return Cow::Owned(code.to_string()),
    })
}

fn parse_mei_identity(pdu: &[u8], identity: &mut Identity) {
    // fc(43) mei(0x0E) code conformity more next count {id len value}*
    if pdu.len() < 7 {
        return;
    }
    let count = pdu[6];
    let mut off = 7;
    for _ in 0..count {
        if off + 2 > pdu.len() {
            break;
        }
        let (id, len) = (pdu[off], pdu[off + 1] as usize);
        let end = (off + 2 + len).min(pdu.len());
        let value = latin1(&pdu[off + 2..end]).trim().to_string();
        off += 2 + len;
        if value.is_empty() {
            continue;
        }
        match id {
            0 => identity.vendor = Some(value.into()),
            1 => identity.product_code = Some(value.into()),
            2 => identity.firmware = Some(value.into()),
            5 => identity.model = Some(value.into()),
            _ => {}
        }
    }
}

pub fn dissect(payload: &[u8], to_server: bool, out: &mut Vec<Finding>) {
    let mut off = 0;
    while off + 8 <= payload.len() {
        let (Some(proto), Some(length)) = (be16(payload, off + 2), be16(payload, off + 4)) else { break };
        let length = length as usize;
        if proto != 0 || !(2..=254).contains(&length) {
            break;
        }
        let tid = be16(payload, off).unwrap_or(0);
        let unit = payload[off + 6];
        let end = (off + 6 + length).min(payload.len());
        let pdu = &payload[off + 7..end];
        off += 6 + length;
        if pdu.is_empty() {
            break;
        }
        out.push(dissect_pdu(pdu, unit, tid, to_server));
    }
}

fn read_table(fc: u8) -> Option<&'static str> {
    Some(match fc {
        1 => "CO",
        2 => "DI",
        3 | 23 => "HR",
        4 => "IR",
        _ => return None,
    })
}

/// Values of a read response, addressed by the request it answers.
pub fn decode_read(item: &ReadItem, bytes: &[u8], out: &mut Finding) {
    let ReadItem::Modbus { unit, table, start, count } = *item else { return };
    let n = count.min(MAX_VALUES_PER_PDU as u16);
    for i in 0..n {
        let addr = start.wrapping_add(i);
        let point = PointId::Modbus { unit, table, addr };
        if matches!(table, "CO" | "DI") {
            if let Some(byte) = bytes.get(i as usize / 8) {
                out.measure(point, ((byte >> (i % 8)) & 1) as f64, true);
            }
        } else if let Some(v) = be16(bytes, i as usize * 2) {
            out.measure(point, v as f64, false);
        }
    }
}

fn dissect_pdu(pdu: &[u8], unit: u8, tid: u16, to_server: bool) -> Finding {
    let fc = pdu[0];
    let mut f = Finding::new("Modbus/TCP")
        .req(Some(to_server))
        .roles(to_server, "Modbus client", "Modbus server")
        .hint("PLC", 0.75);
    f.function_code = Some((fc & 0x7F) as u32);
    f.detail("unit_id", Detail::Int(unit as i64));
    // Reads are paired by (unit, transaction id): the response carries values but no addresses.
    let tx = (unit as u32) << 16 | tid as u32;
    if let Some(table) = read_table(fc) {
        if to_server {
            if let (Some(start), Some(count)) = (be16(pdu, 1), be16(pdu, 3)) {
                f.read_request = Some((tx, vec![ReadItem::Modbus { unit, table, start, count }]));
            }
        } else if let Some(&byte_count) = pdu.get(1) {
            let bytes = pdu.get(2..2 + byte_count as usize).unwrap_or(&pdu[2.min(pdu.len())..]);
            f.read_response = Some((tx, ReadData::Modbus { bytes: bytes.to_vec() }));
        }
    }

    if !to_server && fc & 0x80 != 0 {
        let code = pdu.get(1).copied().unwrap_or(0);
        f.operation = Cow::Owned(format!("Exception: {} ({})", function_name(fc & 0x7F), exception_name(code)));
        f.category = DIAGNOSTIC;
        f.detail("exception", Detail::Int(code as i64));
        return f;
    }
    let (name, category) = match function(fc) {
        Some((n, c)) => (Cow::Borrowed(n), c),
        None => (Cow::Owned(format!("Function {fc}")), ""),
    };
    f.operation = name;
    f.category = category;

    if fc == 8 && pdu.len() >= 3 {
        let sub = be16(pdu, 1).unwrap_or(0);
        let diag = match sub {
            0x0001 => Some(("Restart Communications Option", CONTROL, "high")),
            0x0004 => Some(("Force Listen Only Mode", CONTROL, "high")),
            0x000A => Some(("Clear Counters and Diagnostic Register", CONFIG, "medium")),
            _ => None,
        };
        if let Some((sub_name, sub_category, severity)) = diag {
            f.operation = Cow::Owned(format!("Diagnostics: {sub_name}"));
            f.category = sub_category;
            if to_server {
                f.alert = Some((severity, Cow::Owned(format!("Modbus 진단 명령: {sub_name}"))));
            }
        }
    } else if fc == 43 && pdu.get(1) == Some(&0x0E) {
        f.operation = Cow::Borrowed("Read Device Identification");
        if !to_server {
            parse_mei_identity(pdu, &mut f.identity);
            f.identity_of_dst = false;
        }
    } else if fc == 90 && pdu.len() >= 3 {
        let code = pdu[2];
        let (umas_name, umas_category) = match umas(code) {
            Some((n, c)) => (Cow::Borrowed(n), c),
            None => (Cow::Owned(format!("UMAS 0x{code:02X}")), DIAGNOSTIC),
        };
        f.protocol = Cow::Borrowed("Modbus/UMAS");
        f.detail("umas_function", Detail::Int(code as i64));
        if to_server {
            if umas_category == CONTROL {
                f.alert = Some(("critical", Cow::Owned(format!("Schneider PLC 운전 상태 변경: {umas_name}"))));
            } else if matches!(code, 0x30..=0x32) {
                f.alert = Some(("critical", Cow::Owned(format!("Schneider PLC 프로그램 다운로드: {umas_name}"))));
            } else if matches!(code, 0x33..=0x35) {
                f.alert = Some(("high", Cow::Owned(format!("Schneider PLC 프로그램 업로드: {umas_name}"))));
            }
        }
        f.operation = umas_name;
        f.category = umas_category;
    } else if to_server && pdu.len() >= 3 && matches!(fc, 5 | 6 | 15 | 16 | 22 | 23) {
        f.detail("address", Detail::Int(be16(pdu, 1).unwrap_or(0) as i64));
        written_values(pdu, unit, &mut f);
    }
    f
}

/// Process values carried by write requests. Points are named by unit and 0-based wire address:
/// `u1 HR16` (holding register), `u1 CO5` (coil).
fn written_values(pdu: &[u8], unit: u8, f: &mut Finding) {
    let register = |addr: u16| PointId::Modbus { unit, table: "HR", addr };
    let coil = |addr: u16| PointId::Modbus { unit, table: "CO", addr };
    let registers = |f: &mut Finding, start: u16, count: u16, data: &[u8]| {
        for i in 0..count.min(MAX_VALUES_PER_PDU as u16) {
            if let Some(v) = be16(data, i as usize * 2) {
                f.value(register(start.wrapping_add(i)), v as f64, false);
            }
        }
    };
    let (Some(addr), Some(word)) = (be16(pdu, 1), be16(pdu, 3)) else { return };
    match pdu[0] {
        5 => f.value(coil(addr), if word == 0xFF00 { 1.0 } else { 0.0 }, true),
        6 => f.value(register(addr), word as f64, false),
        16 => registers(f, addr, word, pdu.get(6..).unwrap_or(&[])),
        15 => {
            let bits = pdu.get(6..).unwrap_or(&[]);
            for i in 0..word.min(MAX_VALUES_PER_PDU as u16) {
                if let Some(byte) = bits.get(i as usize / 8) {
                    f.value(coil(addr.wrapping_add(i)), ((byte >> (i % 8)) & 1) as f64, true);
                }
            }
        }
        23 => {
            // Read/Write Multiple: write start at 5, quantity at 7, values from 10.
            if let (Some(start), Some(count)) = (be16(pdu, 5), be16(pdu, 7)) {
                registers(f, start, count, pdu.get(10..).unwrap_or(&[]));
            }
        }
        _ => {}
    }
}
