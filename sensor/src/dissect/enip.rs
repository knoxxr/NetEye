//! EtherNet/IP encapsulation (TCP/UDP 44818) and CIP explicit messaging.

use super::base::*;
use crate::decode::{le16, le32};
use std::borrow::Cow;

pub const PORT: u16 = 44818;
pub const IO_PORT: u16 = 2222;

fn command(code: u16) -> Option<(&'static str, &'static str)> {
    Some(match code {
        0x0004 => ("List Services", DISCOVERY),
        0x0063 => ("List Identity", DISCOVERY),
        0x0064 => ("List Interfaces", DISCOVERY),
        0x0065 => ("Register Session", SESSION),
        0x0066 => ("Unregister Session", SESSION),
        0x006F => ("SendRRData", ""),
        0x0070 => ("SendUnitData", ""),
        _ => return None,
    })
}

fn cip_service(code: u8) -> Option<(&'static str, &'static str)> {
    Some(match code {
        0x01 => ("Get Attributes All", READ),
        0x02 => ("Set Attributes All", CONFIG),
        0x03 => ("Get Attribute List", READ),
        0x04 => ("Set Attribute List", CONFIG),
        0x05 => ("Reset", CONTROL),
        0x06 => ("Start", CONTROL),
        0x07 => ("Stop", CONTROL),
        0x08 => ("Create", CONFIG),
        0x09 => ("Delete", CONFIG),
        0x0A => ("Multiple Service Packet", ""),
        0x0D => ("Apply Attributes", CONFIG),
        0x0E => ("Get Attribute Single", READ),
        0x10 => ("Set Attribute Single", CONFIG),
        0x15 => ("Restore", CONFIG),
        0x16 => ("Save", CONFIG),
        _ => return None,
    })
}

fn connection_manager(code: u8) -> Option<(&'static str, &'static str)> {
    Some(match code {
        0x52 => ("Unconnected Send", ""),
        0x54 => ("Forward Open", SESSION),
        0x5B => ("Large Forward Open", SESSION),
        0x4E => ("Forward Close", SESSION),
        _ => return None,
    })
}

fn logix(code: u8) -> Option<(&'static str, &'static str)> {
    Some(match code {
        0x4C => ("Read Tag", READ),
        0x4D => ("Write Tag", WRITE),
        0x4E => ("Read Modify Write Tag", WRITE),
        0x52 => ("Read Tag Fragmented", READ),
        0x53 => ("Write Tag Fragmented", WRITE),
        0x55 => ("Get Instance Attribute List", READ),
        _ => return None,
    })
}

fn cip_class(class: u32) -> Option<&'static str> {
    Some(match class {
        0x01 => "Identity",
        0x02 => "Message Router",
        0x04 => "Assembly",
        0x06 => "Connection Manager",
        0x64 => "Program",
        0x6B => "Symbol",
        0x6C => "Template",
        0x8E => "Controller",
        0xF5 => "TCP/IP",
        0xF6 => "Ethernet Link",
        0xA1 => "Non-Volatile Storage",
        _ => return None,
    })
}

fn vendor_name(vendor: u16) -> String {
    match vendor {
        1 => "Rockwell Automation/Allen-Bradley".to_string(),
        v => format!("CIP Vendor {v}"),
    }
}

fn device_type(code: u16) -> String {
    match code {
        0x00 | 0x2B => "Generic Device".into(),
        0x02 => "AC Drive".into(),
        0x07 => "General Purpose Discrete I/O".into(),
        0x0C => "Communications Adapter".into(),
        0x0E => "PLC".into(),
        0x18 => "HMI".into(),
        c => format!("CIP Device Type 0x{c:02X}"),
    }
}

fn set_identity_hint(f: &mut Finding) {
    match f.identity.device_class.as_deref() {
        Some("PLC") => f.device_hint = Some(("PLC".into(), 0.95)),
        Some(class) if !class.is_empty() => f.device_hint = Some((class.to_string().into(), 0.9)),
        _ => {}
    }
}

/// CIP Identity item (type 0x0C) as returned by ListIdentity.
fn parse_identity_item(item: &[u8]) -> Option<Identity> {
    if item.len() < 33 {
        return None;
    }
    let name_len = item[32] as usize;
    let name = latin1(&item[33..(33 + name_len).min(item.len())]);
    Some(Identity {
        vendor: Some(vendor_name(le16(item, 18)?).into()),
        device_class: Some(device_type(le16(item, 20)?).into()),
        product_code: Some(le16(item, 22)?.to_string().into()),
        firmware: Some(format!("{}.{:03}", item[24], item[25]).into()),
        serial: Some(format!("0x{:08X}", le32(item, 28)?).into()),
        model: Some(name.trim().to_string().into()),
        ..Identity::default()
    })
}

/// Identity object Get_Attributes_All reply; recognised by its self-consistent layout.
fn parse_identity_attributes(data: &[u8]) -> Option<Identity> {
    if data.len() < 15 {
        return None;
    }
    let name_len = data[14] as usize;
    let name = data.get(15..15 + name_len)?;
    if name_len == 0 || data.len() > 15 + name_len + 16 || !name.iter().all(|b| (32..127).contains(b)) {
        return None;
    }
    Some(Identity {
        vendor: Some(vendor_name(le16(data, 0)?).into()),
        device_class: Some(device_type(le16(data, 2)?).into()),
        product_code: Some(le16(data, 4)?.to_string().into()),
        firmware: Some(format!("{}.{:03}", data[6], data[7]).into()),
        serial: Some(format!("0x{:08X}", le32(data, 10)?).into()),
        model: Some(latin1(name).trim().to_string().into()),
        ..Identity::default()
    })
}

/// Decode `count` Logix elements of atomic type `kind` (BOOL..LREAL); structures are skipped.
fn logix_values(tag: &str, kind: u16, count: usize, elements: &[u8], measured: bool, f: &mut Finding) {
    let size = match kind {
        0xC1 | 0xC2 | 0xC6 => 1,
        0xC3 | 0xC7 => 2,
        0xC4 | 0xC8 | 0xCA => 4,
        0xC5 | 0xCB => 8,
        _ => return, // structures, strings
    };
    let count = count.max(1);
    for i in 0..count.min(MAX_VALUES_PER_PDU) {
        let Some(raw) = elements.get(i * size..i * size + size) else { break };
        let value = match kind {
            0xC1 => (raw[0] != 0) as u8 as f64,
            0xC2 => raw[0] as i8 as f64,
            0xC6 => raw[0] as f64,
            0xC3 => i16::from_le_bytes([raw[0], raw[1]]) as f64,
            0xC7 => u16::from_le_bytes([raw[0], raw[1]]) as f64,
            0xC4 => i32::from_le_bytes(raw.try_into().unwrap()) as f64,
            0xC8 => u32::from_le_bytes(raw.try_into().unwrap()) as f64,
            0xCA => f32::from_le_bytes(raw.try_into().unwrap()) as f64,
            0xC5 => i64::from_le_bytes(raw.try_into().unwrap()) as f64,
            _ => f64::from_le_bytes(raw.try_into().unwrap()), // LREAL
        };
        let point = PointId::Tag(if count > 1 { format!("{tag}[{i}]") } else { tag.to_string() });
        if measured { f.measure(point, value, kind == 0xC1) } else { f.value(point, value, kind == 0xC1) }
    }
}

/// Logix "Write Tag" (0x4D) request data: type(2 LE), element count(2 LE), elements.
fn logix_write_values(tag: &str, data: &[u8], f: &mut Finding) {
    let (Some(kind), Some(count)) = (le16(data, 0), le16(data, 2)) else { return };
    logix_values(tag, kind, count as usize, data.get(4..).unwrap_or(&[]), false, f);
}

/// Values of a Read Tag reply (type code + elements), addressed by the request it answers.
pub fn decode_read(item: &ReadItem, data: &[u8], out: &mut Finding) {
    let ReadItem::Cip { tag: Some(tag), count } = item else { return };
    let Some(kind) = le16(data, 0) else { return };
    logix_values(tag, kind, *count as usize, data.get(2..).unwrap_or(&[]), true, out);
}

fn push_read(f: &mut Finding, item: ReadItem) {
    f.read_request.get_or_insert_with(|| (0, Vec::new())).1.push(item);
}

/// The data of a successful reply: after service, reserved, general status, extended status words.
fn reply_data(reply: &[u8]) -> Option<&[u8]> {
    if reply.len() < 4 || reply[2] != 0 {
        return None;
    }
    reply.get(4 + reply[3] as usize * 2..)
}

/// Requests packed in a Multiple Service Packet: count(2), offsets(2 each, from the count), messages.
fn packed(data: &[u8]) -> Vec<&[u8]> {
    let count = le16(data, 0).unwrap_or(0) as usize;
    let offsets: Vec<usize> = (0..count.min(256)).filter_map(|i| le16(data, 2 + i * 2).map(usize::from)).collect();
    offsets.iter().enumerate().map(|(i, &start)| {
        let end = offsets.get(i + 1).copied().unwrap_or(data.len()).min(data.len());
        data.get(start.min(end)..end).unwrap_or(&[])
    }).collect()
}

/// One service inside a Multiple Service Packet request: reads are remembered (by position),
/// writes give their values.
fn packed_request(message: &[u8], f: &mut Finding) {
    let (Some(&service), Some(&words)) = (message.first(), message.get(1)) else {
        push_read(f, ReadItem::Cip { tag: None, count: 0 });
        return;
    };
    let path_end = (2 + words as usize * 2).min(message.len());
    let path = parse_path(&message[2..path_end]);
    let data = &message[path_end..];
    match (service, path.tag) {
        (0x4C, Some(tag)) => push_read(f, ReadItem::Cip { tag: Some(tag), count: le16(data, 0).unwrap_or(1) }),
        (0x4D, Some(tag)) => {
            logix_write_values(&tag, data, f);
            push_read(f, ReadItem::Cip { tag: None, count: 0 });
        }
        _ => push_read(f, ReadItem::Cip { tag: None, count: 0 }),
    }
}

#[derive(Default)]
struct CipPath {
    class: Option<u32>,
    tag: Option<String>,
}

fn parse_path(path: &[u8]) -> CipPath {
    let mut result = CipPath::default();
    let mut i = 0;
    while i < path.len() {
        let seg = path[i];
        match seg {
            0x20 if i + 1 < path.len() => { result.class = Some(path[i + 1] as u32); i += 2; }
            0x21 if i + 3 < path.len() => { result.class = le16(path, i + 2).map(u32::from); i += 4; }
            0x24 if i + 1 < path.len() => i += 2,
            0x25 if i + 3 < path.len() => i += 4,
            0x30 if i + 1 < path.len() => i += 2,
            0x91 if i + 1 < path.len() => {
                let n = path[i + 1] as usize;
                result.tag = Some(latin1(&path[(i + 2).min(path.len())..(i + 2 + n).min(path.len())]));
                i += 2 + n + n % 2;
            }
            _ => break,
        }
    }
    result
}

fn cip(message: &[u8], to_server: bool, f: &mut Finding) {
    let Some(&service) = message.first() else { return };
    if service & 0x80 != 0 {
        let code = service & 0x7F;
        let name: Str = cip_service(code).or_else(|| logix(code)).or_else(|| connection_manager(code))
            .map(|(n, _)| Cow::Borrowed(n)).unwrap_or_else(|| format!("Service 0x{code:02X}").into());
        f.operation = format!("CIP {name} (Response)").into();
        if f.category.is_empty() {
            f.category = READ;
        }
        if code == 0x4C {
            let data = reply_data(message).map(<[u8]>::to_vec);
            f.read_response = Some((0, ReadData::Cip { items: vec![data] }));
        } else if code == 0x0A && message.len() >= 4 {
            // Replies are listed even when some services failed (general status 0x1E).
            let body = message.get(4 + message[3] as usize * 2..).unwrap_or(&[]);
            let items = packed(body).into_iter()
                .map(|reply| (reply.first() == Some(&0xCC)).then(|| reply_data(reply).map(<[u8]>::to_vec)).flatten())
                .collect();
            f.read_response = Some((0, ReadData::Cip { items }));
        }
        if code == 0x01 && message.len() >= 4 && message[2] == 0 {
            let start = 4 + message[3] as usize * 2;
            if let Some(identity) = message.get(start..).and_then(parse_identity_attributes) {
                f.identity = identity;
                f.identity_of_dst = false;
                set_identity_hint(f);
            }
        }
        return;
    }
    if message.len() < 2 {
        return;
    }
    let path_end = (2 + message[1] as usize * 2).min(message.len());
    let path = parse_path(&message[2..path_end]);
    let request_data = &message[path_end..];
    let cls = path.class;
    f.function_code = Some(service as u32);
    f.detail("cip_service", Detail::Hex(service as u32, 2));
    if let Some(c) = cls {
        f.detail("cip_class", cip_class(c).map(Detail::Static).unwrap_or(Detail::Hex(c, 2)));
    }
    if let Some(tag) = path.tag {
        if service == 0x4D && to_server {
            logix_write_values(&tag, request_data, f);
        } else if service == 0x4C && to_server {
            push_read(f, ReadItem::Cip { tag: Some(tag.clone()), count: le16(request_data, 0).unwrap_or(1) });
        }
        f.detail("tag", Detail::Str(tag));
    }
    if service == 0x0A && to_server {
        for message in packed(request_data) {
            packed_request(message, f);
        }
        // Remember the packet only if it actually reads tags.
        if f.read_request.as_ref().is_some_and(|(_, items)| items.iter().all(|i| matches!(i, ReadItem::Cip { tag: None, .. }))) {
            f.read_request = None;
        }
    }

    let (name, category): (Str, &'static str) = if cls == Some(0x06) && connection_manager(service).is_some() {
        let (n, c) = connection_manager(service).unwrap();
        if service == 0x52 && request_data.len() >= 4 {
            let size = le16(request_data, 2).unwrap_or(0) as usize;
            cip(&request_data[4..(4 + size).min(request_data.len())], to_server, f);
            return;
        }
        (n.into(), c)
    } else if cls == Some(0xA1) && service >= 0x4B {
        // Object-specific services of the Non-Volatile Storage object carry firmware images.
        ("Firmware Update".into(), FIRMWARE)
    } else if let Some((n, c)) = cip_service(service).or_else(|| logix(service)) {
        (n.into(), c)
    } else {
        (format!("Service 0x{service:02X}").into(), DIAGNOSTIC)
    };

    let target = cls.and_then(cip_class).unwrap_or("");
    let suffix = if target.is_empty() { String::new() } else { format!(" [{target}]") };
    f.operation = format!("CIP {name}{suffix}").into();
    f.category = category;
    if to_server {
        if category == FIRMWARE {
            f.alert = Some(("critical", "CIP 펌웨어 업데이트 (Non-Volatile Storage)".into()));
        } else if service == 0x05 && matches!(cls, Some(1) | None) {
            f.alert = Some(("critical", "CIP Identity Reset (장비 재시작) 명령".into()));
        } else if matches!(service, 0x06 | 0x07) {
            f.alert = Some(("critical", format!("CIP {name} 명령{suffix}").into()));
        } else if matches!(cls, Some(0x64 | 0x8E)) && (category == CONFIG || category == WRITE) {
            f.alert = Some(("high", format!("Logix 컨트롤러/프로그램 객체 변경: {name}").into()));
        } else if cls == Some(0xF5) && category == CONFIG {
            f.alert = Some(("high", "CIP TCP/IP 설정 변경".into()));
        }
    }
}

pub fn dissect(payload: &[u8], to_server: bool, out: &mut Vec<Finding>) {
    if payload.len() < 24 {
        return;
    }
    let (Some(cmd), Some(length), Some(status)) = (le16(payload, 0), le16(payload, 2), le32(payload, 8)) else { return };
    let Some((name, category)) = command(cmd) else { return };
    let mut f = Finding::new("EtherNet/IP")
        .op(name, category)
        .req(Some(to_server))
        .roles(to_server, "EtherNet/IP scanner", "EtherNet/IP adapter")
        .hint("Industrial device (CIP)", 0.7);
    f.function_code = Some(cmd as u32);
    let body = &payload[24..(24 + length as usize).min(payload.len())];
    if status != 0 {
        f.detail("status", Detail::Int(status as i64));
    }
    if cmd == 0x0063 && !to_server && body.len() >= 6 {
        let item_type = le16(body, 2).unwrap_or(0);
        let item_len = le16(body, 4).unwrap_or(0) as usize;
        if item_type == 0x0C
            && let Some(identity) = parse_identity_item(&body[6..(6 + item_len).min(body.len())]) {
                f.identity = identity;
                set_identity_hint(&mut f);
            }
    } else if matches!(cmd, 0x006F | 0x0070) && body.len() >= 8 {
        // Replies echo the sender context (unconnected) or the sequence count (connected).
        let mut tx = (le32(payload, 12).unwrap_or(0) ^ le32(payload, 16).unwrap_or(0)) & 0x7FFF_FFFF;
        let count = le16(body, 6).unwrap_or(0);
        let mut off = 8;
        for _ in 0..count {
            if off + 4 > body.len() {
                break;
            }
            let item_type = le16(body, off).unwrap_or(0);
            let item_len = le16(body, off + 2).unwrap_or(0) as usize;
            let item = &body[off + 4..(off + 4 + item_len).min(body.len())];
            off += 4 + item_len;
            if item_type == 0x00B2 {
                cip(item, to_server, &mut f);
            } else if item_type == 0x00B1 && item.len() > 2 {
                tx = 0x8000_0000 | le16(item, 0).unwrap_or(0) as u32;
                cip(&item[2..], to_server, &mut f);
            }
        }
        if let Some((key, _)) = f.read_request.as_mut() {
            *key = tx;
        }
        if let Some((key, _)) = f.read_response.as_mut() {
            *key = tx;
        }
    }
    out.push(f);
}

pub fn dissect_io(out: &mut Vec<Finding>) {
    out.push(Finding::new("EtherNet/IP I/O").op("Implicit I/O (Class 1)", MONITOR).hint("Industrial device (CIP)", 0.6));
}
