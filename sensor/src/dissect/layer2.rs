//! Layer-2 industrial protocols: IEC 61850 GOOSE/SV, PROFINET (DCP/RT), CC-Link IE, LLDP.

use super::base::*;
use crate::decode::{be16, be32};

fn ber_items(data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        if i + 2 > data.len() {
            return None;
        }
        let tag = data[i];
        let mut length = data[i + 1] as usize;
        i += 2;
        if length & 0x80 != 0 {
            let n = length & 0x7F;
            let bytes = &data[i.min(data.len())..(i + n).min(data.len())];
            length = bytes.iter().fold(0usize, |acc, b| acc.saturating_mul(256).saturating_add(*b as usize));
            i += n;
        }
        let value = &data[i.min(data.len())..i.saturating_add(length).min(data.len())];
        i = i.saturating_add(length);
        Some((tag, value))
    })
}

fn uint(bytes: &[u8]) -> i64 {
    bytes.iter().take(8).fold(0i64, |acc, b| (acc << 8) | *b as i64)
}

pub fn goose(payload: &[u8], out: &mut Vec<Finding>) {
    let mut f = Finding::new("IEC 61850 GOOSE").op("GOOSE Publish", MONITOR).hint("IED (IEC 61850)", 0.85);
    f.role_src = Some("GOOSE publisher");
    if payload.len() >= 10 {
        f.detail("appid", Detail::Hex(be16(payload, 0).unwrap_or(0) as u32, 4));
        for (tag, value) in ber_items(&payload[8..]) {
            if tag != 0x61 {
                continue;
            }
            for (inner_tag, inner) in ber_items(value) {
                match inner_tag {
                    0x80 => {
                        let reference = latin1(inner);
                        f.identity.name = Some(reference.split('/').next().unwrap_or("").to_string().into());
                        f.detail("gocbRef", Detail::Str(reference));
                    }
                    0x83 => f.detail("goID", Detail::Str(latin1(inner))),
                    0x85 => f.detail("stNum", Detail::Int(uint(inner))),
                    0x86 => f.detail("sqNum", Detail::Int(uint(inner))),
                    0x87 if inner.first().is_some_and(|b| *b != 0) => {
                        f.detail("simulation", Detail::Bool(true));
                        f.alert = Some(("medium", "GOOSE 시뮬레이션/테스트 플래그가 설정된 메시지".into()));
                    }
                    0x88 => f.detail("confRev", Detail::Int(uint(inner))),
                    _ => {}
                }
            }
        }
    }
    out.push(f);
}

pub fn sampled_values(payload: &[u8], out: &mut Vec<Finding>) {
    let mut f = Finding::new("IEC 61850 Sampled Values").op("SV Publish", MONITOR)
        .hint("Merging Unit (IEC 61850-9-2)", 0.85);
    f.role_src = Some("SV publisher (Merging Unit)");
    f.detail("appid", Detail::Hex(be16(payload, 0).unwrap_or(0) as u32, 4));
    out.push(f);
}

fn dcp_set_target(option: u8, sub: u8) -> Str {
    match (option, sub) {
        (1, 2) => "IP 주소".into(),
        (2, 2) => "Station Name".into(),
        (5, 3) => "LED 점멸(Signal)".into(),
        (5, 4) => "Response Delay".into(),
        (5, 6) => "공장 초기화(Reset to Factory)".into(),
        (o, s) => format!("Option {o}.{s}").into(),
    }
}

pub fn profinet(payload: &[u8], out: &mut Vec<Finding>) {
    let Some(frame_id) = be16(payload, 0) else { return };
    if (0x8000..=0xBFFF).contains(&frame_id) || (0xC000..=0xFBFF).contains(&frame_id) {
        out.push(Finding::new("PROFINET RT").op("Cyclic I/O", MONITOR).hint("PROFINET device", 0.6));
        return;
    }
    if matches!(frame_id, 0xFC01 | 0xFE01) {
        out.push(Finding::new("PROFINET RT").op("Alarm", MONITOR));
        return;
    }
    if !(0xFEFC..=0xFEFF).contains(&frame_id) || payload.len() < 12 {
        out.push(Finding::new("PROFINET").op(format!("Frame 0x{frame_id:04X}"), MONITOR));
        return;
    }
    let (service_id, service_type) = (payload[2], payload[3]);
    let data_len = be16(payload, 10).unwrap_or(0) as usize;
    let is_response = service_type & 0x01 == 1;
    let service: Str = match service_id {
        3 => "Get".into(), 4 => "Set".into(), 5 => "Identify".into(), 6 => "Hello".into(),
        s => format!("Service {s}").into(),
    };
    let mut f = Finding::new("PROFINET DCP")
        .op(format!("DCP {service} {}", if is_response { "Response" } else { "Request" }), DISCOVERY)
        .req(Some(!is_response));
    let blocks = &payload[12..(12 + data_len).min(payload.len())];
    let mut i = 0;
    let mut set_targets: Vec<Str> = Vec::new();
    while i + 4 <= blocks.len() {
        let (option, sub) = (blocks[i], blocks[i + 1]);
        let blen = be16(blocks, i + 2).unwrap_or(0) as usize;
        let mut value = &blocks[(i + 4).min(blocks.len())..(i + 4 + blen).min(blocks.len())];
        i += 4 + blen + blen % 2;
        if is_response || service_id == 6 || service_id == 4 {
            value = value.get(2..).unwrap_or(&[]); // BlockInfo / BlockQualifier
        }
        if service_id == 4 && !is_response {
            set_targets.push(dcp_set_target(option, sub));
            continue;
        }
        match (option, sub) {
            (2, 1) => f.identity.model = Some(strip_chars(&latin1(value), &[' ', '\0']).to_string().into()),
            (2, 2) => f.identity.name = Some(strip_chars(&latin1(value), &[' ', '\0']).to_string().into()),
            (2, 3) if value.len() >= 4 => {
                let vendor_id = be16(value, 0).unwrap_or(0);
                f.identity.vendor = Some(match vendor_id {
                    0x002A => "Siemens".into(),
                    0x0019 => "Phoenix Contact".into(),
                    0x011E => "Mitsubishi Electric".into(),
                    v => format!("PROFINET Vendor 0x{v:04X}").into(),
                });
                f.detail("device_id", Detail::Hex(be16(value, 2).unwrap_or(0) as u32, 4));
            }
            (1, 2) if value.len() >= 12 => {
                let ip = be32(value, 0).unwrap_or(0);
                if ip != 0 {
                    f.announced_ip = Some(ip);
                }
            }
            _ => {}
        }
    }
    if is_response && f.identity.fields().iter().any(|(_, v)| v.is_some()) {
        f.role_src = Some("PROFINET device");
        f.device_hint = Some(("PROFINET device".into(), 0.85));
        let model = f.identity.model.as_deref().unwrap_or("").to_uppercase();
        if ["S7-", "CPU", "PLC"].iter().any(|t| model.contains(t)) {
            f.device_hint = Some(("PLC (PROFINET)".into(), 0.9));
        }
    }
    if service_id == 4 && !is_response {
        let joined = set_targets.iter().map(|t| t.as_ref()).collect::<Vec<_>>().join(", ");
        f.category = CONFIG;
        f.operation = format!("DCP Set: {}", if joined.is_empty() { "unknown" } else { &joined }).into();
        let severity = if set_targets.iter().any(|t| t.contains("초기화")) { "critical" } else { "high" };
        f.alert = Some((severity, format!("PROFINET DCP 설정 변경: {joined}").into()));
        f.identity_of_dst = true;
    }
    out.push(f);
}

pub fn simple(protocol: &'static str, operation: &'static str, role: &'static str, hint: &'static str,
              confidence: f32, out: &mut Vec<Finding>) {
    let mut f = Finding::new(protocol).op(operation, MONITOR).hint(hint, confidence);
    f.role_src = Some(role);
    out.push(f);
}

pub fn lldp(payload: &[u8], out: &mut Vec<Finding>) {
    let mut f = Finding::new("LLDP").op("LLDP Advertisement", DISCOVERY);
    let mut i = 0;
    while i + 2 <= payload.len() {
        let header = be16(payload, i).unwrap_or(0);
        let (tlv_type, length) = (header >> 9, (header & 0x01FF) as usize);
        let value = &payload[(i + 2).min(payload.len())..(i + 2 + length).min(payload.len())];
        i += 2 + length;
        match tlv_type {
            0 => break,
            5 => f.identity.name = Some(String::from_utf8_lossy(value).trim().to_string().into()),
            6 => f.identity.description = Some(String::from_utf8_lossy(value).trim().chars().take(200).collect::<String>().into()),
            4 => f.detail("port", Detail::Str(String::from_utf8_lossy(value).trim().to_string())),
            8 if value.len() >= 6 && value[1] == 1 && value[0] == 5 => f.announced_ip = be32(value, 2),
            _ => {}
        }
    }
    out.push(f);
}

pub fn dissect(ethertype: u16, payload: &[u8], out: &mut Vec<Finding>) {
    match ethertype {
        0x88B8 => goose(payload, out),
        0x88BA => sampled_values(payload, out),
        0x8892 => profinet(payload, out),
        0x890F => simple("CC-Link IE", "CC-Link IE frame", "CC-Link IE station",
                         "CC-Link IE station (Mitsubishi ecosystem)", 0.6, out),
        0x88CC => lldp(payload, out),
        0x88A4 => simple("EtherCAT", "EtherCAT frame", "EtherCAT node", "EtherCAT device", 0.55, out),
        0x88AB => simple("POWERLINK", "POWERLINK frame", "POWERLINK node", "POWERLINK device", 0.55, out),
        _ => {}
    }
}
