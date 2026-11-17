//! Mitsubishi SLMP/MC, OPC UA, BACnet and port-only signatures.

use super::base::*;
use crate::decode::le16;

fn slmp_command(code: u16) -> Option<(&'static str, &'static str)> {
    Some(match code {
        0x0401 => ("Batch Read", READ), 0x1401 => ("Batch Write", WRITE),
        0x0403 => ("Random Read", READ), 0x1402 => ("Random Write", WRITE),
        0x0406 => ("Multiple Block Batch Read", READ), 0x1406 => ("Multiple Block Batch Write", WRITE),
        0x0101 => ("Read CPU Model", DISCOVERY),
        0x1001 => ("Remote RUN", CONTROL), 0x1002 => ("Remote STOP", CONTROL),
        0x1003 => ("Remote PAUSE", CONTROL), 0x1005 => ("Remote Latch Clear", CONTROL),
        0x1006 => ("Remote RESET", CONTROL), 0x1630 => ("Remote Password Unlock", SESSION),
        0x1631 => ("Remote Password Lock", SESSION),
        _ => return None,
    })
}

/// SLMP / MC protocol 3E binary frame, detected by content on any port.
pub fn slmp(payload: &[u8], _to_server: bool, out: &mut Vec<Finding>) -> bool {
    if payload.len() < 11 || !(payload[0..2] == [0x50, 0x00] || payload[0..2] == [0xD0, 0x00]) {
        return false;
    }
    if payload[3] != 0xFF || le16(payload, 4) != Some(0x03FF) {
        return false;
    }
    if 9 + le16(payload, 7).unwrap_or(0) as usize != payload.len() {
        return false;
    }
    let is_request = payload[0] == 0x50;
    let mut f = Finding::new("Mitsubishi SLMP/MC")
        .req(Some(is_request))
        .roles(is_request, "SLMP client", "SLMP server (MELSEC)")
        .hint("PLC (Mitsubishi MELSEC)", 0.85);
    f.identity_of_dst = is_request;
    f.identity.vendor = Some("Mitsubishi Electric".into());
    if is_request && payload.len() >= 15 {
        let command = le16(payload, 11).unwrap_or(0);
        let sub = le16(payload, 13).unwrap_or(0);
        let (name, category): (Str, &str) = match slmp_command(command) {
            Some((n, c)) => (n.into(), c),
            None => (format!("Command 0x{command:04X}").into(), MONITOR),
        };
        f.function_code = Some(command as u32);
        f.detail("subcommand", Detail::Hex(sub as u32, 4));
        let severity = match command {
            0x1001 | 0x1002 | 0x1003 | 0x1005 | 0x1006 => Some("critical"),
            0x1630 => Some("medium"),
            _ => None,
        };
        if let Some(severity) = severity {
            f.alert = Some((severity, format!("MELSEC PLC {name} 명령").into()));
        }
        f.operation = name;
        f.category = category;
    } else {
        let end_code = le16(payload, 9).unwrap_or(0);
        f.operation = if end_code == 0 { "Response".into() } else { format!("Error Response 0x{end_code:04X}").into() };
        f.category = MONITOR;
        let body = &payload[11..];
        if end_code == 0 && body.len() == 18 {
            let head = &body[..16];
            let trimmed_len = head.iter().rposition(|b| *b != b' ' && *b != 0).map_or(0, |p| p + 1);
            if head[..trimmed_len].iter().all(|b| (32..127).contains(b)) {
                let model = strip_chars(&latin1(head), &[' ', '\0']).to_string();
                if !model.is_empty() {
                    f.identity.model = Some(model.into());
                    f.operation = "Read CPU Model (Response)".into();
                }
            }
        }
    }
    out.push(f);
    true
}

pub fn opcua(payload: &[u8], to_server: bool, out: &mut Vec<Finding>) -> bool {
    if payload.len() < 8 || !matches!(payload[3], b'F' | b'C' | b'A') {
        return false;
    }
    let name = match &payload[0..3] {
        b"HEL" => "Hello",
        b"ACK" => "Acknowledge",
        b"OPN" => "Open Secure Channel",
        b"MSG" => "Message",
        b"CLO" => "Close Secure Channel",
        b"ERR" => "Error",
        _ => return false,
    };
    let mut f = Finding::new("OPC UA")
        .op(name, if &payload[0..3] == b"MSG" { MONITOR } else { SESSION })
        .req(Some(to_server))
        .roles(to_server, "OPC UA client", "OPC UA server")
        .hint("OT server/gateway (OPC UA)", 0.7);
    if &payload[0..3] == b"OPN" && payload.len() > 16 {
        let uri_len = i32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        if uri_len > 0 && uri_len < 200 {
            let policy = latin1(&payload[16..(16 + uri_len as usize).min(payload.len())]);
            f.detail("security_policy", Detail::Str(policy.rsplit('#').next().unwrap_or("").to_string()));
            if policy.ends_with("#None") {
                f.alert = Some(("low", "OPC UA 보안 정책 None(암호화 없음) 사용".into()));
            }
        }
    }
    out.push(f);
    true
}

pub fn bacnet(payload: &[u8], _to_server: bool, out: &mut Vec<Finding>) {
    if payload.len() >= 4 && payload[0] == 0x81 {
        out.push(Finding::new("BACnet/IP").op("BVLC", MONITOR).hint("Building automation device", 0.7));
    }
}

/// (is_tcp, port) -> (protocol, device hint, confidence) for port-only detection.
pub fn port_signature(is_tcp: bool, port: u16) -> Option<(&'static str, &'static str, f32)> {
    Some(match (is_tcp, port) {
        (false, 61450 | 61451) => ("CC-Link IE Field Basic", "CC-Link IE Field Basic station", 0.7),
        (_, 9600) => ("Omron FINS", "PLC (Omron)", 0.7),
        (_, 5094) => ("HART-IP", "HART-IP gateway", 0.65),
        (true, 1217 | 2455) => ("CODESYS", "PLC (CODESYS runtime)", 0.6),
        (true, 18245) => ("GE SRTP", "PLC (GE)", 0.65),
        (true, 1962) => ("PCWorx", "PLC (Phoenix Contact)", 0.65),
        (true, 20547) => ("ProConOS", "PLC (ProConOS)", 0.6),
        (false, 34964) => ("PROFINET CM", "PROFINET device", 0.6),
        (true, 1911) => ("Niagara Fox", "Building automation controller", 0.6),
        (true, 4911) => ("Niagara Fox (TLS)", "Building automation controller", 0.6),
        _ => return None,
    })
}

pub fn port_only(sig: (&'static str, &'static str, f32), to_server: bool, out: &mut Vec<Finding>) {
    let (protocol, hint, confidence) = sig;
    out.push(Finding::new(protocol).op(protocol, MONITOR).req(Some(to_server)).hint(hint, confidence));
}
