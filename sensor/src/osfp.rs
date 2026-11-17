//! Passive host identification: operating system and computer name, from what hosts already send.
//!
//! Sources, roughly from weakest to strongest:
//! - TCP SYN / SYN-ACK fingerprint: initial TTL, window, option order (p0f style, OS family only).
//! - Text a host announces about itself: HTTP User-Agent, SSH banner, SSDP SERVER / USER-AGENT.
//! - DHCP requests: vendor class (option 60), parameter list (55), host name (12).
//! - NetBIOS name registration (UDP 137) and browser announcements (UDP 138, also the Windows
//!   version), mDNS (UDP 5353) and LLMNR (UDP 5355) answers for the host's own address.
//!
//! Everything here describes the *sender* of the packet, except DHCP from 0.0.0.0, which names
//! the client by its hardware address and requested address.

use crate::decode::{self, be16, be32, Frame, Transport};

#[derive(Debug, Clone, PartialEq)]
pub struct OsGuess {
    pub name: String,
    pub confidence: f64,
    pub evidence: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HostInfo {
    pub os: Option<OsGuess>,
    pub hostname: Option<(String, f64)>,
    /// DHCP only: the client this describes (packet source may be 0.0.0.0).
    pub client: Option<(u64, Option<u32>)>,
}

impl HostInfo {
    fn os(name: impl Into<String>, confidence: f64, evidence: impl Into<String>) -> Self {
        HostInfo { os: Some(OsGuess { name: name.into(), confidence, evidence: evidence.into() }), ..Default::default() }
    }
    fn is_empty(&self) -> bool {
        self.os.is_none() && self.hostname.is_none()
    }
}

/// Cheap pre-filter + dispatch. Returns None for the vast majority of frames.
pub fn inspect(frame: &Frame) -> Option<HostInfo> {
    let info = match frame.transport {
        Transport::Tcp => {
            if frame.tcp_flags & 0x02 != 0 {
                frame.src_ip.filter(|&ip| decode::is_private_ip(ip)).and_then(|_| tcp_fingerprint(frame))
            } else if frame.payload.len() >= 8 {
                tcp_text(frame)
            } else {
                None
            }
        }
        Transport::Udp => match (frame.src_port, frame.dst_port) {
            (68, 67) => dhcp(frame.payload),
            (137, _) => netbios_ns(frame.payload),
            (138, _) => browser(frame.payload),
            (1900, _) | (_, 1900) => ssdp(frame.payload),
            (5353, _) | (5355, _) => dns_self_name(frame.payload, frame.src_ip?),
            _ => None,
        },
        _ => None,
    }?;
    (!info.is_empty()).then_some(info)
}

// ------------------------------------------------------------------ TCP fingerprint

fn tcp_fingerprint(frame: &Frame) -> Option<HostInfo> {
    let ttl = frame.ttl;
    let initial = match ttl {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    };
    let (layout, wscale) = tcp_options(frame.tcp_options);
    let win = frame.tcp_window;
    let windows = layout.starts_with("M,N,W,N,N,S") || layout.starts_with("M,N,W,N,N,T");
    let (name, confidence) = match initial {
        128 if windows && (wscale == Some(8) || win == 64240) => ("Windows 10/11 · Server 2016 이상", 0.5),
        128 if windows && wscale == Some(2) && win == 8192 => ("Windows 7/8 · Server 2008/2012", 0.5),
        128 if windows => ("Windows", 0.45),
        128 if layout == "M,N,N,S" || layout == "M,N,N,S,N,N,T" => ("Windows XP/2003 (구형)", 0.4),
        64 if layout.starts_with("M,S,T,N,W") || layout.starts_with("M,N,N,S,N,W") => ("Linux / Android", 0.45),
        64 if layout.starts_with("M,N,W,N,N,T,S") => ("macOS / iOS", 0.45),
        64 if layout.starts_with("M,N,W,S,T") || layout.starts_with("M,N,W,N,N,S") => ("FreeBSD 계열", 0.4),
        255 if layout == "M" && win == 4128 => ("Cisco IOS", 0.45),
        255 if layout.starts_with("N,N,T,M,N,W") => ("Solaris", 0.4),
        32 | 64 | 255 if layout.is_empty() || layout == "M" => ("임베디드 TCP/IP 스택 (RTOS)", 0.35),
        _ => return None,
    };
    let kind = if frame.tcp_flags & 0x10 != 0 { "SYN-ACK" } else { "SYN" };
    let layout = if layout.is_empty() { "없음".to_string() } else { layout };
    Some(HostInfo::os(name, confidence,
        format!("TCP {kind} 지문: TTL {ttl}(초기 {initial}), 윈도 {win}, 옵션 {layout}")))
}

/// Option order as letters (M=MSS N=NOP W=window scale S=SACK-permitted T=timestamp E=EOL).
fn tcp_options(opts: &[u8]) -> (String, Option<u8>) {
    let mut out: Vec<&str> = Vec::new();
    let mut wscale = None;
    let mut i = 0;
    while i < opts.len() && out.len() < 16 {
        match opts[i] {
            0 => { out.push("E"); break; }
            1 => { out.push("N"); i += 1; continue; }
            kind => {
                let Some(&len) = opts.get(i + 1) else { break };
                if len < 2 { break; }
                match kind {
                    2 => out.push("M"),
                    3 => { out.push("W"); wscale = opts.get(i + 2).copied(); }
                    4 => out.push("S"),
                    8 => out.push("T"),
                    _ => out.push("?"),
                }
                i += len as usize;
            }
        }
    }
    (out.join(","), wscale)
}

// ------------------------------------------------------------------ announced software

/// Operating system named in a User-Agent, SERVER header or SSH banner.
pub fn os_from_text(text: &str) -> Option<(String, f64)> {
    let t = text;
    let after = |key: &str| -> Option<String> {
        let start = t.find(key)? + key.len();
        Some(t[start..].chars().take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '_').collect::<String>()
            .replace('_', "."))
    };
    if let Some(v) = after("Windows NT ") {
        let name = match v.as_str() {
            "10.0" => "Windows 10/11",
            "6.3" => "Windows 8.1",
            "6.2" => "Windows 8",
            "6.1" => "Windows 7",
            "6.0" => "Windows Vista",
            "5.1" | "5.2" => "Windows XP/2003",
            _ => "Windows",
        };
        return Some((name.into(), 0.75));
    }
    if let Some(v) = after("Microsoft-Windows/") {
        return Some((if v.starts_with("10.") { "Windows 10/11".into() } else { format!("Windows {v}") }, 0.7));
    }
    if t.contains("OpenSSH_for_Windows") || t.contains("Microsoft-CryptoAPI") || t.contains("Windows-Update-Agent")
        || t.contains("Microsoft-Delivery-Optimization") {
        return Some(("Windows".into(), 0.7));
    }
    if let Some(v) = after("iPhone OS ") {
        return Some((format!("iOS {v}"), 0.75));
    }
    if t.contains("iPad") || t.contains("iPhone") {
        return Some(("iOS".into(), 0.65));
    }
    if let Some(v) = after("Mac OS X ") {
        return Some((if v.is_empty() { "macOS".into() } else { format!("macOS {v}") }, 0.7));
    }
    if t.contains("Darwin/") || t.contains("Macintosh") {
        return Some(("macOS".into(), 0.6));
    }
    if let Some(v) = after("Android ").or_else(|| after("Android/")) {
        return Some((if v.is_empty() { "Android".into() } else { format!("Android {v}") }, 0.75));
    }
    if t.contains("CrOS") {
        return Some(("ChromeOS".into(), 0.7));
    }
    for (needle, name) in [("Ubuntu", "Ubuntu Linux"), ("Debian", "Debian Linux"), ("Raspbian", "Raspberry Pi OS"),
                           ("CentOS", "CentOS Linux"), ("Red Hat", "Red Hat Enterprise Linux"), ("Fedora", "Fedora Linux")] {
        if t.contains(needle) {
            return Some((name.into(), 0.75));
        }
    }
    if t.contains("FreeBSD") {
        return Some(("FreeBSD".into(), 0.75));
    }
    if t.starts_with("SSH-") {
        if t.contains("Cisco") {
            return Some(("Cisco IOS".into(), 0.8));
        }
        if t.contains("ROSSSH") {
            return Some(("MikroTik RouterOS".into(), 0.8));
        }
        if t.to_ascii_lowercase().contains("dropbear") {
            return Some(("임베디드 Linux (Dropbear)".into(), 0.6));
        }
        if t.contains("OpenSSH") {
            return Some(("Linux / Unix".into(), 0.5));
        }
    }
    if let Some(v) = after("Linux/") {
        return Some((if v.is_empty() { "Linux".into() } else { format!("Linux {}", major_minor(&v)) }, 0.6));
    }
    if t.contains("Linux") {
        return Some(("Linux".into(), 0.55));
    }
    None
}

fn major_minor(v: &str) -> String {
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// SSH banners and HTTP requests in the first segment of a TCP stream.
fn tcp_text(frame: &Frame) -> Option<HostInfo> {
    let p = frame.payload;
    if p.starts_with(b"SSH-") {
        let line = p.split(|&b| b == b'\r' || b == b'\n').next()?;
        let banner = std::str::from_utf8(line).ok()?;
        let (name, confidence) = os_from_text(banner)?;
        return Some(HostInfo::os(name, confidence, format!("SSH 배너: {}", clip(banner))));
    }
    let method = p.iter().position(|&b| b == b' ').filter(|&n| (3..=7).contains(&n))?;
    if !p[..method].iter().all(u8::is_ascii_uppercase) {
        return None;
    }
    let head = &p[..p.len().min(2048)];
    let text = std::str::from_utf8(head).unwrap_or_else(|e| std::str::from_utf8(&head[..e.valid_up_to()]).unwrap());
    let agent = header(text, "User-Agent")?;
    let (name, confidence) = os_from_text(agent)?;
    Some(HostInfo::os(name, confidence, format!("HTTP User-Agent: {}", clip(agent))))
}

fn ssdp(p: &[u8]) -> Option<HostInfo> {
    let text = std::str::from_utf8(&p[..p.len().min(1500)]).ok()?;
    let (field, value) = header(text, "SERVER").map(|v| ("SERVER", v))
        .or_else(|| header(text, "USER-AGENT").map(|v| ("USER-AGENT", v)))?;
    let (name, confidence) = os_from_text(value)?;
    Some(HostInfo::os(name, confidence, format!("SSDP {field}: {}", clip(value))))
}

fn clip(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(120).collect();
    s
}

// ------------------------------------------------------------------ DHCP

fn dhcp(p: &[u8]) -> Option<HostInfo> {
    if p.len() < 240 || p[0] != 1 || be32(p, 236)? != 0x6382_5363 {
        return None;
    }
    let mac = p[28..34].iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
    let ciaddr = be32(p, 12).filter(|&ip| ip != 0);
    let (mut hostname, mut vendor, mut params, mut requested) = (None, None, None, None);
    let mut i = 240;
    while i + 1 < p.len() {
        let code = p[i];
        if code == 255 { break; }
        if code == 0 { i += 1; continue; }
        let len = p[i + 1] as usize;
        let Some(value) = p.get(i + 2..i + 2 + len) else { break };
        match code {
            12 => hostname = Some(String::from_utf8_lossy(value).trim_end_matches('\0').to_string()),
            50 if len == 4 => requested = be32(value, 0),
            55 => params = Some(value),
            60 => vendor = Some(String::from_utf8_lossy(value).to_string()),
            _ => {}
        }
        i += 2 + len;
    }
    let mut info = HostInfo { client: Some((mac, ciaddr.or(requested))), ..Default::default() };
    if let Some(name) = hostname.filter(|h| valid_hostname(h)) {
        info.hostname = Some((name, 0.8));
    }
    let os = vendor.as_deref().and_then(|v| {
        let (name, confidence) = if v.starts_with("MSFT 5.0") {
            ("Windows".to_string(), 0.7)
        } else if let Some(rest) = v.strip_prefix("android-dhcp-") {
            (format!("Android {rest}"), 0.75)
        } else if v.starts_with("dhcpcd") {
            // e.g. "dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:BCM2835"
            let kernel = v.split(':').find_map(|f| f.strip_prefix("Linux-")).map(major_minor);
            (kernel.map(|k| format!("Linux {k}")).unwrap_or_else(|| "Linux".into()), 0.65)
        } else if v.starts_with("udhcp") {
            ("임베디드 Linux (BusyBox)".into(), 0.6)
        } else {
            return None;
        };
        Some(OsGuess { name, confidence, evidence: format!("DHCP 벤더 클래스: {}", clip(v)) })
    }).or_else(|| {
        // Apple clients send no vendor class but a recognisable parameter list.
        let params = params?;
        params.starts_with(&[1, 121, 3, 6, 15]).then(|| params.contains(&108) || params.contains(&114))
            .filter(|&apple| apple)
            .map(|_| OsGuess { name: "macOS / iOS".into(), confidence: 0.6, evidence: "DHCP 요청 옵션 순서 (Apple)".into() })
    });
    info.os = os;
    Some(info)
}

/// Stored results that later rules no longer support (re-checked when the database loads).
pub fn stale_os(ip: Option<u32>, os: &str, evidence: &str) -> bool {
    (evidence.starts_with("TCP ") && ip.is_some_and(|ip| !decode::is_private_ip(ip))) || os.starts_with("Windows (버전")
}

pub fn valid_hostname(h: &str) -> bool {
    let identifier = h.len() >= 24 && h.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    !h.is_empty() && h.len() <= 63 && !identifier
        && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// ------------------------------------------------------------------ NetBIOS

/// First-level decoding of a NetBIOS name (32 letters 'A'..'P' -> 16 bytes): name and suffix.
fn netbios_name(encoded: &[u8]) -> Option<(String, u8)> {
    if encoded.len() < 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (i, pair) in encoded[..32].chunks(2).enumerate() {
        let (a, b) = (pair[0].checked_sub(b'A')?, pair[1].checked_sub(b'A')?);
        if a > 15 || b > 15 {
            return None;
        }
        raw[i] = (a << 4) | b;
    }
    let name = String::from_utf8_lossy(&raw[..15]).trim_end().to_string();
    Some((name, raw[15]))
}

/// Name registration / refresh: a host claiming its unique workstation or server name.
fn netbios_ns(p: &[u8]) -> Option<HostInfo> {
    let flags = be16(p, 2)?;
    let opcode = (flags >> 11) & 0xF;
    if flags & 0x8000 != 0 || !matches!(opcode, 5 | 8 | 9) || p.get(12) != Some(&0x20) {
        return None;
    }
    let (name, suffix) = netbios_name(p.get(13..45)?)?;
    // Additional record: pointer(2) type(2) class(2) ttl(4) rdlength(2) nb_flags(2) address(4)
    let nb_flags = be16(p, 12 + 34 + 4 + 12)?;
    if nb_flags & 0x8000 != 0 || !matches!(suffix, 0x00 | 0x20) || !valid_hostname(&name) || name == "*" {
        return None;
    }
    Some(HostInfo { hostname: Some((name, 0.75)), ..Default::default() })
}

/// Browser "Host Announcement" on \MAILSLOT\BROWSE: computer name and Windows version.
fn browser(p: &[u8]) -> Option<HostInfo> {
    const SLOT: &[u8] = b"\\MAILSLOT\\BROWSE\0";
    let at = p.windows(SLOT.len()).position(|w| w == SLOT)? + SLOT.len();
    let d = p.get(at..)?;
    if !matches!(d.first(), Some(0x01 | 0x0F)) || d.len() < 32 {
        return None;
    }
    let name = String::from_utf8_lossy(&d[6..22]).trim_end_matches('\0').trim().to_string();
    let (major, minor) = (d[22], d[23]);
    let server_type = u32::from_le_bytes([d[24], d[25], d[26], d[27]]);
    let mut info = HostInfo::default();
    if valid_hostname(&name) {
        info.hostname = Some((name, 0.85));
    }
    let os = if server_type & 0x0000_0800 != 0 {
        "Linux / Unix (Samba)".to_string()
    } else {
        match (major, minor) {
            (10, 0) => "Windows 10/11 · Server 2016 이상".into(),
            (6, 3) => "Windows 8.1 · Server 2012 R2".into(),
            (6, 2) => "Windows 8 · Server 2012".into(),
            (6, 1) => "Windows 7 · Server 2008 R2".into(),
            (6, 0) => "Windows Vista · Server 2008".into(),
            (5, 1) | (5, 2) => "Windows XP/2003".into(),
            _ => String::new(),
        }
    };
    if !os.is_empty() {
        info.os = Some(OsGuess { name: os, confidence: 0.75, evidence: format!("NetBIOS 브라우저 알림: OS 버전 {major}.{minor}") });
    }
    Some(info)
}

// ------------------------------------------------------------------ mDNS / LLMNR

/// A DNS name at `off` (with compression); returns the name and the offset after it.
fn dns_name(p: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..32 {
        let len = *p.get(off)? as usize;
        if len == 0 {
            off += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = (be16(p, off)? & 0x3FFF) as usize;
            end.get_or_insert(off + 2);
            off = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(p.get(off + 1..off + 1 + len)?).to_string());
        off += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(off)))
}

/// Answers in which a host announces an A record for its own address.
fn dns_self_name(p: &[u8], src_ip: u32) -> Option<HostInfo> {
    let flags = be16(p, 2)?;
    if flags & 0x8000 == 0 {
        return None; // queries, not answers
    }
    let (qd, an) = (be16(p, 4)? as usize, be16(p, 6)? as usize);
    let mut off = 12;
    for _ in 0..qd.min(16) {
        off = dns_name(p, off)?.1 + 4;
    }
    for _ in 0..an.min(32) {
        let (name, next) = dns_name(p, off)?;
        let (rtype, rdlen) = (be16(p, next)?, be16(p, next + 8)? as usize);
        let rdata = p.get(next + 10..next + 10 + rdlen)?;
        if rtype == 1 && rdlen == 4 && be32(rdata, 0)? == src_ip {
            let host = name.trim_end_matches('.').trim_end_matches(".local").to_string();
            if valid_hostname(&host) && !host.contains("._") {
                return Some(HostInfo { hostname: Some((host, 0.7)), ..Default::default() });
            }
        }
        off = next + 10 + rdlen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_sources_name_the_os() {
        assert_eq!(os_from_text("Mozilla/5.0 (Windows NT 10.0; Win64; x64)").unwrap().0, "Windows 10/11");
        assert_eq!(os_from_text("Mozilla/5.0 (Windows NT 6.1)").unwrap().0, "Windows 7");
        assert_eq!(os_from_text("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6").unwrap().0, "Ubuntu Linux");
        assert_eq!(os_from_text("SSH-2.0-OpenSSH_for_Windows_8.1").unwrap().0, "Windows");
        assert_eq!(os_from_text("Linux/4.9.253, UPnP/1.0, Portable SDK").unwrap().0, "Linux 4.9");
        assert_eq!(os_from_text("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X)").unwrap().0, "iOS 17.1");
        assert_eq!(os_from_text("Dalvik/2.1.0 (Linux; U; Android 13; SM-S911N)").unwrap().0, "Android 13");
        assert_eq!(os_from_text("Microsoft-CryptoAPI/10.0").unwrap().0, "Windows");
        assert!(os_from_text("curl/8.4.0").is_none());
    }

    #[test]
    fn tcp_options_layout() {
        let win10 = [2, 4, 5, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2];
        assert_eq!(tcp_options(&win10), ("M,N,W,N,N,S".to_string(), Some(8)));
        let linux = [2, 4, 5, 0xB4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7];
        assert_eq!(tcp_options(&linux).0, "M,S,T,N,W");
    }

    #[test]
    fn identifiers_are_not_hostnames() {
        assert!(valid_hostname("DESKTOP-0B8LAQQ"));
        assert!(!valid_hostname("39e64da0-50d4-5b9c-7c6f-a7cd75ba264d"));
    }

    #[test]
    fn netbios_names_decode() {
        // "DESKTOP-01" padded to 15 with spaces, suffix 0x00
        let mut raw = *b"DESKTOP-01     \0";
        raw[15] = 0;
        let enc: Vec<u8> = raw.iter().flat_map(|b| [b'A' + (b >> 4), b'A' + (b & 0xF)]).collect();
        assert_eq!(netbios_name(&enc), Some(("DESKTOP-01".to_string(), 0)));
    }
}
