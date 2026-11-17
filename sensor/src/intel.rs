//! External address intelligence: who owns an internet address (offline IP-to-ASN database),
//! well-known services, threat lists, names seen on the wire (DNS answers, TLS SNI, HTTP Host),
//! and the port rules used to judge connections to and from the internet.
//!
//! Everything is local: the sensor never queries an outside service about the traffic it sees.

use crate::decode::{be16, be32, Frame, Transport};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

// ------------------------------------------------------------------ ASN database

/// Address ranges -> autonomous system, country and holder (iptoasn.com `ip2asn-v4.tsv[.gz]`,
/// public domain). Ranges are disjoint and sorted, so a lookup is a binary search.
pub struct AsnDb {
    starts: Vec<u32>,
    ends: Vec<u32>,
    asn: Vec<u32>,
    country: Vec<[u8; 2]>,
    holder: Vec<u32>,
    names: Vec<String>,
    pub source: String,
}

pub struct AsnInfo<'a> {
    pub asn: u32,
    pub country: &'a str,
    pub holder: &'a str,
}

fn open_text(path: &Path) -> io::Result<Box<dyn BufRead>> {
    let file = std::fs::File::open(path)?;
    let reader: Box<dyn Read> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(flate2::read::GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    Ok(Box::new(BufReader::with_capacity(1 << 20, reader)))
}

fn parse_v4(s: &str) -> Option<u32> {
    s.trim().parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

impl AsnDb {
    pub fn load(path: &Path) -> io::Result<AsnDb> {
        let mut db = AsnDb { starts: Vec::new(), ends: Vec::new(), asn: Vec::new(), country: Vec::new(),
                             holder: Vec::new(), names: Vec::new(), source: path.display().to_string() };
        let mut index: HashMap<String, u32> = HashMap::new();
        for line in open_text(path)?.lines() {
            let line = line?;
            let mut f = line.split('\t');
            let (Some(start), Some(end), Some(asn), Some(cc), Some(holder)) = (f.next(), f.next(), f.next(), f.next(), f.next())
                else { continue };
            let (Some(start), Some(end), Ok(asn)) = (parse_v4(start), parse_v4(end), asn.trim().parse::<u32>()) else { continue };
            if asn == 0 {
                continue; // "Not routed"
            }
            let id = *index.entry(holder.to_string()).or_insert_with(|| {
                db.names.push(holder.to_string());
                (db.names.len() - 1) as u32
            });
            let cc = cc.as_bytes();
            db.starts.push(start);
            db.ends.push(end);
            db.asn.push(asn);
            db.country.push([*cc.first().unwrap_or(&b'-'), *cc.get(1).unwrap_or(&b'-')]);
            db.holder.push(id);
        }
        if db.starts.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no address ranges found"));
        }
        if db.starts.windows(2).any(|w| w[0] > w[1]) {
            // Keep lookups correct even for a file that is not sorted.
            let mut order: Vec<usize> = (0..db.starts.len()).collect();
            order.sort_by_key(|&i| db.starts[i]);
            let pick = |v: &Vec<u32>| order.iter().map(|&i| v[i]).collect::<Vec<_>>();
            (db.starts, db.ends, db.asn, db.holder) = (pick(&db.starts), pick(&db.ends), pick(&db.asn), pick(&db.holder));
            db.country = order.iter().map(|&i| db.country[i]).collect();
        }
        Ok(db)
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn lookup(&self, ip: u32) -> Option<AsnInfo<'_>> {
        let i = self.starts.partition_point(|&s| s <= ip).checked_sub(1)?;
        (ip <= self.ends[i]).then(|| AsnInfo {
            asn: self.asn[i],
            country: std::str::from_utf8(&self.country[i]).unwrap_or("--"),
            holder: &self.names[self.holder[i] as usize],
        })
    }
}

/// Familiar names for networks that most sites talk to every day.
pub fn well_known(asn: u32) -> Option<&'static str> {
    Some(match asn {
        15169 | 396982 | 36040 | 36384 | 43515 | 139070 => "Google",
        8075 | 8068 | 8069 | 12076 | 3598 | 6584 => "Microsoft",
        16509 | 14618 | 8987 | 38895 => "Amazon AWS",
        13335 | 209242 => "Cloudflare",
        20940 | 16625 | 16702 | 21342 | 33905 | 35994 | 23454 => "Akamai",
        54113 => "Fastly",
        714 | 6185 => "Apple",
        32934 | 63293 => "Meta (Facebook)",
        36459 => "GitHub",
        31898 => "Oracle Cloud",
        45102 | 37963 => "Alibaba Cloud",
        13238 => "Yandex",
        2906 | 40027 => "Netflix",
        23576 | 38099 | 38661 => "NAVER",
        10158 | 38102 | 9764 => "Kakao",
        4766 | 9947 | 17858 | 38369 => "KT",
        9318 | 10049 | 17839 => "SK브로드밴드",
        3786 | 17853 => "LG U+",
        3462 => "HiNet (Chunghwa Telecom)",
        2914 => "NTT",
        174 => "Cogent",
        3356 | 3549 => "Lumen (Level 3)",
        16276 => "OVHcloud",
        24940 => "Hetzner",
        14061 => "DigitalOcean",
        63949 => "Akamai Linode",
        20473 => "Vultr (Choopa)",
        19551 | 55002 => "Imperva",
        30148 => "Sucuri",
        46489 => "Twitch",
        47541 | 47542 => "VK",
        9644 => "SK텔레콤",
        45974 => "NHN Cloud",
        399358 => "Anthropic",
        62014 | 62041 | 59930 => "Telegram",
        30103 => "Zoom",
        19679 => "Dropbox",
        14413 => "LinkedIn",
        13414 => "X (Twitter)",
        14340 => "Salesforce",
        22822 => "Edgio (Limelight)",
        60068 => "CDN77",
        15133 => "Edgecast",
        4808 | 4837 | 4134 => "중국 통신사 (China Unicom/Telecom)",
        _ => return None,
    })
}

/// A readable holder name: the familiar name when known, else the registry holder text without
/// its network handle ("SKTELECOM-NET-AS-KR - SK Telecom" -> "SK Telecom",
/// "TABOOLA-AS Taboola.com ltd" -> "Taboola.com ltd").
pub fn org_label(asn: u32, holder: &str) -> String {
    if let Some(name) = well_known(asn) {
        return name.to_string();
    }
    let holder = holder.trim();
    if let Some((_, name)) = holder.split_once(" - ") {
        return name.trim().to_string();
    }
    let mut words = holder.split_whitespace();
    let (Some(first), Some(second)) = (words.next(), words.next()) else { return holder.to_string() };
    let handle = first.len() > 2 && first.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if handle || first.eq_ignore_ascii_case(second) {
        return holder[first.len()..].trim().to_string();
    }
    holder.to_string()
}

// ------------------------------------------------------------------ threat lists

/// Addresses and networks from threat lists (one entry per line: `address[/prefix]  # source`).
/// Built by `tools/threatintel_build.py` from abuse.ch Feodo Tracker and Spamhaus DROP, and may be
/// extended by hand.
pub struct Blocklist {
    starts: Vec<u32>,
    ends: Vec<u32>,
    max_end: Vec<u32>,
    source: Vec<u16>,
    sources: Vec<String>,
    pub path: String,
}

impl Blocklist {
    pub fn load(path: &Path) -> io::Result<Blocklist> {
        let mut entries: Vec<(u32, u32, u16)> = Vec::new();
        let mut sources: Vec<String> = Vec::new();
        for line in open_text(path)?.lines() {
            let line = line?;
            let (spec, comment) = match line.split_once('#') {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (line.trim(), ""),
            };
            if spec.is_empty() {
                continue;
            }
            let (addr, prefix) = match spec.split_once('/') {
                Some((a, p)) => (a, p.trim().parse::<u32>().ok().filter(|p| *p <= 32)),
                None => (spec, Some(32)),
            };
            let (Some(ip), Some(prefix)) = (parse_v4(addr), prefix) else { continue };
            if prefix < 8 {
                continue; // refuse entries that would cover a large part of the internet
            }
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let source = if comment.is_empty() { "사용자 목록" } else { comment };
            let id = match sources.iter().position(|s| s == source) {
                Some(i) => i,
                None => {
                    sources.push(source.to_string());
                    sources.len() - 1
                }
            };
            entries.push((ip & mask, (ip & mask) | !mask, id as u16));
        }
        entries.sort_unstable();
        let mut max_end = Vec::with_capacity(entries.len());
        let mut m = 0;
        for e in &entries {
            m = m.max(e.1);
            max_end.push(m);
        }
        Ok(Blocklist {
            starts: entries.iter().map(|e| e.0).collect(),
            ends: entries.iter().map(|e| e.1).collect(),
            source: entries.iter().map(|e| e.2).collect(),
            max_end,
            sources,
            path: path.display().to_string(),
        })
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// The list that names this address, if any.
    pub fn lookup(&self, ip: u32) -> Option<&str> {
        let mut i = self.starts.partition_point(|&s| s <= ip);
        while i > 0 {
            i -= 1;
            if self.max_end[i] < ip {
                return None; // no earlier range reaches this far
            }
            if self.ends[i] >= ip {
                return Some(&self.sources[self.source[i] as usize]);
            }
        }
        None
    }
}

// ------------------------------------------------------------------ ports

/// Ordinary internet services (the port a client connects to).
pub fn internet_service(transport: Transport, port: u16) -> Option<&'static str> {
    Some(match (transport, port) {
        (Transport::Udp | Transport::Tcp, 53) => "DNS",
        (Transport::Tcp, 80) => "HTTP",
        (Transport::Tcp, 443) => "HTTPS",
        (Transport::Udp, 443) => "QUIC (HTTP/3)",
        (Transport::Udp, 123) => "NTP",
        (Transport::Tcp, 853) => "DNS over TLS",
        (Transport::Tcp, 25 | 465 | 587) => "메일 (SMTP)",
        (Transport::Tcp, 993) => "메일 (IMAPS)",
        (Transport::Tcp, 995) => "메일 (POP3S)",
        (Transport::Tcp, 22) => "SSH",
        (Transport::Tcp, 21) => "FTP",
        (Transport::Tcp, 5223) => "Apple 푸시",
        (Transport::Tcp, 5228) => "Google 푸시",
        (Transport::Udp, 3478 | 3479 | 19302..=19309) => "STUN/TURN (화상 통화)",
        (Transport::Tcp, 8080 | 8443) => "HTTP (대체 포트)",
        (Transport::Udp, 500 | 4500) => "IPsec VPN",
        (Transport::Udp, 1194) | (Transport::Tcp, 1194) => "OpenVPN",
        (Transport::Udp, 51820) => "WireGuard",
        (Transport::Tcp, 3389) => "원격 데스크톱 (RDP)",
        (Transport::Tcp, 5900..=5903) => "VNC",
        (Transport::Tcp, 445) => "SMB (파일 공유)",
        (Transport::Tcp | Transport::Udp, 1900) => "SSDP",
        _ => return None,
    })
}

/// Remote-access and file-sharing services that should not face the internet from a plant.
pub fn risky_service(transport: Transport, port: u16) -> bool {
    matches!((transport, port), (Transport::Tcp, 21 | 23 | 445 | 3389 | 5900..=5903) | (Transport::Udp, 1900))
}

/// Industrial protocols by port (the service side).
pub fn industrial_service(transport: Transport, port: u16) -> Option<&'static str> {
    Some(match (transport, port) {
        (Transport::Tcp, 102) => "S7comm / IEC 61850 MMS",
        (Transport::Tcp, 502) => "Modbus/TCP",
        (Transport::Tcp | Transport::Udp, 44818) | (Transport::Udp, 2222) => "EtherNet/IP",
        (Transport::Tcp | Transport::Udp, 20000) => "DNP3",
        (Transport::Tcp, 2404) => "IEC 60870-5-104",
        (Transport::Tcp, 4840) => "OPC UA",
        (Transport::Udp, 47808) => "BACnet/IP",
        (Transport::Tcp, 1911 | 4911) => "Niagara Fox",
        (Transport::Tcp | Transport::Udp, 9600) => "Omron FINS",
        (Transport::Tcp | Transport::Udp, 5007) => "MELSEC (SLMP)",
        (Transport::Tcp, 18245 | 18246) => "GE SRTP",
        (Transport::Tcp, 789) => "Red Lion Crimson",
        (Transport::Tcp, 1962) => "PCWorx",
        (Transport::Tcp, 2455) => "CODESYS",
        (Transport::Udp, 34962..=34964) => "PROFINET",
        (Transport::Tcp, 20547) => "ProConOS",
        (Transport::Tcp, 1089..=1091) => "Foundation Fieldbus HSE",
        _ => return None,
    })
}

/// A port that names a service (internet or industrial) rather than a temporary client port.
pub fn known_port(transport: Transport, port: u16) -> bool {
    internet_service(transport, port).is_some() || industrial_service(transport, port).is_some()
}

/// Which side of a conversation offers the service: (service port, client is the source).
pub fn service_side(transport: Transport, src_port: u16, dst_port: u16, tcp_flags: u8) -> (u16, bool) {
    if transport == Transport::Tcp {
        match tcp_flags & 0x12 {
            0x02 => return (dst_port, true),  // SYN: the source opens the connection
            0x12 => return (src_port, false), // SYN-ACK: the source accepts it
            _ => {}
        }
    }
    let known = |p: u16| known_port(transport, p);
    match (known(src_port), known(dst_port)) {
        (false, true) => (dst_port, true),
        (true, false) => (src_port, false),
        _ if dst_port <= src_port => (dst_port, true),
        _ => (src_port, false),
    }
}

// ------------------------------------------------------------------ names on the wire

/// Names learned for internet addresses: DNS answers, TLS server names, HTTP Host headers.
/// Returns (address, name, how it was seen).
pub fn names(frame: &Frame) -> Vec<(u32, String, &'static str)> {
    let p = frame.payload;
    match frame.transport {
        Transport::Udp if frame.src_port == 53 => dns_answers(p),
        Transport::Tcp if p.len() > 43 && p[0] == 0x16 && p[5] == 0x01 => {
            match (frame.dst_ip, tls_sni(p)) {
                (Some(ip), Some(name)) => vec![(ip, name, "TLS SNI")],
                _ => Vec::new(),
            }
        }
        Transport::Tcp if p.len() > 16 && (p.starts_with(b"GET ") || p.starts_with(b"POST ") || p.starts_with(b"HEAD ")) => {
            match (frame.dst_ip, http_host(p)) {
                (Some(ip), Some(name)) => vec![(ip, name, "HTTP Host")],
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

fn valid_name(n: &str) -> bool {
    n.len() >= 3 && n.len() <= 253 && n.contains('.')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        && n.parse::<std::net::Ipv4Addr>().is_err()
}

fn dns_answers(p: &[u8]) -> Vec<(u32, String, &'static str)> {
    let mut out = Vec::new();
    let Some(flags) = be16(p, 2) else { return out };
    if flags & 0x8000 == 0 || flags & 0x000F != 0 {
        return out; // only successful responses
    }
    let (Some(qd), Some(an)) = (be16(p, 4), be16(p, 6)) else { return out };
    if qd != 1 {
        return out;
    }
    let Some((qname, mut off)) = crate::osfp::dns_name(p, 12) else { return out };
    off += 4;
    let qname = qname.to_ascii_lowercase();
    if !valid_name(&qname) {
        return out;
    }
    for _ in 0..an.min(32) {
        let Some((_, next)) = crate::osfp::dns_name(p, off) else { break };
        let (Some(rtype), Some(rdlen)) = (be16(p, next), be16(p, next + 8)) else { break };
        let rdlen = rdlen as usize;
        if rtype == 1 && rdlen == 4
            && let Some(addr) = be32(p, next + 10) {
                out.push((addr, qname.clone(), "DNS"));
            }
        off = next + 10 + rdlen;
    }
    out
}

/// Server name from a TLS ClientHello (first segment of the handshake).
fn tls_sni(p: &[u8]) -> Option<String> {
    let mut o = 5 + 4 + 2 + 32; // record header, handshake header, version, random
    o += 1 + *p.get(o)? as usize; // session id
    o += 2 + be16(p, o)? as usize; // cipher suites
    o += 1 + *p.get(o)? as usize; // compression methods
    let end = (o + 2 + be16(p, o)? as usize).min(p.len());
    o += 2;
    while o + 4 <= end {
        let (kind, len) = (be16(p, o)?, be16(p, o + 2)? as usize);
        if kind == 0 {
            // server_name: list length(2), type(1) = host_name, length(2), name
            let name_len = be16(p, o + 7)? as usize;
            let name = std::str::from_utf8(p.get(o + 9..o + 9 + name_len)?).ok()?.to_ascii_lowercase();
            return valid_name(&name).then_some(name);
        }
        o += 4 + len;
    }
    None
}

fn http_host(p: &[u8]) -> Option<String> {
    let head = &p[..p.len().min(2048)];
    let text = String::from_utf8_lossy(head);
    let host = text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_string())
    })?;
    let host = host.rsplit_once(':').filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h.to_string()).unwrap_or(host).to_ascii_lowercase();
    valid_name(&host).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_ranges_and_sources() {
        let path = std::env::temp_dir().join(format!("neteye-bl-{}.txt", std::process::id()));
        std::fs::write(&path, "# comment\n203.0.113.0/24 # Spamhaus DROP\n198.51.100.7 # Feodo Tracker\n10.0.0.0/4 # too wide\n").unwrap();
        let bl = Blocklist::load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(bl.len(), 2);
        assert_eq!(bl.lookup(u32::from(std::net::Ipv4Addr::new(203, 0, 113, 77))), Some("Spamhaus DROP"));
        assert_eq!(bl.lookup(u32::from(std::net::Ipv4Addr::new(198, 51, 100, 7))), Some("Feodo Tracker"));
        assert_eq!(bl.lookup(u32::from(std::net::Ipv4Addr::new(198, 51, 100, 8))), None);
    }

    #[test]
    fn asn_lookup() {
        let path = std::env::temp_dir().join(format!("neteye-asn-{}.tsv", std::process::id()));
        std::fs::write(&path, "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n9.9.9.0\t9.9.9.255\t0\tNone\tNot routed\n").unwrap();
        let db = AsnDb::load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let g = db.lookup(u32::from(std::net::Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        assert_eq!((g.asn, g.country, org_label(g.asn, g.holder).as_str()), (15169, "US", "Google"));
        assert_eq!(org_label(1, "SOMENET-AS-KR - Some Net"), "Some Net");
        assert_eq!(org_label(1, "TABOOLA-AS Taboola.com ltd"), "Taboola.com ltd");
        assert_eq!(org_label(1, "Acme Acme Messenger Inc"), "Acme Messenger Inc");
        assert_eq!(org_label(1, "Hetzner Online GmbH"), "Hetzner Online GmbH");
        assert!(db.lookup(u32::from(std::net::Ipv4Addr::new(9, 9, 9, 9))).is_none());
        assert!(db.lookup(u32::from(std::net::Ipv4Addr::new(1, 0, 1, 0))).is_none());
    }

    #[test]
    fn service_side_from_flags_and_ports() {
        assert_eq!(service_side(Transport::Tcp, 51000, 443, 0x02), (443, true));
        assert_eq!(service_side(Transport::Tcp, 443, 51000, 0x12), (443, false));
        assert_eq!(service_side(Transport::Tcp, 443, 51000, 0x18), (443, false));
        assert_eq!(service_side(Transport::Udp, 50000, 123, 0), (123, true));
    }
}
