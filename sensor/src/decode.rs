//! Zero-copy Ethernet / 802.1Q / IPv4 / TCP / UDP / ARP decoder.
//!
//! Addresses are kept as integers (`u32` IPv4, `u64` MAC); strings are only produced when an
//! asset is first created or serialized.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    None, // pure layer-2 frame
    Arp,
    Tcp,
    Udp,
    Icmp,
    Ip(u8),
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
            Transport::Arp => "ARP",
            Transport::Icmp => "ICMP",
            Transport::Ip(_) | Transport::None => "",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub ts_ms: i64,
    pub size: u32,
    pub src_mac: u64,
    pub dst_mac: u64,
    pub ethertype: u16,
    pub vlan: Option<u16>,
    pub src_ip: Option<u32>,
    pub dst_ip: Option<u32>,
    pub transport: Transport,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    /// IPv4 TTL, TCP window and raw TCP options: passive OS fingerprinting.
    pub ttl: u8,
    pub tcp_window: u16,
    pub tcp_options: &'a [u8],
    /// L4 payload for TCP/UDP, L2 payload for non-IP frames.
    pub payload: &'a [u8],
}

#[inline]
pub fn be16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
#[inline]
pub fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(o)?, *d.get(o + 1)?]))
}
#[inline]
pub fn be32(d: &[u8], o: usize) -> Option<u32> {
    let b = d.get(o..o + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
#[inline]
pub fn le32(d: &[u8], o: usize) -> Option<u32> {
    let b = d.get(o..o + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
#[inline]
fn mac_at(d: &[u8], o: usize) -> u64 {
    d[o..o + 6].iter().fold(0u64, |acc, b| (acc << 8) | *b as u64)
}

pub fn mac_string(mac: u64) -> String {
    let b = mac.to_be_bytes();
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[2], b[3], b[4], b[5], b[6], b[7])
}

pub fn ip_string(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

pub fn parse_ip(s: &str) -> Option<u32> {
    s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

pub fn parse_mac(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    parts.iter().try_fold(0u64, |acc, p| u8::from_str_radix(p, 16).ok().map(|b| (acc << 8) | b as u64))
}

/// Unicast host address as the Python engine defined it (no multicast, 0.0.0.0, broadcast, x.x.x.255).
#[inline]
pub fn is_unicast_ip(ip: u32) -> bool {
    let first = (ip >> 24) as u8;
    !((224..=239).contains(&first) || ip == 0 || ip == u32::MAX || ip & 0xFF == 0xFF)
}

#[inline]
pub fn is_unicast_mac(mac: u64) -> bool {
    mac != 0 && (mac >> 40) & 0x01 == 0
}

pub fn is_private_ip(ip: u32) -> bool {
    let a = std::net::Ipv4Addr::from(ip);
    a.is_private() || a.is_loopback() || a.is_link_local() || a.is_unspecified()
        || ip >> 24 == 0 || a.is_documentation() || (ip >> 8) == 0xC0_00_00 // 192.0.0.0/24
        || (ip >> 17) == (198u32 << 7 | 9) // 198.18.0.0/15 benchmarking
        || ip >> 28 == 0xF // 240.0.0.0/4 reserved
}

pub fn decode(data: &[u8], ts_ms: i64) -> Option<Frame<'_>> {
    if data.len() < 14 {
        return None;
    }
    let mut frame = Frame {
        ts_ms,
        size: data.len() as u32,
        dst_mac: mac_at(data, 0),
        src_mac: mac_at(data, 6),
        ethertype: be16(data, 12)?,
        vlan: None,
        src_ip: None,
        dst_ip: None,
        transport: Transport::None,
        src_port: 0,
        dst_port: 0,
        tcp_flags: 0,
        ttl: 0,
        tcp_window: 0,
        tcp_options: &[],
        payload: &[],
    };
    let mut off = 14;
    while matches!(frame.ethertype, 0x8100 | 0x88A8 | 0x9100) && data.len() >= off + 4 {
        frame.vlan = Some(be16(data, off)? & 0x0FFF);
        frame.ethertype = be16(data, off + 2)?;
        off += 4;
    }

    if frame.ethertype == 0x0806 {
        let arp = data.get(off..off + 28)?;
        frame.transport = Transport::Arp;
        frame.src_mac = mac_at(arp, 8);
        frame.src_ip = Some(be32(arp, 14)?);
        frame.dst_mac = mac_at(arp, 18);
        frame.dst_ip = Some(be32(arp, 24)?);
        return Some(frame);
    }
    if frame.ethertype != 0x0800 {
        frame.payload = &data[off..];
        return Some(frame);
    }

    let ip = data.get(off..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    let total_len = be16(ip, 2)? as usize;
    let frag = be16(ip, 6)?;
    let proto = ip[9];
    frame.src_ip = Some(be32(ip, 12)?);
    frame.dst_ip = Some(be32(ip, 16)?);
    frame.ttl = ip[8];
    let ip_end = if total_len > 0 { total_len.min(ip.len()) } else { ip.len() };
    if frag & 0x1FFF != 0 {
        frame.transport = Transport::Ip(proto);
        return Some(frame);
    }
    match proto {
        6 if ip_end >= ihl + 20 => {
            let tcp = &ip[ihl..ip_end];
            frame.transport = Transport::Tcp;
            frame.src_port = be16(tcp, 0)?;
            frame.dst_port = be16(tcp, 2)?;
            frame.tcp_flags = tcp[13];
            frame.tcp_window = be16(tcp, 14)?;
            let data_off = ((tcp[12] >> 4) as usize) * 4;
            frame.tcp_options = tcp.get(20..data_off).unwrap_or(&[]);
            frame.payload = tcp.get(data_off..).unwrap_or(&[]);
        }
        17 if ip_end >= ihl + 8 => {
            let udp = &ip[ihl..ip_end];
            frame.transport = Transport::Udp;
            frame.src_port = be16(udp, 0)?;
            frame.dst_port = be16(udp, 2)?;
            frame.payload = &udp[8..];
        }
        1 => frame.transport = Transport::Icmp,
        p => frame.transport = Transport::Ip(p),
    }
    Some(frame)
}
