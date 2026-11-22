//! On-demand non-root LAN discovery for mobile (Android) and desktop environments without SPAN/libpcap.
//!
//! Never runs automatically — only triggered explicitly via `POST /api/discover` (Operator+).
//! Uses standard unprivileged TCP/UDP sockets only (no raw sockets / CAP_NET_RAW):
//! - Multicast SSDP (UDP 1900) and mDNS (UDP 5353)
//! - Subnet broadcast EtherNet/IP ListIdentity (UDP 44818) and BACnet Who-Is (UDP 47808)
//! - Fast bounded TCP connect sweep across a private /24 (max 254 hosts) with safe read-only
//!   banner/identification grabs (SSH, HTTP, Modbus MEI, EtherNet/IP ListIdentity)
//! - ConnectionRefused (TCP RST) detection to discover quiet alive LAN hosts with no open ports.

use crate::decode;
use crate::engine::Engine;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const WORKER_THREADS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);
const BANNER_TIMEOUT: Duration = Duration::from_millis(250);

/// Curated OT/ICS + common IT ports to probe on each private LAN host.
const PROBE_PORTS: &[u16] = &[
    // OT/ICS protocols
    502,   // Modbus/TCP
    102,   // Siemens S7comm / IEC 61850 MMS
    44818, // EtherNet/IP (CIP)
    2404,  // IEC 60870-5-104
    20000, // DNP3
    4840,  // OPC UA
    // Common LAN / device services
    80,    // HTTP
    443,   // HTTPS
    22,    // SSH
    445,   // SMB (Windows / NAS)
    53,    // DNS (Router / Gateway)
    8080,  // HTTP Alt
    554,   // RTSP (IP Camera)
    631,   // IPP (Printer)
    62078, // Apple iOS/macOS
];

#[derive(Clone, Debug)]
pub struct LanTarget {
    pub local_ip: Ipv4Addr,
    pub network: u32,
    pub prefix: u8,
    pub cidr: String,
    pub hosts: Vec<Ipv4Addr>,
    pub broadcast: Ipv4Addr,
}

#[derive(Default)]
struct ScanResult {
    alive: HashSet<Ipv4Addr>,
    frames: Vec<Vec<u8>>,
    services: usize,
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Detect the active local IPv4 address using a non-transmitting UDP route lookup.
pub fn detect_local_ipv4() -> Option<Ipv4Addr> {
    for probe in ["192.0.2.1:80", "10.255.255.1:80", "192.168.1.1:80"] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0")
            && sock.connect(probe).is_ok()
            && let Ok(SocketAddr::V4(addr)) = sock.local_addr()
        {
            let ip = *addr.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                return Some(ip);
            }
        }
    }
    if let Ok(env_cidr) = std::env::var("NETEYE_LAN_CIDR")
        && let Some((ip_s, _)) = env_cidr.split_once('/')
        && let Ok(ip) = ip_s.trim().parse::<Ipv4Addr>()
        && !ip.is_loopback()
    {
        return Some(ip);
    }
    None
}

/// Parse and validate a private LAN CIDR (clamped to /24../30, max 254 hosts).
pub fn resolve_target(requested_cidr: Option<&str>) -> Result<LanTarget, String> {
    let detected = detect_local_ipv4();
    let (base_ip, prefix) = if let Some(raw) = requested_cidr.map(str::trim).filter(|s| !s.is_empty()) {
        parse_cidr(raw)?
    } else if let Some(ip) = detected {
        let mut pfx = 24u8;
        if let Ok(env_cidr) = std::env::var("NETEYE_LAN_CIDR")
            && let Ok((env_ip, env_p)) = parse_cidr(&env_cidr)
            && (u32::from(env_ip) & !0xFF) == (u32::from(ip) & !0xFF)
        {
            pfx = env_p.max(24);
        }
        (ip, pfx)
    } else if let Ok(env_cidr) = std::env::var("NETEYE_LAN_CIDR") {
        parse_cidr(&env_cidr)?
    } else {
        return Err("Could not detect an active Wi-Fi or LAN IPv4 address. Connect to a local network or specify a /24 subnet.".to_string());
    };

    let ip_u32 = u32::from(base_ip);
    if !is_allowed_lan_ip(ip_u32) {
        return Err(format!("Refusing to scan non-private address {base_ip}. Only RFC1918/link-local LAN subnets are allowed."));
    }
    if !(24..=30).contains(&prefix) {
        return Err(format!("Subnet prefix /{prefix} is out of range (must be /24 through /30, max 254 hosts)."));
    }

    let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let network = ip_u32 & mask;
    let bcast_u32 = network | !mask;
    let local_ip = detected.unwrap_or(base_ip);

    let mut hosts = Vec::new();
    for addr in (network + 1)..bcast_u32 {
        let h = Ipv4Addr::from(addr);
        if h != local_ip {
            hosts.push(h);
        }
    }
    let cidr = format!("{}/{prefix}", Ipv4Addr::from(network));
    Ok(LanTarget {
        local_ip,
        network,
        prefix,
        cidr,
        hosts,
        broadcast: Ipv4Addr::from(bcast_u32),
    })
}

fn parse_cidr(raw: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip_str, pfx_str) = match raw.split_once('/') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (raw.trim(), "24"),
    };
    let ip: Ipv4Addr = ip_str.parse().map_err(|_| format!("Invalid IPv4 address: {ip_str}"))?;
    let prefix: u8 = pfx_str.parse().map_err(|_| format!("Invalid subnet prefix: /{pfx_str}"))?;
    Ok((ip, prefix))
}

fn is_allowed_lan_ip(ip: u32) -> bool {
    let a = (ip >> 24) as u8;
    let b = ((ip >> 16) & 0xFF) as u8;
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b))
}

/// Read `/proc/net/arp` when available (Linux & older Android) to enrich MAC addresses.
fn read_arp_table() -> HashMap<Ipv4Addr, [u8; 6]> {
    let mut map = HashMap::new();
    let Ok(text) = std::fs::read_to_string("/proc/net/arp") else { return map };
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4
            && let Ok(ip) = cols[0].parse::<Ipv4Addr>()
            && let Some(mac) = parse_mac(cols[3])
            && mac != [0u8; 6]
        {
            map.insert(ip, mac);
        }
    }
    map
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

/// Deterministic locally-administered unicast MAC for synthetic frames when real L2 MAC is unavailable.
fn synthetic_mac(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, 0x4E, o[0], o[1], o[2], o[3]]
}

fn build_ether(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + payload.len());
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, l4: &[u8]) -> Vec<u8> {
    let total = (20 + l4.len()).min(u16::MAX as usize) as u16;
    let mut out = Vec::with_capacity(20 + l4.len());
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 64, proto, 0, 0]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(l4);
    out
}

fn build_tcp_frame(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    payload: &[u8],
    smac: [u8; 6],
    dmac: [u8; 6],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(20 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 5 << 4, flags, 0xFA, 0xF0, 0, 0, 0, 0]);
    seg.extend_from_slice(payload);
    build_ether(dmac, smac, 0x0800, &build_ipv4(src_ip, dst_ip, 6, &seg))
}

fn build_udp_frame(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
    smac: [u8; 6],
    dmac: [u8; 6],
) -> Vec<u8> {
    let mut seg = Vec::with_capacity(8 + payload.len());
    seg.extend_from_slice(&sport.to_be_bytes());
    seg.extend_from_slice(&dport.to_be_bytes());
    seg.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    seg.extend_from_slice(&[0, 0]);
    seg.extend_from_slice(payload);
    build_ether(dmac, smac, 0x0800, &build_ipv4(src_ip, dst_ip, 17, &seg))
}

/// Synthetic ARP reply frame so alive hosts without open TCP ports appear on the map cleanly.
fn build_arp_announce(ip: Ipv4Addr, mac: [u8; 6], target_ip: Ipv4Addr, target_mac: [u8; 6]) -> Vec<u8> {
    let mut arp = Vec::with_capacity(28);
    arp.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]); // Ethernet/IPv4 reply
    arp.extend_from_slice(&mac);
    arp.extend_from_slice(&ip.octets());
    arp.extend_from_slice(&target_mac);
    arp.extend_from_slice(&target_ip.octets());
    build_ether(target_mac, mac, 0x0806, &arp)
}

/// Safe read-only probes over UDP multicast/broadcast (SSDP, mDNS, EtherNet/IP ListIdentity, BACnet Who-Is).
fn run_udp_discovery(target: &LanTarget, arp: &HashMap<Ipv4Addr, [u8; 6]>) -> ScanResult {
    let mut res = ScanResult::default();
    let local_mac = *arp.get(&target.local_ip).unwrap_or(&synthetic_mac(target.local_ip));

    // 1) SSDP M-SEARCH (239.255.255.250:1900)
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
        let req = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
        let _ = sock.send_to(req, "239.255.255.250:1900");
        let deadline = Instant::now() + Duration::from_millis(900);
        let mut buf = [0u8; 2048];
        while Instant::now() < deadline {
            match sock.recv_from(&mut buf) {
                Ok((n, SocketAddr::V4(from))) if *from.ip() != target.local_ip => {
                    let ip = *from.ip();
                    let mac = *arp.get(&ip).unwrap_or(&synthetic_mac(ip));
                    res.alive.insert(ip);
                    res.frames.push(build_udp_frame(ip, target.local_ip, 1900, 51900, &buf[..n], mac, local_mac));
                }
                _ => break,
            }
        }
    }

    // 2) mDNS PTR query for local hosts/services (224.0.0.251:5353)
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
        // DNS standard query: _services._dns-sd._udp.local PTR IN (unicast-response bit set)
        let mdns_q: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            9, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's',
            7, b'_', b'd', b'n', b's', b'-', b's', b'd',
            4, b'_', b'u', b'd', b'p',
            5, b'l', b'o', b'c', b'a', b'l', 0,
            0x00, 0x0c, 0x80, 0x01,
        ];
        let _ = sock.send_to(mdns_q, "224.0.0.251:5353");
        let deadline = Instant::now() + Duration::from_millis(800);
        let mut buf = [0u8; 2048];
        while Instant::now() < deadline {
            match sock.recv_from(&mut buf) {
                Ok((n, SocketAddr::V4(from))) if *from.ip() != target.local_ip => {
                    let ip = *from.ip();
                    let mac = *arp.get(&ip).unwrap_or(&synthetic_mac(ip));
                    res.alive.insert(ip);
                    res.frames.push(build_udp_frame(ip, target.local_ip, 5353, 5353, &buf[..n], mac, local_mac));
                }
                _ => break,
            }
        }
    }

    // 3) EtherNet/IP ListIdentity broadcast (UDP 44818) & BACnet Who-Is (UDP 47808)
    for (port, probe) in [
        (44818u16, &[0x63u8, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..]),
        (47808u16, &[0x81u8, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08][..]),
    ] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            let _ = sock.set_broadcast(true);
            let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
            let _ = sock.send_to(probe, SocketAddrV4::new(target.broadcast, port));
            let deadline = Instant::now() + Duration::from_millis(600);
            let mut buf = [0u8; 2048];
            while Instant::now() < deadline {
                match sock.recv_from(&mut buf) {
                    Ok((n, SocketAddr::V4(from))) if *from.ip() != target.local_ip => {
                        let ip = *from.ip();
                        let mac = *arp.get(&ip).unwrap_or(&synthetic_mac(ip));
                        res.alive.insert(ip);
                        res.services += 1;
                        res.frames.push(build_udp_frame(target.local_ip, ip, 52000, port, probe, local_mac, mac));
                        res.frames.push(build_udp_frame(ip, target.local_ip, port, 52000, &buf[..n], mac, local_mac));
                    }
                    _ => break,
                }
            }
        }
    }

    res
}

/// Safe read-only banner / identification probe on an already-connected TCP service.
fn grab_service_banner(port: u16, host: Ipv4Addr, stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let _ = stream.set_read_timeout(Some(BANNER_TIMEOUT));
    let _ = stream.set_write_timeout(Some(BANNER_TIMEOUT));
    let mut buf = [0u8; 1024];
    match port {
        22 => {
            // SSH servers immediately send their banner upon connect.
            let n = stream.read(&mut buf).ok()?;
            (n > 0).then(|| (Vec::new(), buf[..n].to_vec()))
        }
        80 | 8080 => {
            let req = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: NetEye\r\n\r\n");
            let _ = stream.write_all(req.as_bytes());
            let n = stream.read(&mut buf).ok()?;
            (n > 0).then(|| (req.into_bytes(), buf[..n].to_vec()))
        }
        502 => {
            // Modbus/TCP Read Device Identification (MEI FC 43 / 0x0E, basic read-only)
            let req = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00];
            let _ = stream.write_all(&req);
            let n = stream.read(&mut buf).ok()?;
            (n >= 9).then(|| (req, buf[..n].to_vec()))
        }
        44818 => {
            // EtherNet/IP List Identity (0x0063, read-only)
            let mut req = vec![0u8; 24];
            req[0] = 0x63;
            let _ = stream.write_all(&req);
            let n = stream.read(&mut buf).ok()?;
            (n >= 24).then(|| (req, buf[..n].to_vec()))
        }
        _ => None,
    }
}

/// Run the full on-demand LAN discovery sweep and feed discovered hosts/services into `engine`.
pub fn scan_lan<F>(
    engine: &Arc<Mutex<Engine>>,
    requested_cidr: Option<&str>,
    on_progress: F,
) -> Result<Value, String>
where
    F: Fn(usize, usize, usize) + Send + Sync,
{
    let target = resolve_target(requested_cidr)?;
    let started = Instant::now();
    let total = target.hosts.len();
    on_progress(0, total, 0);

    let arp_before = read_arp_table();
    let mut combined = run_udp_discovery(&target, &arp_before);

    // Parallel bounded TCP connect sweep across the /24 hosts.
    let next_idx = AtomicUsize::new(0);
    let done_hosts = AtomicUsize::new(0);
    let found_hosts = AtomicUsize::new(combined.alive.len());
    let shared_frames: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
    let shared_alive: Mutex<HashSet<Ipv4Addr>> = Mutex::new(HashSet::new());
    let shared_services = AtomicUsize::new(combined.services);

    let local_mac = *arp_before.get(&target.local_ip).unwrap_or(&synthetic_mac(target.local_ip));
    let threads = WORKER_THREADS.min(total.max(1));

    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let i = next_idx.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let host = target.hosts[i];
                    let mut host_alive = false;
                    let mut open_ports = Vec::new();
                    let mut host_frames = Vec::new();
                    let host_mac = *arp_before.get(&host).unwrap_or(&synthetic_mac(host));

                    for (p_idx, &port) in PROBE_PORTS.iter().enumerate() {
                        let addr = SocketAddr::new(IpAddr::V4(host), port);
                        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                            Ok(mut stream) => {
                                host_alive = true;
                                open_ports.push(port);
                                let sport = 54000u16.wrapping_add((i as u16 * 17 + p_idx as u16) % 9000);
                                host_frames.push(build_tcp_frame(target.local_ip, host, sport, port, 0x02, &[], local_mac, host_mac));
                                host_frames.push(build_tcp_frame(host, target.local_ip, port, sport, 0x12, &[], host_mac, local_mac));
                                if let Some((req, resp)) = grab_service_banner(port, host, &mut stream) {
                                    if !req.is_empty() {
                                        host_frames.push(build_tcp_frame(target.local_ip, host, sport, port, 0x18, &req, local_mac, host_mac));
                                    }
                                    host_frames.push(build_tcp_frame(host, target.local_ip, port, sport, 0x18, &resp, host_mac, local_mac));
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                                // Host kernel replied with TCP RST -> host is definitely alive on the LAN.
                                host_alive = true;
                            }
                            Err(_) => {
                                // If the first 3 most-common ports all time out on a host not yet seen alive,
                                // assume the IP is unoccupied to keep /24 sweeps under ~3-4 seconds.
                                if !host_alive && p_idx >= 8 {
                                    break;
                                }
                            }
                        }
                    }

                    if host_alive {
                        if open_ports.is_empty() {
                            host_frames.push(build_arp_announce(host, host_mac, target.local_ip, local_mac));
                        }
                        shared_services.fetch_add(open_ports.len(), Ordering::Relaxed);
                        let newly = shared_alive.lock().insert(host);
                        if newly {
                            found_hosts.fetch_add(1, Ordering::Relaxed);
                        }
                        shared_frames.lock().extend(host_frames);
                    }
                    let done = done_hosts.fetch_add(1, Ordering::Relaxed) + 1;
                    if done % 8 == 0 || done == total {
                        on_progress(done, total, found_hosts.load(Ordering::Relaxed));
                    }
                }
            });
        }
    });

    // Re-read ARP cache after probes (the OS kernel now populated fresh ARP entries on Linux/older Android!).
    let arp_after = read_arp_table();
    for (ip, mac) in arp_after {
        if (u32::from(ip) & (!0u32 << (32 - target.prefix))) == target.network && ip != target.local_ip {
            combined.alive.insert(ip);
            combined.frames.push(build_arp_announce(ip, mac, target.local_ip, local_mac));
        }
    }

    combined.alive.extend(shared_alive.into_inner());
    combined.frames.extend(shared_frames.into_inner());
    combined.services = shared_services.load(Ordering::Relaxed);

    // Ensure the local device itself is represented too.
    combined.frames.push(build_arp_announce(target.local_ip, local_mac, target.local_ip, local_mac));

    // Ingest all synthetic/captured discovery frames into the NetEye Engine.
    let ts_base = now_ms();
    {
        let mut eng = engine.lock();
        for (idx, frame) in combined.frames.iter().enumerate() {
            if decode::decode(frame, ts_base + idx as i64).is_some() {
                eng.process_raw(frame, ts_base + idx as i64);
            }
        }
    }

    Ok(json!({
        "cidr": target.cidr,
        "local_ip": target.local_ip.to_string(),
        "scanned": total,
        "hosts_found": combined.alive.len(),
        "services_found": combined.services,
        "duration_ms": started.elapsed().as_millis() as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_validation_accepts_private_and_rejects_public_or_huge() {
        let t = resolve_target(Some("192.168.10.0/24")).unwrap();
        assert_eq!(t.cidr, "192.168.10.0/24");
        assert!(t.hosts.len() == 254 || t.hosts.len() == 253);
        assert_eq!(t.broadcast, Ipv4Addr::new(192, 168, 10, 255));

        assert!(resolve_target(Some("8.8.8.0/24")).is_err());
        assert!(resolve_target(Some("10.0.0.0/16")).is_err());
        assert!(resolve_target(Some("not-an-ip")).is_err());
    }

    #[test]
    fn synthetic_frames_decode_and_populate_engine() {
        let mut eng = Engine::new();
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(192, 168, 1, 10);
        let smac = synthetic_mac(src);
        let dmac = synthetic_mac(dst);
        let syn = build_tcp_frame(src, dst, 54001, 22, 0x02, &[], smac, dmac);
        let synack = build_tcp_frame(dst, src, 22, 54001, 0x12, &[], dmac, smac);
        let banner = build_tcp_frame(dst, src, 22, 54001, 0x18, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n", dmac, smac);
        let arp = build_arp_announce(Ipv4Addr::new(192, 168, 1, 77), synthetic_mac(Ipv4Addr::new(192, 168, 1, 77)), src, smac);
        for (i, f) in [&syn, &synack, &banner, &arp].iter().enumerate() {
            assert!(decode::decode(f, 1_700_000_000_000 + i as i64 * 10).is_some());
            eng.process_raw(f, 1_700_000_000_000 + i as i64 * 10);
        }
        let snap: Value = serde_json::from_str(&eng.snapshot_json(1_700_000_001_000)).unwrap();
        let labels: Vec<&str> = snap["assets"].as_array().unwrap().iter().map(|a| a["label"].as_str().unwrap()).collect();
        assert!(labels.contains(&"192.168.1.10"));
        assert!(labels.contains(&"192.168.1.77"));
    }
}
