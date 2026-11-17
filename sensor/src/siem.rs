//! SIEM forwarding: alerts and audit events as syslog (RFC 5424) over UDP/TCP, in CEF or JSON.
//!
//! `NETEYE_SYSLOG=udp://10.0.0.5:514,tcp://siem.plant.local:601`, `NETEYE_SYSLOG_FORMAT=cef|json`,
//! `NETEYE_SYSLOG_FACILITY=20` (local4). Each destination has its own sender thread and bounded
//! queue, so a slow or unreachable SIEM never delays packet processing or another destination.
//! TCP reconnects with backoff and resends the event that failed; when a queue is full the oldest
//! events are dropped and counted.

use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

pub const QUEUE_CAPACITY: usize = 10_000;
const UDP_MAX: usize = 8 * 1024;

/// One security event, independent of the wire format.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SiemEvent {
    #[serde(serialize_with = "iso_ms")]
    pub time: i64,
    /// "alert" or "audit"
    pub class: &'static str,
    /// Stable event-type identifier for SIEM rules, e.g. NE-POLICY-CONTROL.
    pub signature: String,
    pub name: String,
    pub severity: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reopened: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub operation: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_mac: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub src_device: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dst_device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

fn iso_ms<S: serde::Serializer>(ms: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&rfc3339(*ms))
}

fn rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

pub fn cef_severity(severity: &str) -> u8 {
    match severity {
        "critical" => 10,
        "high" => 8,
        "medium" => 5,
        "low" => 3,
        _ => 1,
    }
}

fn syslog_severity(severity: &str) -> u8 {
    match severity {
        "critical" => 2, // crit
        "high" => 3,     // err
        "medium" => 4,   // warning
        "low" => 5,      // notice
        _ => 6,          // info
    }
}

fn cef_header(value: &str) -> String {
    value.replace('\\', "\\\\").replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn cef_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('=', "\\=").replace('\n', "\\n").replace('\r', "\\r")
}

/// ArcSight Common Event Format, understood by Splunk, QRadar, ArcSight, Elastic, Sentinel and others.
pub fn to_cef(e: &SiemEvent) -> String {
    let mut ext: Vec<(&str, String)> = vec![("rt", e.time.to_string())];
    let mut push = |k: &'static str, v: &Option<String>| if let Some(v) = v { ext.push((k, v.clone())) };
    push("src", &e.src_ip);
    push("dst", &e.dst_ip);
    push("smac", &e.src_mac);
    push("dmac", &e.dst_mac);
    push("suser", &e.user);
    for (k, v) in [("app", &e.protocol), ("act", &e.operation), ("cat", &e.category)] {
        if !v.is_empty() {
            ext.push((k, v.clone()));
        }
    }
    if let Some(n) = e.count {
        ext.push(("cnt", n.to_string()));
    }
    if let Some(id) = e.alert_id {
        ext.push(("externalId", id.to_string()));
    }
    if let Some(o) = e.outcome {
        ext.push(("outcome", o.to_string()));
    }
    let custom = [("cs1Label", "cs1", "detection", &e.source), ("cs2Label", "cs2", "srcDevice", &e.src_device),
                  ("cs3Label", "cs3", "dstDevice", &e.dst_device)];
    for (label_key, key, label, value) in custom {
        if !value.is_empty() {
            ext.push((label_key, label.to_string()));
            ext.push((key, value.clone()));
        }
    }
    if e.reopened {
        ext.push(("cs4Label", "state".into()));
        ext.push(("cs4", "reopened".into()));
    }
    if !e.details.is_null() && e.details.as_object().is_some_and(|o| !o.is_empty()) {
        ext.push(("cs5Label", "details".into()));
        ext.push(("cs5", e.details.to_string()));
    }
    ext.push(("msg", e.name.clone()));
    let extension = ext.iter().map(|(k, v)| format!("{k}={}", cef_value(v))).collect::<Vec<_>>().join(" ");
    format!("CEF:0|SMIC|NetEye|{}|{}|{}|{}|{}", env!("CARGO_PKG_VERSION"), cef_header(&e.signature),
            cef_header(&e.name), cef_severity(e.severity), extension)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Cef,
    Json,
}

/// RFC 5424 syslog line (without framing).
pub fn to_syslog(e: &SiemEvent, format: Format, facility: u8, hostname: &str) -> String {
    let pri = facility as u16 * 8 + syslog_severity(e.severity) as u16;
    let body = match format {
        Format::Cef => to_cef(e),
        Format::Json => serde_json::to_string(e).unwrap_or_default(),
    };
    format!("<{pri}>1 {} {hostname} neteye - {} - {body}", rfc3339(e.time), e.class)
}

// ------------------------------------------------------------- transport
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    Udp,
    Tcp,
}

#[derive(Clone, Debug, Serialize)]
pub struct DestinationStatus {
    pub url: String,
    /// "tcp" (delivery confirmed by the connection, resent after reconnect) or "udp" (fire-and-forget).
    pub transport: &'static str,
    pub connected: bool,
    pub sent: u64,
    pub dropped: u64,
    pub queued: usize,
    pub last_error: Option<String>,
}

struct Queue {
    items: VecDeque<String>,
    status: DestinationStatus,
}

struct Destination {
    queue: Arc<(Mutex<Queue>, parking_lot::Condvar)>,
}

pub struct Forwarder {
    destinations: Vec<Destination>,
    pub format: Format,
    facility: u8,
    hostname: String,
}

fn parse_url(url: &str) -> Result<(Proto, String), String> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| format!("{url}: expected udp://host:port or tcp://host:port"))?;
    let proto = match scheme.to_ascii_lowercase().as_str() {
        "udp" => Proto::Udp,
        "tcp" => Proto::Tcp,
        other => return Err(format!("{url}: unsupported scheme {other} (udp or tcp)")),
    };
    let address = if rest.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) {
        rest.to_string()
    } else {
        format!("{rest}:514")
    };
    Ok((proto, address))
}

impl Forwarder {
    /// Parses `NETEYE_SYSLOG`-style settings; None when no destination is configured.
    pub fn from_settings(urls: Option<&str>, format: Option<&str>, facility: Option<&str>) -> Result<Option<Forwarder>, String> {
        let Some(urls) = urls.map(str::trim).filter(|u| !u.is_empty()) else { return Ok(None) };
        let format = match format.unwrap_or("cef").to_ascii_lowercase().as_str() {
            "cef" => Format::Cef,
            "json" => Format::Json,
            other => return Err(format!("NETEYE_SYSLOG_FORMAT: {other} (cef or json)")),
        };
        let facility = facility.map(|f| f.parse::<u8>().map_err(|_| format!("NETEYE_SYSLOG_FACILITY: {f}")))
            .transpose()?.unwrap_or(20);
        if facility > 23 {
            return Err("NETEYE_SYSLOG_FACILITY must be 0..23".into());
        }
        let hostname = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "neteye".into()).replace(' ', "_");
        let mut destinations = Vec::new();
        for url in urls.split(',').map(str::trim).filter(|u| !u.is_empty()) {
            let (proto, address) = parse_url(url)?;
            let queue = Arc::new((Mutex::new(Queue {
                items: VecDeque::new(),
                status: DestinationStatus { url: url.to_string(), connected: false, sent: 0, dropped: 0, queued: 0,
                                            transport: if proto == Proto::Tcp { "tcp" } else { "udp" },
                                            last_error: None },
            }), parking_lot::Condvar::new()));
            let worker = queue.clone();
            std::thread::Builder::new().name(format!("siem {url}")).spawn(move || sender(proto, address, worker))
                .map_err(|e| e.to_string())?;
            destinations.push(Destination { queue });
        }
        Ok(Some(Forwarder { destinations, format, facility, hostname }))
    }

    /// Never blocks: queues the formatted line on every destination.
    pub fn send(&self, event: &SiemEvent) {
        let line = to_syslog(event, self.format, self.facility, &self.hostname);
        for d in &self.destinations {
            let (lock, ready) = &*d.queue;
            let mut q = lock.lock();
            if q.items.len() >= QUEUE_CAPACITY {
                q.items.pop_front(); // keep the newest events
                q.status.dropped += 1;
            }
            q.items.push_back(line.clone());
            ready.notify_one();
        }
    }

    pub fn status(&self) -> Value {
        let destinations: Vec<DestinationStatus> = self.destinations.iter().map(|d| {
            let q = d.queue.0.lock();
            DestinationStatus { queued: q.items.len(), ..q.status.clone() }
        }).collect();
        json!({"format": match self.format { Format::Cef => "cef", Format::Json => "json" },
               "facility": self.facility, "destinations": destinations})
    }
}

fn sender(proto: Proto, address: String, queue: Arc<(Mutex<Queue>, parking_lot::Condvar)>) {
    let (lock, ready) = &*queue;
    let mut tcp: Option<TcpStream> = None;
    let mut udp: Option<UdpSocket> = None;
    let mut backoff = Duration::from_secs(1);
    loop {
        let line = {
            let mut q = lock.lock();
            while q.items.is_empty() {
                ready.wait(&mut q);
            }
            q.items.front().cloned().unwrap()
        };
        let result: std::io::Result<()> = (|| {
            match proto {
                Proto::Udp => {
                    if udp.is_none() {
                        let target = address.to_socket_addrs()?.next()
                            .ok_or_else(|| std::io::Error::other("address did not resolve"))?;
                        let socket = UdpSocket::bind(if target.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" })?;
                        socket.connect(target)?;
                        udp = Some(socket);
                    }
                    let bytes = line.as_bytes();
                    udp.as_ref().unwrap().send(&bytes[..bytes.len().min(UDP_MAX)])?;
                }
                Proto::Tcp => {
                    if tcp.is_none() {
                        let target = address.to_socket_addrs()?.next()
                            .ok_or_else(|| std::io::Error::other("address did not resolve"))?;
                        let stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
                        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
                        stream.set_nodelay(true)?;
                        tcp = Some(stream);
                    }
                    // Newline framing (RFC 6587 non-transparent): accepted by rsyslog, syslog-ng,
                    // Splunk, QRadar and Elastic.
                    let stream = tcp.as_mut().unwrap();
                    stream.write_all(line.as_bytes())?;
                    stream.write_all(b"\n")?;
                }
            }
            Ok(())
        })();
        let mut q = lock.lock();
        match result {
            Ok(()) => {
                if q.items.front() == Some(&line) {
                    q.items.pop_front();
                }
                q.status.sent += 1;
                q.status.connected = true;
                q.status.last_error = None;
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                // Keep the event at the head of the queue and retry after a pause.
                q.status.connected = false;
                q.status.last_error = Some(e.to_string());
                tcp = None;
                udp = None;
                drop(q);
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    fn sample() -> SiemEvent {
        SiemEvent {
            time: 1_700_000_000_123, class: "alert", signature: "NE-POLICY-CONTROL".into(),
            name: "S7 PLC Stop 명령".into(), severity: "critical", alert_id: Some(7), count: Some(1),
            source: "policy".into(), protocol: "S7comm".into(), operation: "PLC Stop".into(),
            category: "control".into(), src_ip: Some("10.0.0.40".into()), dst_ip: Some("10.0.0.11".into()),
            src_device: "Engineering workstation".into(), dst_device: "PLC (Siemens S7) Siemens 6ES7 315".into(),
            details: json!({"tag": "a=b|c"}), ..Default::default()
        }
    }

    #[test]
    fn cef_layout_and_escaping() {
        let cef = to_cef(&sample());
        assert!(cef.starts_with("CEF:0|SMIC|NetEye|"), "{cef}");
        assert!(cef.contains("|NE-POLICY-CONTROL|S7 PLC Stop 명령|10|rt=1700000000123 src=10.0.0.40 dst=10.0.0.11"));
        assert!(cef.contains("app=S7comm act=PLC Stop cat=control cnt=1 externalId=7"));
        assert!(cef.contains(r#"cs5={"tag":"a\=b|c"}"#), "extension '=' escaped, '|' allowed: {cef}");
        let mut evil = sample();
        evil.name = "a|b\nc".into();
        let cef = to_cef(&evil);
        assert!(cef.contains(r"|a\|b c|"), "header pipe escaped, newline removed: {cef}");
        assert!(cef.contains(r"msg=a|b\nc"));
    }

    #[test]
    fn syslog_header_and_json() {
        let line = to_syslog(&sample(), Format::Cef, 20, "sensor01");
        assert!(line.starts_with("<162>1 2023-11-14T22:13:20.123Z sensor01 neteye - alert - CEF:0|"), "{line}");
        let line = to_syslog(&sample(), Format::Json, 20, "sensor01");
        let body: Value = serde_json::from_str(line.split(" - alert - ").nth(1).unwrap()).unwrap();
        assert_eq!(body["signature"], "NE-POLICY-CONTROL");
        assert_eq!(body["time"], "2023-11-14T22:13:20.123Z");
        assert!(body.get("user").is_none(), "empty fields omitted");
    }

    #[test]
    fn settings_validation() {
        assert!(Forwarder::from_settings(None, None, None).unwrap().is_none());
        assert!(Forwarder::from_settings(Some("http://x:1"), None, None).is_err());
        assert!(Forwarder::from_settings(Some("udp://127.0.0.1:9"), Some("leef"), None).is_err());
        assert!(Forwarder::from_settings(Some("udp://127.0.0.1:9"), None, Some("99")).is_err());
        assert_eq!(parse_url("udp://siem").unwrap(), (Proto::Udp, "siem:514".into()));
    }

    /// Accepts within `limit`, so a broken forwarder fails the test instead of hanging it.
    fn accept_within(listener: &TcpListener, limit: Duration) -> Option<TcpStream> {
        let deadline = std::time::Instant::now() + limit;
        while std::time::Instant::now() < deadline {
            if let Ok((conn, _)) = listener.accept() {
                conn.set_nonblocking(false).unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                return Some(conn);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    #[test]
    fn tcp_delivery_and_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let forwarder = Forwarder::from_settings(Some(&format!("tcp://127.0.0.1:{port}")), Some("cef"), None).unwrap().unwrap();
        forwarder.send(&sample());
        let conn = accept_within(&listener, Duration::from_secs(10)).expect("forwarder never connected");
        let mut line = String::new();
        BufReader::new(conn.try_clone().unwrap()).read_line(&mut line).unwrap();
        assert!(line.contains("NE-POLICY-CONTROL"));
        drop(conn); // the SIEM restarts

        // Writes into the closed connection may be absorbed by the OS until the reset arrives, so
        // keep producing events until the forwarder notices and reconnects (with backoff).
        let mut second = sample();
        second.signature = "NE-AUDIT-LOGIN".into();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let conn = loop {
            assert!(std::time::Instant::now() < deadline, "forwarder did not reconnect: {}", forwarder.status());
            forwarder.send(&second);
            if let Some(conn) = accept_within(&listener, Duration::from_millis(300)) {
                break conn;
            }
        };
        let mut line = String::new();
        BufReader::new(conn).read_line(&mut line).unwrap();
        assert!(line.contains("NE-AUDIT-LOGIN"), "{line}");
        assert!(forwarder.status()["destinations"][0]["sent"].as_u64().unwrap() >= 2);
    }
}
