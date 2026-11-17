//! Turns decoded frames + protocol findings into assets, communication links, baseline and alerts.
//!
//! Hot-path design: assets/links are keyed by integers (IPv4 u32, MAC u64, interned protocol ids),
//! timestamps are integer milliseconds, and labels/evidence strings are interned so a steady-state
//! packet allocates nothing. Strings are only materialized for persistence and snapshots.

use crate::baseline::{self, Baseline, Item, Mode};
use crate::profile::{Anomaly, LinkProfile, PointAnomaly, PointProfile};
use crate::decode::{self, Frame, Transport};
use crate::intel;
use crate::osfp;
use crate::dissect::{self, base::{category_label, Finding, PointId, PointValue, ReadItem, CONTROL, PROGRAM}};
use crate::vulns::{risk_level, VulnDb, VulnMatch, CONFIRMED, LIKELY, POSSIBLE};
use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt::{self, Write as _};
use std::sync::Arc;

pub type Sym = u32;
/// (client, server, protocol, transaction) of a read waiting for its response.
type PendingKey = (AssetKey, AssetKey, Sym, u32);
pub const ONLINE_WINDOW_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AssetKey {
    Ip(u32),
    Mac(u64),
}

impl fmt::Display for AssetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b;
        match self {
            AssetKey::Ip(ip) => {
                b = ip.to_be_bytes();
                write!(f, "{}.{}.{}.{}", b[0], b[1], b[2], b[3])
            }
            AssetKey::Mac(mac) => write!(f, "mac:{}", decode::mac_string(*mac)),
        }
    }
}

impl AssetKey {
    pub fn parse(s: &str) -> Option<AssetKey> {
        match s.strip_prefix("mac:") {
            Some(mac) => decode::parse_mac(mac).map(AssetKey::Mac),
            None => decode::parse_ip(s).map(AssetKey::Ip),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkKey {
    pub client: AssetKey,
    pub server: AssetKey,
    pub proto: Sym,
}

#[derive(Default)]
pub struct Interner {
    map: FxHashMap<Box<str>, Sym>,
    strs: Vec<Box<str>>,
}

impl Interner {
    pub fn intern(&mut self, s: &str) -> Sym {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        let id = self.strs.len() as Sym;
        self.strs.push(s.into());
        self.map.insert(s.into(), id);
        id
    }
    pub fn get(&self, id: Sym) -> &str {
        &self.strs[id as usize]
    }
}

pub const IDENTITY_FIELDS: [&str; 8] =
    ["vendor", "model", "firmware", "serial", "name", "product_code", "device_class", "description"];

pub struct Asset {
    pub key: AssetKey,
    pub ip: Option<u32>,
    pub macs: Vec<u64>,
    pub vlans: Vec<u16>,
    pub device_type: Sym,
    pub confidence: f64,
    pub identity: [String; 8],
    pub roles: Vec<Sym>,
    pub protocols: Vec<Sym>,
    pub evidence: Vec<Sym>,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub vulns: Vec<VulnMatch>,
    pub risk: f64,
    pub risk_level: &'static str,
    /// Computer name and operating system, inferred passively (see osfp.rs).
    pub hostname: String,
    pub hostname_confidence: f64,
    pub os: String,
    pub os_confidence: f64,
    pub os_evidence: String,
    pub manual: ManualInfo,
    /// Names other hosts used to reach this address (DNS answers, TLS SNI, HTTP Host).
    pub domains: Vec<String>,
    dirty: bool,
}

/// Asset details entered by an operator. Non-empty values take precedence over what was
/// identified automatically; the automatic values are kept and shown alongside.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ManualInfo {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub device_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vendor: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub firmware: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub owner: String,
    /// "", "low", "medium", "high" or "critical".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub criticality: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_by: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
}

/// Distinct alerts kept (each one aggregates every repetition of the same event).
const MAX_ALERTS: usize = if cfg!(test) { 300 } else { 50_000 };
const ALERT_OVERFLOW_TITLE: &str = "경고 수 한도 도달 (이후 새 경고는 이 항목에 집계)";
const OVERFLOW_RECENT: usize = 50;
/// SIEM events per summary/overflow alert between two drains of the queue (the rest are batched).
const FOLD_EVENTS_PER_KEY: u32 = 100;
/// Entries kept for aggregate events across all alerts between two drains.
const MAX_HELD_ENTRIES: usize = 100_000;

#[derive(Default)]
struct FoldState {
    queued: u32,
    held: u32,
    entries: Vec<Value>,
}
const EXTERNAL_BUDGET_WINDOW_MS: i64 = 3_600_000;
/// Internet peers per (alert kind, internal host) that get their own alert before a summary.
const EXTERNAL_ALERT_PEERS: u32 = 20;
/// The same for threat-list matches, which matter more and are rarer.
const EXTERNAL_THREAT_PEERS: u32 = 200;

/// Process points tracked across all devices (learned values, last value, states).
pub const MAX_POINTS: usize = 100_000;
/// Read requests waiting for their response.
const MAX_PENDING_READS: usize = 4096;
/// Individual "unlearned address" alerts per client/server and window before they are summarised.
const NEW_POINT_ALERTS: u32 = 20;
const NEW_POINT_WINDOW_MS: i64 = 10 * 60 * 1000;
const NEW_POINT_ALERTS_EVER: u32 = 200;
/// Addresses listed by name in a summary alert (the rest are counted).
const SUMMARY_POINTS: usize = 200;

pub const CRITICALITY: [&str; 5] = ["", "low", "medium", "high", "critical"];

impl ManualInfo {
    fn has_values(&self) -> bool {
        [&self.name, &self.device_type, &self.vendor, &self.model, &self.firmware, &self.os, &self.location,
         &self.owner, &self.criticality, &self.notes].iter().any(|v| !v.is_empty())
    }

    /// Trim, bound and check user input. Returns a message for the first invalid field.
    pub fn sanitize(mut self) -> Result<ManualInfo, String> {
        let fields: [(&str, &mut String, usize); 10] = [
            ("name", &mut self.name, 80), ("device_type", &mut self.device_type, 80),
            ("vendor", &mut self.vendor, 120), ("model", &mut self.model, 120),
            ("firmware", &mut self.firmware, 60), ("os", &mut self.os, 120),
            ("location", &mut self.location, 120), ("owner", &mut self.owner, 120),
            ("criticality", &mut self.criticality, 10), ("notes", &mut self.notes, 2000),
        ];
        for (field, value, max) in fields {
            let keep_newlines = field == "notes";
            let cleaned: String = value.trim().chars().filter(|c| !c.is_control() || (keep_newlines && *c == '\n')).collect();
            if cleaned.chars().count() > max {
                return Err(format!("{field}: 최대 {max}자"));
            }
            *value = cleaned;
        }
        if !CRITICALITY.contains(&self.criticality.as_str()) {
            return Err("criticality: low, medium, high, critical 중 하나".into());
        }
        Ok(self)
    }
}

/// The operator's value when given, otherwise the automatic one.
fn pick<'a>(manual: &'a str, auto: &'a str) -> &'a str {
    if manual.is_empty() { auto } else { manual }
}

pub struct Link {
    pub key: LinkKey,
    pub packets: u64,
    /// Of `packets`, those sent server -> client (replies, reports). Kept in memory only, for the
    /// live traffic view.
    pub packets_back: u64,
    pub bytes: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub operations: Vec<(Sym, u64)>,
    pub categories: Vec<(&'static str, u64)>,
    pub profile: LinkProfile,
    dirty: bool,
}

/// A process point (register, tag, information object) on a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PointKey {
    pub server: AssetKey,
    pub proto: Sym,
    pub point: Sym,
    /// Read back / reported by the device (true) or written to it (false).
    pub measured: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AlertKey {
    pub title: Sym,
    pub src: AssetKey,
    pub dst: Option<AssetKey>,
}

pub struct Alert {
    pub id: u64,
    pub key: AlertKey,
    pub severity: &'static str,
    pub protocol: Sym,
    pub operation: Sym,
    pub category: &'static str,
    pub src: AssetKey,
    pub dst: Option<AssetKey>,
    pub count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub acknowledged: bool,
    /// Raised by the statistical profile (volume, timing, silence) rather than policy or baseline.
    pub anomaly: bool,
    /// Raised by the internet-connection rules (threat lists, exposure, OT devices online).
    pub external: bool,
    pub baseline: Option<Item>,
    pub details: Vec<(String, Value)>,
    dirty: bool,
}

struct Hint {
    label: &'static str,
    device: &'static str,
    confidence: f64,
}

fn port_hint(transport: Transport, port: u16) -> Option<Hint> {
    let (label, device, confidence) = match (transport, port) {
        (Transport::Tcp, 102) => ("ISO-TSAP (S7/MMS)", "PLC/IED candidate", 0.45),
        (Transport::Tcp, 502) => ("Modbus/TCP", "PLC candidate", 0.45),
        (Transport::Tcp | Transport::Udp, 44818) => ("EtherNet/IP", "Industrial device candidate", 0.45),
        (Transport::Tcp, 20000) => ("DNP3", "RTU/IED candidate", 0.45),
        (Transport::Tcp, 2404) => ("IEC 60870-5-104", "RTU/IED candidate", 0.45),
        (Transport::Tcp, 4840) => ("OPC UA", "OT server/gateway candidate", 0.4),
        (Transport::Udp, 47808) => ("BACnet/IP", "Building automation device", 0.5),
        _ => return None,
    };
    Some(Hint { label, device, confidence })
}

fn l2_label(ethertype: u16) -> String {
    if ethertype < 0x0600 {
        return "802.3 LLC (STP 등)".into();
    }
    match ethertype {
        0x86DD => "IPv6".into(),
        0x88CC => "LLDP".into(),
        0x8100 => "VLAN".into(),
        0x88E5 => "MACsec".into(),
        0x888E => "802.1X".into(),
        0x88F7 => "PTP".into(),
        e => format!("L2 0x{e:04X}"),
    }
}

pub fn iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string())
        .unwrap_or_default()
}

pub fn parse_iso(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|t| t.timestamp_millis())
}

fn static_str(s: &str, choices: &[&'static str]) -> &'static str {
    choices.iter().find(|c| **c == s).copied().unwrap_or("")
}

pub const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];
const CATEGORIES: [&str; 11] = ["read", "monitor", "session", "discovery", "diagnostic", "write", "command",
                                "config", "program", "control", "firmware"];

fn severity_rank(s: &str) -> usize {
    SEVERITIES.iter().position(|x| *x == s).unwrap_or(0)
}

#[derive(Default, Clone, Copy)]
pub struct Stats {
    pub frames: u64,
    pub dissected: u64,
}

/// Records produced by `Engine::take_changes` for the store.
#[derive(Default)]
pub struct Changes {
    pub assets: Vec<(String, String)>,
    pub links: Vec<(String, String)>,
    pub alerts: Vec<(u64, String, String, String, String, String)>,
    pub deleted_assets: Vec<String>,
    pub deleted_links: Vec<String>,
    pub baseline_items: Vec<(String, String)>,
    pub baseline_rewrite: bool,
    pub baseline_meta: Option<String>,
    pub points: Vec<(String, String)>,
    pub points_reset: bool,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.assets.is_empty() && self.links.is_empty() && self.alerts.is_empty() && self.deleted_assets.is_empty()
            && self.deleted_links.is_empty() && self.baseline_items.is_empty() && !self.baseline_rewrite
            && self.baseline_meta.is_none() && self.points.is_empty() && !self.points_reset
    }
}

pub struct Engine {
    pub syms: Interner,
    pub assets: FxHashMap<AssetKey, Asset>,
    pub links: FxHashMap<LinkKey, Link>,
    pub alerts: FxHashMap<AlertKey, Alert>,
    mac_ips: FxHashMap<u64, Vec<u32>>,
    /// DHCP names/OS for clients not yet seen with an address, applied when their MAC shows up.
    pending_hosts: FxHashMap<u64, osfp::HostInfo>,
    /// Address intelligence (optional data files) and the conversations crossing the internet edge.
    asn_db: Option<Arc<intel::AsnDb>>,
    blocklist: Option<Arc<intel::Blocklist>>,
    internal_nets: Vec<(u32, u32)>,
    external: FxHashMap<ExtKey, ExtConn>,
    /// Names learned for addresses that have no asset yet.
    pending_names: FxHashMap<u32, Vec<String>>,
    /// Internet peers alerted per (alert title, internal host) in the current hour: (count, window start).
    external_alert_peers: FxHashMap<(Sym, u32, bool), (u32, i64)>,
    next_external_sweep: i64,
    /// New-point alerts per (client, server): (count in window, window start, individual alerts ever).
    new_point_alerts: FxHashMap<(AssetKey, AssetKey), (u32, i64, u32)>,
    conversations: FxHashMap<(AssetKey, AssetKey, &'static str), Sym>,
    next_alert_id: u64,
    dirty_assets: Vec<AssetKey>,
    dirty_links: Vec<LinkKey>,
    dirty_alerts: Vec<AlertKey>,
    deleted_assets: FxHashSet<AssetKey>,
    deleted_links: FxHashSet<LinkKey>,
    pub stats: Stats,
    pub baseline: Baseline,
    pub vulndb: Option<Arc<VulnDb>>,
    learning: bool,
    scratch: String,
    /// (kind, a, b) -> interned evidence sentence; avoids formatting text on every packet.
    evidence_cache: FxHashMap<(u8, Sym, Sym), Sym>,
    findings: Vec<Finding>,
    sym_unknown: Sym,
    sym_empty: Sym,
    /// Bumped on every mutation; lets the API skip rebuilding unchanged snapshots.
    pub generation: u64,
    /// Packet-time clock and the next silence check (every 10 s of capture time).
    clock: i64,
    next_silence_check: i64,
    /// When true, new and re-opened alerts are queued for SIEM forwarding.
    pub emit_events: bool,
    /// SIEM events waiting for the forwarder: alert, reopened, and for folded alerts / new summary
    /// peers the specific entry (so each one is forwarded with its own content).
    events: Vec<(AlertKey, bool, Option<Value>)>,
    /// Per summary/overflow alert since the last drain: events queued, and entries held back for
    /// one aggregate event at drain time (count, and the entries themselves within a global bound).
    fold_counts: FxHashMap<AlertKey, FoldState>,
    held_entries: usize,
    /// After an eviction attempt that freed nothing, the next one waits until this time (or an
    /// acknowledgement), so a full table is not rescanned for every new alert.
    alert_room_retry_at: i64,
    /// Learned process values per written point.
    pub points: FxHashMap<PointKey, PointProfile>,
    dirty_points: Vec<PointKey>,
    /// Structured point id -> interned name, so polling responses never re-format names.
    point_syms: FxHashMap<PointId, Sym>,
    points_reset: bool,
    /// Read requests waiting for their response: (client, server, protocol, transaction) -> items.
    pending_reads: FxHashMap<PendingKey, (i64, Vec<ReadItem>)>,
    read_scratch: Finding,
}

impl Default for Engine {
    fn default() -> Self {
        Engine::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        let mut syms = Interner::default();
        let sym_empty = syms.intern("");
        let sym_unknown = syms.intern("Unknown");
        let baseline = Baseline::default();
        let learning = baseline.mode == Mode::Learning;
        Engine {
            syms,
            assets: Default::default(),
            links: Default::default(),
            alerts: Default::default(),
            mac_ips: Default::default(),
            pending_hosts: Default::default(),
            asn_db: None,
            blocklist: None,
            internal_nets: Vec::new(),
            external: Default::default(),
            pending_names: Default::default(),
            external_alert_peers: Default::default(),
            next_external_sweep: 0,
            new_point_alerts: Default::default(),
            conversations: Default::default(),
            next_alert_id: 1,
            dirty_assets: Vec::new(),
            dirty_links: Vec::new(),
            dirty_alerts: Vec::new(),
            deleted_assets: Default::default(),
            deleted_links: Default::default(),
            stats: Stats::default(),
            baseline,
            vulndb: None,
            learning,
            scratch: String::with_capacity(128),
            evidence_cache: Default::default(),
            findings: Vec::with_capacity(8),
            sym_unknown,
            sym_empty,
            generation: 0,
            emit_events: false,
            clock: 0,
            next_silence_check: 0,
            events: Vec::new(),
            alert_room_retry_at: 0,
            fold_counts: Default::default(),
            held_entries: 0,
            points: Default::default(),
            dirty_points: Default::default(),
            point_syms: Default::default(),
            points_reset: false,
            pending_reads: Default::default(),
            read_scratch: Finding::new(""),
        }
    }

    // ---------------------------------------------------------------- input
    pub fn process_raw(&mut self, data: &[u8], ts_ms: i64) {
        if let Some(frame) = decode::decode(data, ts_ms) {
            let mut findings = std::mem::take(&mut self.findings);
            dissect::dissect(&frame, &mut findings);
            self.apply(&frame, &mut findings);
            self.findings = findings;
        }
    }

    /// Apply one decoded frame and its (already computed) findings.
    pub fn apply(&mut self, frame: &Frame, findings: &mut [Finding]) {
        self.refresh_learning();
        self.stats.frames += 1;
        if !findings.is_empty() {
            self.stats.dissected += 1;
        }
        self.generation += 1;
        self.observe(frame, findings);
        if frame.ts_ms > self.clock {
            self.clock = frame.ts_ms;
        }
        if self.clock >= self.next_external_sweep {
            self.next_external_sweep = self.clock + 60_000;
            self.sweep_external(self.clock);
        }
        if self.clock >= self.next_silence_check {
            self.next_silence_check = self.clock + 10_000;
            if !self.learning {
                self.check_silences(self.clock);
            }
        }
    }

    /// Pair read requests with their responses and judge the values they carry.
    fn observe_reads(&mut self, client: AssetKey, server: AssetKey, proto: Sym, f: &mut Finding, now: i64) {
        if let (Some(true), Some((tx, items))) = (f.is_request, f.read_request.take()) {
            if self.pending_reads.len() >= MAX_PENDING_READS {
                self.pending_reads.retain(|_, (ts, _)| now - *ts < 30_000); // unanswered requests
                if self.pending_reads.len() >= MAX_PENDING_READS {
                    self.pending_reads.clear(); // a flood of fresh requests: hard limit regardless of age
                }
            }
            self.pending_reads.insert((client, server, proto, tx), (now, items));
        }
        if let (Some(false), Some((tx, data))) = (f.is_request, f.read_response.as_ref()) {
            let Some((_, items)) = self.pending_reads.remove(&(client, server, proto, *tx)) else { return };
            let mut scratch = std::mem::replace(&mut self.read_scratch, Finding::new(""));
            scratch.values.clear();
            dissect::decode_read(&items, data, &mut scratch);
            if !scratch.values.is_empty() {
                self.observe_values(client, server, proto, &scratch.values, &f.operation, f.category, now);
            }
            self.read_scratch = scratch;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_values(&mut self, client: AssetKey, server: AssetKey, proto: Sym, values: &[PointValue],
                      operation: &str, category: &'static str, now: i64) {
        let learning = self.learning;
        let fmt = |x: f64| if x.fract() == 0.0 && x.abs() < 1e15 { Value::from(x as i64) } else { Value::from(x) };
        for v in values {
            let full = self.points.len() >= MAX_POINTS;
            let cached = self.point_syms.get(&v.point).copied();
            let tracked = cached.is_some_and(|point| {
                self.points.contains_key(&PointKey { server, proto, point, measured: v.measured })
            });
            if full && !tracked {
                // The table is full: the address is not learned or stored, but a write to it is still
                // reported (fail closed), and the operator is told that tracking hit its limit.
                self.point_alert("high", "공정 포인트 추적 한도 도달", vec![("limit".into(), Value::from(MAX_POINTS))],
                                 proto, operation, category, client, server, now);
                if !v.measured && !learning {
                    self.new_point_alert(client, server, proto, operation, category, v.point.to_string(),
                                         fmt(v.value), now, true);
                }
                continue;
            }
            let point = match cached {
                Some(sym) => sym,
                None => {
                    if self.point_syms.len() >= 200_000 {
                        self.point_syms.clear(); // name cache only; names stay interned
                    }
                    let sym = self.sym_fmt(format_args!("{}", v.point));
                    self.point_syms.insert(v.point.clone(), sym);
                    sym
                }
            };
            let key = PointKey { server, proto, point, measured: v.measured };
            let profile = self.points.entry(key).or_default();
            let anomaly = profile.observe_kind(v.value, v.discrete, learning, now, v.measured);
            if !profile.dirty {
                profile.dirty = true;
                self.dirty_points.push(key);
            }
            let Some(anomaly) = anomaly else { continue };
            let name = self.syms.get(point).to_string();
            let (severity, title, details): (&'static str, String, Vec<(String, Value)>) = match (anomaly, v.measured) {
                (PointAnomaly::Range { value, min, max }, measured) => (
                    if measured { "medium" } else { "high" },
                    format!("{}: {name}", if measured { "측정값 범위 이탈" } else { "공정 값 범위 이탈" }),
                    vec![("value".into(), fmt(value)), ("learned_min".into(), fmt(min)), ("learned_max".into(), fmt(max))]),
                (PointAnomaly::State { value, states }, measured) => (
                    if measured { "low" } else { "medium" },
                    format!("{}: {name}", if measured { "측정 상태 미학습 값" } else { "학습되지 않은 상태 값" }),
                    vec![("value".into(), fmt(value)),
                         ("learned_values".into(), Value::Array(states.into_iter().map(fmt).collect()))]),
                (PointAnomaly::NewPoint { value }, _) => {
                    self.new_point_alert(client, server, proto, operation, category, name, fmt(value), now, false);
                    continue;
                }
            };
            self.point_alert(severity, &title, details, proto, operation, category, client, server, now);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn point_alert(&mut self, severity: &'static str, title: &str, details: Vec<(String, Value)>, proto: Sym,
                   operation: &str, category: &'static str, client: AssetKey, server: AssetKey, now: i64) -> AlertKey {
        let title = self.syms.intern(title);
        let op = self.syms.intern(operation);
        self.alert(severity, title, proto, op, client, Some(server), now, category, details, None);
        let key = AlertKey { title, src: client, dst: Some(server) };
        if let Some(alert) = self.alerts.get_mut(&key) {
            alert.anomaly = true;
        }
        key
    }

    /// Writes to addresses never seen while learning. The first few per client/server pair in a
    /// 10-minute window get their own alert; beyond that (a write sweep) they go into one summary
    /// alert that still lists every address (up to a bound) and counts every write.
    #[allow(clippy::too_many_arguments)]
    fn new_point_alert(&mut self, client: AssetKey, server: AssetKey, proto: Sym, operation: &str,
                       category: &'static str, name: String, value: Value, now: i64, force_summary: bool) {
        let window = self.new_point_alerts.entry((client, server)).or_insert((0, now, 0));
        if now - window.1 > NEW_POINT_WINDOW_MS {
            (window.0, window.1) = (0, now);
        }
        window.0 += 1;
        // Individual alerts per pair are limited per window and for good, so even a slow sweep
        // over months cannot grow the alert list (or the name table) without bound.
        if !force_summary && window.0 <= NEW_POINT_ALERTS && window.2 < NEW_POINT_ALERTS_EVER {
            window.2 += 1;
            let details = vec![("value".into(), value), ("point".into(), Value::from(name.clone()))];
            self.point_alert("medium", &format!("학습되지 않은 주소에 쓰기: {name}"), details, proto, operation,
                             category, client, server, now);
            return;
        }
        let key = self.point_alert("high", "학습되지 않은 주소에 쓰기 (다수 주소)", vec![("value".into(), value)],
                                   proto, operation, category, client, server, now);
        if let Some(alert) = self.alerts.get_mut(&key) {
            if !alert.details.iter().any(|(k, _)| k == "points") {
                alert.details.push(("points".into(), Value::Array(Vec::new())));
            }
            let at = alert.details.iter().position(|(k, _)| k == "points").unwrap();
            let Value::Array(points) = &mut alert.details[at].1 else { return };
            let name = Value::from(name);
            if points.contains(&name) {
                return;
            }
            if points.len() < SUMMARY_POINTS {
                points.push(name);
            } else {
                match alert.details.iter_mut().find(|(k, _)| k == "points_unlisted") {
                    Some((_, n)) => *n = Value::from(n.as_u64().unwrap_or(0) + 1),
                    None => alert.details.push(("points_unlisted".into(), Value::from(1u64))),
                }
            }
        }
    }

    fn check_silences(&mut self, now: i64) {
        let mut found = Vec::new();
        for (key, link) in self.links.iter_mut() {
            if let Some(anomaly) = link.profile.check_silence(now, false) {
                found.push((*key, anomaly));
            }
        }
        for (key, anomaly) in found {
            self.anomaly_alert(key, anomaly, now);
        }
    }

    fn anomaly_alert(&mut self, key: LinkKey, anomaly: Anomaly, now: i64) {
        let proto = self.syms.get(key.proto).to_string();
        let (severity, title, details): (&'static str, String, Vec<(String, Value)>) = match anomaly {
            Anomaly::Spike { observed, expected } => ("medium", format!("트래픽 급증: {proto}"), vec![
                ("packets_per_minute".into(), observed.into()),
                ("expected_per_minute".into(), ((expected * 10.0).round() / 10.0).into())]),
            Anomaly::Interval { observed_ms, expected_ms } => ("medium", format!("폴링 주기 변화: {proto}"), vec![
                ("interval_ms".into(), observed_ms.round().into()),
                ("expected_interval_ms".into(), expected_ms.round().into())]),
            Anomaly::Silence { silent_ms, expected_ms } => ("high", format!("통신 중단: {proto}"), vec![
                ("silent_seconds".into(), (silent_ms / 1000).into()),
                ("expected_interval_ms".into(), expected_ms.round().into())]),
        };
        let title = self.syms.intern(&title);
        self.alert(severity, title, key.proto, self.sym_empty, key.client, Some(key.server), now, "", details, None);
        if let Some(alert) = self.alerts.get_mut(&AlertKey { title, src: key.client, dst: Some(key.server) }) {
            alert.anomaly = true;
        }
    }

    fn refresh_learning(&mut self) {
        if self.baseline.expired() {
            self.set_mode(Mode::Detecting, None, false); // learning window elapsed: freeze what was seen
        }
        self.learning = self.baseline.mode == Mode::Learning;
    }

    fn evidence(&mut self, kind: u8, a: Sym, b: Sym) -> Sym {
        if let Some(&sym) = self.evidence_cache.get(&(kind, a, b)) {
            return sym;
        }
        let (x, y) = (self.syms.get(a).to_string(), self.syms.get(b).to_string());
        let sym = match kind {
            0 => self.sym_fmt(format_args!("{x} 서버 동작 관측")),
            1 => self.sym_fmt(format_args!("{x} 송신 동작 관측")),
            2 => self.sym_fmt(format_args!("{x} {y} 명령 송신")),
            3 => self.sym_fmt(format_args!("{x} 클라이언트 동작 관측")),
            4 => self.sym_fmt(format_args!("{x} 식별 정보 응답")),
            _ => self.sym_fmt(format_args!("{x} 서비스 응답 관측")),
        };
        self.evidence_cache.insert((kind, a, b), sym);
        sym
    }

    fn sym_fmt(&mut self, args: fmt::Arguments) -> Sym {
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.clear();
        let _ = scratch.write_fmt(args);
        let id = self.syms.intern(&scratch);
        self.scratch = scratch;
        id
    }

    fn observe(&mut self, frame: &Frame, findings: &mut [Finding]) {
        let now = frame.ts_ms;
        if frame.transport == Transport::Arp {
            let ip = frame.src_ip.unwrap_or(0);
            if decode::is_unicast_ip(ip) {
                let key = self.asset_for_ip(ip, now);
                let arp = self.syms.intern("ARP");
                self.touch(key, frame.size, now, Some(arp));
                self.bind_mac(key, frame.src_mac, ip);
            }
            return;
        }

        let host = if frame.src_ip.is_some() { osfp::inspect(frame) } else { None };
        if let Some(info) = host.as_ref().filter(|i| i.client.is_some()) {
            self.apply_dhcp_host(info);
        }

        let (src, dst);
        if let Some(sip) = frame.src_ip {
            if !decode::is_unicast_ip(sip) {
                return;
            }
            src = self.asset_for_ip(sip, now);
            self.bind_mac(src, frame.src_mac, sip);
            let dip = frame.dst_ip.unwrap_or(0);
            dst = if decode::is_unicast_ip(dip) { Some(self.asset_for_ip(dip, now)) } else { None };
            if let Some(d) = dst {
                self.bind_mac(d, frame.dst_mac, dip);
            }
        } else {
            if !decode::is_unicast_mac(frame.src_mac) {
                return;
            }
            src = self.asset_for_mac(frame.src_mac, now);
            dst = if decode::is_unicast_mac(frame.dst_mac) { Some(self.asset_for_mac(frame.dst_mac, now)) } else { None };
        }

        if let Some(vlan) = frame.vlan {
            let asset = self.assets.get_mut(&src).unwrap();
            if !asset.vlans.contains(&vlan) {
                asset.vlans.push(vlan);
            }
        }
        self.touch(src, frame.size, now, None);
        if let Some(info) = host.filter(|i| i.client.is_none()) {
            self.apply_host(src, &info);
        }
        if frame.src_ip.is_some() && matches!(frame.transport, Transport::Tcp | Transport::Udp) {
            for (ip, name, _) in intel::names(frame) {
                self.add_domain(ip, name);
            }
            self.observe_external(frame, now);
        }
        if let Some(d) = dst {
            self.touch(d, frame.size, now, None);
        }

        if findings.is_empty() {
            self.observe_unparsed(frame, src, dst, now);
            return;
        }
        for finding in findings.iter_mut() {
            self.apply_finding(frame, finding, src, dst, now);
        }
    }

    fn observe_unparsed(&mut self, frame: &Frame, src: AssetKey, dst: Option<AssetKey>, now: i64) {
        let mut label = match frame.transport {
            Transport::None => self.syms.intern(&l2_label(frame.ethertype)),
            Transport::Ip(p) => self.sym_fmt(format_args!("IP/{p}")),
            t => self.syms.intern(t.label()),
        };
        let mut hint = None;
        let (mut server, mut client) = (dst, Some(src));
        if frame.src_port != frame.dst_port {
            hint = port_hint(frame.transport, frame.dst_port);
            if hint.is_none() {
                hint = port_hint(frame.transport, frame.src_port);
                (server, client) = (Some(src), dst);
            }
        }
        if let (Some(h), Some(s), Some(c)) = (&hint, server, client) {
            // Empty segments / unparsed PDUs of a conversation we already understand.
            if let Some(&known) = self.conversations.get(&(c, s, h.label)) {
                self.add_protocol(src, known);
                if let Some(d) = dst {
                    self.add_protocol(d, known);
                }
                self.link(c, s, known, frame.size, now, None, "", false, false, src != c);
                return;
            }
        }
        if let Some(h) = &hint {
            label = self.syms.intern(h.label);
            // A service is only evidenced by traffic *from* its port (not a refused/RST probe to it).
            let rst = frame.transport == Transport::Tcp && frame.tcp_flags & 0x04 != 0;
            if server == Some(src) && !rst {
                let evidence = self.evidence(5, label, 0);
                let device = self.syms.intern(h.device);
                self.apply_hint(src, device, h.confidence, evidence);
            }
        }
        self.add_protocol(src, label);
        if let Some(d) = dst {
            self.add_protocol(d, label);
            if frame.src_ip.is_some() {
                match (&hint, client, server) {
                    (Some(_), Some(c), Some(s)) => self.link(c, s, label, frame.size, now, None, "", false, false, src != c),
                    _ => self.link(src, d, label, frame.size, now, None, "", false, false, false),
                }
            }
        }
    }

    fn apply_finding(&mut self, frame: &Frame, f: &mut Finding, mut src: AssetKey, dst: Option<AssetKey>, now: i64) {
        if let Some(ip) = f.announced_ip
            && decode::is_unicast_ip(ip) && frame.src_ip.is_none() {
                src = self.promote_mac_asset(src, ip, frame.src_mac, now);
            }
        let proto = self.syms.intern(&f.protocol);
        self.add_protocol(src, proto);
        if let Some(d) = dst {
            self.add_protocol(d, proto);
        }
        if let Some(role) = f.role_src {
            let r = self.syms.intern(role);
            self.add_role(src, r);
        }
        if let (Some(role), Some(d)) = (f.role_dst, dst) {
            let r = self.syms.intern(role);
            self.add_role(d, r);
        }

        let (server, client) = if f.is_request == Some(true) { (dst, Some(src)) } else { (Some(src), dst) };
        if let (Some((device, confidence)), Some(s)) = (&f.device_hint, server) {
            let evidence = self.evidence(if f.is_request.is_some() { 0 } else { 1 }, proto, 0);
            let device = self.syms.intern(device);
            self.apply_hint(s, device, *confidence as f64, evidence);
        }
        if let (Some(c), Some(is_request)) = (client, f.is_request)
            && f.has_roles() {
                if is_request && (f.category == PROGRAM || f.category == CONTROL) {
                    let op = self.syms.intern(&f.operation);
                    let evidence = self.evidence(2, proto, op);
                    let device = self.syms.intern("Engineering workstation");
                    self.apply_hint(c, device, 0.8, evidence);
                } else {
                    let evidence = self.evidence(3, proto, 0);
                    let device = self.syms.intern("SCADA/HMI/EWS candidate");
                    self.apply_hint(c, device, 0.4, evidence);
                }
            }

        let target = if f.identity_of_dst { dst } else { Some(src) };
        if let Some(t) = target {
            self.apply_identity(t, f, proto, now);
        }

        let check_op = f.is_request == Some(true);
        if let (Some(c), Some(s), true) = (client, server, frame.src_ip.is_some()) {
            self.link(c, s, proto, frame.size, now, Some(&f.operation), f.category, check_op, f.alert.is_some(), src != c);
            let server_port = if check_op { frame.dst_port } else { frame.src_port };
            if let Some(h) = port_hint(frame.transport, server_port) {
                self.conversations.insert((c, s, h.label), proto);
            }
        } else if let (Some(d), true) = (dst, frame.src_ip.is_none()) {
            self.link(src, d, proto, frame.size, now, Some(&f.operation), f.category,
                      f.is_request != Some(false), f.alert.is_some(), false);
        }

        if let (Some(c), Some(s)) = (client, server) {
            // Writes travel client -> server; reports and read responses come back from the server.
            if !f.values.is_empty() && f.is_request.is_some() {
                self.observe_values(c, s, proto, &f.values, &f.operation, f.category, now);
            }
            if f.read_request.is_some() || f.read_response.is_some() {
                self.observe_reads(c, s, proto, f, now);
            }
        }

        if let Some((severity, title)) = &f.alert {
            // Attribute to the initiating client -> targeted server when roles are known.
            let (origin, target) = match (f.is_request, client, server) {
                (Some(_), Some(c), Some(s)) => (c, Some(s)),
                _ => (src, dst),
            };
            let title = self.syms.intern(title);
            let op = self.syms.intern(&f.operation);
            // Details are kept from the first occurrence only: skip building them for repeats.
            let known = self.alerts.contains_key(&AlertKey { title, src: origin, dst: target });
            let details = if known { Vec::new() }
                          else { f.details.iter().map(|(k, v)| (k.to_string(), v.to_json())).collect() };
            self.alert(severity, title, proto, op, origin, target, now, f.category, details, None);
        }
    }

    fn apply_identity(&mut self, target: AssetKey, f: &Finding, proto: Sym, now: i64) {
        let mut changed = false;
        let mut firmware_change = None;
        {
            let asset = self.assets.get_mut(&target).unwrap();
            for (i, value) in f.identity.fields() {
                let Some(value) = value.as_deref().filter(|v| !v.is_empty()) else { continue };
                if asset.identity[i] != value {
                    let previous = std::mem::replace(&mut asset.identity[i], value.to_string());
                    changed = true;
                    if i == 2 && !previous.is_empty() {
                        firmware_change = Some(format!("펌웨어 버전 변경: {previous} → {value}"));
                    }
                }
            }
        }
        if let Some(title) = firmware_change {
            let title = self.syms.intern(&title);
            let op = self.syms.intern("Firmware change");
            self.alert("high", title, proto, op, target, None, now, "", Vec::new(), None);
        }
        if changed {
            let evidence = self.evidence(4, proto, 0);
            let asset = self.assets.get_mut(&target).unwrap();
            if !asset.evidence.contains(&evidence) {
                asset.evidence.push(evidence);
            }
            self.mark_asset(target);
            self.match_vulns(target, now);
        }
    }

    // -------------------------------------------------------------- assets
    // ------------------------------------------------------ internet edge
    pub fn set_intel(&mut self, asn: Option<Arc<intel::AsnDb>>, blocklist: Option<Arc<intel::Blocklist>>) {
        self.asn_db = asn;
        self.blocklist = blocklist;
        self.generation += 1;
    }

    /// Networks to treat as internal even though their addresses are public (plants that number
    /// their networks out of public space).
    pub fn set_internal_nets(&mut self, nets: &[String]) -> Result<(), String> {
        let mut out = Vec::new();
        for net in nets {
            let (addr, prefix) = net.split_once('/').unwrap_or((net, "32"));
            let ip = addr.trim().parse::<std::net::Ipv4Addr>().map_err(|_| format!("NETEYE_INTERNAL_NETS: {net}"))?;
            let prefix: u32 = prefix.trim().parse().ok().filter(|p| *p <= 32).ok_or(format!("NETEYE_INTERNAL_NETS: {net}"))?;
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            out.push((u32::from(ip) & mask, mask));
        }
        self.internal_nets = out;
        Ok(())
    }

    /// An address on the internet: routable, not private, not one of the site's own networks.
    pub fn is_internet(&self, ip: u32) -> bool {
        decode::is_unicast_ip(ip) && !decode::is_private_ip(ip)
            && !self.internal_nets.iter().any(|(net, mask)| ip & mask == *net)
    }

    fn add_domain(&mut self, ip: u32, name: String) {
        if !self.is_internet(ip) {
            return;
        }
        match self.assets.get_mut(&AssetKey::Ip(ip)) {
            Some(a) => {
                if !a.domains.contains(&name) {
                    if a.domains.len() >= MAX_DOMAINS {
                        a.domains.remove(0);
                    }
                    a.domains.push(name);
                    self.mark_asset(AssetKey::Ip(ip));
                }
            }
            None => {
                if self.pending_names.len() >= 50_000 {
                    self.pending_names.clear();
                }
                let names = self.pending_names.entry(ip).or_default();
                if !names.contains(&name) && names.len() < MAX_DOMAINS {
                    names.push(name);
                }
            }
        }
    }

    /// Whether an internal asset is part of the control system (by type or by the protocols it uses).
    fn is_ot_asset(&self, ip: u32) -> bool {
        let Some(a) = self.assets.get(&AssetKey::Ip(ip)) else { return false };
        let kind = pick(&a.manual.device_type, self.syms.get(a.device_type)).to_ascii_lowercase();
        if ["it workstation", "printer", "server", "router", "firewall", "switch", "camera"].iter().any(|k| kind.contains(k)) {
            return false;
        }
        const OT_TYPES: [&str; 14] = ["plc", "rtu", "ied", "hmi", "scada", "engineering", "i/o", "drive",
                                      "industrial", "historian", "merging", "building", "controller", "adapter"];
        const OT_PROTOCOLS: [&str; 18] = ["s7", "modbus", "ethernet/ip", "cip", "dnp3", "60870", "61850", "mms",
                                          "goose", "profinet", "cc-link", "ethercat", "powerlink", "bacnet", "opc",
                                          "fins", "melsec", "iso-tsap"];
        OT_TYPES.iter().any(|t| kind.contains(t))
            || a.protocols.iter().any(|p| {
                let p = self.syms.get(*p).to_ascii_lowercase();
                OT_PROTOCOLS.iter().any(|o| p.contains(o))
            })
    }

    /// Conversations between the site and the internet: who opened them, on which service, and
    /// whether they break a rule (threat list, industrial protocol, OT device, inbound access).
    fn observe_external(&mut self, frame: &Frame, now: i64) {
        let (Some(s), Some(d)) = (frame.src_ip, frame.dst_ip) else { return };
        let (s_net, d_net) = (self.is_internet(s), self.is_internet(d));
        if s_net == d_net || !decode::is_unicast_ip(if s_net { d } else { s }) {
            return; // purely internal, purely external, or broadcast/multicast
        }
        let (internal, outside) = if s_net { (d, s) } else { (s, d) };
        let (mut port, client_is_src) = intel::service_side(frame.transport, frame.src_port, frame.dst_port, frame.tcp_flags);
        let mut inbound = (if client_is_src { s } else { d }) == outside;
        let (internal_port, outside_port) = if s == internal { (frame.src_port, frame.dst_port) } else { (frame.dst_port, frame.src_port) };
        // UDP between two temporary ports (voice/video calls, games, P2P after NAT traversal) has no
        // server side: it is recorded as the site talking to that peer, never as inbound access.
        if frame.transport == Transport::Udp && internal_port >= 1024 && outside_port >= 1024
            && !intel::known_port(frame.transport, internal_port) && !intel::known_port(frame.transport, outside_port) {
            (port, inbound) = (outside_port, false);
        }
        let key = ExtKey { internal, external: outside, tcp: frame.transport == Transport::Tcp, port, inbound };
        let from_inside = s == internal;
        let is_new = !self.external.contains_key(&key);
        if is_new {
            // Rules always run (alerts are budgeted per host); only storing the conversation is
            // skipped while the table is full. Old entries are cleared by the periodic sweep.
            self.external_rules_new(&key, now);
            if self.external.len() >= MAX_EXTERNAL {
                return;
            }
        }
        let conn = self.external.entry(key).or_insert_with(|| ExtConn { first_seen: now, ..Default::default() });
        conn.last_seen = now;
        if frame.transport == Transport::Tcp && frame.tcp_flags & 0x12 == 0x02 {
            conn.opened = true;
        }
        if from_inside {
            conn.packets_out += 1;
            conn.bytes_out += frame.size as u64;
        } else {
            conn.packets_in += 1;
            conn.bytes_in += frame.size as u64;
        }
        // An inbound conversation the internal host answers was accepted: a TCP SYN-ACK, or a UDP
        // reply from a service port.
        let answered = match frame.transport {
            Transport::Tcp => frame.tcp_flags & 0x12 == 0x12,
            _ => true,
        };
        if inbound && from_inside && answered && !conn.accepted {
            conn.accepted = true;
            self.external_inbound_accepted(&key, now);
        }
    }

    fn external_alert(&mut self, severity: &'static str, title: &str, key: &ExtKey, details: Vec<(String, Value)>, now: i64) {
        let (src, dst) = if key.inbound { (AssetKey::Ip(key.external), AssetKey::Ip(key.internal)) }
                         else { (AssetKey::Ip(key.internal), AssetKey::Ip(key.external)) };
        let transport = if key.tcp { Transport::Tcp } else { Transport::Udp };
        let service = intel::industrial_service(transport, key.port).or_else(|| intel::internet_service(transport, key.port));
        let proto = self.sym_fmt(format_args!("{}/{}", if key.tcp { "TCP" } else { "UDP" }, key.port));
        let title = self.syms.intern(title);
        let op = self.syms.intern("External connection");
        let mut details = details;
        details.push(("port".into(), Value::from(format!("{}/{}", key.port, if key.tcp { "TCP" } else { "UDP" }))));
        if let Some(service) = service {
            details.push(("service".into(), Value::from(service)));
        }
        details.push(("direction".into(), Value::from(if key.inbound { "인터넷 → 내부" } else { "내부 → 인터넷" })));
        if let Some(org) = self.org_of(key.external) {
            details.push(("organization".into(), Value::from(org.name)));
        }
        // The first EXTERNAL_ALERT_PEERS internet peers per internal host get their own alert; more
        // (a scan, a spray from many sources) are folded into one summary listing the peers.
        let threat = self.syms.get(title).starts_with("위협 인텔리전스");
        if self.external_alert_peers.len() >= 100_000 {
            self.external_alert_peers.clear();
        }
        // Budgets are kept per direction, so (possibly spoofed) inbound traffic cannot use up the
        // budget that covers connections the internal host itself opens.
        let budget = self.external_alert_peers.entry((title, key.internal, key.inbound)).or_insert((0, now));
        if now - budget.1 > EXTERNAL_BUDGET_WINDOW_MS {
            *budget = (0, now);
        }
        let known = self.alerts.contains_key(&AlertKey { title, src, dst: Some(dst) });
        // Threat-list matches get a much larger budget than the other kinds, but still a bounded one.
        let limit = if threat { EXTERNAL_THREAT_PEERS } else { EXTERNAL_ALERT_PEERS };
        let alert_key = if known || budget.0 < limit {
            if !known {
                budget.0 += 1;
            }
            self.alert(severity, title, proto, op, src, Some(dst), now, "", details, None);
            AlertKey { title, src, dst: Some(dst) }
        } else {
            let summary_title = format!("{} (다수 주소)", self.syms.get(title));
            let summary = self.syms.intern(&summary_title);
            let internal = AssetKey::Ip(key.internal);
            let mut entry: serde_json::Map<String, Value> = details.iter().cloned().collect();
            entry.insert("peer".into(), Value::from(decode::ip_string(key.external)));
            self.alert(severity, summary, proto, op, internal, None, now, "", details, None);
            let k = AlertKey { title: summary, src: internal, dst: None };
            let mut added = false;
            if let Some(alert) = self.alerts.get_mut(&k) {
                let peer = Value::from(decode::ip_string(key.external));
                match alert.details.iter_mut().find(|(n, _)| n == "peers") {
                    Some((_, Value::Array(list))) => {
                        if !list.contains(&peer) {
                            // Most recent peers are kept.
                            if list.len() >= SUMMARY_POINTS {
                                list.remove(0);
                            }
                            list.push(peer);
                            added = true;
                        }
                    }
                    _ => {
                        alert.details.push(("peers".into(), Value::Array(vec![peer])));
                        added = true;
                    }
                }
            }
            // Each new peer in a summary is forwarded to the SIEM with its own address and details.
            if added {
                self.queue_fold_event(k, Value::Object(entry));
            }
            k
        };
        if let Some(alert) = self.alerts.get_mut(&alert_key) {
            alert.external = true;
        }
    }

    fn external_rules_new(&mut self, key: &ExtKey, now: i64) {
        let transport = if key.tcp { Transport::Tcp } else { Transport::Udp };
        if let Some(list) = self.blocklist.as_ref().and_then(|b| b.lookup(key.external)).map(str::to_string) {
            self.external_alert("critical", "위협 인텔리전스 목록 주소와 통신", key,
                                vec![("threat_list".into(), Value::from(list))], now);
        }
        if let Some(protocol) = intel::industrial_service(transport, key.port) {
            self.external_alert("critical", "산업 프로토콜의 인터넷 통신", key,
                                vec![("protocol".into(), Value::from(protocol))], now);
        }
        if !key.inbound && self.is_ot_asset(key.internal) {
            self.external_alert("high", "OT 장비의 인터넷 통신", key, Vec::new(), now);
        }
    }

    fn external_inbound_accepted(&mut self, key: &ExtKey, now: i64) {
        let transport = if key.tcp { Transport::Tcp } else { Transport::Udp };
        let severity = if intel::risky_service(transport, key.port) || self.is_ot_asset(key.internal) { "critical" } else { "high" };
        self.external_alert(severity, "인터넷에서 내부 서비스로 접속", key, Vec::new(), now);
    }

    /// Devices identified as OT only after their first internet conversation are caught here.
    fn sweep_external(&mut self, now: i64) {
        if self.external.len() >= MAX_EXTERNAL * 9 / 10 {
            self.external.retain(|_, c| now - c.last_seen < 3_600_000);
        }
        self.external_alert_peers.retain(|_, (_, start)| now - *start <= EXTERNAL_BUDGET_WINDOW_MS);
        let pending: Vec<ExtKey> = self.external.iter()
            .filter(|(k, c)| !k.inbound && !c.ot_checked && now - c.last_seen < 3_600_000)
            .map(|(k, _)| *k).collect();
        for key in pending {
            if self.is_ot_asset(key.internal) {
                self.external_alert("high", "OT 장비의 인터넷 통신", &key, Vec::new(), now);
                if let Some(c) = self.external.get_mut(&key) {
                    c.ot_checked = true;
                }
            }
        }
    }

    fn org_of(&self, ip: u32) -> Option<OrgView> {
        let db = self.asn_db.as_ref()?;
        let info = db.lookup(ip)?;
        Some(OrgView {
            asn: info.asn, country: info.country.to_string(), holder: info.holder.to_string(),
            name: intel::org_label(info.asn, info.holder), well_known: intel::well_known(info.asn).is_some(),
        })
    }

    /// One row per internet address: who owns it, what the site does with it, and why it may matter.
    fn external_views(&self, now: i64) -> Vec<ExternalView> {
        let mut by_ip: FxHashMap<u32, Vec<(&ExtKey, &ExtConn)>> = FxHashMap::default();
        for (k, c) in &self.external {
            by_ip.entry(k.external).or_default().push((k, c));
        }
        let mut views: Vec<ExternalView> = by_ip.into_iter().map(|(ip, conns)| {
            let org = self.org_of(ip);
            let asset = self.assets.get(&AssetKey::Ip(ip));
            let domains = asset.map(|a| a.domains.clone()).unwrap_or_default();
            let threat = self.blocklist.as_ref().and_then(|b| b.lookup(ip)).map(str::to_string);
            let mut peers: Vec<u32> = conns.iter().map(|(k, _)| k.internal).collect();
            peers.sort_unstable();
            peers.dedup();
            let mut reasons: Vec<(u32, String)> = Vec::new();
            if let Some(list) = &threat {
                reasons.push((100, format!("위협 인텔리전스 목록 ({list})")));
            }
            let mut services: Vec<ServiceView> = Vec::new();
            let (mut pout, mut pin, mut bout, mut bin, mut first, mut last) = (0, 0, 0, 0, i64::MAX, 0);
            for (k, c) in &conns {
                let transport = if k.tcp { Transport::Tcp } else { Transport::Udp };
                let ics = intel::industrial_service(transport, k.port);
                let name = ics.or_else(|| intel::internet_service(transport, k.port));
                if let Some(p) = ics {
                    reasons.push((90, format!("산업 프로토콜 {p} ({}/{})", k.port, if k.tcp { "TCP" } else { "UDP" })));
                }
                if k.inbound && c.accepted {
                    reasons.push((if intel::risky_service(transport, k.port) { 85 } else { 70 },
                                  format!("인터넷에서 내부로 접속 허용 (포트 {})", k.port)));
                } else if k.inbound {
                    reasons.push((20, format!("인터넷에서 접속 시도 (포트 {})", k.port)));
                } else if name.is_none() {
                    reasons.push((15, format!("비표준 포트 {}/{}", k.port, if k.tcp { "TCP" } else { "UDP" })));
                }
                if !k.inbound && self.is_ot_asset(k.internal) {
                    reasons.push((80, format!("OT 장비와 통신 ({})", decode::ip_string(k.internal))));
                }
                if services.len() < 12 && !services.iter().any(|s| s.port == k.port && s.tcp == k.tcp && s.inbound == k.inbound) {
                    services.push(ServiceView { port: k.port, tcp: k.tcp, inbound: k.inbound, accepted: c.accepted,
                                                name: name.unwrap_or("") });
                }
                pout += c.packets_out;
                pin += c.packets_in;
                bout += c.bytes_out;
                bin += c.bytes_in;
                first = first.min(c.first_seen);
                last = last.max(c.last_seen);
            }
            let well_known = org.as_ref().is_some_and(|o| o.well_known);
            // Judged only for conversations seen from their start: a session opened before capture
            // began may well have used a name the sensor never saw.
            if domains.is_empty() && !well_known && conns.iter().any(|(k, c)| !k.inbound && c.opened) {
                reasons.push((15, "DNS·SNI 이름 없이 직접 접속".into()));
            }
            if self.asn_db.is_some() && org.is_none() {
                reasons.push((10, "조직 정보 없음".into()));
            }
            reasons.sort_by_key(|r| std::cmp::Reverse(r.0));
            reasons.dedup_by(|a, b| a.1 == b.1);
            // The strongest reason sets the level; weaker ones add a little.
            let score = reasons.first().map(|r| r.0).unwrap_or(0)
                + reasons.iter().skip(1).map(|r| r.0 / 3).sum::<u32>();
            ExternalView {
                id: AssetKey::Ip(ip).to_string(), ip: decode::ip_string(ip), org, domains, threat,
                peer_count: peers.len(), peers: peers.iter().take(8).map(|p| decode::ip_string(*p)).collect(),
                services, packets_out: pout, packets_in: pin, bytes_out: bout, bytes_in: bin,
                first_seen: iso(first), last_seen: iso(last), online: now - last <= ONLINE_WINDOW_MS,
                score: score.min(100), reasons: reasons.into_iter().map(|r| r.1).collect(),
            }
        }).collect();
        views.sort_by(|a, b| b.score.cmp(&a.score).then((b.packets_out + b.packets_in).cmp(&(a.packets_out + a.packets_in))));
        views.truncate(500);
        views
    }

    fn intel_status(&self) -> Value {
        json!({
            "asn": self.asn_db.as_ref().map(|db| json!({"ranges": db.len(), "source": db.source})),
            "blocklist": self.blocklist.as_ref().map(|b| json!({"entries": b.len(), "sources": b.sources(), "path": b.path})),
            "internal_nets": self.internal_nets.len(),
        })
    }

    /// Keep the better-supported OS guess and computer name.
    fn apply_host(&mut self, key: AssetKey, info: &osfp::HostInfo) {
        let Some(a) = self.assets.get_mut(&key) else { return };
        let mut changed = false;
        if let Some(g) = &info.os
            && g.confidence > a.os_confidence {
                (a.os, a.os_confidence, a.os_evidence) = (g.name.clone(), g.confidence, g.evidence.clone());
                changed = true;
            }
        if let Some((name, confidence)) = &info.hostname
            && (*confidence > a.hostname_confidence || (*confidence == a.hostname_confidence && a.hostname != *name)) {
                (a.hostname, a.hostname_confidence) = (name.clone(), *confidence);
                changed = true;
            }
        if changed {
            self.mark_asset(key);
        }
    }

    /// DHCP requests often come from 0.0.0.0: the client is named by its hardware address and the
    /// address it asks for.
    /// Never creates an asset: the requested address may not be granted.
    fn apply_dhcp_host(&mut self, info: &osfp::HostInfo) {
        let Some((mac, ip)) = info.client else { return };
        let by_ip = ip.map(AssetKey::Ip).filter(|k| self.assets.get(k).is_some_and(|a| a.macs.contains(&mac)));
        let by_mac = || match self.mac_ips.get(&mac).map(Vec::as_slice) {
            Some([only]) => Some(AssetKey::Ip(*only)).filter(|k| self.assets.contains_key(k)),
            _ => None,
        };
        match by_ip.or_else(by_mac) {
            Some(key) => self.apply_host(key, info),
            None => {
                if self.pending_hosts.len() >= 4096 {
                    self.pending_hosts.clear();
                }
                self.pending_hosts.insert(mac, info.clone());
            }
        }
    }

    fn mark_asset(&mut self, key: AssetKey) {
        if let Some(asset) = self.assets.get_mut(&key)
            && !asset.dirty {
                asset.dirty = true;
                self.dirty_assets.push(key);
            }
    }

    fn new_asset(&mut self, key: AssetKey, now: i64) {
        let asset = Asset {
            key,
            ip: if let AssetKey::Ip(ip) = key { Some(ip) } else { None },
            macs: Vec::new(),
            vlans: Vec::new(),
            device_type: self.sym_unknown,
            confidence: 0.0,
            identity: Default::default(),
            roles: Vec::new(),
            protocols: Vec::new(),
            evidence: Vec::new(),
            packets: 0,
            bytes: 0,
            first_seen: now,
            last_seen: now,
            vulns: Vec::new(),
            risk: 0.0,
            risk_level: "none",
            hostname: String::new(),
            hostname_confidence: 0.0,
            os: String::new(),
            os_confidence: 0.0,
            os_evidence: String::new(),
            manual: ManualInfo::default(),
            domains: match key {
                AssetKey::Ip(ip) => self.pending_names.remove(&ip).unwrap_or_default(),
                AssetKey::Mac(_) => Vec::new(),
            },
            dirty: false,
        };
        self.assets.insert(key, asset);
        self.deleted_assets.remove(&key);
        self.mark_asset(key);
        let item = Item::Asset(key);
        if self.learning {
            self.baseline.add(item);
        } else if !self.baseline.has(&item) {
            let internal = match key {
                AssetKey::Ip(ip) => decode::is_private_ip(ip),
                AssetKey::Mac(_) => true,
            };
            let title = self.syms.intern(if internal { "신규 자산 발견" } else { "신규 외부(인터넷) 주소 관측" });
            let op = self.syms.intern("New asset");
            self.alert("medium", title, self.sym_empty, op, key, None, now, "", Vec::new(), Some(item));
        }
    }

    fn asset_for_ip(&mut self, ip: u32, now: i64) -> AssetKey {
        let key = AssetKey::Ip(ip);
        if !self.assets.contains_key(&key) {
            self.new_asset(key, now);
        }
        key
    }

    fn asset_for_mac(&mut self, mac: u64, now: i64) -> AssetKey {
        if let Some(ips) = self.mac_ips.get(&mac)
            && ips.len() == 1 && self.assets.contains_key(&AssetKey::Ip(ips[0])) {
                return AssetKey::Ip(ips[0]);
            }
        let key = AssetKey::Mac(mac);
        if !self.assets.contains_key(&key) {
            self.new_asset(key, now);
            self.assets.get_mut(&key).unwrap().macs.push(mac);
        }
        key
    }

    fn bind_mac(&mut self, asset: AssetKey, mac: u64, ip: u32) {
        if !decode::is_unicast_mac(mac) {
            return;
        }
        let ips = self.mac_ips.entry(mac).or_default();
        if !ips.contains(&ip) {
            ips.push(ip);
            if ips.len() == 2 {
                // One MAC behind several IPs: a router/gateway. Un-attribute it from every host.
                let others = ips.clone();
                for other_ip in others {
                    let key = AssetKey::Ip(other_ip);
                    if let Some(other) = self.assets.get_mut(&key)
                        && let Some(pos) = other.macs.iter().position(|m| *m == mac) {
                            other.macs.remove(pos);
                            self.mark_asset(key);
                        }
                }
            }
        }
        if self.mac_ips[&mac].len() > 1 {
            return;
        }
        let a = self.assets.get_mut(&asset).unwrap();
        if !a.macs.contains(&mac) {
            a.macs.push(mac);
            self.mark_asset(asset);
            if let Some(info) = self.pending_hosts.remove(&mac) {
                self.apply_host(asset, &info);
            }
        }
        let orphan = AssetKey::Mac(mac);
        if orphan != asset && self.assets.contains_key(&orphan) {
            self.merge(orphan, asset);
        }
    }

    fn promote_mac_asset(&mut self, asset: AssetKey, ip: u32, mac: u64, now: i64) -> AssetKey {
        let target = self.asset_for_ip(ip, now);
        self.bind_mac(target, mac, ip);
        if asset != target && self.assets.contains_key(&asset) {
            self.merge(asset, target);
        }
        target
    }

    fn merge(&mut self, source: AssetKey, target: AssetKey) {
        let src = self.assets.remove(&source).unwrap();
        self.deleted_assets.insert(source);
        {
            let t = self.assets.get_mut(&target).unwrap();
            for m in src.macs { if !t.macs.contains(&m) { t.macs.push(m); } }
            for v in src.vlans { if !t.vlans.contains(&v) { t.vlans.push(v); } }
            for r in src.roles { if !t.roles.contains(&r) { t.roles.push(r); } }
            for p in src.protocols { if !t.protocols.contains(&p) { t.protocols.push(p); } }
            for e in src.evidence { if !t.evidence.contains(&e) { t.evidence.push(e); } }
            for (i, value) in src.identity.into_iter().enumerate() {
                if !value.is_empty() && t.identity[i].is_empty() {
                    t.identity[i] = value;
                }
            }
            if src.confidence > t.confidence {
                t.device_type = src.device_type;
                t.confidence = src.confidence;
            }
            if src.os_confidence > t.os_confidence {
                (t.os, t.os_confidence, t.os_evidence) = (src.os, src.os_confidence, src.os_evidence);
            }
            if !t.manual.has_values() && src.manual.has_values() {
                t.manual = src.manual;
            }
            if src.hostname_confidence > t.hostname_confidence {
                (t.hostname, t.hostname_confidence) = (src.hostname, src.hostname_confidence);
            }
            t.packets += src.packets;
            t.bytes += src.bytes;
            t.first_seen = t.first_seen.min(src.first_seen);
            t.last_seen = t.last_seen.max(src.last_seen);
        }
        self.mark_asset(target);
        let last_seen = self.assets[&target].last_seen;
        self.match_vulns(target, last_seen);

        let rename = |k: AssetKey| if k == source { target } else { k };
        let moved: Vec<LinkKey> = self.links.keys().filter(|k| k.client == source || k.server == source).copied().collect();
        for old in moved {
            let mut link = self.links.remove(&old).unwrap();
            self.deleted_links.insert(old);
            let new = LinkKey { client: rename(old.client), server: rename(old.server), proto: old.proto };
            link.key = new;
            link.dirty = true;
            self.deleted_links.remove(&new);
            self.links.insert(new, link);
            self.dirty_links.push(new);
        }
        // Baseline keys follow the asset.
        let b = &mut self.baseline;
        let mut changed = false;
        if b.assets.remove(&source) {
            b.assets.insert(target);
            changed = true;
        }
        let relink = |l: &LinkKey| LinkKey { client: rename(l.client), server: rename(l.server), proto: l.proto };
        let stale: Vec<LinkKey> = b.links.iter().filter(|l| l.client == source || l.server == source).copied().collect();
        for l in stale {
            b.links.remove(&l);
            b.links.insert(relink(&l));
            changed = true;
        }
        let stale: Vec<(LinkKey, Sym)> = b.ops.iter().filter(|(l, _)| l.client == source || l.server == source).copied().collect();
        for (l, o) in stale {
            b.ops.remove(&(l, o));
            b.ops.insert((relink(&l), o));
            changed = true;
        }
        if changed {
            b.rewrite = true;
        }
        let moved: Vec<PointKey> = self.points.keys().filter(|k| k.server == source).copied().collect();
        for old in moved {
            let profile = self.points.remove(&old).unwrap();
            let new = PointKey { server: target, ..old };
            self.points.entry(new).or_insert(profile);
            self.dirty_points.push(new);
            self.points_reset = true; // rewrite the table so the old key disappears
        }
        let mut touched = Vec::new();
        for alert in self.alerts.values_mut() {
            let mut hit = false;
            if alert.src == source { alert.src = target; hit = true; }
            if alert.dst == Some(source) { alert.dst = Some(target); hit = true; }
            if hit && !alert.dirty { alert.dirty = true; touched.push(alert.key); }
        }
        self.dirty_alerts.extend(touched);
    }

    fn touch(&mut self, key: AssetKey, size: u32, now: i64, protocol: Option<Sym>) {
        let a = self.assets.get_mut(&key).unwrap();
        a.packets += 1;
        a.bytes += size as u64;
        a.last_seen = a.last_seen.max(now);
        a.first_seen = a.first_seen.min(now);
        if let Some(p) = protocol
            && !a.protocols.contains(&p) {
                a.protocols.push(p);
            }
        self.mark_asset(key);
    }

    fn add_protocol(&mut self, key: AssetKey, proto: Sym) {
        let a = self.assets.get_mut(&key).unwrap();
        if !a.protocols.contains(&proto) {
            a.protocols.push(proto);
        }
    }

    fn add_role(&mut self, key: AssetKey, role: Sym) {
        let a = self.assets.get_mut(&key).unwrap();
        if !a.roles.contains(&role) {
            a.roles.push(role);
            self.mark_asset(key);
        }
    }

    fn apply_hint(&mut self, key: AssetKey, device: Sym, confidence: f64, evidence: Sym) {
        let a = self.assets.get_mut(&key).unwrap();
        if !a.evidence.contains(&evidence) {
            a.evidence.push(evidence);
        }
        if confidence > a.confidence {
            a.device_type = device;
            a.confidence = confidence;
        }
        self.mark_asset(key);
    }

    // --------------------------------------------------------------- links
    #[allow(clippy::too_many_arguments)]
    fn link(&mut self, src: AssetKey, dst: AssetKey, proto: Sym, size: u32, now: i64, operation: Option<&str>,
            category: &'static str, check_op: bool, explicit_alert: bool, back: bool) {
        if src == dst {
            return;
        }
        let key = LinkKey { client: src, server: dst, proto };
        let op = match operation {
            Some(op) if !op.is_empty() => Some(self.syms.intern(op)),
            _ => None,
        };
        let link = self.links.entry(key).or_insert_with(|| Link {
            key, packets: 0, packets_back: 0, bytes: 0, first_seen: now, last_seen: now,
            operations: Vec::new(), categories: Vec::new(), profile: LinkProfile::default(), dirty: false,
        });
        link.packets += 1;
        link.packets_back += back as u64;
        link.bytes += size as u64;
        link.last_seen = link.last_seen.max(now);
        if let Some(op) = op {
            match link.operations.iter_mut().find(|(o, _)| *o == op) {
                Some((_, n)) => *n += 1,
                None => link.operations.push((op, 1)),
            }
        }
        if !category.is_empty() {
            match link.categories.iter_mut().find(|(c, _)| *c == category) {
                Some((_, n)) => *n += 1,
                None => link.categories.push((category, 1)),
            }
        }
        if !link.dirty {
            link.dirty = true;
            self.dirty_links.push(key);
        }
        let learning = self.learning;
        let anomalies = self.links.get_mut(&key).map(|l| l.profile.observe(now, check_op, learning)).unwrap_or_default();
        for anomaly in anomalies {
            self.anomaly_alert(key, anomaly, now);
        }
        self.check_baseline(key, now, if check_op { op } else { None }, category, explicit_alert);
    }

    fn check_baseline(&mut self, key: LinkKey, now: i64, op: Option<Sym>, category: &'static str, explicit_alert: bool) {
        let link_item = Item::Link(key);
        if !self.baseline.has(&link_item) {
            if self.learning {
                self.baseline.add(link_item);
                if let Some(op) = op {
                    self.baseline.add(Item::Op(key, op));
                }
            } else if !explicit_alert {
                let proto = self.syms.get(key.proto).to_string();
                let severity = if baseline::is_generic(&proto) { "low" } else { "high" };
                let title = self.sym_fmt(format_args!("새로운 통신: {proto}"));
                self.alert(severity, title, key.proto, op.unwrap_or(self.sym_empty), key.client, Some(key.server),
                           now, category, Vec::new(), Some(link_item));
            }
            return;
        }
        let Some(op) = op else { return };
        let op_item = Item::Op(key, op);
        if self.baseline.has(&op_item) {
            return;
        }
        if self.learning {
            self.baseline.add(op_item);
        } else if !explicit_alert {
            let (proto, op_name) = (self.syms.get(key.proto).to_string(), self.syms.get(op).to_string());
            let title = self.sym_fmt(format_args!("새로운 명령: {proto} {op_name}"));
            self.alert(baseline::op_severity(category), title, key.proto, op, key.client, Some(key.server), now,
                       category, Vec::new(), Some(op_item));
        }
    }

    // -------------------------------------------------------------- alerts
    #[allow(clippy::too_many_arguments)]
    fn alert(&mut self, severity: &'static str, title: Sym, protocol: Sym, operation: Sym, src: AssetKey,
             dst: Option<AssetKey>, now: i64, category: &'static str, details: Vec<(String, Value)>,
             baseline: Option<Item>) {
        let mut key = AlertKey { title, src, dst };
        let mut overflow = false;
        if !self.alerts.contains_key(&key) && self.alerts.len() >= MAX_ALERTS && !self.make_alert_room(now) {
            // Nothing can be evicted (every alert is open and medium or worse). High and critical
            // alerts are still admitted up to a hard limit; anything else is counted in a summary.
            let serious = matches!(severity, "critical" | "high");
            overflow = !serious || self.alerts.len() >= MAX_ALERTS * 2;
        }
        let folded = overflow.then(|| json!({"title": self.syms.get(title), "severity": severity,
            "src": src.to_string(), "dst": dst.map(|d| d.to_string()), "time": iso(now)}));
        if overflow {
            key = AlertKey { title: self.syms.intern(ALERT_OVERFLOW_TITLE), src: AssetKey::Ip(0), dst: None };
        }
        let (severity, src, dst) = if overflow { ("high", key.src, key.dst) } else { (severity, src, dst) };
        let next_id = &mut self.next_alert_id;
        let alert = self.alerts.entry(key).or_insert_with(|| {
            let id = *next_id;
            *next_id += 1;
            Alert { id, key, severity, protocol, operation, category, src, dst, count: 0, first_seen: now,
                    last_seen: now, acknowledged: false, anomaly: false, external: false, baseline, details, dirty: false }
        });
        let created = alert.count == 0;
        alert.count += 1;
        if let Some(entry) = folded.clone() {
            // The most recent folded alerts stay readable in the summary.
            if !alert.details.iter().any(|(k, _)| k == "recent") {
                alert.details = vec![("recent".into(), Value::Array(Vec::new()))];
            }
            if let Some((_, Value::Array(list))) = alert.details.iter_mut().find(|(k, _)| k == "recent") {
                if list.len() >= OVERFLOW_RECENT {
                    list.remove(0);
                }
                list.push(entry);
            }
        }
        alert.last_seen = alert.last_seen.max(now);
        let mut reopened = false;
        if alert.acknowledged && alert.last_seen == now {
            alert.acknowledged = false; // re-opened by recurrence
            reopened = true;
        }
        if !alert.dirty {
            alert.dirty = true;
            self.dirty_alerts.push(key);
        }
        // Bounded so a stalled forwarder can never exhaust memory.
        if self.emit_events && (created || reopened) && self.events.len() < 100_000 {
            self.events.push((key, reopened, None));
        }
        // Every folded alert is forwarded with its own content.
        if let Some(entry) = folded.filter(|_| !created && !reopened) {
            self.queue_fold_event(key, entry);
        }
    }

    /// Free space in a full alert table: acknowledged alerts first, then open low/info ones, oldest
    /// first, in batches. Open medium-or-worse alerts are never dropped. (Dropped alerts stay in
    /// the database.) Returns whether anything was freed.
    fn make_alert_room(&mut self, now: i64) -> bool {
        if now < self.alert_room_retry_at {
            return false;
        }
        // Never evict what the store or the SIEM has not received yet.
        let queued: FxHashSet<AlertKey> = self.events.iter().map(|(k, _, _)| *k).collect();
        let mut candidates: Vec<(bool, i64, AlertKey)> = self.alerts.iter()
            .filter(|(k, a)| (a.acknowledged || matches!(a.severity, "low" | "info")) && !a.dirty && !queued.contains(k))
            .map(|(k, a)| (!a.acknowledged, a.last_seen, *k)).collect();
        if candidates.is_empty() {
            self.alert_room_retry_at = now + 60_000;
            return false;
        }
        candidates.sort_unstable_by_key(|c| (c.0, c.1));
        for (_, _, key) in candidates.into_iter().take(MAX_ALERTS / 20) {
            self.alerts.remove(&key);
        }
        true
    }

    fn alert_by_id(&mut self, id: u64) -> Option<&mut Alert> {
        self.alerts.values_mut().find(|a| a.id == id)
    }

    pub fn acknowledge(&mut self, id: u64) -> bool {
        let Some(alert) = self.alert_by_id(id) else { return false };
        alert.acknowledged = true;
        let key = alert.key;
        self.mark_alert(key);
        self.alert_room_retry_at = 0; // acknowledged alerts can be evicted now
        true
    }

    /// Queue a SIEM event for one folded alert or one new summary peer, carrying that entry. Folds
    /// use at most 90% of the queue, so room always remains for new and reopened alerts.
    ///
    /// Fairness between alerts: the first fold of each alert per drain is always queued; after
    /// that each alert gets at most FOLD_EVENTS_PER_KEY per drain, and what is dropped is counted
    /// and reported on its last queued event. One flooded summary cannot crowd out the others.
    fn queue_fold_event(&mut self, key: AlertKey, entry: Value) {
        if !self.emit_events {
            return;
        }
        let held_entries = self.held_entries;
        let state = self.fold_counts.entry(key).or_default();
        let first = state.queued == 0;
        // New and reopened alerts keep the top 5% of the queue to themselves.
        if (first && self.events.len() < 95_000)
            || (state.queued < FOLD_EVENTS_PER_KEY && self.events.len() < 90_000) {
            state.queued += 1;
            self.events.push((key, false, Some(entry)));
        } else {
            // Over this alert's share: held for one aggregate event at drain time, content included.
            state.held += 1;
            if held_entries < MAX_HELD_ENTRIES {
                state.entries.push(entry);
                self.held_entries += 1;
            }
        }
    }

    fn mark_alert(&mut self, key: AlertKey) {
        self.generation += 1;
        if let Some(a) = self.alerts.get_mut(&key)
            && !a.dirty {
                a.dirty = true;
                self.dirty_alerts.push(key);
            }
    }

    /// Accept the behaviour behind a baseline alert as normal.
    pub fn learn_alert(&mut self, id: u64) -> bool {
        let Some(alert) = self.alert_by_id(id) else { return false };
        alert.acknowledged = true;
        let (key, item) = (alert.key, alert.baseline);
        if let Some(item) = item {
            self.baseline.add(item);
            if let Item::Link(link_key) = item
                && let Some(link) = self.links.get(&link_key) {
                    let ops: Vec<Sym> = link.operations.iter().map(|(o, _)| *o).collect();
                    for op in ops {
                        self.baseline.add(Item::Op(link_key, op));
                    }
                }
        }
        self.mark_alert(key);
        true
    }

    pub fn set_mode(&mut self, mode: Mode, hours: Option<f64>, reset: bool) -> Value {
        if reset {
            self.baseline.clear();
            self.points.clear();
            self.dirty_points.clear();
            self.points_reset = true;
            for link in self.links.values_mut() {
                link.profile.reset();
                link.dirty = true;
            }
            self.dirty_links.extend(self.links.keys().copied());
        }
        if mode == Mode::Detecting {
            // Everything observed so far (including inventory restored from disk) is normal.
            let assets: Vec<AssetKey> = self.assets.keys().copied().collect();
            for a in assets {
                self.baseline.add(Item::Asset(a));
            }
            let links: Vec<(LinkKey, Vec<Sym>)> = self.links.iter()
                .map(|(k, l)| (*k, l.operations.iter().map(|(o, _)| *o).collect())).collect();
            for (k, ops) in links {
                self.baseline.add(Item::Link(k));
                for op in ops {
                    self.baseline.add(Item::Op(k, op));
                }
            }
        }
        self.baseline.set_mode(mode, hours);
        self.learning = mode == Mode::Learning;
        self.generation += 1;
        self.baseline.status_json()
    }

    /// Store operator-entered details for an asset (empty fields fall back to automatic values).
    pub fn set_manual(&mut self, id: &str, info: ManualInfo, user: &str, now: i64) -> Result<(), String> {
        let key = AssetKey::parse(id).filter(|k| self.assets.contains_key(k)).ok_or("asset not found")?;
        let mut info = info.sanitize()?;
        if info.has_values() {
            info.updated_by = user.to_string();
            info.updated_at = iso(now);
        } else {
            info = ManualInfo::default();
        }
        self.assets.get_mut(&key).unwrap().manual = info;
        self.mark_asset(key);
        self.match_vulns(key, now);
        self.generation += 1;
        Ok(())
    }

    // ------------------------------------------------------ vulnerabilities
    pub fn set_vulndb(&mut self, db: Option<Arc<VulnDb>>) {
        self.vulndb = db;
        let keys: Vec<(AssetKey, i64)> = self.assets.iter().map(|(k, a)| (*k, a.last_seen)).collect();
        for (k, last_seen) in keys {
            self.match_vulns(k, last_seen);
        }
        self.generation += 1;
    }

    fn match_vulns(&mut self, key: AssetKey, now: i64) {
        let asset = &self.assets[&key];
        let m = &asset.manual;
        let (vendor, model, firmware) = (pick(&m.vendor, &asset.identity[0]), pick(&m.model, &asset.identity[1]),
                                         pick(&m.firmware, &asset.identity[2]));
        let vulns = match &self.vulndb {
            Some(db) if !(vendor.is_empty() && model.is_empty()) => db.matches(vendor, model, firmware),
            _ => Vec::new(),
        };
        let risk = vulns.iter().map(|v| v.score).fold(0.0, f64::max);
        if vulns == asset.vulns && risk == asset.risk {
            return;
        }
        let solid: Vec<&VulnMatch> = vulns.iter().filter(|v| v.level == CONFIRMED || v.level == LIKELY).collect();
        let kev: Vec<&str> = solid.iter().filter(|v| v.kev).map(|v| v.id.as_str()).collect();
        let critical: Vec<&str> = solid.iter().filter(|v| v.cvss.unwrap_or(0.0) >= 9.0).map(|v| v.id.as_str()).collect();
        let alert = if !kev.is_empty() {
            Some(("critical", "악용 중인 취약점(KEV) 보유 자산", kev.iter().take(5).copied().collect::<Vec<_>>().join(", ")))
        } else if solid.iter().any(|v| v.level == CONFIRMED && v.cvss.unwrap_or(0.0) >= 9.0) {
            Some(("high", "치명적(CVSS 9+) 취약점 보유 자산", critical.join(", ")))
        } else {
            None
        };
        let asset = self.assets.get_mut(&key).unwrap();
        asset.vulns = vulns;
        asset.risk = risk;
        asset.risk_level = risk_level(risk);
        self.mark_asset(key);
        if let Some((severity, title, advisories)) = alert {
            let title = self.syms.intern(title);
            let akey = AlertKey { title, src: key, dst: None };
            if !self.alerts.contains_key(&akey) {
                let op = self.syms.intern("Vulnerability");
                self.alert(severity, title, self.sym_empty, op, key, None, now, "",
                           vec![("advisories".into(), Value::from(advisories))], None);
            }
        }
    }

    // ------------------------------------------------------- serialization
    fn item_key(&self, item: &Item) -> String {
        match item {
            Item::Asset(a) => a.to_string(),
            Item::Link(l) => self.link_key_string(l),
            Item::Op(l, o) => format!("{}|{}", self.link_key_string(l), self.syms.get(*o)),
        }
    }

    pub fn link_key_string(&self, l: &LinkKey) -> String {
        format!("{}|{}|{}", l.client, l.server, self.syms.get(l.proto))
    }

    pub fn alert_key_string(&self, k: &AlertKey) -> String {
        let dst = k.dst.map(|d| d.to_string()).unwrap_or_else(|| "None".into());
        format!("{}|{}|{}", self.syms.get(k.title), k.src, dst)
    }

    fn parse_link_key(&mut self, s: &str) -> Option<LinkKey> {
        let mut parts = s.splitn(3, '|');
        let client = AssetKey::parse(parts.next()?)?;
        let server = AssetKey::parse(parts.next()?)?;
        let proto = self.syms.intern(parts.next()?);
        Some(LinkKey { client, server, proto })
    }

    fn parse_item(&mut self, kind: &str, key: &str) -> Option<Item> {
        match kind {
            "asset" => AssetKey::parse(key).map(Item::Asset),
            "link" => self.parse_link_key(key).map(Item::Link),
            "op" => {
                let mut parts = key.splitn(4, '|');
                let (c, s, p, o) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
                let link = self.parse_link_key(&format!("{c}|{s}|{p}"))?;
                Some(Item::Op(link, self.syms.intern(o)))
            }
            _ => None,
        }
    }

    fn sorted_strs(&self, syms: &[Sym]) -> Vec<&str> {
        let mut v: Vec<&str> = syms.iter().map(|s| self.syms.get(*s)).collect();
        v.sort_unstable();
        v
    }

    fn asset_view<'a>(&'a self, a: &'a Asset, now_ms: Option<i64>) -> AssetView<'a> {
        let live = now_ms.is_some(); // snapshot (effective values) vs. storage (automatic values)
        let m = &a.manual;
        let mut macs = a.macs.clone();
        macs.sort_unstable();
        let mut vlans = a.vlans.clone();
        vlans.sort_unstable();
        let macs: Vec<String> = macs.into_iter().map(decode::mac_string).collect();
        let ip = a.ip.map(decode::ip_string).unwrap_or_default();
        let label = now_ms.map(|_| {
            if !ip.is_empty() { ip.clone() }
            else if !a.identity[4].is_empty() { a.identity[4].clone() }
            else { macs.first().cloned().unwrap_or_else(|| a.key.to_string()) }
        });
        AssetView {
            id: a.key.to_string(), ip, macs, vlans,
            device_type: if live { pick(&m.device_type, self.syms.get(a.device_type)) } else { self.syms.get(a.device_type) },
            confidence: a.confidence,
            vendor: if live { pick(&m.vendor, &a.identity[0]) } else { &a.identity[0] },
            model: if live { pick(&m.model, &a.identity[1]) } else { &a.identity[1] },
            firmware: if live { pick(&m.firmware, &a.identity[2]) } else { &a.identity[2] },
            serial: &a.identity[3],
            name: &a.identity[4], product_code: &a.identity[5], device_class: &a.identity[6],
            description: &a.identity[7],
            roles: self.sorted_strs(&a.roles), protocols: self.sorted_strs(&a.protocols),
            evidence: self.sorted_strs(&a.evidence),
            packets: a.packets, bytes: a.bytes, first_seen: iso(a.first_seen), last_seen: iso(a.last_seen),
            vulns: &a.vulns, risk: a.risk, risk_level: a.risk_level, points: Vec::new(),
            hostname: &a.hostname, hostname_confidence: a.hostname_confidence,
            os: if live { pick(&m.os, &a.os) } else { &a.os }, os_confidence: a.os_confidence, os_evidence: &a.os_evidence,
            manual: a.manual.has_values().then_some(&a.manual),
            domains: &a.domains,
            org: if live { a.ip.filter(|ip| self.is_internet(*ip)).and_then(|ip| self.org_of(ip)) } else { None },
            auto: (live && a.manual.has_values()).then(|| AutoView {
                device_type: self.syms.get(a.device_type), vendor: &a.identity[0], model: &a.identity[1],
                firmware: &a.identity[2], os: &a.os,
            }),
            status: now_ms.map(|now| if now - a.last_seen <= ONLINE_WINDOW_MS { "online" } else { "stale" }),
            label,
        }
    }

    fn link_view<'a>(&'a self, l: &'a Link) -> LinkView<'a> {
        LinkView {
            source: l.key.client.to_string(), target: l.key.server.to_string(),
            protocol: self.syms.get(l.key.proto), packets: l.packets, packets_back: l.packets_back, bytes: l.bytes,
            first_seen: iso(l.first_seen), last_seen: iso(l.last_seen),
            operations: l.operations.iter().map(|(o, n)| (self.syms.get(*o), *n)).collect(),
            categories: l.categories.iter().map(|(c, n)| (*c, *n)).collect(),
            profile: l.profile.is_learned().then_some(&l.profile),
        }
    }

    fn alert_view<'a>(&'a self, a: &'a Alert) -> AlertView<'a> {
        AlertView {
            id: a.id, key: self.alert_key_string(&a.key), severity: a.severity, title: self.syms.get(a.key.title),
            protocol: self.syms.get(a.protocol), operation: self.syms.get(a.operation), category: a.category,
            category_label: category_label(a.category), src: a.src.to_string(), dst: a.dst.map(|d| d.to_string()),
            count: a.count, first_seen: iso(a.first_seen), last_seen: iso(a.last_seen),
            status: if a.acknowledged { "acknowledged" } else { "new" },
            source: if a.baseline.is_some() { "baseline" } else if a.anomaly { "anomaly" }
                    else if a.external { "external" } else { "policy" },
            baseline: a.baseline.map(|item| BaselineRef { kind: item.kind(), key: self.item_key(&item) }),
            details: a.details.iter().map(|(k, v)| (k.as_str(), v)).collect(),
        }
    }

    /// Full dashboard snapshot as a JSON object string (without the closing brace when `open`).
    pub fn snapshot_json(&mut self, now_ms: i64) -> String {
        self.refresh_learning();
        let mut assets: Vec<&Asset> = self.assets.values().collect();
        assets.sort_by(|a, b| match (a.key, b.key) {
            (AssetKey::Ip(x), AssetKey::Ip(y)) => x.cmp(&y),
            (AssetKey::Ip(_), AssetKey::Mac(_)) => std::cmp::Ordering::Less,
            (AssetKey::Mac(_), AssetKey::Ip(_)) => std::cmp::Ordering::Greater,
            (x, y) => x.to_string().cmp(&y.to_string()),
        });
        let mut by_server: FxHashMap<AssetKey, Vec<PointView>> = FxHashMap::default();
        for (key, p) in &self.points {
            by_server.entry(key.server).or_default().push(PointView {
                protocol: self.syms.get(key.proto), point: self.syms.get(key.point), writes: p.writes,
                kind: if key.measured { "read" } else { "write" },
                last: p.last, last_seen: iso(p.last_seen), learned: p.stats.n, min: p.min, max: p.max,
                mean: p.stats.mean, stateful: p.is_stateful(),
                states: if p.is_stateful() { p.states.clone() } else { Vec::new() },
            });
        }
        for list in by_server.values_mut() {
            list.sort_by(|a, b| (a.protocol, a.point).cmp(&(b.protocol, b.point)));
            list.truncate(200);
        }
        let asset_views: Vec<AssetView> = assets.iter().map(|a| {
            let mut view = self.asset_view(a, Some(now_ms));
            view.points = by_server.remove(&a.key).unwrap_or_default();
            view
        }).collect();
        let mut link_views: Vec<LinkView> = self.links.values().map(|l| self.link_view(l)).collect();
        link_views.sort_by(|a, b| (&a.source, &a.target, a.protocol).cmp(&(&b.source, &b.target, b.protocol)));
        let mut alerts: Vec<&Alert> = self.alerts.values().collect();
        alerts.sort_by_key(|a| (a.acknowledged, std::cmp::Reverse(severity_rank(a.severity)), a.last_seen, a.id));
        let open: Vec<&&Alert> = alerts.iter().filter(|a| !a.acknowledged).collect();
        let stats = json!({
            "frames": self.stats.frames,
            "dissected": self.stats.dissected,
            "asset_count": asset_views.len(),
            "ot_asset_count": assets.iter().filter(|a| a.device_type != self.sym_unknown).count(),
            "link_count": link_views.len(),
            "alert_open": open.len(),
            "alert_critical": open.iter().filter(|a| a.severity == "critical" || a.severity == "high").count(),
            "vulnerable_assets": assets.iter().filter(|a| a.vulns.iter().any(|v| v.level != POSSIBLE)).count(),
            "kev_assets": assets.iter().filter(|a| a.vulns.iter().any(|v| v.kev && v.level != POSSIBLE)).count(),
        });
        let external = self.external_views(now_ms);
        let alert_views: Vec<AlertView> = alerts.iter().take(500).map(|a| self.alert_view(a)).collect();
        let snapshot = Snapshot {
            assets: asset_views,
            links: link_views,
            alerts: alert_views,
            baseline: self.baseline.status_json(),
            vulndb: self.vulndb.as_ref().map(|db| db.info()),
            stats,
            external,
            intel: self.intel_status(),
        };
        serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".into())
    }

    // ----------------------------------------------------------- persistence
    /// Drain dirty records into serialized rows for the store.
    pub fn take_changes(&mut self) -> Changes {
        self.alert_room_retry_at = 0; // dirty alerts become evictable once stored
        let mut changes = Changes::default();
        for key in std::mem::take(&mut self.dirty_assets) {
            if let Some(a) = self.assets.get(&key)
                && a.dirty {
                    let view = self.asset_view(a, None);
                    changes.assets.push((view.id.clone(), serde_json::to_string(&view).unwrap()));
                }
            if let Some(a) = self.assets.get_mut(&key) {
                a.dirty = false;
            }
        }
        for key in std::mem::take(&mut self.dirty_links) {
            if let Some(l) = self.links.get(&key)
                && l.dirty {
                    changes.links.push((self.link_key_string(&key), serde_json::to_string(&self.link_view(l)).unwrap()));
                }
            if let Some(l) = self.links.get_mut(&key) {
                l.dirty = false;
            }
        }
        for key in std::mem::take(&mut self.dirty_alerts) {
            if let Some(a) = self.alerts.get(&key)
                && a.dirty {
                    let view = self.alert_view(a);
                    changes.alerts.push((a.id, view.key.clone(), a.severity.to_string(), view.status.to_string(),
                                         view.last_seen.clone(), serde_json::to_string(&view).unwrap()));
                }
            if let Some(a) = self.alerts.get_mut(&key) {
                a.dirty = false;
            }
        }
        let deleted: Vec<AssetKey> = self.deleted_assets.drain().collect();
        changes.deleted_assets = deleted.into_iter().filter(|k| !self.assets.contains_key(k)).map(|k| k.to_string()).collect();
        let deleted: Vec<LinkKey> = self.deleted_links.drain().collect();
        changes.deleted_links = deleted.iter().filter(|k| !self.links.contains_key(k)).map(|k| self.link_key_string(k)).collect();
        changes.baseline_rewrite = std::mem::take(&mut self.baseline.rewrite);
        let items = if changes.baseline_rewrite { self.baseline.items() } else { std::mem::take(&mut self.baseline.pending) };
        self.baseline.pending.clear();
        changes.baseline_items = items.iter().map(|i| (i.kind().to_string(), self.item_key(i))).collect();
        changes.points_reset = std::mem::take(&mut self.points_reset);
        let dirty: Vec<PointKey> = if changes.points_reset { self.points.keys().copied().collect() }
                                   else { std::mem::take(&mut self.dirty_points) };
        self.dirty_points.clear();
        for key in &dirty {
            if let Some(p) = self.points.get_mut(key) {
                p.dirty = false;
            }
        }
        for key in dirty {
            if let Some(profile) = self.points.get(&key) {
                let doc = json!({"server": key.server.to_string(), "protocol": self.syms.get(key.proto),
                                 "point": self.syms.get(key.point), "kind": if key.measured { "read" } else { "write" },
                                 "profile": profile});
                changes.points.push((self.point_key_string(&key), doc.to_string()));
            }
        }
        if std::mem::take(&mut self.baseline.meta_dirty) {
            changes.baseline_meta = Some(self.baseline.meta_json().to_string());
        }
        changes
    }

    /// Restore state from stored documents (same JSON layout as the snapshot).
    pub fn point_key_string(&self, k: &PointKey) -> String {
        let kind = if k.measured { "|read" } else { "" };
        format!("{}|{}|{}{kind}", k.server, self.syms.get(k.proto), self.syms.get(k.point))
    }

    pub fn restore_points(&mut self, docs: Vec<Value>) {
        for doc in docs {
            let field = |k: &str| doc.get(k).and_then(|v| v.as_str());
            let (Some(server), Some(proto), Some(point)) = (field("server").and_then(AssetKey::parse), field("protocol"), field("point"))
                else { continue };
            let Some(profile) = doc.get("profile").cloned().and_then(|p| serde_json::from_value(p).ok()) else { continue };
            let measured = field("kind") == Some("read");
            let key = PointKey { server, proto: self.syms.intern(proto), point: self.syms.intern(point), measured };
            self.points.insert(key, profile);
        }
    }

    pub fn restore(&mut self, assets: Vec<Value>, links: Vec<Value>, alerts: Vec<Value>,
                   baseline_meta: Option<Value>, baseline_items: Vec<(String, String)>) {
        if let Some(meta) = &baseline_meta {
            self.baseline.restore_meta(meta);
        }
        for (kind, key) in baseline_items {
            if let Some(item) = self.parse_item(&kind, &key) {
                match item {
                    Item::Asset(a) => { self.baseline.assets.insert(a); }
                    Item::Link(l) => { self.baseline.links.insert(l); }
                    Item::Op(l, o) => { self.baseline.ops.insert((l, o)); }
                }
            }
        }
        let s = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let n = |v: &Value, k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        let strs = |v: &Value, k: &str| -> Vec<String> {
            v.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        for doc in assets {
            let Some(key) = AssetKey::parse(&s(&doc, "id")) else { continue };
            let device_type = self.syms.intern(doc.get("device_type").and_then(|x| x.as_str()).unwrap_or("Unknown"));
            let mut identity: [String; 8] = Default::default();
            for (i, field) in IDENTITY_FIELDS.iter().enumerate() {
                identity[i] = s(&doc, field);
            }
            let syms = |this: &mut Self, k: &str| strs(&doc, k).iter().map(|x| this.syms.intern(x)).collect::<Vec<_>>();
            let roles = syms(self, "roles");
            let protocols = syms(self, "protocols");
            let evidence = syms(self, "evidence");
            let ip = decode::parse_ip(&s(&doc, "ip"));
            let (mut os, mut os_evidence) = (s(&doc, "os"), s(&doc, "os_evidence"));
            let mut os_confidence = doc.get("os_confidence").and_then(|x| x.as_f64()).unwrap_or(0.0);
            if osfp::stale_os(ip, &os, &os_evidence) {
                (os, os_evidence, os_confidence) = (String::new(), String::new(), 0.0);
            }
            let mut hostname = s(&doc, "hostname");
            if !hostname.is_empty() && !osfp::valid_hostname(&hostname) {
                hostname.clear();
            }
            let asset = Asset {
                key,
                ip,
                macs: strs(&doc, "macs").iter().filter_map(|m| decode::parse_mac(m)).collect(),
                vlans: doc.get("vlans").and_then(|x| x.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect()).unwrap_or_default(),
                device_type,
                confidence: doc.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0),
                identity,
                roles, protocols, evidence,
                packets: n(&doc, "packets"),
                bytes: n(&doc, "bytes"),
                first_seen: parse_iso(&s(&doc, "first_seen")).unwrap_or(0),
                last_seen: parse_iso(&s(&doc, "last_seen")).unwrap_or(0),
                hostname_confidence: if hostname.is_empty() { 0.0 }
                    else { doc.get("hostname_confidence").and_then(|x| x.as_f64()).unwrap_or(0.0) },
                hostname, os, os_confidence, os_evidence,
                manual: doc.get("manual").cloned().and_then(|m| serde_json::from_value(m).ok()).unwrap_or_default(),
                domains: strs(&doc, "domains").into_iter().take(MAX_DOMAINS).collect(),
                vulns: doc.get("vulns").cloned().and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default(),
                risk: doc.get("risk").and_then(|x| x.as_f64()).unwrap_or(0.0),
                risk_level: static_str(&s(&doc, "risk_level"), &["critical", "high", "medium", "low", "none"]),
                dirty: false,
            };
            if let Some(ip) = asset.ip {
                for mac in &asset.macs {
                    let ips = self.mac_ips.entry(*mac).or_default();
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
            self.assets.insert(key, asset);
        }
        for doc in links {
            let (Some(client), Some(server)) = (AssetKey::parse(&s(&doc, "source")), AssetKey::parse(&s(&doc, "target")))
                else { continue };
            let proto = self.syms.intern(&s(&doc, "protocol"));
            let key = LinkKey { client, server, proto };
            let mut operations = Vec::new();
            if let Some(ops) = doc.get("operations").and_then(|x| x.as_object()) {
                for (op, count) in ops {
                    operations.push((self.syms.intern(op), count.as_u64().unwrap_or(0)));
                }
            }
            let categories = doc.get("categories").and_then(|x| x.as_object())
                .map(|c| c.iter().map(|(k, v)| (static_str(k, &CATEGORIES), v.as_u64().unwrap_or(0)))
                    .filter(|(k, _)| !k.is_empty()).collect()).unwrap_or_default();
            self.links.insert(key, Link {
                key, packets: n(&doc, "packets"), packets_back: 0, bytes: n(&doc, "bytes"),
                first_seen: parse_iso(&s(&doc, "first_seen")).unwrap_or(0),
                last_seen: parse_iso(&s(&doc, "last_seen")).unwrap_or(0),
                operations, categories, dirty: false,
                profile: doc.get("profile").cloned().and_then(|p| serde_json::from_value(p).ok()).unwrap_or_default(),
            });
        }
        for doc in alerts {
            let key_string = s(&doc, "key");
            let mut parts = key_string.rsplitn(3, '|');
            let (Some(dst), Some(src), Some(title)) = (parts.next(), parts.next(), parts.next()) else { continue };
            let Some(src_key) = AssetKey::parse(src) else { continue };
            let key = AlertKey { title: self.syms.intern(title), src: src_key, dst: AssetKey::parse(dst) };
            let baseline = doc.get("baseline").filter(|b| b.is_object())
                .and_then(|b| { let (k, v) = (s(b, "kind"), s(b, "key")); self.parse_item(&k, &v) });
            let id = n(&doc, "id");
            self.next_alert_id = self.next_alert_id.max(id + 1);
            let alert = Alert {
                id, key,
                severity: static_str(&s(&doc, "severity"), &SEVERITIES),
                protocol: self.syms.intern(&s(&doc, "protocol")),
                operation: self.syms.intern(&s(&doc, "operation")),
                category: static_str(&s(&doc, "category"), &CATEGORIES),
                src: AssetKey::parse(&s(&doc, "src")).unwrap_or(src_key),
                dst: doc.get("dst").and_then(|d| d.as_str()).and_then(AssetKey::parse),
                count: n(&doc, "count"),
                first_seen: parse_iso(&s(&doc, "first_seen")).unwrap_or(0),
                last_seen: parse_iso(&s(&doc, "last_seen")).unwrap_or(0),
                acknowledged: s(&doc, "status") == "acknowledged",
                anomaly: s(&doc, "source") == "anomaly",
                external: s(&doc, "source") == "external",
                baseline,
                details: doc.get("details").and_then(|d| d.as_object())
                    .map(|d| d.iter().map(|(k, v)| (k.clone(), v.clone())).collect()).unwrap_or_default(),
                dirty: false,
            };
            self.alerts.insert(key, alert);
        }
        self.learning = self.baseline.mode == Mode::Learning;
        self.generation += 1;
    }

    /// One-time data corrections for databases written by earlier versions. Run after the
    /// internal-network settings are applied (they decide what counts as the internet), and only
    /// once per database (the caller records that it ran).
    pub fn run_migrations(&mut self) {
        self.forget_ephemeral_misidentification();
        self.drop_ephemeral_links();
        self.acknowledge_p2p_inbound_alerts();
        self.generation += 1;
    }

    /// Conversations with the internet that earlier versions labelled with a port-only fieldbus
    /// protocol (a client's random source port) are removed.
    fn drop_ephemeral_links(&mut self) {
        let suspect: Vec<Sym> = ["CC-Link IE Field Basic", "PROFINET CM"].iter().map(|p| self.syms.intern(p)).collect();
        let internet = |k: AssetKey| matches!(k, AssetKey::Ip(ip) if self.is_internet(ip));
        let stale: Vec<LinkKey> = self.links.keys()
            .filter(|l| suspect.contains(&l.proto) && (internet(l.client) || internet(l.server))).copied().collect();
        for key in stale {
            self.links.remove(&key);
            self.deleted_links.insert(key);
        }
    }

    /// An early build reported UDP between two temporary ports (calls, P2P) as inbound access.
    fn acknowledge_p2p_inbound_alerts(&mut self) {
        let title = self.syms.intern("인터넷에서 내부 서비스로 접속");
        let stale: Vec<AlertKey> = self.alerts.iter().filter(|(k, a)| {
            k.title == title && !a.acknowledged && a.details.iter().any(|(name, v)| {
                name == "port" && v.as_str().and_then(|p| p.strip_suffix("/UDP")).and_then(|n| n.parse::<u16>().ok())
                    .is_some_and(|n| n >= 1024 && !intel::known_port(Transport::Udp, n))
            })
        }).map(|(k, _)| *k).collect();
        for key in stale {
            if let Some(alert) = self.alerts.get_mut(&key) {
                alert.acknowledged = true;
            }
            self.mark_alert(key);
        }
    }

    /// Earlier versions took a client's random source port (UDP 61450/61451, 34964) for CC-Link IE
    /// Field Basic or PROFINET CM. Hosts whose only industrial trait is such a port-only match are
    /// returned to "Unknown", and the internet alerts that rested on it are dropped.
    fn forget_ephemeral_misidentification(&mut self) {
        let suspect = ["CC-Link IE Field Basic", "PROFINET CM"];
        let suspect_syms: Vec<Sym> = suspect.iter().map(|p| self.syms.intern(p)).collect();
        let hints = ["CC-Link IE Field Basic station", "PROFINET device"];
        // A real fieldbus station does not browse the internet; a misread PC does.
        let online: FxHashSet<AssetKey> = self.links.keys().flat_map(|l| {
            let public = |k: AssetKey| matches!(k, AssetKey::Ip(ip) if self.is_internet(ip));
            [(public(l.server), l.client), (public(l.client), l.server)]
        }).filter(|(other_public, _)| *other_public).map(|(_, k)| k).collect();
        let mut fixed = Vec::new();
        for (key, a) in self.assets.iter_mut() {
            if !hints.contains(&self.syms.get(a.device_type)) || !online.contains(key) {
                continue;
            }
            let other_ot = a.protocols.iter().any(|p| {
                let name = self.syms.get(*p);
                !suspect_syms.contains(p) && !matches!(name, "ARP" | "TCP" | "UDP" | "ICMP" | "IPv6")
                    && !name.starts_with("IP/") && !name.starts_with("L2 ") && !name.starts_with("802.")
            });
            if other_ot {
                continue;
            }
            a.device_type = self.sym_unknown;
            a.confidence = 0.0;
            a.protocols.retain(|p| !suspect_syms.contains(p));
            a.evidence.retain(|e| !suspect.iter().any(|s| self.syms.get(*e).contains(s)));
            a.dirty = true;
            fixed.push(*key);
        }
        if fixed.is_empty() {
            return;
        }
        self.dirty_assets.extend(fixed.iter().copied());
        let ot_title = self.syms.intern("OT 장비의 인터넷 통신");
        let stale: Vec<AlertKey> = self.alerts.keys()
            .filter(|k| k.title == ot_title && fixed.contains(&k.src)).copied().collect();
        for key in stale {
            // Acknowledged rather than deleted: the history stays, the open list is corrected.
            if let Some(alert) = self.alerts.get_mut(&key) {
                alert.acknowledged = true;
            }
            self.mark_alert(key);
        }
    }

    // ----------------------------------------------------------------- SIEM
    fn device_summary(&self, key: Option<AssetKey>) -> String {
        let Some(asset) = key.and_then(|k| self.assets.get(&k)) else { return String::new() };
        let mut parts = vec![self.syms.get(asset.device_type).to_string()];
        for field in [&asset.identity[0], &asset.identity[1], &asset.identity[2]] {
            if !field.is_empty() {
                parts.push(field.clone());
            }
        }
        parts.join(" ")
    }

    /// Drain queued alert notifications into SIEM events, with asset context.
    pub fn take_events(&mut self) -> Vec<crate::siem::SiemEvent> {
        let queued = std::mem::take(&mut self.events);
        self.alert_room_retry_at = 0; // queued alerts were the ones that could not be evicted
        // Entries held back over an alert's share go out as one aggregate event per alert, always.
        let mut queued = queued;
        self.held_entries = 0;
        for (key, state) in std::mem::take(&mut self.fold_counts) {
            if state.held > 0 {
                let held = state.held;
                let mut aggregate = serde_json::Map::new();
                aggregate.insert("aggregated_events".into(), Value::from(held));
                aggregate.insert("entries".into(), Value::Array(state.entries));
                queued.push((key, false, Some(Value::Object(aggregate))));
            }
        }
        let mut out = Vec::with_capacity(queued.len());
        for (key, reopened, folded) in queued {
            let Some(a) = self.alerts.get(&key) else { continue };
            let title = self.syms.get(a.key.title);
            let operation = self.syms.get(a.operation);
            let signature = match (a.baseline, operation) {
                (Some(Item::Asset(_)), _) => "NE-ASSET-NEW".to_string(),
                (Some(Item::Link(_)), _) => "NE-BASELINE-COMM".to_string(),
                (Some(Item::Op(..)), _) => "NE-BASELINE-CMD".to_string(),
                (None, "Firmware change") => "NE-FIRMWARE-CHANGE".to_string(),
                (None, "Vulnerability") if title.contains("KEV") => "NE-VULN-KEV".to_string(),
                (None, "Vulnerability") => "NE-VULN-CRITICAL".to_string(),
                (None, _) if a.external && title.starts_with("위협 인텔리전스") => "NE-EXT-THREAT".to_string(),
                (None, _) if a.external && title.starts_with("산업 프로토콜") => "NE-EXT-ICS".to_string(),
                (None, _) if a.external && title.starts_with("OT 장비") => "NE-EXT-OT".to_string(),
                (None, _) if a.external => "NE-EXT-INBOUND".to_string(),
                (None, _) if a.anomaly && title.starts_with("측정값 범위") => "NE-MEASURE-RANGE".to_string(),
                (None, _) if a.anomaly && title.starts_with("측정 상태") => "NE-MEASURE-STATE".to_string(),
                (None, _) if a.anomaly && title.starts_with("공정 값 범위") => "NE-PROCESS-RANGE".to_string(),
                (None, _) if a.anomaly && title.starts_with("학습되지 않은 상태") => "NE-PROCESS-STATE".to_string(),
                (None, _) if a.anomaly && title.starts_with("학습되지 않은 주소") => "NE-PROCESS-NEWPOINT".to_string(),
                (None, _) if a.anomaly && title.starts_with("통신 중단") => "NE-ANOMALY-SILENCE".to_string(),
                (None, _) if a.anomaly && title.starts_with("폴링 주기") => "NE-ANOMALY-INTERVAL".to_string(),
                (None, _) if a.anomaly => "NE-ANOMALY-VOLUME".to_string(),
                (None, _) if !a.category.is_empty() => format!("NE-POLICY-{}", a.category.to_ascii_uppercase()),
                (None, _) => "NE-POLICY".to_string(),
            };
            let ip = |k: Option<AssetKey>| match k { Some(AssetKey::Ip(ip)) => Some(decode::ip_string(ip)), _ => None };
            let mac = |k: Option<AssetKey>| match k {
                Some(AssetKey::Mac(m)) => Some(decode::mac_string(m)),
                Some(k) => self.assets.get(&k).and_then(|x| x.macs.first()).map(|m| decode::mac_string(*m)),
                None => None,
            };
            out.push(crate::siem::SiemEvent {
                time: a.last_seen,
                class: "alert",
                signature,
                name: title.to_string(),
                severity: a.severity,
                alert_id: Some(a.id),
                count: Some(a.count),
                reopened,
                source: if a.baseline.is_some() { "baseline" } else if a.anomaly { "anomaly" }
                        else if a.external { "external" } else { "policy" }.to_string(),
                protocol: self.syms.get(a.protocol).to_string(),
                operation: operation.to_string(),
                category: a.category.to_string(),
                src_ip: ip(Some(a.src)),
                dst_ip: ip(a.dst),
                src_mac: mac(Some(a.src)),
                dst_mac: mac(a.dst),
                src_device: self.device_summary(Some(a.src)),
                dst_device: self.device_summary(a.dst),
                user: None,
                outcome: None,
                details: match folded {
                    Some(entry) => entry,
                    None if a.details.is_empty() => Value::Null,
                    None => Value::Object(a.details.iter().cloned().collect()),
                },
            });
        }
        out
    }

    // ------------------------------------------------------------- queries
    pub fn alerts_json(&self, status: Option<&str>) -> Value {
        let mut alerts: Vec<&Alert> = self.alerts.values().collect();
        alerts.sort_by_key(|a| (a.acknowledged, std::cmp::Reverse(severity_rank(a.severity)), a.last_seen, a.id));
        let views: Vec<AlertView> = alerts.iter().map(|a| self.alert_view(a))
            .filter(|v| status.is_none_or(|s| v.status == s)).collect();
        serde_json::to_value(views).unwrap_or(Value::Null)
    }

    pub fn vulns_json(&self) -> Value {
        let mut rows = Vec::new();
        for a in self.assets.values() {
            let view = self.asset_view(a, Some(0));
            for v in &a.vulns {
                let mut row = serde_json::to_value(v).unwrap();
                let obj = row.as_object_mut().unwrap();
                obj.insert("asset".into(), view.id.clone().into());
                obj.insert("label".into(), view.label.clone().unwrap_or_default().into());
                obj.insert("vendor".into(), a.identity[0].clone().into());
                obj.insert("model".into(), a.identity[1].clone().into());
                obj.insert("firmware".into(), a.identity[2].clone().into());
                rows.push((v.score, view.label.clone().unwrap_or_default(), row));
            }
        }
        rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then_with(|| a.1.cmp(&b.1)));
        Value::Array(rows.into_iter().map(|r| r.2).collect())
    }

    pub fn baseline_status(&mut self) -> Value {
        self.refresh_learning();
        self.baseline.status_json()
    }
}

// ------------------------------------------------------------------ views
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ExtKey {
    internal: u32,
    external: u32,
    tcp: bool,
    /// The service port (the side that accepts the conversation).
    port: u16,
    /// Opened from the internet.
    inbound: bool,
}

#[derive(Default)]
struct ExtConn {
    packets_out: u64,
    packets_in: u64,
    bytes_out: u64,
    bytes_in: u64,
    first_seen: i64,
    last_seen: i64,
    accepted: bool,
    ot_checked: bool,
    /// The opening of the conversation was seen (TCP SYN), so a missing name means none was used.
    opened: bool,
}

const MAX_EXTERNAL: usize = 100_000;
const MAX_DOMAINS: usize = 8;

#[derive(Serialize)]
struct OrgView {
    asn: u32,
    name: String,
    holder: String,
    country: String,
    well_known: bool,
}

#[derive(Serialize)]
struct ServiceView {
    port: u16,
    tcp: bool,
    inbound: bool,
    accepted: bool,
    name: &'static str,
}

#[derive(Serialize)]
struct ExternalView {
    id: String,
    ip: String,
    org: Option<OrgView>,
    domains: Vec<String>,
    threat: Option<String>,
    peers: Vec<String>,
    peer_count: usize,
    services: Vec<ServiceView>,
    packets_out: u64,
    packets_in: u64,
    bytes_out: u64,
    bytes_in: u64,
    first_seen: String,
    last_seen: String,
    online: bool,
    score: u32,
    reasons: Vec<String>,
}

/// Automatically identified values, shown next to what an operator entered.
#[derive(Serialize)]
struct AutoView<'a> {
    device_type: &'a str,
    vendor: &'a str,
    model: &'a str,
    firmware: &'a str,
    os: &'a str,
}

fn is_zero(v: &f64) -> bool {
    *v == 0.0
}

#[derive(Serialize)]
struct AssetView<'a> {
    id: String,
    ip: String,
    macs: Vec<String>,
    vlans: Vec<u16>,
    device_type: &'a str,
    confidence: f64,
    vendor: &'a str,
    model: &'a str,
    firmware: &'a str,
    serial: &'a str,
    name: &'a str,
    product_code: &'a str,
    device_class: &'a str,
    description: &'a str,
    roles: Vec<&'a str>,
    protocols: Vec<&'a str>,
    evidence: Vec<&'a str>,
    packets: u64,
    bytes: u64,
    first_seen: String,
    last_seen: String,
    vulns: &'a [VulnMatch],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    points: Vec<PointView<'a>>,
    risk: f64,
    risk_level: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    hostname: &'a str,
    #[serde(skip_serializing_if = "is_zero")]
    hostname_confidence: f64,
    #[serde(skip_serializing_if = "str::is_empty")]
    os: &'a str,
    #[serde(skip_serializing_if = "is_zero")]
    os_confidence: f64,
    #[serde(skip_serializing_if = "str::is_empty")]
    os_evidence: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    manual: Option<&'a ManualInfo>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    domains: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    org: Option<OrgView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto: Option<AutoView<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Serialize)]
struct PointView<'a> {
    protocol: &'a str,
    point: &'a str,
    kind: &'static str,
    writes: u64,
    last: f64,
    last_seen: String,
    learned: u64,
    min: f64,
    max: f64,
    mean: f64,
    stateful: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    states: Vec<f64>,
}

#[derive(Serialize)]
struct LinkView<'a> {
    source: String,
    target: String,
    protocol: &'a str,
    packets: u64,
    packets_back: u64,
    bytes: u64,
    first_seen: String,
    last_seen: String,
    #[serde(serialize_with = "ordered_map")]
    operations: Vec<(&'a str, u64)>,
    #[serde(serialize_with = "ordered_map")]
    categories: Vec<(&'static str, u64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a LinkProfile>,
}

#[derive(Serialize)]
struct BaselineRef {
    kind: &'static str,
    key: String,
}

#[derive(Serialize)]
struct AlertView<'a> {
    id: u64,
    key: String,
    severity: &'static str,
    title: &'a str,
    protocol: &'a str,
    operation: &'a str,
    category: &'static str,
    category_label: &'static str,
    src: String,
    dst: Option<String>,
    count: u64,
    first_seen: String,
    last_seen: String,
    status: &'static str,
    source: &'static str,
    baseline: Option<BaselineRef>,
    #[serde(serialize_with = "ordered_map")]
    details: Vec<(&'a str, &'a Value)>,
}

#[derive(Serialize)]
struct Snapshot<'a> {
    assets: Vec<AssetView<'a>>,
    links: Vec<LinkView<'a>>,
    alerts: Vec<AlertView<'a>>,
    baseline: Value,
    vulndb: Option<Value>,
    stats: Value,
    external: Vec<ExternalView>,
    intel: Value,
}

fn ordered_map<S: serde::Serializer, K: Serialize, V: Serialize>(items: &[(K, V)], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut map = s.serialize_map(Some(items.len()))?;
    for (k, v) in items {
        map.serialize_entry(k, v)?;
    }
    map.end()
}
