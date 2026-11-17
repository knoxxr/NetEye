use std::borrow::Cow;

pub type Str = Cow<'static, str>;

pub const READ: &str = "read";
pub const MONITOR: &str = "monitor";
pub const SESSION: &str = "session";
pub const DISCOVERY: &str = "discovery";
pub const DIAGNOSTIC: &str = "diagnostic";
pub const WRITE: &str = "write";
pub const COMMAND: &str = "command";
pub const CONFIG: &str = "config";
pub const PROGRAM: &str = "program";
pub const CONTROL: &str = "control";
pub const FIRMWARE: &str = "firmware";

pub fn category_label(category: &str) -> &'static str {
    match category {
        READ => "읽기",
        MONITOR => "모니터링",
        SESSION => "세션",
        DISCOVERY => "탐색",
        DIAGNOSTIC => "진단",
        WRITE => "쓰기",
        COMMAND => "제어 명령",
        CONFIG => "설정 변경",
        PROGRAM => "프로그램 변경",
        CONTROL => "운전 상태 제어",
        FIRMWARE => "펌웨어",
        _ => "",
    }
}

/// Identity attributes learned about one endpoint (static strings need no allocation).
#[derive(Default, Debug, Clone)]
pub struct Identity {
    pub vendor: Option<Str>,
    pub model: Option<Str>,
    pub firmware: Option<Str>,
    pub serial: Option<Str>,
    pub name: Option<Str>,
    pub product_code: Option<Str>,
    pub device_class: Option<Str>,
    pub description: Option<Str>,
}

impl Identity {
    /// In the fixed order the engine applies them (matches the Python IDENTITY_FIELDS order).
    pub fn fields(&self) -> [(usize, &Option<Str>); 8] {
        [(0, &self.vendor), (1, &self.model), (2, &self.firmware), (3, &self.serial), (4, &self.name),
         (5, &self.product_code), (6, &self.device_class), (7, &self.description)]
    }
}

/// Alert detail values. Numbers stay numbers until an alert is actually raised.
#[derive(Debug, Clone)]
pub enum Detail {
    Str(String),
    Static(&'static str),
    Int(i64),
    Bool(bool),
    /// value, hex digits: rendered as "0x00AB"
    Hex(u32, u8),
}

impl Detail {
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Detail::Str(s) => s.clone().into(),
            Detail::Static(s) => (*s).into(),
            Detail::Int(i) => (*i).into(),
            Detail::Bool(b) => (*b).into(),
            Detail::Hex(v, w) => format!("0x{:0width$X}", v, width = *w as usize).into(),
        }
    }
}

/// Up to eight details stored inline: no heap allocation per finding.
#[derive(Debug, Clone, Default)]
pub struct Details {
    len: u8,
    items: [Option<(&'static str, Detail)>; 8],
}

impl Details {
    pub fn push(&mut self, key: &'static str, value: Detail) {
        if (self.len as usize) < self.items.len() {
            self.items[self.len as usize] = Some((key, value));
            self.len += 1;
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = &(&'static str, Detail)> {
        self.items[..self.len as usize].iter().flatten()
    }
}

/// What a dissector understood about one PDU.
#[derive(Debug, Clone)]
pub struct Finding {
    pub protocol: Str,
    pub operation: Str,
    pub category: &'static str,
    /// Some(true): src is client/master; Some(false): src is server; None: publisher / unknown.
    pub is_request: Option<bool>,
    pub function_code: Option<u32>,
    pub identity: Identity,
    pub identity_of_dst: bool,
    pub role_src: Option<&'static str>,
    pub role_dst: Option<&'static str>,
    pub device_hint: Option<(Str, f32)>,
    pub details: Details,
    pub alert: Option<(&'static str, Str)>,
    pub announced_ip: Option<u32>,
    /// Process values written by this PDU (setpoints, coils, tags). Empty for everything else.
    pub values: Vec<PointValue>,
    /// A read request to pair with its response: (transaction key, requested ranges).
    pub read_request: Option<(u32, Vec<ReadItem>)>,
    /// A read response: (transaction key, raw data per requested range).
    pub read_response: Option<(u32, ReadData)>,
}

/// A process point on a device, kept structured so naming it costs no allocation on the hot path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PointId {
    /// Modbus table: "HR" holding register, "IR" input register, "CO" coil, "DI" discrete input.
    Modbus { unit: u8, table: &'static str, addr: u16 },
    /// S7 area 0x84 DB, 0x83 M, 0x81 I, 0x82 Q; letter B/W/D, or a bit.
    S7 { area: u8, db: u16, letter: char, byte: u32, bit: Option<u8> },
    Iec104 { ca: u16, ioa: u32, kind: &'static str },
    Tag(String),
}

impl std::fmt::Display for PointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PointId::Modbus { unit, table, addr } => write!(f, "u{unit} {table}{addr}"),
            PointId::S7 { area, db, letter, byte, bit } => {
                let prefix = match area { 0x84 => "", 0x83 => "M", 0x81 => "I", _ => "Q" };
                match (area, bit) {
                    (0x84, Some(b)) => write!(f, "DB{db}.DBX{byte}.{b}"),
                    (0x84, None) => write!(f, "DB{db}.DB{letter}{byte}"),
                    (_, Some(b)) => write!(f, "{prefix}{byte}.{b}"),
                    (_, None) => write!(f, "{prefix}{letter}{byte}"),
                }
            }
            PointId::Iec104 { ca, ioa, kind } => write!(f, "CA{ca} IOA{ioa} {kind}"),
            PointId::Tag(name) => f.write_str(name),
        }
    }
}

/// One process value: written by a command (setpoint, coil, tag) or measured (read response,
/// spontaneous report).
#[derive(Debug, Clone, PartialEq)]
pub struct PointValue {
    pub point: PointId,
    pub value: f64,
    /// On/off style values (coils, BOOL, commands): judged by the set of learned states.
    pub discrete: bool,
    /// Measured by the device rather than written to it.
    pub measured: bool,
}

/// A requested read range, remembered until its response arrives.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadItem {
    Modbus { unit: u8, table: &'static str, start: u16, count: u16 },
    S7 { area: u8, db: u16, tsize: u8, bit_address: u32, count: u16 },
    /// Logix Read Tag; `tag` is None for a non-read service inside a Multiple Service Packet
    /// (kept so replies stay aligned by position).
    Cip { tag: Option<String>, count: u16 },
}

/// Raw data of a read response, decoded once matched with its request.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadData {
    Modbus { bytes: Vec<u8> },
    /// One entry per requested item; None when the device refused that item.
    S7 { items: Vec<Option<Vec<u8>>> },
    /// One entry per reply (a Multiple Service Packet has several): type code + values.
    Cip { items: Vec<Option<Vec<u8>>> },
}

/// Upper bound of values taken from one write (large array writes are sampled, not exploded).
pub const MAX_VALUES_PER_PDU: usize = 16;

impl Finding {
    pub fn new(protocol: impl Into<Str>) -> Self {
        Finding {
            protocol: protocol.into(),
            operation: Cow::Borrowed(""),
            category: "",
            is_request: None,
            function_code: None,
            identity: Identity::default(),
            identity_of_dst: false,
            role_src: None,
            role_dst: None,
            device_hint: None,
            details: Details::default(),
            alert: None,
            announced_ip: None,
            values: Vec::new(),
            read_request: None,
            read_response: None,
        }
    }
    pub fn op(mut self, operation: impl Into<Str>, category: &'static str) -> Self {
        self.operation = operation.into();
        self.category = category;
        self
    }
    pub fn req(mut self, is_request: Option<bool>) -> Self {
        self.is_request = is_request;
        self
    }
    pub fn hint(mut self, device: impl Into<Str>, confidence: f32) -> Self {
        self.device_hint = Some((device.into(), confidence));
        self
    }
    /// Roles given as (client, server) and oriented by `to_server`.
    pub fn roles(mut self, to_server: bool, client: &'static str, server: &'static str) -> Self {
        if to_server {
            self.role_src = Some(client);
            self.role_dst = Some(server);
        } else {
            self.role_src = Some(server);
            self.role_dst = Some(client);
        }
        self
    }
    pub fn has_roles(&self) -> bool {
        self.role_src.is_some() || self.role_dst.is_some()
    }
    pub fn detail(&mut self, key: &'static str, value: Detail) {
        self.details.push(key, value);
    }
}

/// latin-1 decode, as Python's `bytes.decode("latin-1")`.
pub fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Python `str.strip()` for the characters our dissectors strip.
pub fn strip_chars<'a>(s: &'a str, chars: &[char]) -> &'a str {
    s.trim_matches(|c| chars.contains(&c))
}

impl Finding {
    /// A value written to the device.
    pub fn value(&mut self, point: PointId, value: f64, discrete: bool) {
        if self.values.len() < MAX_VALUES_PER_PDU && value.is_finite() {
            self.values.push(PointValue { point, value, discrete, measured: false });
        }
    }
    /// A value measured/reported by the device.
    pub fn measure(&mut self, point: PointId, value: f64, discrete: bool) {
        if self.values.len() < MAX_VALUES_PER_PDU && value.is_finite() {
            self.values.push(PointValue { point, value, discrete, measured: true });
        }
    }
}
