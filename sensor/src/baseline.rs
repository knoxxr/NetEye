//! Behavioural baseline: assets, client->server conversations and the operations used on them.

use crate::engine::{AssetKey, LinkKey, Sym};
use rustc_hash::FxHashSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Learning,
    Detecting,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Learning => "learning",
            Mode::Detecting => "detecting",
        }
    }
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "learning" => Some(Mode::Learning),
            "detecting" => Some(Mode::Detecting),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Item {
    Asset(AssetKey),
    Link(LinkKey),
    Op(LinkKey, Sym),
}

impl Item {
    pub fn kind(&self) -> &'static str {
        match self {
            Item::Asset(_) => "asset",
            Item::Link(_) => "link",
            Item::Op(..) => "op",
        }
    }
}

/// Transport-level labels: a new conversation of this kind is low severity.
pub fn is_generic(protocol: &str) -> bool {
    matches!(protocol, "TCP" | "UDP" | "ICMP" | "ARP" | "IPv6" | "LLDP" | "802.3 LLC (STP 등)")
        || protocol.starts_with("L2 ")
}

pub fn op_severity(category: &str) -> &'static str {
    match category {
        "control" | "program" | "firmware" | "config" | "command" => "high",
        "write" | "discovery" | "diagnostic" => "medium",
        _ => "low",
    }
}

pub fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

pub struct Baseline {
    pub assets: FxHashSet<AssetKey>,
    pub links: FxHashSet<LinkKey>,
    pub ops: FxHashSet<(LinkKey, Sym)>,
    pub mode: Mode,
    pub mode_since: f64,
    pub learning_until: Option<f64>,
    pub pending: Vec<Item>,
    pub meta_dirty: bool,
    pub rewrite: bool,
}

impl Default for Baseline {
    fn default() -> Self {
        Baseline {
            assets: Default::default(),
            links: Default::default(),
            ops: Default::default(),
            mode: Mode::Learning,
            mode_since: unix_now(),
            learning_until: None,
            pending: Vec::new(),
            meta_dirty: true,
            rewrite: false,
        }
    }
}

impl Baseline {
    pub fn has(&self, item: &Item) -> bool {
        match item {
            Item::Asset(a) => self.assets.contains(a),
            Item::Link(l) => self.links.contains(l),
            Item::Op(l, o) => self.ops.contains(&(*l, *o)),
        }
    }

    pub fn add(&mut self, item: Item) -> bool {
        let new = match item {
            Item::Asset(a) => self.assets.insert(a),
            Item::Link(l) => self.links.insert(l),
            Item::Op(l, o) => self.ops.insert((l, o)),
        };
        if new {
            self.pending.push(item);
        }
        new
    }

    pub fn clear(&mut self) {
        self.assets.clear();
        self.links.clear();
        self.ops.clear();
        self.pending.clear();
        self.rewrite = true;
    }

    pub fn set_mode(&mut self, mode: Mode, hours: Option<f64>) {
        self.mode = mode;
        self.mode_since = unix_now();
        self.learning_until = match (mode, hours) {
            (Mode::Learning, Some(h)) if h > 0.0 => Some(self.mode_since + h * 3600.0),
            _ => None,
        };
        self.meta_dirty = true;
    }

    pub fn expired(&self) -> bool {
        self.mode == Mode::Learning && self.learning_until.is_some_and(|until| unix_now() >= until)
    }

    pub fn items(&self) -> Vec<Item> {
        let mut out: Vec<Item> = self.assets.iter().map(|a| Item::Asset(*a)).collect();
        out.extend(self.links.iter().map(|l| Item::Link(*l)));
        out.extend(self.ops.iter().map(|(l, o)| Item::Op(*l, *o)));
        out
    }

    pub fn meta_json(&self) -> serde_json::Value {
        serde_json::json!({"mode": self.mode.as_str(), "mode_since": self.mode_since,
                           "learning_until": self.learning_until})
    }

    pub fn restore_meta(&mut self, meta: &serde_json::Value) {
        if let Some(mode) = meta.get("mode").and_then(|m| m.as_str()).and_then(Mode::parse) {
            self.mode = mode;
        }
        if let Some(since) = meta.get("mode_since").and_then(|v| v.as_f64()) {
            self.mode_since = since;
        }
        self.learning_until = meta.get("learning_until").and_then(|v| v.as_f64());
        self.meta_dirty = false;
    }

    pub fn status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode.as_str(), "mode_since": self.mode_since, "learning_until": self.learning_until,
            "counts": {"asset": self.assets.len(), "link": self.links.len(), "op": self.ops.len()},
        })
    }
}
