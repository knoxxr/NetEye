//! Offline vulnerability matching against `vulndb.json` (built by tools/vulndb_build.py).

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

pub const CONFIRMED: &str = "confirmed";
pub const LIKELY: &str = "likely";
pub const POSSIBLE: &str = "possible";

fn weight(level: &str) -> f64 {
    match level {
        CONFIRMED => 1.0,
        LIKELY => 0.8,
        _ => 0.5,
    }
}

fn label(level: &str) -> &'static str {
    match level {
        CONFIRMED => "확정",
        LIKELY => "유력",
        _ => "가능",
    }
}

pub fn norm(text: &str) -> String {
    text.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}

fn words(text: &str) -> Vec<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[a-z0-9]+").unwrap());
    let lower = text.to_lowercase();
    RE.find_iter(&lower).map(|m| m.as_str().to_string()).collect()
}

pub fn spaced(text: &str) -> String {
    format!(" {} ", words(text).join(" "))
}

pub fn vendor_key(vendor: &str) -> String {
    match words(vendor).into_iter().next() {
        None => String::new(),
        Some(w) => match w.as_str() {
            "allen" | "ab" => "rockwell".to_string(),
            _ => w,
        },
    }
}

/// Model / station-type -> product-family patterns on word boundaries of advisory product names.
static FAMILY_RULES: LazyLock<Vec<(&'static str, Regex, Vec<Regex>)>> = LazyLock::new(|| {
    // Model patterns accept order numbers as devices report them and family names as people type them.
    let s7 = |n: &str| format!(r"\bs7 ?{n}\b");
    let rules: Vec<(&str, &str, Vec<String>)> = vec![
        ("siemens", r"^(6es731|6ag131|s7300)", vec![s7("300")]),
        ("siemens", r"^(6es741|6ag141|s7400)", vec![s7("400")]),
        ("siemens", r"^(6es721|6ag121|s71200)", vec![s7("1200")]),
        ("siemens", r"^(6es751|6ag151|s71500)", vec![s7("1500")]),
        ("siemens", r"^(6es71518|6ag11518)", vec![r"\bet ?200 ?s\b".into(), s7("300")]),
        ("rockwell", r"^(1756l6|controllogix5560)", vec![r"\bcontrollogix ?5560\b".into(), r"\b1756 ?l6".into()]),
        ("rockwell", r"^(1756l7|controllogix5570)", vec![r"\bcontrollogix ?5570\b".into(), r"\b1756 ?l7".into()]),
        ("rockwell", r"^(1756l8|controllogix5580)", vec![r"\bcontrollogix ?5580\b".into(), r"\b1756 ?l8".into()]),
        ("rockwell", r"^(1769l3|compactlogix5370)", vec![r"\bcompactlogix ?5370\b".into(), r"\b1769 ?l3".into()]),
        ("rockwell", r"^(5069l3|compactlogix5380)", vec![r"\bcompactlogix ?5380\b".into(), r"\b5069 ?l3".into()]),
        ("schneider", r"^(bmxp34|modiconm340|m340)", vec![r"\bm340\b".into()]),
        ("schneider", r"^(bmep58|bmeh58|modiconm580|m580)", vec![r"\bm580\b".into()]),
        ("schneider", r"^(140cpu|modiconquantum|quantum)", vec![r"\bquantum\b".into()]),
        ("schneider", r"^(tm221|modiconm221|m221)", vec![r"\bm221\b".into()]),
        ("schneider", r"^(tm241|modiconm241|m241)", vec![r"\bm241\b".into()]),
        ("schneider", r"^(tm251|modiconm251|m251)", vec![r"\bm251\b".into()]),
        ("mitsubishi", r"^r\d+(en)?cpu", vec![r"\biq ?r\b".into()]),
        ("mitsubishi", r"^fx5", vec![r"\biq ?f\b".into(), r"\bfx5".into()]),
        ("mitsubishi", r"^q\d+\w*cpu", vec![r"\bmelsec ?q\b".into(), r"\bq ?series\b".into()]),
        ("mitsubishi", r"^l\d+\w*cpu", vec![r"\bmelsec ?l\b".into(), r"\bl ?series\b".into()]),
    ];
    rules.into_iter()
        .map(|(v, m, fams)| (v, Regex::new(m).unwrap(), fams.iter().map(|f| Regex::new(f).unwrap()).collect()))
        .collect()
});

static ORDER_NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(
    r"(?i)\b(?:6(?:ES7|AG1|GK1|ES5)\s?\d{3}-\w{5}-\w{4}|17\d\d-\w+|5069-\w+|BM[XE]\w{4,}|140CPU\w+|TM2\d\d\w+)\b").unwrap());
static CONTROLLER_WORDS: LazyLock<Regex> = LazyLock::new(||
    Regex::new(r"\b(cpu|cpus|family|controllers?|plcs?|series|firmware)\b").unwrap());

fn families(vkey: &str, model: &str) -> Vec<&'static Regex> {
    let m = norm(model);
    let mut found: Vec<&'static Regex> = Vec::new();
    if m.is_empty() {
        return found;
    }
    for (vendor, pattern, fams) in FAMILY_RULES.iter() {
        if *vendor == vkey && pattern.is_match(&m) {
            for f in fams {
                if !found.iter().any(|x| x.as_str() == f.as_str()) {
                    found.push(f);
                }
            }
        }
    }
    found
}

// ------------------------------------------------------------------- versions
pub fn parse_version(text: &str, wildcard_from: Option<&[u64]>) -> Option<Vec<u64>> {
    static SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[.\s_\-]+|update|sp").unwrap());
    let text = text.trim();
    if text.is_empty() || !text.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    let lowered = text.to_lowercase();
    let stripped = lowered.trim_start_matches('v');
    let mut out = Vec::new();
    for (i, part) in SPLIT.split(stripped).filter(|p| !p.is_empty()).enumerate() {
        let part = part.trim_start_matches('v');
        if part == "x" || part == "*" {
            let wf = wildcard_from?;
            out.push(*wf.get(i)?);
            continue;
        }
        let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        out.push(digits.chars().take(18).collect::<String>().parse().unwrap_or(u64::MAX));
    }
    if out.is_empty() { None } else { Some(out) }
}

fn compare(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let width = a.len().max(b.len());
    (0..width).map(|i| a.get(i).unwrap_or(&0).cmp(b.get(i).unwrap_or(&0)))
        .find(|o| o.is_ne()).unwrap_or(std::cmp::Ordering::Equal)
}

/// Some(true/false) if decidable; None when the spec or the firmware cannot be interpreted.
pub fn version_affected(spec: &str, firmware: &str) -> Option<bool> {
    static CONSTRAINT_SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\||,|\band\b").unwrap());
    static RANGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\S+\s*-\s*\S+$").unwrap());
    static OP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(<=|>=|!=|<|>|=)?\s*(.+)").unwrap());
    let mut spec = spec.trim().to_string();
    let lowered = spec.to_lowercase();
    if spec.is_empty() || matches!(lowered.as_str(), "*" | "vers:all/*" | "all versions" | "all")
        || lowered.ends_with("/*") || lowered.starts_with("all versions") {
        return Some(true);
    }
    let fw = parse_version(firmware, None)?;
    if lowered.starts_with("vers:") {
        spec = spec.split_once('/').map(|(_, rest)| rest.to_string()).unwrap_or_default();
    }
    let mut constraints: Vec<String> = CONSTRAINT_SPLIT.split(&spec)
        .map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
    if constraints.len() == 1 && RANGE.is_match(&constraints[0]) && !spec.contains('<') {
        let (low, high) = constraints[0].split_once('-').unwrap();
        constraints = vec![format!(">={}", low.trim()), format!("<={}", high.trim())];
    }
    let mut decided = false;
    for constraint in &constraints {
        let caps = OP.captures(constraint)?;
        let op = caps.get(1).map(|m| m.as_str());
        let reference = parse_version(caps.get(2)?.as_str(), Some(&fw))?;
        let ord = compare(&fw, &reference);
        let ok = match op {
            // Bare version = that release line (prefix match); a shorter firmware never matches.
            None => fw.starts_with(&reference),
            Some("<") => ord.is_lt(),
            Some("<=") => ord.is_le(),
            Some(">") => ord.is_gt(),
            Some(">=") => ord.is_ge(),
            Some("=") => ord.is_eq(),
            Some("!=") => ord.is_ne(),
            Some(_) => unreachable!(),
        };
        if !ok {
            return Some(false);
        }
        decided = true;
    }
    if decided { Some(true) } else { None }
}

/// Python `round(x, 1)`: rounds the exact binary value (Rust's formatter does the same).
fn round1(x: f64) -> f64 {
    format!("{x:.1}").parse().unwrap_or(x)
}

pub fn risk_level(score: f64) -> &'static str {
    if score >= 9.0 { "critical" } else if score >= 7.0 { "high" } else if score >= 4.0 { "medium" }
    else if score > 0.0 { "low" } else { "none" }
}

// ------------------------------------------------------------------- database
#[derive(Deserialize)]
struct RawProduct {
    vendor: String,
    product: String,
    #[serde(default)]
    versions: String,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    cves: Vec<String>,
    #[serde(default)]
    cvss: Option<f64>,
    #[serde(default)]
    remediation: String,
}

#[derive(Deserialize)]
struct RawAdvisory {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    cves: Vec<String>,
    #[serde(default)]
    cvss: Option<f64>,
    products: Vec<RawProduct>,
    #[serde(default)]
    kev_cves: Vec<String>,
}

struct Product {
    raw: RawProduct,
    norm: String,
    spaced: String,
    has_specific_model: bool,
}

struct Advisory {
    raw: RawAdvisory,
    products: Vec<Product>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VulnMatch {
    pub id: String,
    pub title: String,
    pub url: String,
    pub published: String,
    pub cves: Vec<String>,
    pub cvss: Option<f64>,
    pub kev: bool,
    pub level: String,
    pub level_label: String,
    pub product: String,
    pub versions: String,
    pub remediation: String,
    pub score: f64,
}

pub struct VulnDb {
    meta: serde_json::Map<String, serde_json::Value>,
    advisories: Vec<Advisory>,
    by_vendor: rustc_hash::FxHashMap<String, Vec<(usize, usize)>>,
    by_model: rustc_hash::FxHashMap<String, Vec<(usize, usize)>>,
}

impl VulnDb {
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let obj = value.as_object_mut().ok_or("not a JSON object")?;
        if obj.get("format").and_then(|v| v.as_str()) != Some("neteye-vulndb/1") {
            return Err("not a NetEye vulnerability database (format neteye-vulndb/1)".into());
        }
        let raw = obj.remove("advisories").ok_or("missing advisories")?;
        let raw: Vec<RawAdvisory> = serde_json::from_value(raw).map_err(|e| e.to_string())?;
        let mut db = VulnDb { meta: obj.clone(), advisories: Vec::new(), by_vendor: Default::default(), by_model: Default::default() };
        for (ai, adv) in raw.into_iter().enumerate() {
            let mut products = Vec::new();
            for (pi, p) in adv.products.into_iter().enumerate() {
                db.by_vendor.entry(vendor_key(&p.vendor)).or_default().push((ai, pi));
                for model in &p.models {
                    db.by_model.entry(norm(model)).or_default().push((ai, pi));
                }
                products.push(Product {
                    norm: norm(&p.product),
                    spaced: spaced(&p.product),
                    has_specific_model: !p.models.is_empty() || ORDER_NUMBER.is_match(&p.product),
                    raw: p,
                });
            }
            db.advisories.push(Advisory { raw: RawAdvisory { products: Vec::new(), ..adv }, products });
        }
        Ok(db)
    }

    pub fn info(&self) -> serde_json::Value {
        let mut info = self.meta.clone();
        info.insert("advisory_count".into(), self.advisories.len().into());
        serde_json::Value::Object(info)
    }

    pub fn advisory_count(&self) -> usize {
        self.advisories.len()
    }

    pub fn matches(&self, vendor: &str, model: &str, firmware: &str) -> Vec<VulnMatch> {
        let vkey = vendor_key(vendor);
        let model_n = norm(model);
        let fams = families(&vkey, model);
        if vkey.is_empty() && model_n.is_empty() {
            return Vec::new();
        }
        let mut candidates: Vec<(usize, usize, bool)> = Vec::new(); // (adv, product, is_model_match)
        if !model_n.is_empty() {
            for &(a, p) in self.by_model.get(&model_n).into_iter().flatten() {
                candidates.push((a, p, true));
            }
        }
        if !vkey.is_empty() {
            for &(a, p) in self.by_vendor.get(&vkey).into_iter().flatten() {
                let product = &self.advisories[a].products[p];
                let pn = &product.norm;
                if model_n.len() >= 8 && (pn.contains(&model_n)
                    || (pn.len() >= 6 && model_n.starts_with(pn.as_str()) && pn.chars().any(|c| c.is_ascii_digit()))) {
                    candidates.push((a, p, true));
                } else if !fams.is_empty() && !product.has_specific_model
                    && CONTROLLER_WORDS.is_match(&product.spaced)
                    && fams.iter().any(|f| f.is_match(&product.spaced)) {
                    candidates.push((a, p, false));
                }
            }
        }

        let mut results: Vec<VulnMatch> = Vec::new();
        for (a, p, model_match) in candidates {
            let adv = &self.advisories[a];
            let product = &adv.products[p].raw;
            let affected = version_affected(&product.versions, firmware);
            if affected == Some(false) {
                continue;
            }
            let level = if affected.is_none() || (!model_match && firmware.is_empty()) {
                POSSIBLE
            } else if model_match { CONFIRMED } else { LIKELY };
            let existing = results.iter().position(|r| r.id == adv.raw.id);
            if let Some(i) = existing
                && weight(&results[i].level) >= weight(level) {
                    continue;
                }
            let cvss = product.cvss.filter(|c| *c != 0.0).or(adv.raw.cvss);
            let cves = if product.cves.is_empty() { adv.raw.cves.clone() } else { product.cves.clone() };
            let kev = cves.iter().any(|c| adv.raw.kev_cves.contains(c));
            let score = round1(f64::min(10.0, cvss.unwrap_or(5.0) * weight(level) + if kev { 1.5 } else { 0.0 }));
            let m = VulnMatch {
                id: adv.raw.id.clone(), title: adv.raw.title.clone(), url: adv.raw.url.clone(),
                published: adv.raw.published.clone(), cves, cvss, kev,
                level: level.to_string(), level_label: label(level).to_string(),
                product: product.product.clone(), versions: product.versions.clone(),
                remediation: product.remediation.clone(), score,
            };
            match existing {
                Some(i) => results[i] = m,
                None => results.push(m),
            }
        }
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap().then_with(|| a.id.cmp(&b.id)));
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_ranges() {
        let cases = [
            ("vers:intdot/<3.2.17", "V3.2.6", Some(true)), ("vers:intdot/<3.2.17", "V3.2.17", Some(false)),
            ("<V3.2.16", "V3.2.6", Some(true)), ("<= 3.2.12", "3.2.12", Some(true)), ("<= 3.2.12", "3.2.13", Some(false)),
            ("vers:intdot/>=2.0|<3.0", "2.5", Some(true)), ("vers:intdot/>=2.0|<3.0", "3.1", Some(false)),
            ("<V3.X.14", "V3.3.9", Some(true)), ("<V3.X.14", "V3.3.14", Some(false)),
            ("20-33", "20.011", Some(true)), ("20-33", "34.1", Some(false)),
            ("3.2", "V3.2.6", Some(true)), ("3.2", "V3.3.0", Some(false)),
            ("vers:all/*", "", Some(true)), ("All versions", "1.0", Some(true)),
            ("<V2.0", "", None), ("<=first five digits of serial", "1.0", None),
        ];
        for (spec, fw, expected) in cases {
            assert_eq!(version_affected(spec, fw), expected, "{spec} / {fw}");
        }
        assert_eq!(parse_version("V16 Update 5", None), Some(vec![16, 5]));
        assert_eq!(parse_version("4.003", None), Some(vec![4, 3]));
    }

    #[test]
    fn python_compatible_rounding() {
        assert_eq!(round1(8.1 * 0.5), 4.0); // 4.05 is 4.0499999... in binary, as Python rounds it
        assert_eq!(round1(9.6 * 0.8), 7.7);
    }
}
