//! Version metadata, GitHub Releases update checker, SHA-256 verification, and safe self-updater.

use flate2::read::GzDecoder;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_REPO: &str = "knoxxr/NetEye";
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct UpdateConfig {
    pub repo: String,
    pub auto_check: bool,
    pub auto_apply: bool,
    pub interval_hours: u64,
}

impl UpdateConfig {
    pub fn from_env() -> Self {
        let repo = std::env::var("NETEYE_UPDATE_REPO")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| valid_repo(s))
            .unwrap_or_else(|| DEFAULT_REPO.to_string());
        let auto_check = !matches!(
            std::env::var("NETEYE_UPDATE_CHECK").ok().as_deref(),
            Some("0" | "false" | "FALSE" | "no" | "NO")
        );
        let auto_apply = matches!(
            std::env::var("NETEYE_AUTO_UPDATE").ok().as_deref(),
            Some("1" | "true" | "TRUE" | "yes" | "YES")
        );
        let interval_hours = std::env::var("NETEYE_UPDATE_CHECK_HOURS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&h| (1..=720).contains(&h))
            .unwrap_or(24);
        UpdateConfig { repo, auto_check, auto_apply, interval_hours }
    }
}

fn valid_repo(repo: &str) -> bool {
    let Some((owner, name)) = repo.split_once('/') else { return false };
    let ok = |s: &str| !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    ok(owner) && ok(name) && !name.contains('/')
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateStatus {
    pub current_version: String,
    pub platform: String,
    pub arch: String,
    pub repo: String,
    pub issues_url: String,
    pub discussions_url: String,
    pub releases_url: String,
    pub auto_check: bool,
    pub auto_apply: bool,
    pub interval_hours: u64,
    pub can_self_update: bool,
    pub checking: bool,
    pub applying: bool,
    pub last_checked: Option<String>,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: Option<String>,
    pub release_notes: Option<String>,
    pub published_at: Option<String>,
    pub asset_name: Option<String>,
    pub asset_url: Option<String>,
    pub asset_size: Option<u64>,
    pub checksum_url: Option<String>,
    pub status_message: Option<String>,
    pub last_error: Option<String>,
    pub restart_required: bool,
    pub downloaded_path: Option<String>,
}

pub struct UpdateManager {
    state: Mutex<UpdateStatus>,
    data_dir: PathBuf,
    frontend_dir: PathBuf,
}

impl UpdateManager {
    pub fn new(config: UpdateConfig, data_dir: PathBuf, frontend_dir: PathBuf) -> Self {
        let base_url = format!("https://github.com/{}", config.repo);
        let status = UpdateStatus {
            current_version: VERSION.to_string(),
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            repo: config.repo,
            issues_url: format!("{base_url}/issues/new/choose"),
            discussions_url: format!("{base_url}/discussions"),
            releases_url: format!("{base_url}/releases"),
            auto_check: config.auto_check,
            auto_apply: config.auto_apply,
            interval_hours: config.interval_hours,
            can_self_update: matches!(std::env::consts::OS, "linux" | "macos"),
            checking: false,
            applying: false,
            last_checked: None,
            latest_version: None,
            update_available: false,
            release_url: None,
            release_notes: None,
            published_at: None,
            asset_name: None,
            asset_url: None,
            asset_size: None,
            checksum_url: None,
            status_message: None,
            last_error: None,
            restart_required: false,
            downloaded_path: None,
        };
        UpdateManager { state: Mutex::new(status), data_dir, frontend_dir }
    }

    pub fn status(&self) -> UpdateStatus {
        self.state.lock().clone()
    }

    pub fn set_settings(&self, auto_check: Option<bool>, auto_apply: Option<bool>) -> UpdateStatus {
        let mut s = self.state.lock();
        if let Some(v) = auto_check {
            s.auto_check = v;
        }
        if let Some(v) = auto_apply {
            s.auto_apply = v;
        }
        s.clone()
    }

    pub fn check_now(&self) -> UpdateStatus {
        let repo = {
            let mut s = self.state.lock();
            if s.checking {
                return s.clone();
            }
            s.checking = true;
            s.last_error = None;
            s.repo.clone()
        };

        let result = fetch_latest_release(&repo);
        let now = iso_now();
        let mut s = self.state.lock();
        s.checking = false;
        s.last_checked = Some(now);
        match result {
            Ok(None) => {
                s.update_available = false;
                s.latest_version = Some(VERSION.to_string());
                s.status_message = Some("No published GitHub releases yet.".to_string());
                s.last_error = None;
            }
            Ok(Some(rel)) => {
                let newer = is_newer(&rel.tag, VERSION);
                let matched = select_asset(&rel.assets, std::env::consts::OS, std::env::consts::ARCH);
                let checksum = rel.assets.iter().find(|a| a.name.eq_ignore_ascii_case("SHA256SUMS.txt"));
                s.latest_version = Some(rel.tag.trim_start_matches('v').to_string());
                s.update_available = newer;
                s.release_url = Some(rel.html_url);
                s.release_notes = Some(truncate_notes(&rel.body, 2000));
                s.published_at = rel.published_at;
                s.asset_name = matched.map(|a| a.name.clone());
                s.asset_url = matched.map(|a| a.url.clone());
                s.asset_size = matched.map(|a| a.size);
                s.checksum_url = checksum.map(|a| a.url.clone());
                s.last_error = None;
                s.status_message = Some(if newer {
                    format!("Update available: v{}", rel.tag.trim_start_matches('v'))
                } else {
                    format!("NetEye v{VERSION} is up to date.")
                });
            }
            Err(e) => {
                s.last_error = Some(e);
                s.status_message = Some("Unable to reach GitHub Releases (offline or rate-limited).".to_string());
            }
        }
        s.clone()
    }

    pub fn apply_now(&self) -> Result<UpdateStatus, String> {
        // Refresh release metadata if never checked yet.
        if self.state.lock().last_checked.is_none() {
            self.check_now();
        }

        let (asset_name, asset_url, checksum_url, latest_ver) = {
            let mut s = self.state.lock();
            if s.applying {
                return Err("An update is already in progress.".to_string());
            }
            if !s.update_available {
                return Err(format!("NetEye v{VERSION} is already up to date."));
            }
            let Some(name) = s.asset_name.clone() else {
                return Err(format!("No compatible release asset found for {}/{}.", s.platform, s.arch));
            };
            let Some(url) = s.asset_url.clone() else {
                return Err("Release asset URL is missing.".to_string());
            };
            let ver = s.latest_version.clone().unwrap_or_else(|| "latest".to_string());
            s.applying = true;
            s.last_error = None;
            s.status_message = Some(format!("Downloading {name}..."));
            (name, url, s.checksum_url.clone(), ver)
        };

        let outcome = self.download_and_install(&asset_name, &asset_url, checksum_url.as_deref(), &latest_ver);
        let mut s = self.state.lock();
        s.applying = false;
        match outcome {
            Ok((msg, restart, path)) => {
                s.status_message = Some(msg);
                s.last_error = None;
                s.restart_required = restart;
                s.downloaded_path = path;
                if restart {
                    s.update_available = false;
                }
                Ok(s.clone())
            }
            Err(e) => {
                s.last_error = Some(e.clone());
                s.status_message = Some(format!("Update failed: {e}"));
                Err(e)
            }
        }
    }

    fn download_and_install(
        &self,
        asset_name: &str,
        asset_url: &str,
        checksum_url: Option<&str>,
        latest_ver: &str,
    ) -> Result<(String, bool, Option<String>), String> {
        if !asset_url.starts_with("https://") {
            return Err("Refusing non-HTTPS update URL.".to_string());
        }
        let bytes = http_get_bytes(asset_url, MAX_DOWNLOAD_BYTES)?;
        let actual_sha = sha256_hex(&bytes);

        if let Some(sum_url) = checksum_url {
            if !sum_url.starts_with("https://") {
                return Err("Refusing non-HTTPS checksum URL.".to_string());
            }
            let sum_bytes = http_get_bytes(sum_url, MAX_CHECKSUM_BYTES)?;
            let sum_text = String::from_utf8_lossy(&sum_bytes);
            if let Some(expected) = find_sha256_entry(&sum_text, asset_name) {
                if !expected.eq_ignore_ascii_case(&actual_sha) {
                    return Err(format!("SHA-256 mismatch for {asset_name} (expected {expected}, got {actual_sha})."));
                }
            }
        }

        if matches!(std::env::consts::OS, "linux" | "macos") && asset_name.ends_with(".tar.gz") {
            self.apply_unix_tarball(&bytes)?;
            return Ok((
                format!("Installed v{latest_ver} (SHA-256 verified). Restart the NetEye service to activate."),
                true,
                None,
            ));
        }

        // Windows / Android / other: save verified package into data/updates/ for installation.
        let updates_dir = self.data_dir.join("updates");
        fs::create_dir_all(&updates_dir).map_err(|e| format!("cannot create updates dir: {e}"))?;
        let safe_name = Path::new(asset_name)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("invalid asset filename")?;
        let dest = updates_dir.join(safe_name);
        fs::write(&dest, &bytes).map_err(|e| format!("cannot write downloaded installer: {e}"))?;
        Ok((
            format!("Downloaded and verified v{latest_ver} to {}. Run it to finish upgrading.", dest.display()),
            false,
            Some(dest.display().to_string()),
        ))
    }

    fn apply_unix_tarball(&self, targz: &[u8]) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| format!("cannot locate current executable: {e}"))?;
        let exe_dir = exe.parent().ok_or("cannot determine executable directory")?;
        let stage = exe_dir.join(format!(".neteye-update-{}", std::process::id()));
        let _ = fs::remove_dir_all(&stage);
        fs::create_dir_all(&stage).map_err(|e| format!("cannot create staging directory in {}: {e}", exe_dir.display()))?;

        let extract_res = extract_payload_tar_gz(targz, &stage);
        if let Err(e) = extract_res {
            let _ = fs::remove_dir_all(&stage);
            return Err(e);
        }

        let new_neteye = stage.join("neteye");
        if !new_neteye.is_file() {
            let _ = fs::remove_dir_all(&stage);
            return Err("Update archive does not contain payload/neteye.".to_string());
        }
        set_executable(&new_neteye)?;

        // Replace neteye atomically with a .bak rollback copy.
        let bak = exe.with_extension("bak");
        let _ = fs::remove_file(&bak);
        fs::rename(&exe, &bak).map_err(|e| format!("cannot back up current binary: {e}"))?;
        if let Err(e) = fs::rename(&new_neteye, &exe) {
            let _ = fs::rename(&bak, &exe);
            let _ = fs::remove_dir_all(&stage);
            return Err(format!("cannot replace binary: {e}"));
        }

        // Replace sibling bangdb if present in archive.
        let new_bangdb = stage.join("bangdb");
        let cur_bangdb = exe_dir.join("bangdb");
        if new_bangdb.is_file() && cur_bangdb.exists() {
            let _ = set_executable(&new_bangdb);
            let _ = fs::rename(&new_bangdb, &cur_bangdb);
        }

        // Refresh frontend static files if writable.
        let new_frontend = stage.join("frontend");
        if new_frontend.is_dir() && self.frontend_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&new_frontend) {
                for entry in entries.flatten() {
                    let src = entry.path();
                    if src.is_file()
                        && let Some(name) = src.file_name() {
                            let _ = fs::copy(&src, self.frontend_dir.join(name));
                        }
                }
            }
        }

        let _ = fs::remove_dir_all(&stage);
        Ok(())
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod failed: {e}"))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

struct ReleaseAsset {
    name: String,
    url: String,
    size: u64,
}

struct ReleaseInfo {
    tag: String,
    html_url: String,
    published_at: Option<String>,
    body: String,
    assets: Vec<ReleaseAsset>,
}

fn http_agent(timeout_secs: u64) -> ureq::Agent {
    #[allow(unused_mut)]
    let mut cfg = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(timeout_secs)));
    #[cfg(not(target_os = "android"))]
    {
        cfg = cfg.tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        );
    }
    cfg.build().into()
}

fn fetch_latest_release(repo: &str) -> Result<Option<ReleaseInfo>, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let agent = http_agent(15);
    let mut resp = agent
        .get(&url)
        .header("User-Agent", &format!("NetEye/{VERSION}"))
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    if status != 200 {
        return Err(format!("GitHub API returned HTTP {status}"));
    }
    let body: Value = resp.body_mut().read_json().map_err(|e| format!("invalid JSON: {e}"))?;
    let tag = body["tag_name"].as_str().ok_or("missing tag_name")?.to_string();
    let html_url = body["html_url"].as_str().unwrap_or("").to_string();
    let published_at = body["published_at"].as_str().map(str::to_string);
    let notes = body["body"].as_str().unwrap_or("").to_string();
    let assets = body["assets"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    Some(ReleaseAsset {
                        name: a["name"].as_str()?.to_string(),
                        url: a["browser_download_url"].as_str()?.to_string(),
                        size: a["size"].as_u64().unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(ReleaseInfo { tag, html_url, published_at, body: notes, assets }))
}

fn http_get_bytes(url: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let agent = http_agent(120);
    let mut resp = agent
        .get(url)
        .header("User-Agent", &format!("NetEye/{VERSION}"))
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(format!("download returned HTTP {status}"));
    }
    let mut out = Vec::new();
    let mut reader = resp.body_mut().as_reader().take(max_bytes + 1);
    reader.read_to_end(&mut out).map_err(|e| format!("read failed: {e}"))?;
    if out.len() as u64 > max_bytes {
        return Err("downloaded file exceeds safety limit".to_string());
    }
    Ok(out)
}

fn select_asset<'a>(assets: &'a [ReleaseAsset], os: &str, arch: &str) -> Option<&'a ReleaseAsset> {
    let lower = |a: &ReleaseAsset| a.name.to_ascii_lowercase();
    match (os, arch) {
        ("linux", "x86_64") => assets.iter().find(|a| lower(a).ends_with("linux-x86_64.tar.gz")),
        ("macos", _) => assets.iter().find(|a| lower(a).ends_with("macos-universal.tar.gz"))
            .or_else(|| assets.iter().find(|a| lower(a).ends_with("macos-universal.pkg"))),
        ("windows", _) => assets.iter().find(|a| lower(a).starts_with("neteye-setup-") && lower(a).ends_with(".exe"))
            .or_else(|| assets.iter().find(|a| lower(a).ends_with(".msi"))),
        ("android", _) => assets.iter().find(|a| lower(a).ends_with(".apk")),
        _ => None,
    }
}

pub fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches(['v', 'V']).split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

fn truncate_notes(s: &str, max_chars: usize) -> String {
    let mut out: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

fn iso_now() -> String {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

pub fn find_sha256_entry(text: &str, filename: &str) -> Option<String> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(hash) = parts.next() else { continue };
        let Some(name) = parts.next() else { continue };
        let clean = name.trim_start_matches('*');
        if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
            && (clean == filename || Path::new(clean).file_name().and_then(|n| n.to_str()) == Some(filename))
        {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

/// Extract only `*/payload/*` regular files from a USTAR/GNU `.tar.gz` safely (blocks path traversal & symlinks).
fn extract_payload_tar_gz(targz: &[u8], dest: &Path) -> Result<(), String> {
    let mut dec = GzDecoder::new(targz);
    let mut header = [0u8; 512];
    loop {
        match read_exact_or_eof(&mut dec, &mut header)? {
            false => break,
            true => {}
        }
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let raw_name = cstr(&header[0..100]);
        let prefix = cstr(&header[345..500]);
        let full_name = if prefix.is_empty() { raw_name } else { format!("{prefix}/{raw_name}") };
        let size = parse_octal(&header[124..136])?;
        let typeflag = header[156];

        let mut data = vec![0u8; size as usize];
        if size > 0 {
            dec.read_exact(&mut data).map_err(|e| format!("truncated tar entry: {e}"))?;
        }
        let pad = (512 - (size % 512)) % 512;
        if pad > 0 {
            let mut skip = [0u8; 512];
            dec.read_exact(&mut skip[..pad as usize]).map_err(|e| format!("truncated tar padding: {e}"))?;
        }

        // Only regular files ('0' or '\0') inside `<top>/payload/...`
        if typeflag != b'0' && typeflag != 0 {
            continue;
        }
        let Some((_, rel_str)) = full_name.split_once("/payload/") else { continue };
        let rel = safe_rel_path(rel_str)?;
        let out_path = dest.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
        }
        fs::write(&out_path, &data).map_err(|e| format!("write failed: {e}"))?;
    }
    Ok(())
}

fn read_exact_or_eof(r: &mut impl Read, buf: &mut [u8]) -> Result<bool, String> {
    let mut read = 0;
    while read < buf.len() {
        let n = r.read(&mut buf[read..]).map_err(|e| format!("tar read error: {e}"))?;
        if n == 0 {
            return if read == 0 { Ok(false) } else { Err("unexpected EOF in tar header".to_string()) };
        }
        read += n;
    }
    Ok(true)
}

fn cstr(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn parse_octal(slice: &[u8]) -> Result<u64, String> {
    let s = cstr(slice);
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(trimmed, 8).map_err(|_| format!("invalid tar size: {trimmed}"))
}

fn safe_rel_path(rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(format!("unsafe absolute tar path: {rel}"));
    }
    let mut clean = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(seg) => clean.push(seg),
            Component::CurDir => {}
            _ => return Err(format!("unsafe tar path component: {rel}")),
        }
    }
    if clean.as_os_str().is_empty() {
        return Err("empty tar path".to_string());
    }
    Ok(clean)
}

/// Compact pure-Rust FIPS 180-4 SHA-256 (avoids pulling in an extra crate for release verification).
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut hex = String::with_capacity(64);
    for word in h {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{word:08x}");
    }
    hex
}

pub fn version_summary_json(mgr: &UpdateManager) -> Value {
    let s = mgr.status();
    json!({
        "version": s.current_version,
        "platform": s.platform,
        "arch": s.arch,
        "repo": s.repo,
        "issues_url": s.issues_url,
        "discussions_url": s.discussions_url,
        "releases_url": s.releases_url,
        "update_available": s.update_available,
        "latest_version": s.latest_version,
        "release_url": s.release_url,
        "restart_required": s.restart_required,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_comparison() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        assert!(is_newer("v0.1.1-rc1", "0.1.0"));
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn checksum_lookup_and_asset_matching() {
        let sums = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  neteye-0.2.0-linux-x86_64.tar.gz\n";
        assert_eq!(
            find_sha256_entry(sums, "neteye-0.2.0-linux-x86_64.tar.gz").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        let assets = vec![
            ReleaseAsset { name: "NetEye-Setup-0.2.0.exe".into(), url: "https://x/win".into(), size: 10 },
            ReleaseAsset { name: "neteye-0.2.0-linux-x86_64.tar.gz".into(), url: "https://x/lin".into(), size: 10 },
            ReleaseAsset { name: "neteye-0.2.0-macos-universal.tar.gz".into(), url: "https://x/mac".into(), size: 10 },
            ReleaseAsset { name: "NetEye-0.2.0-android-arm64.apk".into(), url: "https://x/apk".into(), size: 10 },
        ];
        assert_eq!(select_asset(&assets, "linux", "x86_64").unwrap().name, "neteye-0.2.0-linux-x86_64.tar.gz");
        assert_eq!(select_asset(&assets, "macos", "aarch64").unwrap().name, "neteye-0.2.0-macos-universal.tar.gz");
        assert_eq!(select_asset(&assets, "windows", "x86_64").unwrap().name, "NetEye-Setup-0.2.0.exe");
        assert_eq!(select_asset(&assets, "android", "aarch64").unwrap().name, "NetEye-0.2.0-android-arm64.apk");
    }

    #[test]
    fn safe_path_rejects_traversal() {
        assert!(safe_rel_path("../etc/passwd").is_err());
        assert!(safe_rel_path("/etc/passwd").is_err());
        assert_eq!(safe_rel_path("frontend/app.js").unwrap(), PathBuf::from("frontend/app.js"));
    }
}
