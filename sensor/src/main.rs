//! NetEye sensor: passive OT/ICS network security monitoring.
//!
//! Commands:
//!   neteye [serve]                         dashboard + API (+ live capture when NETEYE_INTERFACE is set)
//!   neteye import <file> [--db F] [--vulndb F]   analyse a capture and print a summary
//!   neteye replay [--vulndb F] <file|--detect|--learn>...   print the final snapshot JSON
//!   neteye bench <file|dir>... [--repeat N] [--threads N]  throughput benchmark
//!   neteye interfaces                      list capture interfaces
//!   neteye user list|add|passwd|role|del ...   manage dashboard accounts (NETEYE_PASSWORD or stdin)

mod account;
mod api;
mod auth;
mod baseline;
mod decode;
mod discover;
mod dissect;
mod engine;
mod guard;
mod intel;
mod live;
mod osfp;
mod pcap;
mod profile;
mod siem;
mod storage;
mod update;
mod vulns;
#[cfg(test)]
mod tests;

use engine::Engine;
use parking_lot::{Mutex, MutexGuard};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub db_path: PathBuf,
    pub vulndb_path: PathBuf,
    pub ipasn_path: PathBuf,
    pub blocklist_path: PathBuf,
    pub internal_nets: Vec<String>,
    pub frontend: PathBuf,
    pub interface: Option<String>,
    pub max_pcap_bytes: usize,
    pub learning_hours: f64,
    pub allowed_hosts: guard::AllowedHosts,
    pub cookie_secure: bool,
}

/// The settings file: NETEYE_CONFIG, else `neteye.conf` next to the program, else the platform
/// location used by the installers (/etc/neteye/neteye.conf, %ProgramData%\NetEye\neteye.conf).
pub fn config_file() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NETEYE_CONFIG") {
        return Some(PathBuf::from(p));
    }
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        candidates.push(dir.join("neteye.conf"));
    }
    if cfg!(windows) {
        if let Some(pd) = std::env::var_os("ProgramData") {
            candidates.push(PathBuf::from(pd).join("NetEye").join("neteye.conf"));
        }
    } else if cfg!(target_os = "macos") {
        candidates.push(PathBuf::from("/Library/Application Support/NetEye/neteye.conf"));
        candidates.push(PathBuf::from("/etc/neteye/neteye.conf"));
    } else {
        candidates.push(PathBuf::from("/etc/neteye/neteye.conf"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// `${NAME}` and `%NAME%` in a setting are replaced by environment variables (e.g. ${ProgramData}).
fn expand(value: &str) -> String {
    let mut out = value.to_string();
    for (open, close) in [("${", "}"), ("%", "%")] {
        let mut from = 0;
        while let Some(start) = out[from..].find(open).map(|i| i + from) {
            let Some(end) = out[start + open.len()..].find(close).map(|i| i + start + open.len()) else { break };
            let name = &out[start + open.len()..end];
            match std::env::var(name) {
                Ok(v) if !name.is_empty() => {
                    out.replace_range(start..end + close.len(), &v);
                    from = start + v.len();
                }
                _ => from = end + close.len(),
            }
        }
    }
    out
}

/// Read `KEY=VALUE` lines (`#` comments, optional quotes) into the environment. Variables that are
/// already set win, so a service manager or the command line can override the file.
fn load_config_file() -> Option<PathBuf> {
    let path = config_file()?;
    let text = std::fs::read_to_string(&path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=').filter(|_| !line.starts_with('#')) else { continue };
        let key = key.trim();
        if !key.starts_with("NETEYE_") || std::env::var_os(key).is_some() {
            continue;
        }
        let value = expand(value.trim().trim_matches('"'));
        // SAFETY: called at the very start of main, before any other thread exists.
        unsafe { std::env::set_var(key, value) };
    }
    Some(path)
}

/// Set one key in the settings file (created if missing), keeping every other line as it is.
pub fn save_setting(key: &str, value: &str) -> Result<PathBuf, String> {
    let path = config_file().unwrap_or_else(|| {
        std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("neteye.conf")))
            .unwrap_or_else(|| PathBuf::from("neteye.conf"))
    });
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut found = false;
    let mut lines: Vec<String> = text.lines().map(|line| {
        let t = line.trim_start();
        if !t.starts_with('#') && t.split_once('=').is_some_and(|(k, _)| k.trim() == key) {
            found = true;
            format!("{key}={value}")
        } else {
            line.to_string()
        }
    }).collect();
    if !found {
        lines.push(format!("{key}={value}"));
    }
    let tmp = path.with_extension("conf.tmp");
    std::fs::write(&tmp, lines.join("\n") + "\n").and_then(|_| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The project root holding `frontend/` (works from the repo, `sensor/`, or next to the binary).
fn project_root() -> PathBuf {
    let mut candidates = vec![std::env::current_dir().unwrap_or_default()];
    if let Ok(exe) = std::env::current_exe() {
        candidates.extend(exe.ancestors().skip(1).map(Path::to_path_buf));
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    candidates.extend(cwd.ancestors().skip(1).map(Path::to_path_buf));
    candidates.into_iter().find(|p| p.join("frontend").join("index.html").exists()).unwrap_or(cwd)
}

impl Config {
    fn from_env() -> Config {
        let root = project_root();
        Config {
            host: env("NETEYE_HOST").unwrap_or_else(|| "127.0.0.1".into()),
            port: env("NETEYE_PORT").and_then(|p| p.parse().ok()).unwrap_or(8000),
            db_path: env("NETEYE_DB").map(PathBuf::from).unwrap_or_else(|| root.join("data").join("neteye.bdb")),
            vulndb_path: env("NETEYE_VULNDB").map(PathBuf::from).unwrap_or_else(|| root.join("data").join("vulndb.json")),
            ipasn_path: env("NETEYE_IPASN").map(PathBuf::from).unwrap_or_else(|| root.join("data").join("ip2asn-v4.tsv.gz")),
            blocklist_path: env("NETEYE_BLOCKLIST").map(PathBuf::from).unwrap_or_else(|| root.join("data").join("blocklist.txt")),
            internal_nets: env("NETEYE_INTERNAL_NETS").map(|v| v.split(',').map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
            frontend: env("NETEYE_FRONTEND").map(PathBuf::from).unwrap_or_else(|| root.join("frontend")),
            interface: env("NETEYE_INTERFACE"),
            max_pcap_bytes: env("NETEYE_MAX_PCAP_MB").and_then(|v| v.parse::<usize>().ok()).unwrap_or(512) << 20,
            learning_hours: env("NETEYE_LEARNING_HOURS").and_then(|v| v.parse().ok()).unwrap_or(0.0),
            cookie_secure: env("NETEYE_COOKIE_SECURE").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            allowed_hosts: guard::AllowedHosts::new(
                &env("NETEYE_HOST").unwrap_or_else(|| "127.0.0.1".into()),
                &env("NETEYE_ALLOWED_HOSTS").map(|v| v.split(',').map(str::to_string).collect::<Vec<_>>()).unwrap_or_default()),
        }
    }
}

impl Config {
    /// Where the one-time bootstrap administrator password is written (deleted once changed).
    pub fn initial_password_file(&self) -> PathBuf {
        self.db_path.parent().unwrap_or(Path::new(".")).join("initial-admin-password.txt")
    }
}

/// Feed a capture file through the engine, holding the lock in batches so the API stays responsive.
pub fn import_file(engine: &Mutex<Engine>, path: &Path, mut progress: impl FnMut(u64)) -> std::io::Result<pcap::ReadStats> {
    let mut guard = engine.lock();
    let mut count = 0u64;
    let stats = pcap::read_file(path, |data, ts| {
        guard.process_raw(data, ts);
        count += 1;
        if count.is_multiple_of(4096) {
            MutexGuard::bump(&mut guard);
            progress(count);
        }
    });
    progress(count);
    stats
}

/// Offline address intelligence: IP-to-organisation database, threat lists, internal networks.
fn load_intel(engine: &mut Engine, config: &Config) -> Result<(), String> {
    let asn = match intel::AsnDb::load(&config.ipasn_path) {
        Ok(db) => {
            println!("IP 조직 DB: {} 범위 ({})", db.len(), config.ipasn_path.display());
            Some(Arc::new(db))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("IP 조직 DB 없음: python tools/ipasn_build.py 로 만들 수 있습니다 ({})", config.ipasn_path.display());
            None
        }
        Err(e) => return Err(format!("{}: {e}", config.ipasn_path.display())),
    };
    let blocklist = match intel::Blocklist::load(&config.blocklist_path) {
        Ok(bl) => {
            println!("위협 목록: {}개 ({})", bl.len(), bl.sources().join(", "));
            Some(Arc::new(bl))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", config.blocklist_path.display())),
    };
    engine.set_intel(asn, blocklist);
    engine.set_internal_nets(&config.internal_nets)?;
    Ok(())
}

fn load_vulndb(path: &Path) -> Result<Option<Arc<vulns::VulnDb>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    vulns::VulnDb::from_json(&bytes).map(|db| Some(Arc::new(db)))
        .map_err(|e| format!("{}: {e}", path.file_name().unwrap_or_default().to_string_lossy()))
}

fn collect_files(args: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for a in args {
        let p = PathBuf::from(a);
        if p.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&p).into_iter().flatten().flatten().map(|e| e.path())
                .filter(|f| f.extension().is_some_and(|x| x == "pcap" || x == "pcapng" || x == "cap")).collect();
            entries.sort();
            files.extend(entries);
        } else {
            files.push(p);
        }
    }
    files
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.remove(i);
    (i < args.len()).then(|| args.remove(i))
}

fn main() {
    let _ = load_config_file();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let command = if args.is_empty() { "serve".to_string() } else { args.remove(0) };
    let result = match command.as_str() {
        "serve" => serve(),
        "import" => cmd_import(args),
        "replay" => cmd_replay(args),
        "bench" => cmd_bench(args),
        "interfaces" => cmd_interfaces(),
        "version" | "--version" | "-V" => {
            println!("neteye {} ({}/{})", update::VERSION, std::env::consts::OS, std::env::consts::ARCH);
            Ok(())
        }
        "config" => {
            println!("{}", config_file().map(|p| p.display().to_string()).unwrap_or_else(|| "(no config file)".into()));
            Ok(())
        }
        "user" => cmd_user(args),
        "-h" | "--help" | "help" => {
            println!("{}", include_str!("main.rs").lines().take(9).map(|l| l.trim_start_matches("//!")).collect::<Vec<_>>().join("\n"));
            Ok(())
        }
        other => Err(format!("unknown command {other:?} (try --help)")),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn read_password(prompt: &str) -> Result<String, String> {
    if let Some(p) = env("NETEYE_PASSWORD") {
        return Ok(p);
    }
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Account administration from the sensor console (works while the server is stopped or running).
fn cmd_user(args: Vec<String>) -> Result<(), String> {
    let config = Config::from_env();
    let store = open_store(&config.db_path)?;
    let usage = "usage: neteye user list | add <name> <viewer|operator|admin> | passwd <name> | role <name> <role> | del <name>";
    let sub = args.first().map(String::as_str).ok_or(usage)?;
    let name = args.get(1).map(|n| n.trim().to_ascii_lowercase());
    let need_name = || name.clone().ok_or_else(|| usage.to_string());
    match sub {
        "list" => {
            for u in store.list_users().map_err(|e| e.to_string())? {
                println!("{:<24} {:<9} {}{}", u.username, u.role, u.created,
                         if u.must_change { "  (must change password)" } else { "" });
            }
        }
        "add" | "passwd" => {
            let name = need_name()?;
            let existing = store.get_user(&name).map_err(|e| e.to_string())?;
            let role = if sub == "add" {
                if existing.is_some() {
                    return Err(format!("user {name} already exists"));
                }
                if !auth::valid_username(&name) {
                    return Err("username: 3-32 characters of letters, digits, '.', '_' or '-'".into());
                }
                auth::Role::parse(args.get(2).map(String::as_str).unwrap_or("")).ok_or(usage)?.as_str().to_string()
            } else {
                existing.as_ref().ok_or_else(|| format!("no such user {name}"))?.role.clone()
            };
            let password = read_password(&format!("password for {name}: "))?;
            auth::check_password_policy(&name, &password)?;
            let record = storage::UserRecord {
                username: name.clone(), role, password_hash: auth::hash_password(&password)?,
                must_change: false,
                created: existing.map(|u| u.created).unwrap_or_else(|| engine::iso(api::now_ms())),
            };
            store.put_user(&record).map_err(|e| e.to_string())?;
            store.audit(&engine::iso(api::now_ms()), "console", "local", &format!("user {sub}"), 200, &name);
            println!("ok: {name} ({})", record.role);
        }
        "role" => {
            let name = need_name()?;
            let role = auth::Role::parse(args.get(2).map(String::as_str).unwrap_or("")).ok_or(usage)?;
            let mut user = store.get_user(&name).map_err(|e| e.to_string())?.ok_or_else(|| format!("no such user {name}"))?;
            if user.role == "admin" && role != auth::Role::Admin && store.admin_count().unwrap_or(0) <= 1 {
                return Err("cannot demote the last administrator".into());
            }
            user.role = role.as_str().into();
            store.put_user(&user).map_err(|e| e.to_string())?;
            store.audit(&engine::iso(api::now_ms()), "console", "local", "user role", 200, &name);
            println!("ok: {name} -> {}", user.role);
        }
        "del" => {
            let name = need_name()?;
            let user = store.get_user(&name).map_err(|e| e.to_string())?.ok_or_else(|| format!("no such user {name}"))?;
            if user.role == "admin" && store.admin_count().unwrap_or(0) <= 1 {
                return Err("cannot delete the last administrator".into());
            }
            store.delete_user(&name).map_err(|e| e.to_string())?;
            store.audit(&engine::iso(api::now_ms()), "console", "local", "user del", 200, &name);
            println!("deleted {name}");
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

/// BangDB: external server when NETEYE_BANGDB_URL is set, otherwise a managed `bangdb` process on `path`.
fn open_store(path: &Path) -> Result<storage::Store, String> {
    storage::Store::open(storage::Target::from_env(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

/// Creates a file readable only by the sensor's account (0600 on Unix; on Windows the file inherits
/// the ACL of the data directory, which should be restricted to the service account).
fn write_secret_file(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path); // never reuse a file someone else may have pre-created
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(content.as_bytes())
}

/// First start: create `admin` with a random password that must be changed at first sign-in.
fn bootstrap_admin(store: &storage::Store, config: &Config) -> Result<(), String> {
    if store.user_count().map_err(|e| e.to_string())? > 0 {
        return Ok(());
    }
    let password = auth::random_password();
    store.put_user(&storage::UserRecord {
        username: "admin".into(), role: "admin".into(), password_hash: auth::hash_password(&password)?,
        must_change: true, created: engine::iso(api::now_ms()),
    }).map_err(|e| e.to_string())?;
    let file = config.initial_password_file();
    if let Err(e) = write_secret_file(&file, &format!(
        "username: admin\npassword: {password}\n\nThis file is deleted after the password is changed.\n")) {
        eprintln!("warning: could not save {}: {e}", file.display());
    }
    println!("================================================================");
    println!(" Initial administrator account created");
    println!("   username: admin");
    println!("   password: {password}");
    println!(" You must change it at first sign-in. Also saved to {}", file.display());
    println!("================================================================");
    Ok(())
}

fn cmd_interfaces() -> Result<(), String> {
    for d in live::list_devices()? {
        println!("{}\t{}", d.name, d.description);
    }
    Ok(())
}

fn cmd_import(mut args: Vec<String>) -> Result<(), String> {
    let db = take_flag(&mut args, "--db");
    let vulndb = take_flag(&mut args, "--vulndb");
    let file = args.first().ok_or("usage: neteye import <file.pcap> [--db neteye.db] [--vulndb vulndb.json]")?;
    let mut store = db.map(|p| open_store(Path::new(&p))).transpose()?;
    let mut engine = Engine::new();
    if let Some(s) = &store {
        s.load_into(&mut engine).map_err(|e| e.to_string())?;
    }
    if let Some(p) = vulndb {
        engine.set_vulndb(load_vulndb(Path::new(&p))?);
    }
    let engine = Mutex::new(engine);
    let start = Instant::now();
    let stats = import_file(&engine, Path::new(file), |_| {}).map_err(|e| e.to_string())?;
    let elapsed = start.elapsed();
    let mut engine = engine.into_inner();
    if let Some(s) = store.as_mut() {
        s.save(&engine.take_changes()).map_err(|e| e.to_string())?;
    }
    let snap: serde_json::Value = serde_json::from_str(&engine.snapshot_json(api::now_ms())).unwrap();
    let summary = serde_json::json!({
        "import": {"frames": stats.frames, "skipped": stats.skipped, "seconds": elapsed.as_secs_f64()},
        "stats": snap["stats"],
        "assets": snap["assets"].as_array().unwrap().iter().map(|a| serde_json::json!({
            "label": a["label"], "device_type": a["device_type"], "vendor": a["vendor"], "model": a["model"],
            "firmware": a["firmware"], "protocols": a["protocols"], "risk": a["risk"]})).collect::<Vec<_>>(),
        "alerts": snap["alerts"].as_array().unwrap().iter().map(|a| serde_json::json!({
            "severity": a["severity"], "title": a["title"], "src": a["src"], "dst": a["dst"], "count": a["count"]}))
            .collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    Ok(())
}

/// Deterministic replay for differential testing: files in order, `--detect` / `--learn` switch modes.
fn cmd_replay(mut args: Vec<String>) -> Result<(), String> {
    let vulndb = take_flag(&mut args, "--vulndb");
    let mut engine = Engine::new();
    if let Some(p) = vulndb {
        engine.set_vulndb(load_vulndb(Path::new(&p))?);
    }
    let engine = Mutex::new(engine);
    for token in args {
        match token.as_str() {
            "--detect" => { engine.lock().set_mode(baseline::Mode::Detecting, None, false); }
            "--learn" => { engine.lock().set_mode(baseline::Mode::Learning, None, false); }
            file => { import_file(&engine, Path::new(file), |_| {}).map_err(|e| format!("{file}: {e}"))?; }
        }
    }
    println!("{}", engine.lock().snapshot_json(api::now_ms()));
    Ok(())
}

fn cmd_bench(mut args: Vec<String>) -> Result<(), String> {
    let repeat: usize = take_flag(&mut args, "--repeat").and_then(|v| v.parse().ok()).unwrap_or(20);
    let threads: usize = take_flag(&mut args, "--threads").and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4));
    let mut corpus: Vec<(Vec<u8>, i64)> = Vec::new();
    for file in collect_files(&args) {
        pcap::read_file(&file, |d, t| corpus.push((d.to_vec(), t))).map_err(|e| format!("{}: {e}", file.display()))?;
    }
    if corpus.is_empty() {
        return Err("no frames (usage: neteye bench <file|dir>... [--repeat N] [--threads N])".into());
    }
    let bytes: usize = corpus.iter().map(|(d, _)| d.len()).sum();
    let avg = bytes as f64 / corpus.len() as f64;
    let total = corpus.len() * repeat;
    println!("corpus: {} frames, {:.1} MB, avg {:.0} B/frame, x{repeat} = {} frames", corpus.len(), bytes as f64 / 1e6, avg, total);
    let report = |label: &str, elapsed: Duration, frames: usize| {
        let pps = frames as f64 / elapsed.as_secs_f64();
        println!("{label:34} {:9.0} kpps  {:8.2} Gbps  {:6.0} ns/frame", pps / 1e3, pps * avg * 8.0 / 1e9, 1e9 / pps);
    };

    let start = Instant::now();
    let mut sink = 0usize;
    for _ in 0..repeat {
        for (d, t) in &corpus {
            sink += decode::decode(d, *t).map_or(0, |f| f.payload.len());
        }
    }
    report("decode", start.elapsed(), total);

    let start = Instant::now();
    let mut findings = Vec::new();
    for _ in 0..repeat {
        for (d, t) in &corpus {
            if let Some(f) = decode::decode(d, *t) {
                dissect::dissect(&f, &mut findings);
                sink += findings.len();
            }
        }
    }
    report("decode+DPI (1 thread)", start.elapsed(), total);

    let start = Instant::now();
    let mut engine = Engine::new();
    for _ in 0..repeat {
        for (d, t) in &corpus {
            engine.process_raw(d, *t);
        }
    }
    report("full engine (1 thread)", start.elapsed(), total);
    let start = Instant::now();
    let snap = engine.snapshot_json(api::now_ms());
    println!("{:34} {:9.2} ms  ({} bytes)", "snapshot JSON", start.elapsed().as_secs_f64() * 1e3, snap.len());

    let start = Instant::now();
    let chunk = corpus.len().div_ceil(threads);
    let counted: usize = std::thread::scope(|scope| {
        corpus.chunks(chunk).map(|part| scope.spawn(move || {
            let mut findings = Vec::new();
            let mut n = 0;
            for _ in 0..repeat {
                for (d, t) in part {
                    if let Some(f) = decode::decode(d, *t) {
                        dissect::dissect(&f, &mut findings);
                        std::hint::black_box(&findings);
                        n += 1;
                    }
                }
            }
            n
        })).collect::<Vec<_>>().into_iter().map(|h| h.join().unwrap()).sum()
    });
    report(&format!("decode+DPI ({threads} threads)"), start.elapsed(), counted.max(1));
    std::hint::black_box(sink);
    Ok(())
}

fn serve() -> Result<(), String> {
    let config = Config::from_env();
    let store = open_store(&config.db_path)?;
    println!("database: {}", store.description);
    bootstrap_admin(&store, &config)?;
    let mut engine = Engine::new();
    store.load_into(&mut engine).map_err(|e| e.to_string())?;
    if config.learning_hours > 0.0 && engine.baseline.meta_dirty {
        engine.set_mode(baseline::Mode::Learning, Some(config.learning_hours), false);
    }
    let vulndb_error = match load_vulndb(&config.vulndb_path) {
        Ok(db) => { engine.set_vulndb(db); None }
        Err(e) => Some(e),
    };
    load_intel(&mut engine, &config)?;
    // One-time corrections of data written by earlier versions (after the network settings above).
    let marker = config.db_path.with_extension("migrated-v2");
    if !marker.exists() {
        engine.run_migrations();
        if let Err(e) = std::fs::write(&marker, "ephemeral-port misidentification, P2P inbound alerts\n") {
            eprintln!("warning: could not record migration ({}): {e}", marker.display());
        }
    }
    let engine = Arc::new(Mutex::new(engine));
    let env_str = |n: &str| env(n);
    let forwarder = siem::Forwarder::from_settings(env_str("NETEYE_SYSLOG").as_deref(),
                                                   env_str("NETEYE_SYSLOG_FORMAT").as_deref(),
                                                   env_str("NETEYE_SYSLOG_FACILITY").as_deref())?;
    if let Some(f) = &forwarder {
        engine.lock().emit_events = true;
        println!("SIEM forwarding: {}", f.status());
    }
    let mut app_state = api::AppState::new(config.clone(), engine.clone(), Some(store), vulndb_error);
    app_state.siem = forwarder;
    let state = Arc::new(app_state);

    if let Some(path) = config_file() {
        println!("설정 파일: {}", path.display());
    }
    state.set_capture(config.interface.clone());

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let pump = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let s = pump.clone();
                let _ = tokio::task::spawn_blocking(move || s.forward_events()).await;
            }
        });
        let flusher = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let s = flusher.clone();
                let _ = tokio::task::spawn_blocking(move || s.flush()).await;
            }
        });
        let upd_state = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                let status = upd_state.updater.status();
                let wait_hours = status.interval_hours.max(1);
                if status.auto_check {
                    let mgr = upd_state.updater.clone();
                    let checked = tokio::task::spawn_blocking(move || mgr.check_now()).await.ok();
                    if let Some(st) = checked
                        && st.update_available && st.auto_apply && st.can_self_update {
                            let mgr2 = upd_state.updater.clone();
                            let s2 = upd_state.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                if let Ok(res) = mgr2.apply_now() {
                                    s2.flush();
                                    if let Some(msg) = res.status_message {
                                        println!("auto-update: {msg}");
                                    }
                                }
                            }).await;
                        }
                }
                tokio::time::sleep(Duration::from_secs(wait_hours * 3600)).await;
            }
        });
        let addr = format!("{}:{}", config.host, config.port);
        let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| format!("{addr}: {e}"))?;
        println!("NetEye v{} listening on http://{addr}  (frontend: {})", update::VERSION, config.frontend.display());
        let app = api::router(state.clone());
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; })
            .await.map_err(|e| e.to_string())?;
        state.set_capture(None);
        state.flush();
        Ok::<(), String>(())
    })
}

