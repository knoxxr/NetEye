//! Persistence on BangDB (github.com/knoxxr/bangdb) through its HTTP/JSON API.
//!
//! BangDB is an embedded SQL database written in Go. The Rust sensor cannot link Go code without a
//! cgo toolchain, so it talks to BangDB's documented cross-language interface instead:
//!
//! * **Managed** (default): the sensor starts `bangdb` as a child process bound to 127.0.0.1 on a
//!   free port, authenticated by a random per-run token passed through the environment (never on
//!   the command line), and stops it on exit.
//! * **External**: `NETEYE_BANGDB_URL` points at a BangDB server you run yourself
//!   (`NETEYE_BANGDB_TOKEN`, or `NETEYE_BANGDB_USER` + `NETEYE_BANGDB_PASSWORD` for a users-file account).
//!
//! Every flush is one `/batch` request, which BangDB runs as a single transaction.

use crate::engine::{Changes, Engine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, String>;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, data TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS links (key TEXT PRIMARY KEY, data TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, severity TEXT NOT NULL, \
     status TEXT NOT NULL, last_seen TEXT NOT NULL, data TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts(last_seen)",
    "CREATE TABLE IF NOT EXISTS baseline (kind TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (kind, key))",
    "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS points (key TEXT PRIMARY KEY, data TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, role TEXT NOT NULL, password_hash TEXT NOT NULL, \
     must_change INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT NOT NULL, \
     ip TEXT NOT NULL, action TEXT NOT NULL, status INTEGER NOT NULL, detail TEXT NOT NULL)",
];

/// BangDB rejects bodies over 16 MiB; large flushes are split below that.
const MAX_BATCH_BYTES: usize = 8 << 20;
/// Startup loads every asset/link/alert document in one response.
const MAX_RESPONSE_BYTES: u64 = 1 << 30;

#[derive(Clone, Debug, serde::Serialize)]
pub struct UserRecord {
    pub username: String,
    pub role: String,
    #[serde(skip)]
    pub password_hash: String,
    pub must_change: bool,
    pub created: String,
}

/// Where the database lives.
#[derive(Clone, Debug)]
pub enum Target {
    /// Start `binary` serving `database` (a file path, or ":memory:").
    Managed { binary: PathBuf, database: String },
    /// Use a running BangDB HTTP API at `url`; `authorization` is the full header value.
    External { url: String, authorization: String },
}

impl Target {
    /// From the environment: NETEYE_BANGDB_URL selects an external server, otherwise managed mode.
    pub fn from_env(database: &Path) -> Result<Target> {
        let env = |n: &str| std::env::var(n).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        if let Some(url) = env("NETEYE_BANGDB_URL") {
            let authorization = match (env("NETEYE_BANGDB_TOKEN"), env("NETEYE_BANGDB_USER")) {
                (Some(token), _) => format!("Bearer {token}"),
                (None, Some(user)) => {
                    let password = env("NETEYE_BANGDB_PASSWORD").unwrap_or_default();
                    format!("Basic {}", base64(format!("{user}:{password}").as_bytes()))
                }
                (None, None) => return Err("NETEYE_BANGDB_URL needs NETEYE_BANGDB_TOKEN or NETEYE_BANGDB_USER/PASSWORD".into()),
            };
            return Ok(Target::External { url: url.trim_end_matches('/').to_string(), authorization });
        }
        let binary = find_bangdb().ok_or(
            "bangdb executable not found: put bangdb next to neteye, add it to PATH, or set NETEYE_BANGDB_BIN \
             (build: go install github.com/knoxxr/bangdb/cmd/bangdb@v0.7.73)")?;
        if let Some(parent) = database.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Ok(Target::Managed { binary, database: database.display().to_string() })
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) { "bangdb.exe" } else { "bangdb" }
}

/// NETEYE_BANGDB_BIN, then next to (or above) the running executable, then PATH.
pub fn find_bangdb() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NETEYE_BANGDB_BIN").map(PathBuf::from) {
        return p.is_file().then_some(p);
    }
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1).take(3) {
            let candidate = dir.join(exe_name());
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).map(|d| d.join(exe_name())).find(|p| p.is_file())
    })
}

// The managed bangdb must not outlive the sensor: an orphan would keep the database file locked
// and make the next start fail. Graceful exits stop it in `Drop`; these cover crashes and kills.

/// Linux: the kernel sends SIGKILL to bangdb when the sensor dies.
#[cfg(target_os = "linux")]
fn tie_to_parent(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: prctl is async-signal-safe and touches only the child being created.
    unsafe {
        command.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn tie_to_parent(_: &mut Command) {}

/// Windows: put bangdb in a job object that kills its members when the sensor's handle closes,
/// which the OS does however the sensor process ends.
#[cfg(windows)]
fn adopt_child(child: &Child) {
    use std::os::windows::io::AsRawHandle;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    static JOB: OnceLock<usize> = OnceLock::new();
    // SAFETY: plain Win32 calls; the job handle is intentionally kept open for the process lifetime.
    let job = *JOB.get_or_init(|| unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return 0;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &info as *const _ as *const _,
                                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32);
        job as usize
    });
    if job != 0 {
        // SAFETY: both handles are valid for the duration of the call.
        unsafe { AssignProcessToJobObject(job as _, child.as_raw_handle() as _) };
    }
}

#[cfg(not(windows))]
fn adopt_child(_: &Child) {}

fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { T[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

pub struct Store {
    agent: ureq::Agent,
    base: String,
    authorization: String,
    child: Option<Child>,
    pub description: String,
}

impl Store {
    pub fn open(target: Target) -> Result<Store> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .into();
        let mut store = match target {
            Target::External { url, authorization } => Store {
                agent, description: format!("BangDB server {url}"), base: url, authorization, child: None,
            },
            Target::Managed { binary, database } => {
                let token = crate::auth::new_token();
                let port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr())
                    .map_err(|e| format!("no free local port: {e}"))?.port();
                let mut command = Command::new(&binary);
                command
                    .env_remove("BANGDB_CONFIG")
                    .env("BANGDB_DATABASE", &database)
                    .env("BANGDB_HTTP", format!("127.0.0.1:{port}"))
                    .env("BANGDB_PASSWORD", &token) // environment, not argv: hidden from process listings
                    .env("BANGDB_LOG_LEVEL", "warn")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit());
                tie_to_parent(&mut command);
                let child = command.spawn().map_err(|e| format!("{}: {e}", binary.display()))?;
                adopt_child(&child);
                Store {
                    agent, base: format!("http://127.0.0.1:{port}"), authorization: format!("Bearer {token}"),
                    child: Some(child), description: format!("BangDB (managed) {database}"),
                }
            }
        };
        store.wait_ready()?;
        for sql in SCHEMA {
            store.exec(sql, json!([]))?;
        }
        Ok(store)
    }

    /// A throwaway in-memory database (tests).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Store> {
        let binary = find_bangdb().ok_or("tests need the bangdb executable in sensor/target/<profile>/ (see README)")?;
        Store::open(Target::Managed { binary, database: ":memory:".into() })
    }

    fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait() {
                    return Err(format!(
                        "bangdb exited during startup ({status}). If the database is already open, the sensor is \
                         probably running: stop it first, or manage accounts from the dashboard"));
                }
            match self.agent.get(format!("{}/health", self.base)).header("Authorization", &self.authorization).call() {
                Ok(mut r) if r.status() == 200 => {
                    if let Ok(health) = r.body_mut().read_json::<Value>()
                        && let Some(v) = health.get("version").and_then(|v| v.as_str()) {
                            self.description = format!("{} v{v}", self.description);
                        }
                    return Ok(());
                }
                Ok(r) if r.status() == 401 => return Err("BangDB rejected the credentials".into()),
                _ if Instant::now() > deadline => return Err(format!("BangDB at {} did not become ready", self.base)),
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let mut response = self.agent.post(format!("{}{path}", self.base))
            .header("Authorization", &self.authorization)
            .send_json(body)
            .map_err(|e| format!("BangDB {path}: {e}"))?;
        let status = response.status().as_u16();
        let value: Value = response.body_mut().with_config().limit(MAX_RESPONSE_BYTES).read_json()
            .map_err(|e| format!("BangDB {path}: invalid response ({status}): {e}"))?;
        if status != 200 {
            let code = value.get("code").and_then(|c| c.as_str()).unwrap_or("error");
            let message = value.get("error").and_then(|c| c.as_str()).unwrap_or("request failed");
            return Err(format!("BangDB {code} ({status}): {message}"));
        }
        if let Some(error) = value.get("error").and_then(|e| e.as_str()) {
            return Err(format!("BangDB: {error}")); // failure after streaming started
        }
        Ok(value)
    }

    fn exec(&self, sql: &str, args: Value) -> Result<Value> {
        self.post("/exec", &json!({"sql": sql, "args": args}))
    }

    fn query(&self, sql: &str, args: Value) -> Result<Vec<Vec<Value>>> {
        let mut result = self.post("/query", &json!({"sql": sql, "args": args}))?;
        match result.get_mut("rows").map(Value::take) {
            Some(Value::Array(rows)) => Ok(rows.into_iter()
                .map(|r| if let Value::Array(cells) = r { cells } else { Vec::new() }).collect()),
            _ => Ok(Vec::new()),
        }
    }

    /// Runs statements atomically; very large sets are split into several transactions.
    fn batch(&self, statements: Vec<Value>) -> Result<()> {
        let mut chunk: Vec<Value> = Vec::new();
        let mut size = 0;
        for st in statements {
            let len = st.to_string().len();
            if !chunk.is_empty() && size + len > MAX_BATCH_BYTES {
                self.post("/batch", &json!({"statements": std::mem::take(&mut chunk)}))?;
                size = 0;
            }
            size += len;
            chunk.push(st);
        }
        if !chunk.is_empty() {
            self.post("/batch", &json!({"statements": chunk}))?;
        }
        Ok(())
    }

    fn count(&self, sql: &str) -> Result<i64> {
        Ok(self.query(sql, json!([]))?.first().and_then(|r| r.first()).and_then(Value::as_i64).unwrap_or(0))
    }

    // ---------------------------------------------------------------- users
    pub fn user_count(&self) -> Result<i64> {
        self.count("SELECT COUNT(*) FROM users")
    }

    pub fn admin_count(&self) -> Result<i64> {
        self.count("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    }

    fn user_row(row: &[Value]) -> Option<UserRecord> {
        let s = |i: usize| row.get(i).and_then(Value::as_str).map(str::to_string);
        Some(UserRecord {
            username: s(0)?, role: s(1)?, password_hash: s(2)?,
            must_change: row.get(3).and_then(Value::as_i64).unwrap_or(0) != 0, created: s(4)?,
        })
    }

    pub fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let rows = self.query("SELECT username, role, password_hash, must_change, created FROM users WHERE username = ?",
                              json!([username]))?;
        Ok(rows.first().and_then(|r| Self::user_row(r)))
    }

    pub fn list_users(&self) -> Result<Vec<UserRecord>> {
        let rows = self.query("SELECT username, role, password_hash, must_change, created FROM users ORDER BY username",
                              json!([]))?;
        Ok(rows.iter().filter_map(|r| Self::user_row(r)).collect())
    }

    pub fn put_user(&self, user: &UserRecord) -> Result<()> {
        self.exec("INSERT INTO users(username, role, password_hash, must_change, created) VALUES(?, ?, ?, ?, ?) \
                   ON CONFLICT(username) DO UPDATE SET role = excluded.role, password_hash = excluded.password_hash, \
                   must_change = excluded.must_change",
                  json!([user.username, user.role, user.password_hash, user.must_change as i64, user.created]))?;
        Ok(())
    }

    pub fn delete_user(&self, username: &str) -> Result<bool> {
        let result = self.exec("DELETE FROM users WHERE username = ?", json!([username]))?;
        Ok(result.get("rowsAffected").and_then(Value::as_i64).unwrap_or(0) > 0)
    }

    // ---------------------------------------------------------------- audit
    pub fn audit(&self, ts: &str, username: &str, ip: &str, action: &str, status: u16, detail: &str) {
        if let Err(e) = self.exec("INSERT INTO audit(ts, username, ip, action, status, detail) VALUES(?, ?, ?, ?, ?, ?)",
                                  json!([ts, username, ip, action, status, detail])) {
            eprintln!("audit: {e}");
        }
    }

    pub fn audit_log(&self, limit: i64) -> Result<Vec<Value>> {
        let rows = self.query("SELECT id, ts, username, ip, action, status, detail FROM audit ORDER BY id DESC LIMIT ?",
                              json!([limit]))?;
        Ok(rows.into_iter().map(|r| json!({
            "id": r[0], "ts": r[1], "username": r[2], "ip": r[3], "action": r[4], "status": r[5], "detail": r[6],
        })).collect())
    }

    // --------------------------------------------------------------- engine
    fn docs(&self, sql: &str) -> Result<Vec<Value>> {
        Ok(self.query(sql, json!([]))?.into_iter()
            .filter_map(|r| r.first().and_then(Value::as_str).and_then(|s| serde_json::from_str(s).ok()))
            .collect())
    }

    pub fn load_into(&self, engine: &mut Engine) -> Result<()> {
        let assets = self.docs("SELECT data FROM assets")?;
        let links = self.docs("SELECT data FROM links")?;
        let alerts = self.docs("SELECT data FROM alerts ORDER BY id")?;
        let meta = self.query("SELECT v FROM meta WHERE k = 'baseline'", json!([]))?.first()
            .and_then(|r| r.first()).and_then(Value::as_str).and_then(|s| serde_json::from_str(s).ok());
        let items = self.query("SELECT kind, key FROM baseline", json!([]))?.into_iter()
            .filter_map(|r| Some((r.first()?.as_str()?.to_string(), r.get(1)?.as_str()?.to_string())))
            .collect();
        engine.restore(assets, links, alerts, meta, items);
        engine.restore_points(self.docs("SELECT data FROM points")?);
        Ok(())
    }

    /// Persist one flush of engine changes as a single transaction.
    pub fn save(&mut self, changes: &Changes) -> Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        let st = |sql: &str, args: Value| json!({"sql": sql, "args": args});
        let mut statements = Vec::new();
        for (id, data) in &changes.assets {
            statements.push(st("INSERT INTO assets(id, data) VALUES(?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                               json!([id, data])));
        }
        for (key, data) in &changes.links {
            statements.push(st("INSERT INTO links(key, data) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data",
                               json!([key, data])));
        }
        for (id, key, severity, status, last_seen, data) in &changes.alerts {
            statements.push(st("INSERT INTO alerts(id, key, severity, status, last_seen, data) VALUES(?, ?, ?, ?, ?, ?) \
                                ON CONFLICT(key) DO UPDATE SET severity = excluded.severity, status = excluded.status, \
                                last_seen = excluded.last_seen, data = excluded.data",
                               json!([id, key, severity, status, last_seen, data])));
        }
        for id in &changes.deleted_assets {
            statements.push(st("DELETE FROM assets WHERE id = ?", json!([id])));
        }
        for key in &changes.deleted_links {
            statements.push(st("DELETE FROM links WHERE key = ?", json!([key])));
        }
        if changes.baseline_rewrite {
            statements.push(st("DELETE FROM baseline", json!([])));
        }
        for (kind, key) in &changes.baseline_items {
            statements.push(st("INSERT OR IGNORE INTO baseline(kind, key) VALUES(?, ?)", json!([kind, key])));
        }
        if changes.points_reset {
            statements.push(st("DELETE FROM points", json!([])));
        }
        for (key, data) in &changes.points {
            statements.push(st("INSERT INTO points(key, data) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET data = excluded.data",
                               json!([key, data])));
        }
        if let Some(meta) = &changes.baseline_meta {
            statements.push(st("INSERT INTO meta(k, v) VALUES('baseline', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                               json!([meta])));
        }
        self.batch(statements)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // Every acknowledged commit is already durable in BangDB's WAL, so stopping is safe.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"app:s3cret"), "YXBwOnMzY3JldA==");
    }

    #[test]
    fn users_audit_and_atomic_batches() {
        let store = Store::open_in_memory().unwrap();
        let user = UserRecord { username: "alice".into(), role: "operator".into(), password_hash: "$argon2id$x".into(),
                                must_change: true, created: "2026-01-01T00:00:00.000+00:00".into() };
        store.put_user(&user).unwrap();
        assert_eq!(store.get_user("alice").unwrap().unwrap().role, "operator");
        assert!(store.get_user("alice").unwrap().unwrap().must_change);
        assert_eq!(store.user_count().unwrap(), 1);
        assert!(store.delete_user("alice").unwrap());
        assert!(store.get_user("alice").unwrap().is_none());

        store.audit("t1", "bob", "127.0.0.1", "login", 200, "");
        store.audit("t2", "bob", "127.0.0.1", "login", 401, "bad");
        let log = store.audit_log(10).unwrap();
        assert_eq!((log[0]["status"].as_i64(), log[0]["detail"].as_str()), (Some(401), Some("bad")));

        // A failing statement rolls back the whole batch.
        let bad = store.batch(vec![
            json!({"sql": "INSERT INTO meta(k, v) VALUES('x', '1')", "args": []}),
            json!({"sql": "INSERT INTO nosuchtable VALUES(1)", "args": []}),
        ]);
        assert!(bad.is_err());
        assert_eq!(store.count("SELECT COUNT(*) FROM meta WHERE k = 'x'").unwrap(), 0);
    }
}
