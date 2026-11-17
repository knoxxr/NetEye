//! HTTP API + WebSocket + static dashboard (same contract as the original FastAPI service).

use crate::baseline::Mode;
use crate::engine::Engine;
use crate::storage::Store;
use crate::vulns::VulnDb;
use crate::{import_file, Config};
use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use crate::account;
use futures_util::StreamExt;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tower_http::services::{ServeDir, ServeFile};

pub struct AppState {
    pub config: Config,
    pub engine: Arc<Mutex<Engine>>,
    pub store: Mutex<Option<Store>>,
    pub sensor: Mutex<Value>,
    pub import: Arc<Mutex<Value>>,
    pub vulndb_state: Mutex<Value>,
    import_running: AtomicBool,
    cache: Mutex<(u64, i64, Arc<String>)>,
    pub sessions: crate::auth::Sessions,
    /// Syslog/CEF forwarding to the SIEM, when NETEYE_SYSLOG is set.
    pub siem: Option<crate::siem::Forwarder>,
    pub throttle: crate::auth::Throttle,
}

impl AppState {
    pub fn new(config: Config, engine: Arc<Mutex<Engine>>, store: Option<Store>, vulndb_error: Option<String>) -> Self {
        AppState {
            vulndb_state: Mutex::new(json!({"path": config.vulndb_path.display().to_string(), "error": vulndb_error})),
            config,
            engine,
            store: Mutex::new(store),
            sensor: Mutex::new(json!({"enabled": false, "interface": null, "error": null})),
            import: Arc::new(Mutex::new(json!({"running": false, "file": null, "frames": 0, "error": null, "last_result": null}))),
            import_running: AtomicBool::new(false),
            cache: Mutex::new((u64::MAX, 0, Arc::new(String::new()))),
            sessions: Default::default(),
            siem: None,
            throttle: Default::default(),
        }
    }

    /// Snapshot JSON, rebuilt at most once per second or when the engine changed.
    pub fn snapshot(&self) -> Arc<String> {
        let now = now_ms();
        let generation = self.engine.lock().generation;
        {
            let cache = self.cache.lock();
            if cache.0 == generation && now - cache.1 < 1000 {
                return cache.2.clone();
            }
        }
        let body = self.engine.lock().snapshot_json(now);
        let mut text = String::with_capacity(body.len() + 512);
        text.push_str(&body[..body.len().saturating_sub(1)]);
        text.push_str(&format!(",\"sensor\":{},\"import\":{},\"vulndb_state\":{}}}",
                               self.sensor.lock(), self.import.lock(), self.vulndb_state.lock()));
        let text = Arc::new(text);
        *self.cache.lock() = (generation, now, text.clone());
        text
    }

    pub fn invalidate(&self) {
        self.cache.lock().0 = u64::MAX;
    }

    pub fn flush(&self) {
        let changes = self.engine.lock().take_changes();
        if let Some(store) = self.store.lock().as_mut()
            && let Err(e) = store.save(&changes) {
                eprintln!("store: {e}");
            }
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn json_response(body: String) -> Response {
    ([(axum::http::header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn error(status: StatusCode, detail: impl Into<String>) -> Response {
    (status, Json(json!({"detail": detail.into()}))).into_response()
}

pub fn router(state: Arc<AppState>) -> Router {
    let frontend = state.config.frontend.clone();
    Router::new()
        .route_service("/", ServeFile::new(frontend.join("index.html")))
        .route_service("/login.html", ServeFile::new(frontend.join("login.html")))
        .nest_service("/assets", ServeDir::new(frontend))
        .route("/api/snapshot", get(snapshot))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/{id}/ack", post(acknowledge))
        .route("/api/alerts/{id}/learn", post(learn))
        .route("/api/assets/{id}/manual", post(edit_asset))
        .route("/api/baseline", get(baseline))
        .route("/api/baseline/mode", post(set_mode))
        .route("/api/vulns", get(vulns))
        .route("/api/vulndb", get(vulndb_info).post(upload_vulndb).layer(DefaultBodyLimit::max(128 << 20)))
        .route("/api/pcap", post(upload_pcap).layer(DefaultBodyLimit::disable()))
        .route("/ws", get(ws))
        .route("/api/login", post(account::login))
        .route("/api/logout", post(account::logout))
        .route("/api/session", get(account::session))
        .route("/api/password", post(account::change_password))
        .route("/api/users", get(account::list_users).post(account::create_user))
        .route("/api/users/{name}", post(account::update_user).delete(account::delete_user))
        .route("/api/audit", get(account::audit_log))
        .route("/api/integrations", get(integrations))
        // Layers run outermost-last: host/origin guard first, then authentication + audit.
        .layer(axum::middleware::from_fn_with_state(state.clone(), account::middleware))
        .layer(axum::middleware::from_fn_with_state(Arc::new(state.config.allowed_hosts.clone()),
                                                    crate::guard::middleware))
        .with_state(state)
}

async fn integrations(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({"syslog": s.siem.as_ref().map(|f| f.status())}))
}

impl AppState {
    /// Moves new/re-opened alerts from the engine to the SIEM forwarder (non-blocking queues).
    pub fn forward_events(&self) {
        if let Some(siem) = &self.siem {
            let events = self.engine.lock().take_events();
            for event in &events {
                siem.send(event);
            }
        }
    }
}

async fn snapshot(State(s): State<Arc<AppState>>) -> Response {
    let text = tokio::task::spawn_blocking(move || s.snapshot()).await.unwrap();
    json_response(text.as_str().to_owned())
}

#[derive(Deserialize)]
struct StatusQuery {
    status: Option<String>,
}

async fn alerts(State(s): State<Arc<AppState>>, Query(q): Query<StatusQuery>) -> Json<Value> {
    Json(s.engine.lock().alerts_json(q.status.as_deref()))
}

async fn acknowledge(State(s): State<Arc<AppState>>, Path(id): Path<u64>) -> Response {
    if !s.engine.lock().acknowledge(id) {
        return error(StatusCode::NOT_FOUND, "alert not found");
    }
    s.invalidate();
    Json(json!({"ok": true})).into_response()
}

async fn learn(State(s): State<Arc<AppState>>, Path(id): Path<u64>) -> Response {
    if !s.engine.lock().learn_alert(id) {
        return error(StatusCode::NOT_FOUND, "alert not found");
    }
    s.invalidate();
    Json(json!({"ok": true})).into_response()
}

/// Operator-entered asset details (name, type, identity, location, owner, criticality, notes).
async fn edit_asset(State(s): State<Arc<AppState>>, Extension(user): Extension<account::CurrentUser>,
                    Path(id): Path<String>, Json(info): Json<crate::engine::ManualInfo>) -> Response {
    let result = s.engine.lock().set_manual(&id, info, &user.username, now_ms());
    match result {
        Ok(()) => {
            s.invalidate();
            Json(json!({"ok": true})).into_response()
        }
        Err(e) if e == "asset not found" => error(StatusCode::NOT_FOUND, e),
        Err(e) => error(StatusCode::BAD_REQUEST, e),
    }
}

async fn baseline(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(s.engine.lock().baseline_status())
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: String,
    hours: Option<f64>,
    #[serde(default)]
    reset: bool,
}

async fn set_mode(State(s): State<Arc<AppState>>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<ModeRequest>(&body) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "expected {\"mode\": \"learning\"|\"detecting\"}");
    };
    let Some(mode) = Mode::parse(&req.mode) else {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "mode must be learning or detecting");
    };
    if req.hours.is_some_and(|h| !(h > 0.0 && h <= 24.0 * 90.0)) {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "hours must be in (0, 2160]");
    }
    let status = s.engine.lock().set_mode(mode, req.hours, req.reset);
    let state = s.clone();
    tokio::task::spawn_blocking(move || state.flush()).await.unwrap();
    s.invalidate();
    Json(status).into_response()
}

async fn vulns(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(s.engine.lock().vulns_json())
}

async fn vulndb_info(State(s): State<Arc<AppState>>) -> Json<Value> {
    let engine = s.engine.lock();
    let mut info = json!({"loaded": engine.vulndb.is_some()});
    if let (Some(db), Some(obj)) = (&engine.vulndb, info.as_object_mut())
        && let Value::Object(meta) = db.info() {
            obj.extend(meta);
        }
    if let (Value::Object(state), Some(obj)) = (s.vulndb_state.lock().clone(), info.as_object_mut()) {
        obj.extend(state);
    }
    Json(info)
}

async fn upload_vulndb(State(s): State<Arc<AppState>>, body: Bytes) -> Response {
    let parsed = tokio::task::spawn_blocking({
        let body = body.clone();
        move || VulnDb::from_json(&body)
    }).await.unwrap();
    let db = match parsed {
        Ok(db) => Arc::new(db),
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("invalid vulnerability database: {e}")),
    };
    let path = s.config.vulndb_path.clone();
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let temp = path.with_extension("tmp");
    if let Err(e) = tokio::fs::write(&temp, &body).await.and(tokio::fs::rename(&temp, &path).await) {
        return error(StatusCode::INTERNAL_SERVER_ERROR, format!("cannot save database: {e}"));
    }
    let info = db.info();
    let state = s.clone();
    tokio::task::spawn_blocking(move || state.engine.lock().set_vulndb(Some(db))).await.unwrap();
    s.vulndb_state.lock()["error"] = Value::Null;
    s.invalidate();
    let mut result = json!({"ok": true});
    if let (Some(obj), Value::Object(meta)) = (result.as_object_mut(), info) {
        obj.extend(meta);
    }
    Json(result).into_response()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len()
            && let Some(b) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn upload_pcap(State(s): State<Arc<AppState>>, headers: HeaderMap, body: Body) -> Response {
    if s.import_running.swap(true, Ordering::SeqCst) {
        return error(StatusCode::CONFLICT, "another import is running");
    }
    let raw_name = headers.get("x-filename").and_then(|v| v.to_str().ok()).unwrap_or("upload.pcap");
    let decoded = percent_decode(raw_name);
    let name = std::path::Path::new(&decoded).file_name().map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "upload.pcap".into());
    let temp = std::env::temp_dir().join(format!("neteye-{}-{}.pcap", std::process::id(), now_ms()));
    let written = async {
        let mut file = tokio::fs::File::create(&temp).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let mut stream = body.into_data_stream();
        let mut size = 0usize;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            size += chunk.len();
            if size > s.config.max_pcap_bytes {
                return Err((StatusCode::PAYLOAD_TOO_LARGE, "capture file too large".to_string()));
            }
            file.write_all(&chunk).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        file.flush().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(size)
    }.await;
    let size = match written {
        Ok(size) => size,
        Err((status, msg)) => {
            let _ = tokio::fs::remove_file(&temp).await;
            s.import_running.store(false, Ordering::SeqCst);
            return error(status, msg);
        }
    };
    {
        let mut st = s.import.lock();
        st["running"] = true.into();
        st["file"] = name.clone().into();
        st["frames"] = 0.into();
        st["error"] = Value::Null;
    }
    s.invalidate();
    let state = s.clone();
    std::thread::spawn(move || {
        let import = state.import.clone();
        // A parser bug on a hostile capture must not leave the import slot stuck as "running".
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            import_file(&state.engine, &temp, move |n| { import.lock()["frames"] = n.into(); })
        })).unwrap_or_else(|_| Err(std::io::Error::other("캡처 파일 분석 중 내부 오류 (손상된 파일)")));
        {
            let mut st = state.import.lock();
            match result {
                Ok(stats) => st["last_result"] = json!({"file": name, "frames": stats.frames, "skipped": stats.skipped}),
                Err(e) => st["error"] = format!("{name}: {e}").into(),
            }
            st["running"] = false.into();
            st["file"] = Value::Null;
        }
        let _ = std::fs::remove_file(&temp);
        state.flush();
        state.invalidate();
        state.import_running.store(false, Ordering::SeqCst);
    });
    Json(json!({"accepted": true, "bytes": size})).into_response()
}

async fn ws(State(s): State<Arc<AppState>>, Extension(user): Extension<account::CurrentUser>,
            upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(move |socket| stream(socket, s, user.token))
}

async fn stream(mut socket: WebSocket, s: Arc<AppState>, token: String) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last: Option<Arc<String>> = None;
    loop {
        tick.tick().await;
        // Logout, expiry, password change or account removal ends the live feed too.
        if s.sessions.get(&token).is_none_or(|session| session.must_change_password) {
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
        let state = s.clone();
        let text = tokio::task::spawn_blocking(move || state.snapshot()).await.unwrap();
        // Unchanged state is not resent, so an idle network costs the browser nothing.
        if last.as_ref().is_some_and(|prev| Arc::ptr_eq(prev, &text) || prev.as_str() == text.as_str()) {
            continue;
        }
        if socket.send(Message::Text(text.as_str().into())).await.is_err() {
            return;
        }
        last = Some(text);
    }
}
