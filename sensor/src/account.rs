//! Authentication middleware plus login, password, user-management and audit endpoints.

use crate::api::{now_ms, AppState};
use crate::auth::{self, Access, Role};
use crate::engine::iso;
use crate::storage::UserRecord;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

/// Peer address of the request, attached by the middleware for auditing.
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub username: String,
    pub role: Role,
    pub token: String,
}

fn error(status: StatusCode, detail: impl Into<String>) -> Response {
    (status, Json(json!({"detail": detail.into()}))).into_response()
}

fn client_ip(request: &Request) -> String {
    request.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string()).unwrap_or_else(|| "-".into())
}

impl AppState {
    pub fn audit(&self, username: &str, ip: &str, action: &str, status: u16, detail: &str) {
        let now = now_ms();
        if let Some(store) = self.store.lock().as_ref() {
            store.audit(&iso(now), username, ip, action, status, detail);
        }
        if let Some(siem) = &self.siem {
            siem.send(&audit_event(now, username, ip, action, status, detail));
        }
    }

    fn session_cookie(&self, token: &str, max_age: u64) -> HeaderValue {
        let secure = if self.config.cookie_secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!("{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}",
                                       auth::SESSION_COOKIE)).unwrap()
    }
}

/// Audit record as a SIEM event: sign-ins, lockouts, denied attempts and changes.
pub fn audit_event(now: i64, username: &str, ip: &str, action: &str, status: u16, detail: &str) -> crate::siem::SiemEvent {
    let (signature, severity, name) = match (action, status) {
        ("login", 200) => ("NE-AUDIT-LOGIN", "info", "로그인 성공".to_string()),
        ("login", 429) => ("NE-AUDIT-LOCKOUT", "high", "로그인 잠금 (반복 실패)".to_string()),
        ("login", _) => ("NE-AUDIT-LOGIN-FAILED", "medium", "로그인 실패".to_string()),
        (_, 403) if detail.starts_with("denied") => ("NE-AUDIT-DENIED", "medium", format!("권한 없는 요청: {action}")),
        _ => ("NE-AUDIT-CHANGE", "low", format!("설정 변경: {action}")),
    };
    crate::siem::SiemEvent {
        time: now,
        class: "audit",
        signature: signature.into(),
        name,
        severity,
        operation: action.into(),
        src_ip: (ip != "-").then(|| ip.to_string()),
        user: Some(username.to_string()),
        outcome: Some(if status < 400 { "success" } else { "failure" }),
        details: if detail.is_empty() { Value::Null } else { json!({"detail": detail, "status": status}) },
        ..Default::default()
    }
}

/// Authenticates every request against the deny-by-default policy and audits state changes.
pub async fn middleware(State(s): State<Arc<AppState>>, mut request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let ip = client_ip(&request);
    request.extensions_mut().insert(ClientIp(ip.clone()));
    let access = auth::required_access(&method, &path);
    if access == Access::Public {
        return next.run(request).await;
    }
    let token = request.headers().get(header::COOKIE).and_then(|v| v.to_str().ok())
        .and_then(auth::cookie_token).map(str::to_string);
    let session = token.as_deref().and_then(|t| s.sessions.get(t));
    let Some(session) = session else {
        return if access == Access::Page {
            Redirect::to("/login.html").into_response()
        } else {
            error(StatusCode::UNAUTHORIZED, "로그인이 필요합니다")
        };
    };
    if session.must_change_password && access != Access::Session {
        return if access == Access::Page {
            Redirect::to("/login.html").into_response()
        } else {
            error(StatusCode::FORBIDDEN, "초기 비밀번호를 먼저 변경해야 합니다")
        };
    }
    if let Access::Role(required) = access
        && session.role < required {
            // Attempts beyond one's role are exactly what an auditor wants to see.
            s.audit(&session.username, &ip, &format!("{method} {path}"), 403,
                    &format!("denied: requires {}", required.as_str()));
            return error(StatusCode::FORBIDDEN, format!("{} 권한이 필요합니다", required.as_str()));
        }
    let user = CurrentUser { username: session.username.clone(), role: session.role, token: token.unwrap() };
    request.extensions_mut().insert(user.clone());
    let response = next.run(request).await;
    if !matches!(method, Method::GET | Method::HEAD) {
        s.audit(&user.username, &ip, &format!("{method} {path}"), response.status().as_u16(), "");
    }
    response
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login(State(s): State<Arc<AppState>>, Extension(ClientIp(ip)): Extension<ClientIp>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<LoginRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "username and password required");
    };
    let username = req.username.trim().to_ascii_lowercase();
    if let Some(remaining) = s.throttle.locked(&username, &ip) {
        s.audit(&username, &ip, "login", 429, "locked");
        return error(StatusCode::TOO_MANY_REQUESTS,
                     format!("로그인 시도가 너무 많습니다. {}초 후 다시 시도하세요", remaining.as_secs() + 1));
    }
    let user = s.store.lock().as_ref().and_then(|store| store.get_user(&username).ok().flatten());
    let password = req.password;
    let (ok, user) = tokio::task::spawn_blocking(move || match user {
        Some(u) => (auth::verify_password(&password, &u.password_hash), Some(u)),
        None => { auth::verify_dummy(&password); (false, None) }
    }).await.unwrap();
    let exists = user.is_some();
    let Some(user) = user.filter(|_| ok) else {
        s.throttle.failure(&username, &ip, exists);
        s.audit(&username, &ip, "login", 401, "invalid credentials");
        return error(StatusCode::UNAUTHORIZED, "사용자 이름 또는 비밀번호가 올바르지 않습니다");
    };
    s.throttle.success(&username, &ip);
    let role = Role::parse(&user.role).unwrap_or(Role::Viewer);
    let token = s.sessions.create(&user.username, role, user.must_change);
    s.audit(&user.username, &ip, "login", 200, "");
    let mut response = Json(json!({"username": user.username, "role": role.as_str(),
                                   "must_change_password": user.must_change})).into_response();
    response.headers_mut().insert(header::SET_COOKIE, s.session_cookie(&token, auth::SESSION_MAX.as_secs()));
    response
}

pub async fn logout(State(s): State<Arc<AppState>>, Extension(user): Extension<CurrentUser>) -> Response {
    s.sessions.remove(&user.token);
    let mut response = Json(json!({"ok": true})).into_response();
    response.headers_mut().insert(header::SET_COOKIE, s.session_cookie("", 0));
    response
}

pub async fn session(State(s): State<Arc<AppState>>, Extension(user): Extension<CurrentUser>) -> Json<Value> {
    let must_change = s.sessions.get(&user.token).is_some_and(|x| x.must_change_password);
    Json(json!({"username": user.username, "role": user.role.as_str(), "must_change_password": must_change}))
}

#[derive(Deserialize)]
struct PasswordRequest {
    current: String,
    new: String,
}

pub async fn change_password(State(s): State<Arc<AppState>>, Extension(user): Extension<CurrentUser>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<PasswordRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "current and new password required");
    };
    if let Err(e) = auth::check_password_policy(&user.username, &req.new) {
        return error(StatusCode::BAD_REQUEST, e);
    }
    if req.new == req.current {
        return error(StatusCode::BAD_REQUEST, "새 비밀번호는 현재 비밀번호와 달라야 합니다");
    }
    let Some(mut record) = s.store.lock().as_ref().and_then(|st| st.get_user(&user.username).ok().flatten()) else {
        return error(StatusCode::UNAUTHORIZED, "account no longer exists");
    };
    let hash = record.password_hash.clone();
    let (ok, new_hash) = tokio::task::spawn_blocking(move || {
        (auth::verify_password(&req.current, &hash), auth::hash_password(&req.new))
    }).await.unwrap();
    if !ok {
        return error(StatusCode::FORBIDDEN, "현재 비밀번호가 올바르지 않습니다");
    }
    let Ok(new_hash) = new_hash else { return error(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed") };
    record.password_hash = new_hash;
    record.must_change = false;
    if let Some(store) = s.store.lock().as_ref()
        && let Err(e) = store.put_user(&record) {
            return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    s.sessions.password_changed(&user.username, &user.token);
    let _ = std::fs::remove_file(s.config.initial_password_file()); // one-time bootstrap secret is now stale
    Json(json!({"ok": true})).into_response()
}

// ---------------------------------------------------------------- admin
pub async fn list_users(State(s): State<Arc<AppState>>) -> Response {
    match s.store.lock().as_ref().map(|st| st.list_users()) {
        Some(Ok(users)) => Json(users).into_response(),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable"),
    }
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    password: String,
    role: String,
}

pub async fn create_user(State(s): State<Arc<AppState>>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<NewUser>(&body) else {
        return error(StatusCode::BAD_REQUEST, "username, password and role required");
    };
    let username = req.username.trim().to_ascii_lowercase();
    if !auth::valid_username(&username) {
        return error(StatusCode::BAD_REQUEST, "사용자 이름은 3~32자의 영문, 숫자, . _ - 만 사용할 수 있습니다");
    }
    let Some(role) = Role::parse(&req.role) else { return error(StatusCode::BAD_REQUEST, "unknown role") };
    if let Err(e) = auth::check_password_policy(&username, &req.password) {
        return error(StatusCode::BAD_REQUEST, e);
    }
    if s.store.lock().as_ref().and_then(|st| st.get_user(&username).ok().flatten()).is_some() {
        return error(StatusCode::CONFLICT, "이미 존재하는 사용자입니다");
    }
    let password = req.password;
    let Ok(hash) = tokio::task::spawn_blocking(move || auth::hash_password(&password)).await.unwrap() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed");
    };
    // An administrator-chosen password is temporary: the user must replace it at first sign-in.
    let record = UserRecord { username: username.clone(), role: role.as_str().into(), password_hash: hash,
                              must_change: true, created: iso(now_ms()) };
    match s.store.lock().as_ref().map(|st| st.put_user(&record)) {
        Some(Ok(())) => Json(json!({"ok": true, "username": username})).into_response(),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable"),
    }
}

#[derive(Deserialize)]
struct UpdateUser {
    role: Option<String>,
    password: Option<String>,
}

pub async fn update_user(State(s): State<Arc<AppState>>, Path(name): Path<String>, body: Bytes) -> Response {
    let Ok(req) = serde_json::from_slice::<UpdateUser>(&body) else {
        return error(StatusCode::BAD_REQUEST, "role and/or password expected");
    };
    let Some(mut record) = s.store.lock().as_ref().and_then(|st| st.get_user(&name).ok().flatten()) else {
        return error(StatusCode::NOT_FOUND, "user not found");
    };
    if let Some(role) = &req.role {
        let Some(role) = Role::parse(role) else { return error(StatusCode::BAD_REQUEST, "unknown role") };
        let admins = s.store.lock().as_ref().and_then(|st| st.admin_count().ok()).unwrap_or(0);
        if record.role == "admin" && role != Role::Admin && admins <= 1 {
            return error(StatusCode::CONFLICT, "마지막 관리자의 권한은 낮출 수 없습니다");
        }
        record.role = role.as_str().into();
    }
    if let Some(password) = req.password {
        if let Err(e) = auth::check_password_policy(&name, &password) {
            return error(StatusCode::BAD_REQUEST, e);
        }
        let Ok(hash) = tokio::task::spawn_blocking(move || auth::hash_password(&password)).await.unwrap() else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed");
        };
        record.password_hash = hash;
        record.must_change = true;
    }
    match s.store.lock().as_ref().map(|st| st.put_user(&record)) {
        Some(Ok(())) => {
            s.sessions.revoke_user(&name); // new role/password takes effect immediately
            Json(json!({"ok": true})).into_response()
        }
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable"),
    }
}

pub async fn delete_user(State(s): State<Arc<AppState>>, Extension(user): Extension<CurrentUser>,
                         Path(name): Path<String>) -> Response {
    if name == user.username {
        return error(StatusCode::CONFLICT, "자기 자신은 삭제할 수 없습니다");
    }
    let store = s.store.lock();
    let Some(store) = store.as_ref() else { return error(StatusCode::SERVICE_UNAVAILABLE, "user store unavailable") };
    match store.get_user(&name) {
        Ok(Some(target)) if target.role == "admin" && store.admin_count().unwrap_or(0) <= 1 =>
            error(StatusCode::CONFLICT, "마지막 관리자는 삭제할 수 없습니다"),
        Ok(Some(_)) => {
            let _ = store.delete_user(&name);
            s.sessions.revoke_user(&name);
            Json(json!({"ok": true})).into_response()
        }
        _ => error(StatusCode::NOT_FOUND, "user not found"),
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
}

pub async fn audit_log(State(s): State<Arc<AppState>>, Query(q): Query<AuditQuery>) -> Response {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    match s.store.lock().as_ref().map(|st| st.audit_log(limit)) {
        Some(Ok(rows)) => Json(rows).into_response(),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "audit store unavailable"),
    }
}
