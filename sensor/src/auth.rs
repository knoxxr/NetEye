//! Accounts, roles, sessions and login throttling for the dashboard.
//!
//! * Passwords: Argon2id PHC strings (salted, memory-hard).
//! * Sessions: 256-bit random tokens in an HttpOnly + SameSite=Strict cookie, kept in memory,
//!   with idle and absolute expiry; revoked when a user's password/role changes or the user is removed.
//! * Throttling: consecutive failures lock the account name for a while; unknown users cost the
//!   same Argon2 work so login timing does not reveal which accounts exist.
//! * Authorization: deny-by-default route policy (`required_access`).

use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use axum::http::Method;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

pub const SESSION_COOKIE: &str = "neteye_session";
pub const SESSION_IDLE: Duration = Duration::from_secs(8 * 3600);
pub const SESSION_MAX: Duration = Duration::from_secs(24 * 3600);
pub const MAX_FAILURES: u32 = 5;
pub const LOCKOUT: Duration = Duration::from_secs(5 * 60);
pub const MIN_PASSWORD_LEN: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
}

// ----------------------------------------------------------------- passwords
pub fn hash_password(password: &str) -> Result<String, String> {
    Argon2::default().hash_password(password.as_bytes()).map(|h| h.to_string()).map_err(|e| e.to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// Spends the same Argon2 work as a real verification (used when the account does not exist).
pub fn verify_dummy(password: &str) {
    static DUMMY: LazyLock<String> = LazyLock::new(|| hash_password("neteye-dummy-password").unwrap_or_default());
    let _ = verify_password(password, &DUMMY);
}

pub fn check_password_policy(username: &str, password: &str) -> Result<(), &'static str> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err("비밀번호는 10자 이상이어야 합니다");
    }
    if password.eq_ignore_ascii_case(username) {
        return Err("비밀번호는 사용자 이름과 달라야 합니다");
    }
    Ok(())
}

pub fn valid_username(name: &str) -> bool {
    (3..=32).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random number generator unavailable");
    buf
}

pub fn new_token() -> String {
    random_bytes::<32>().iter().map(|b| format!("{b:02x}")).collect()
}

/// Human-typable random password (no ambiguous characters), ~95 bits.
pub fn random_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    random_bytes::<16>().iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

// ------------------------------------------------------------------ sessions
#[derive(Clone, Debug)]
pub struct Session {
    pub username: String,
    pub role: Role,
    pub must_change_password: bool,
    created: Instant,
    last_seen: Instant,
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn create(&self, username: &str, role: Role, must_change_password: bool) -> String {
        let token = new_token();
        let now = Instant::now();
        let mut map = self.map.lock();
        map.retain(|_, s| !expired(s, now));
        map.insert(token.clone(), Session { username: username.to_string(), role, must_change_password,
                                            created: now, last_seen: now });
        token
    }

    /// Looks up a live session and refreshes its idle timer.
    pub fn get(&self, token: &str) -> Option<Session> {
        let now = Instant::now();
        let mut map = self.map.lock();
        let session = map.get_mut(token)?;
        if expired(session, now) {
            map.remove(token);
            return None;
        }
        session.last_seen = now;
        Some(session.clone())
    }

    pub fn remove(&self, token: &str) {
        self.map.lock().remove(token);
    }

    pub fn revoke_user(&self, username: &str) {
        self.map.lock().retain(|_, s| s.username != username);
    }

    pub fn password_changed(&self, username: &str, keep_token: &str) {
        let mut map = self.map.lock();
        map.retain(|token, s| s.username != username || token == keep_token);
        if let Some(s) = map.get_mut(keep_token) {
            s.must_change_password = false;
        }
    }
}

fn expired(s: &Session, now: Instant) -> bool {
    now.duration_since(s.last_seen) > SESSION_IDLE || now.duration_since(s.created) > SESSION_MAX
}

// -------------------------------------------------------------- throttling
#[derive(Default)]
/// Failed sign-ins per (account, client address). Keying on the pair means someone guessing from
/// one machine cannot lock the real user out from another (lockout as a denial of service); each
/// source still gets only MAX_FAILURES guesses per LOCKOUT, on top of Argon2's cost per guess.
pub struct Throttle {
    map: Mutex<HashMap<(String, String), Attempts>>,
}

/// Consecutive failures and, once locked, until when.
type Attempts = (u32, Option<Instant>);

/// Upper bound on tracked (account, client) pairs.
const THROTTLE_ENTRIES: usize = 10_000;

impl Throttle {
    fn key(username: &str, client: &str) -> (String, String) {
        (username.to_string(), client.to_string())
    }
    /// Remaining lockout, if this account is currently locked for this client.
    pub fn locked(&self, username: &str, client: &str) -> Option<Duration> {
        let map = self.map.lock();
        let until = map.get(&Self::key(username, client))?.1?;
        until.checked_duration_since(Instant::now())
    }
    pub fn failure(&self, username: &str, client: &str) {
        let mut map = self.map.lock();
        if map.len() >= THROTTLE_ENTRIES {
            // Keep active lockouts; forget plain counters and expired locks.
            let now = Instant::now();
            map.retain(|_, (_, until)| until.is_some_and(|u| u > now));
            if map.len() >= THROTTLE_ENTRIES {
                map.clear();
            }
        }
        let entry = map.entry(Self::key(username, client)).or_insert((0, None));
        if entry.1.is_some_and(|until| until <= Instant::now()) {
            *entry = (0, None); // previous lock elapsed: start counting again
        }
        entry.0 += 1;
        if entry.0 >= MAX_FAILURES {
            entry.1 = Some(Instant::now() + LOCKOUT);
        }
    }
    pub fn success(&self, username: &str, client: &str) {
        self.map.lock().remove(&Self::key(username, client));
    }
}

// ------------------------------------------------------------------ policy
#[derive(Debug, PartialEq, Eq)]
pub enum Access {
    /// Login page and static assets.
    Public,
    /// The dashboard page: redirect to the login page without a session.
    Page,
    /// Any signed-in user, even one who must still change the initial password.
    Session,
    Role(Role),
}

/// Deny-by-default authorization table.
pub fn required_access(method: &Method, path: &str) -> Access {
    let get = *method == Method::GET || *method == Method::HEAD;
    let post = *method == Method::POST;
    match path {
        "/login.html" => Access::Public,
        p if p.starts_with("/assets/") && get => Access::Public,
        "/api/login" if post => Access::Public,
        "/" if get => Access::Page,
        "/api/session" if get => Access::Session,
        "/api/logout" | "/api/password" if post => Access::Session,
        "/api/snapshot" | "/api/alerts" | "/api/baseline" | "/api/vulns" | "/api/vulndb" | "/ws" if get =>
            Access::Role(Role::Viewer),
        "/api/pcap" if post => Access::Role(Role::Operator),
        p if post && p.starts_with("/api/alerts/") && (p.ends_with("/ack") || p.ends_with("/learn")) =>
            Access::Role(Role::Operator),
        p if post && p.starts_with("/api/assets/") && p.ends_with("/manual") => Access::Role(Role::Operator),
        _ => Access::Role(Role::Admin), // baseline mode, vulndb upload, users, audit, anything new
    }
}

pub fn cookie_token(cookie_header: &str) -> Option<&str> {
    cookie_header.split(';').map(str::trim)
        .find_map(|kv| kv.strip_prefix(SESSION_COOKIE).and_then(|rest| rest.strip_prefix('=')))
        .filter(|v| v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip_and_policy() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &phc));
        assert!(!verify_password("correct horse batterY", &phc));
        assert!(!verify_password("x", "not-a-phc-string"));
        assert_ne!(phc, hash_password("correct horse battery").unwrap(), "salted");
        assert!(check_password_policy("admin", "short").is_err());
        assert!(check_password_policy("administrator", "Administrator").is_err());
        assert!(check_password_policy("admin", "long enough pw").is_ok());
        assert!(valid_username("ops.kim-01") && !valid_username("a") && !valid_username("bad name"));
        assert_eq!(random_password().len(), 16);
    }

    #[test]
    fn sessions_expire_and_revoke() {
        let sessions = Sessions::default();
        let token = sessions.create("alice", Role::Operator, false);
        assert_eq!(sessions.get(&token).unwrap().role, Role::Operator);
        let other = sessions.create("alice", Role::Operator, true);
        sessions.password_changed("alice", &other);
        assert!(sessions.get(&token).is_none(), "other sessions die on password change");
        assert!(!sessions.get(&other).unwrap().must_change_password);
        sessions.revoke_user("alice");
        assert!(sessions.get(&other).is_none());
        let t = sessions.create("bob", Role::Viewer, false);
        sessions.map.lock().get_mut(&t).unwrap().last_seen -= SESSION_IDLE + Duration::from_secs(1);
        assert!(sessions.get(&t).is_none(), "idle timeout");
    }

    #[test]
    fn throttle_locks_after_repeated_failures() {
        let throttle = Throttle::default();
        let (here, there) = ("10.0.0.5", "10.0.0.6");
        for _ in 0..MAX_FAILURES - 1 {
            throttle.failure("admin", here);
        }
        assert!(throttle.locked("admin", here).is_none());
        throttle.failure("admin", here);
        assert!(throttle.locked("admin", here).is_some());
        assert!(throttle.locked("admin", there).is_none(), "guessing elsewhere does not lock the real user out");
        throttle.success("admin", here);
        assert!(throttle.locked("admin", here).is_none());
    }

    #[test]
    fn route_policy_is_deny_by_default() {
        assert_eq!(required_access(&Method::GET, "/assets/app.js"), Access::Public);
        assert_eq!(required_access(&Method::POST, "/api/login"), Access::Public);
        assert_eq!(required_access(&Method::GET, "/"), Access::Page);
        assert_eq!(required_access(&Method::GET, "/ws"), Access::Role(Role::Viewer));
        assert_eq!(required_access(&Method::POST, "/api/alerts/7/ack"), Access::Role(Role::Operator));
        assert_eq!(required_access(&Method::POST, "/api/pcap"), Access::Role(Role::Operator));
        assert_eq!(required_access(&Method::POST, "/api/baseline/mode"), Access::Role(Role::Admin));
        assert_eq!(required_access(&Method::POST, "/api/vulndb"), Access::Role(Role::Admin));
        assert_eq!(required_access(&Method::DELETE, "/api/users/bob"), Access::Role(Role::Admin));
        assert_eq!(required_access(&Method::GET, "/api/something-new"), Access::Role(Role::Admin));
        assert_eq!(required_access(&Method::POST, "/assets/app.js"), Access::Role(Role::Admin));
    }

    #[test]
    fn cookie_parsing() {
        let token = "a".repeat(64);
        assert_eq!(cookie_token(&format!("x=1; neteye_session={token}; y=2")), Some(token.as_str()));
        assert_eq!(cookie_token("neteye_session=short"), None);
        assert_eq!(cookie_token("other=1"), None);
    }
}
