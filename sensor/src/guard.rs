//! Browser-facing request guard for the dashboard API.
//!
//! * Host allow-list on every request: defeats DNS rebinding, where an attacker's domain resolves
//!   to the sensor and the page then reads or drives the API as "same origin".
//! * Origin check on state-changing requests and WebSocket upgrades: defeats CSRF and cross-site
//!   WebSocket hijacking. Browsers always send `Origin` on cross-site POSTs and WebSocket
//!   handshakes; non-browser clients (curl, scripts) send none and are allowed.

use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Hostnames (without port) the API answers to.
#[derive(Clone, Debug)]
pub struct AllowedHosts(Vec<String>);

impl AllowedHosts {
    /// Loopback names, the configured bind host (unless it is a wildcard), plus extras such as the
    /// sensor's DNS name or management IP from `NETEYE_ALLOWED_HOSTS`.
    pub fn new(bind_host: &str, extra: &[String]) -> Self {
        let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "[::1]", "::1"].iter().map(|s| s.to_string()).collect();
        if !matches!(bind_host, "0.0.0.0" | "::" | "[::]" | "") {
            hosts.push(bind_host.to_ascii_lowercase());
        }
        hosts.extend(extra.iter().map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()));
        AllowedHosts(hosts)
    }

    fn contains(&self, host_header: &str) -> bool {
        let name = strip_port(host_header).to_ascii_lowercase();
        self.0.iter().any(|h| *h == name || h.trim_matches(|c| c == '[' || c == ']') == name.trim_matches(|c| c == '[' || c == ']'))
    }
}

/// "example:8000" -> "example", "[::1]:8000" -> "[::1]", "::1" stays.
fn strip_port(host: &str) -> &str {
    if let Some(end) = host.strip_prefix('[').and_then(|rest| rest.find(']')) {
        return &host[..end + 2];
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Decide whether a request may proceed. Pure function so it can be unit tested.
pub fn check(method: &Method, path: &str, host: Option<&str>, origin: Option<&str>,
             allowed: &AllowedHosts) -> Result<(), &'static str> {
    let host = host.ok_or("missing Host header")?;
    if !allowed.contains(host) {
        return Err("host not allowed (set NETEYE_ALLOWED_HOSTS for remote access)");
    }
    let state_changing = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    let websocket = path == "/ws";
    if (state_changing || websocket)
        && let Some(origin) = origin {
            // Origin is scheme://host[:port]; it must name exactly the host the request was sent to.
            let authority = origin.split_once("://").map(|(_, a)| a).unwrap_or("");
            if origin == "null" || !authority.eq_ignore_ascii_case(host) {
                return Err("cross-origin request rejected");
            }
        }
    Ok(())
}

pub async fn middleware(State(allowed): State<Arc<AllowedHosts>>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let api = request.uri().path().starts_with("/api/") || request.uri().path() == "/ws";
    let mut response = match check(request.method(), request.uri().path(), host, origin, &allowed) {
        Ok(()) => next.run(request).await,
        Err(reason) => (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({"detail": reason}))).into_response(),
    };
    let headers = response.headers_mut();
    // API data (assets, accounts, audit) must never be written to a browser/proxy cache; static
    // files are revalidated on every load so an upgraded sensor never runs with stale JS/CSS.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(if api { "no-store" } else { "no-cache" }));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")); // no clickjacking via iframes
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> AllowedHosts {
        AllowedHosts::new("127.0.0.1", &["sensor01.plant.local".into()])
    }

    #[test]
    fn same_origin_dashboard_and_cli_are_allowed() {
        let a = allowed();
        assert!(check(&Method::POST, "/api/baseline/mode", Some("127.0.0.1:8000"), Some("http://127.0.0.1:8000"), &a).is_ok());
        assert!(check(&Method::GET, "/ws", Some("localhost:8000"), Some("http://localhost:8000"), &a).is_ok());
        assert!(check(&Method::POST, "/api/pcap", Some("127.0.0.1:8000"), None, &a).is_ok(), "curl sends no Origin");
        assert!(check(&Method::GET, "/api/snapshot", Some("sensor01.plant.local:8000"), None, &a).is_ok());
    }

    #[test]
    fn csrf_and_websocket_hijacking_are_rejected() {
        let a = allowed();
        assert!(check(&Method::POST, "/api/alerts/1/ack", Some("127.0.0.1:8000"), Some("https://evil.example"), &a).is_err());
        assert!(check(&Method::POST, "/api/vulndb", Some("127.0.0.1:8000"), Some("null"), &a).is_err());
        assert!(check(&Method::GET, "/ws", Some("127.0.0.1:8000"), Some("http://evil.example"), &a).is_err());
        assert!(check(&Method::POST, "/api/pcap", Some("127.0.0.1:8000"), Some("http://127.0.0.1:9999"), &a).is_err());
    }

    #[test]
    fn dns_rebinding_is_rejected() {
        let a = allowed();
        // Attacker page on evil.example rebinds the name to 127.0.0.1: Origin == Host, but the host is foreign.
        assert!(check(&Method::GET, "/api/snapshot", Some("evil.example:8000"), None, &a).is_err());
        assert!(check(&Method::POST, "/api/baseline/mode", Some("evil.example:8000"), Some("http://evil.example:8000"), &a).is_err());
        assert!(check(&Method::GET, "/api/snapshot", None, None, &a).is_err());
    }

    #[test]
    fn host_parsing() {
        assert_eq!(strip_port("[::1]:8000"), "[::1]");
        assert_eq!(strip_port("localhost:8000"), "localhost");
        assert_eq!(strip_port("localhost"), "localhost");
        assert!(AllowedHosts::new("0.0.0.0", &[]).contains("[::1]:8000"));
        assert!(!AllowedHosts::new("0.0.0.0", &[]).contains("0.0.0.0:8000"));
    }
}
