//! Security layer for the email-button web UI. Everything that can trigger an action goes through:
//!   host check -> rate limit -> security headers -> (origin check for writes) -> session check.
//! The router is default-deny: only the explicit public routes skip the session check.
use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const SESSION_TTL_SECS: i64 = 15 * 60;

pub struct Guard {
    /// Host (with port if non-default) taken from BASE_URL. Requests for anything else are refused.
    pub host: String,
    /// `https://host`, compared against Origin/Referer on writes.
    pub origin: String,
    pub secure: bool,
    pub secret: String,
    pub owner_login: String,
    /// Immutable GitHub user id of the owner. Logins can be renamed/reused; ids cannot.
    pub owner_id: i64,
    limiter: Mutex<HashMap<String, (Instant, u32)>>,
    pub rate_limit_per_min: u32,
}

/// Verified session, placed in request extensions by `require_session`.
#[derive(Clone, Debug)]
pub struct Session {
    pub login: String,
    pub csrf: String,
}

impl Guard {
    pub fn new(base_url: &str, secret: String, owner_login: String, owner_id: i64) -> Arc<Self> {
        let (scheme, rest) = base_url.split_once("://").unwrap_or(("http", base_url));
        let host = rest.split('/').next().unwrap_or(rest).to_ascii_lowercase();
        Arc::new(Self {
            origin: format!("{scheme}://{host}"),
            host,
            secure: scheme == "https",
            secret,
            owner_login,
            owner_id,
            limiter: Mutex::new(HashMap::new()),
            rate_limit_per_min: 60,
        })
    }

    pub fn session_cookie_name(&self) -> &'static str {
        // __Host- pins the cookie to this exact host over HTTPS with Path=/ and no Domain.
        if self.secure {
            "__Host-kk_session"
        } else {
            "kk_session"
        }
    }
    pub fn state_cookie_name(&self) -> &'static str {
        if self.secure {
            "__Host-kk_state"
        } else {
            "kk_state"
        }
    }

    pub fn sign(&self, msg: &str) -> String {
        let mut m = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).unwrap();
        m.update(msg.as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    pub fn verify(&self, msg: &str, sig: &str) -> bool {
        let Ok(sig) = hex::decode(sig) else {
            return false;
        };
        let mut m = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).unwrap();
        m.update(msg.as_bytes());
        m.verify_slice(&sig).is_ok()
    }

    /// Cookie value for a session: `login.id.exp.sig`.
    pub fn issue_session(&self, login: &str, id: i64, now: i64) -> String {
        let msg = format!("{login}.{id}.{}", now + SESSION_TTL_SECS);
        format!("{msg}.{}", self.sign(&format!("session|{msg}")))
    }

    pub fn read_session(&self, cookie_value: &str, now: i64) -> Option<Session> {
        let (msg, sig) = cookie_value.rsplit_once('.')?;
        if !self.verify(&format!("session|{msg}"), sig) {
            return None;
        }
        let mut it = msg.split('.');
        let (login, id, exp) = (
            it.next()?,
            it.next()?.parse::<i64>().ok()?,
            it.next()?.parse::<i64>().ok()?,
        );
        if it.next().is_some()
            || exp <= now
            || id != self.owner_id
            || !login.eq_ignore_ascii_case(&self.owner_login)
        {
            return None;
        }
        Some(Session {
            login: login.to_string(),
            csrf: self.sign(&format!("csrf|{msg}")),
        })
    }

    pub fn set_cookie(&self, name: &str, value: &str, max_age: i64) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
        ))
        .unwrap()
    }

    fn allow(&self, key: &str) -> bool {
        let mut m = self.limiter.lock().unwrap();
        let now = Instant::now();
        if m.len() > 4096 {
            m.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let e = m.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= self.rate_limit_per_min
    }
}

pub fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(prefix.as_str()))
}

fn client_key(h: &HeaderMap) -> String {
    ["cf-connecting-ip", "x-forwarded-for"]
        .iter()
        .find_map(|n| h.get(*n).and_then(|v| v.to_str().ok()))
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn client_ip(h: &HeaderMap) -> String {
    client_key(h)
}

/// Refuse requests addressed to any host other than BASE_URL's (rebinding / host-confusion defence).
/// `/healthz` is exempt so kubelet probes (addressed to the pod IP) keep working.
pub async fn host_guard(State(g): State<Arc<Guard>>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.to_ascii_lowercase());
    if host.as_deref() != Some(g.host.as_str()) {
        return (StatusCode::MISDIRECTED_REQUEST, "wrong host").into_response();
    }
    next.run(req).await
}

pub async fn rate_limit(State(g): State<Arc<Guard>>, req: Request, next: Next) -> Response {
    let p = req.uri().path();
    if p == "/healthz" {
        return next.run(req).await;
    }
    let key = client_key(req.headers());
    if !g.allow(&key) {
        let mut r = (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
        r.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return r;
    }
    next.run(req).await
}

/// Same-origin check for every state-changing request. Both Origin/Referer and Fetch-Metadata
/// must be consistent; a missing Origin *and* Referer is refused (browsers always send one on POST).
pub async fn origin_guard(State(g): State<Arc<Guard>>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let h = req.headers();
    let origin_ok = match h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(o) => o.eq_ignore_ascii_case(&g.origin),
        None => h
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|r| r == g.origin || r.starts_with(&format!("{}/", g.origin))),
    };
    let site_ok = h
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|s| s == "same-origin");
    if !origin_ok || !site_ok {
        tracing::warn!("blocked cross-origin write from {}", client_key(h));
        return (StatusCode::FORBIDDEN, "cross-origin request blocked").into_response();
    }
    next.run(req).await
}

/// Default-deny gate: no valid owner session, no handler. GET navigations are sent to sign-in
/// (and return to the same URL afterwards); anything else is a bare 401.
pub async fn require_session(
    State(g): State<Arc<Guard>>,
    mut req: Request,
    next: Next,
) -> Response {
    let now = chrono::Utc::now().timestamp();
    let session =
        cookie(req.headers(), g.session_cookie_name()).and_then(|v| g.read_session(v, now));
    match session {
        Some(s) => {
            req.extensions_mut().insert(s);
            next.run(req).await
        }
        None if req.method() == Method::GET => {
            let p = req.uri().path();
            Redirect::to(&format!(
                "/login?next={}",
                if p.starts_with("/a/") { p } else { "/" }
            ))
            .into_response()
        }
        None => (StatusCode::UNAUTHORIZED, "sign in first").into_response(),
    }
}

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; \
                   connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Security headers on every response; dynamic responses are never cached.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let dynamic = !req.uri().path().starts_with("/assets/");
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", CSP);
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "same-origin");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    set(h, "cross-origin-opener-policy", "same-origin");
    set(
        h,
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    );
    if dynamic {
        set(h, "cache-control", "no-store");
    }
    r
}

#[allow(dead_code)]
fn _body(_: Body) {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::middleware::from_fn_with_state as mw;
    use axum::{
        Router,
        routing::{get, post},
    };
    use tower::ServiceExt;

    fn guard() -> Arc<Guard> {
        Guard::new(
            "https://gh.example.com",
            "s3cret-s3cret-s3cret".into(),
            "Owner".into(),
            42,
        )
    }

    fn app(g: &Arc<Guard>) -> Router {
        let protected = Router::new()
            .route(
                "/a/x",
                get(|| async { "secret" }).post(|| async { "did it" }),
            )
            .layer(mw(g.clone(), require_session))
            .layer(mw(g.clone(), origin_guard));
        Router::new()
            .route("/", get(|| async { "public" }))
            .route("/healthz", get(|| async { "ok" }))
            .merge(protected)
            .layer(axum::middleware::from_fn(security_headers))
            .layer(mw(g.clone(), rate_limit))
            .layer(mw(g.clone(), host_guard))
    }

    fn req(method: Method, path: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "gh.example.com")
    }

    async fn status(app: &Router, r: Request<Body>) -> StatusCode {
        app.clone().oneshot(r).await.unwrap().status()
    }

    fn cookie_hdr(g: &Guard, value: &str) -> String {
        format!("{}={value}", g.session_cookie_name())
    }

    #[tokio::test]
    async fn wrong_host_rejected_but_healthz_allowed() {
        let g = guard();
        let a = app(&g);
        let bad = Request::builder()
            .uri("/")
            .header("host", "evil.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&a, bad).await, StatusCode::MISDIRECTED_REQUEST);
        let hz = Request::builder()
            .uri("/healthz")
            .header("host", "10.0.0.5:8080")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&a, hz).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_route_needs_session() {
        let g = guard();
        let a = app(&g);
        let r = a
            .clone()
            .oneshot(req(Method::GET, "/a/x").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert!(
            r.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("/login?next=/a/x")
        );
        assert_eq!(
            status(&a, req(Method::GET, "/").body(Body::empty()).unwrap()).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn valid_session_passes_forged_and_wrong_user_fail() {
        let g = guard();
        let a = app(&g);
        let now = chrono::Utc::now().timestamp();
        let good = g.issue_session("owner", 42, now);
        let ok = req(Method::GET, "/a/x")
            .header("cookie", cookie_hdr(&g, &good))
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&a, ok).await, StatusCode::OK);

        // right login, wrong numeric id (renamed/recycled account)
        let other_id = g.issue_session("owner", 43, now);
        // tampered signature
        let mut forged = good.clone();
        forged.pop();
        forged.push(if good.ends_with('0') { '1' } else { '0' });
        // expired
        let expired = g.issue_session("owner", 42, now - SESSION_TTL_SECS - 5);
        // signed by a different key
        let other = Guard::new(
            "https://gh.example.com",
            "different-secret-different".into(),
            "Owner".into(),
            42,
        )
        .issue_session("owner", 42, now);
        for bad in [other_id, forged, expired, other] {
            let r = req(Method::GET, "/a/x")
                .header("cookie", cookie_hdr(&g, &bad))
                .body(Body::empty())
                .unwrap();
            assert_eq!(status(&a, r).await, StatusCode::SEE_OTHER, "accepted {bad}");
        }
    }

    #[tokio::test]
    async fn writes_require_same_origin_and_session() {
        let g = guard();
        let a = app(&g);
        let c = cookie_hdr(
            &g,
            &g.issue_session("owner", 42, chrono::Utc::now().timestamp()),
        );
        let mk = |origin: Option<&str>, site: Option<&str>| {
            let mut b = req(Method::POST, "/a/x").header("cookie", c.clone());
            if let Some(o) = origin {
                b = b.header("origin", o);
            }
            if let Some(s) = site {
                b = b.header("sec-fetch-site", s);
            }
            b.body(Body::empty()).unwrap()
        };
        assert_eq!(
            status(&a, mk(Some("https://gh.example.com"), Some("same-origin"))).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&a, mk(Some("https://evil.com"), None)).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(status(&a, mk(None, None)).await, StatusCode::FORBIDDEN);
        assert_eq!(
            status(&a, mk(Some("https://gh.example.com"), Some("cross-site"))).await,
            StatusCode::FORBIDDEN
        );
        // origin ok but no session
        let nosess = req(Method::POST, "/a/x")
            .header("origin", "https://gh.example.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status(&a, nosess).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limited_and_headers_set() {
        let g = guard();
        let a = app(&g);
        let mut last = StatusCode::OK;
        for _ in 0..(g.rate_limit_per_min + 1) {
            last = status(
                &a,
                req(Method::GET, "/")
                    .header("x-forwarded-for", "1.2.3.4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
        let r = app(&guard())
            .oneshot(req(Method::GET, "/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        for h in [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "strict-transport-security",
        ] {
            assert!(r.headers().contains_key(h), "missing {h}");
        }
        assert_eq!(r.headers()["cache-control"], "no-store");
    }

    #[test]
    fn csrf_token_is_bound_to_session() {
        let g = guard();
        let now = chrono::Utc::now().timestamp();
        let a = g
            .read_session(&g.issue_session("owner", 42, now), now)
            .unwrap();
        let b = g
            .read_session(&g.issue_session("owner", 42, now + 1), now)
            .unwrap();
        assert_ne!(a.csrf, b.csrf);
    }
}
