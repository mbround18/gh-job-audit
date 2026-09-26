//! Email-button backend: GitHub sign-in, single-use tokens, NATS JetStream work queue.
//! All protection lives in `security.rs`; handlers here can assume a verified owner `Session`.
use crate::{
    config::Config,
    db,
    security::{self, Guard, Session},
};
use anyhow::{Result, bail};
use axum::{
    Extension, Form, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::from_fn_with_state,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use futures::StreamExt;
use gh_core::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tower_http::{limit::RequestBodyLimitLayer, services::ServeDir, timeout::TimeoutLayer};

pub const STREAM: &str = "KNOCK";
const SUBJECT: &str = "knock.actions.requested";
const RESULT_SUBJECT: &str = "knock.actions.result";

pub struct App {
    pub cfg: Config,
    pub gh: Client,
    pub pool: PgPool,
    pub nats: Option<async_nats::jetstream::Context>,
    pub http: reqwest::Client,
    pub guard: Arc<Guard>,
    pub web_dir: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ActionRequest {
    pub rec_id: i64,
    pub repo: String,
    pub action: String,
    pub actor: String,
    #[serde(default)]
    pub ip: String,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn valid_token(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

fn page(title: &str, body: &str) -> Html<String> {
    // No inline styles/scripts: the CSP forbids them. Uses the bundled stylesheet if present.
    Html(format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
         <title>{t}</title><link rel=stylesheet href=\"/action.css\"></head><body><main><h2>{t}</h2>{body}</main></body></html>",
        t = esc(title)
    ))
}

const ACTION_CSS: &str = "body{font-family:system-ui,sans-serif;background:#0b0d10;color:#e6e8eb;margin:0}\
main{max-width:34rem;margin:4rem auto;padding:0 1rem}button{padding:.6rem 1.2rem;border:0;border-radius:6px;\
background:#b91c1c;color:#fff;font-size:1rem;cursor:pointer}b{color:#fff}";

pub fn router(app: Arc<App>) -> Router {
    let g = app.guard.clone();
    // Default-deny: everything under /a/ needs an owner session and (for writes) same-origin.
    let protected = Router::new()
        .route("/a/{token}", get(confirm).post(execute))
        .layer(from_fn_with_state(g.clone(), security::require_session))
        .layer(from_fn_with_state(g.clone(), security::origin_guard));
    let public = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/action.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], ACTION_CSS) }),
        )
        .route("/login", get(login))
        .route("/callback", get(callback))
        .fallback_service(
            ServeDir::new(app.web_dir.clone()).append_index_html_on_directories(true),
        );
    public
        .merge(protected)
        .with_state(app)
        .layer(axum::middleware::from_fn(security::security_headers))
        .layer(from_fn_with_state(g.clone(), security::rate_limit))
        .layer(from_fn_with_state(g, security::host_guard))
        .layer(RequestBodyLimitLayer::new(8 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(20),
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

#[derive(Deserialize)]
struct LoginQ {
    next: Option<String>,
}

async fn login(State(app): State<Arc<App>>, Query(q): Query<LoginQ>) -> Response {
    let Some(cid) = &app.cfg.oauth_client_id else {
        return (StatusCode::SERVICE_UNAVAILABLE, "sign-in not configured").into_response();
    };
    let g = &app.guard;
    // Only same-site action links are valid post-login destinations (no open redirect).
    let next = q
        .next
        .filter(|n| n.strip_prefix("/a/").is_some_and(valid_token))
        .unwrap_or_else(|| "/".into());
    let state = db::new_token();
    let mut r = Redirect::to(&format!(
        "https://github.com/login/oauth/authorize?client_id={cid}&redirect_uri={}/callback&state={state}&allow_signup=false",
        app.cfg.base_url
    ))
    .into_response();
    let msg = format!("{state}|{next}");
    let cv = format!("{}.{}", hex::encode(&msg), g.sign(&format!("state|{msg}")));
    r.headers_mut().append(
        header::SET_COOKIE,
        g.set_cookie(g.state_cookie_name(), &cv, 600),
    );
    r
}

#[derive(Deserialize)]
struct CallbackQ {
    code: String,
    state: String,
}

async fn callback(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(q): Query<CallbackQ>,
) -> Response {
    let g = &app.guard;
    let (Some(cid), Some(cs)) = (&app.cfg.oauth_client_id, &app.cfg.oauth_client_secret) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "sign-in not configured").into_response();
    };
    let Some(next) = (|| {
        let (hexmsg, sig) = security::cookie(&headers, g.state_cookie_name())?.rsplit_once('.')?;
        let msg = String::from_utf8(hex::decode(hexmsg).ok()?).ok()?;
        let (state, next) = msg.split_once('|')?;
        (g.verify(&format!("state|{msg}"), sig) && state == q.state).then(|| next.to_string())
    })() else {
        return (StatusCode::BAD_REQUEST, "bad state").into_response();
    };
    let res: Result<(String, i64)> = async {
        let v: serde_json::Value = app
            .http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .json(&serde_json::json!({"client_id": cid, "client_secret": cs, "code": q.code, "redirect_uri": format!("{}/callback", app.cfg.base_url)}))
            .send()
            .await?
            .json()
            .await?;
        let Some(tok) = v["access_token"].as_str() else { bail!("no access token") };
        Client::oauth_user(&app.http, tok).await
    }
    .await;
    let (login, id) = match res {
        // Identity is pinned by immutable numeric id, not by (renameable) login.
        Ok((l, id)) if id == g.owner_id => (l, id),
        Ok((l, id)) => {
            tracing::warn!(
                "sign-in rejected for {l} (id {id}) from {}",
                security::client_ip(&headers)
            );
            return (StatusCode::FORBIDDEN, "this account is not allowed").into_response();
        }
        Err(e) => {
            tracing::warn!("oauth: {e:#}");
            return (StatusCode::BAD_GATEWAY, "GitHub sign-in failed").into_response();
        }
    };
    let cv = g.issue_session(&login, id, chrono::Utc::now().timestamp());
    let mut r = Redirect::to(&next).into_response();
    r.headers_mut().append(
        header::SET_COOKIE,
        g.set_cookie(g.session_cookie_name(), &cv, security::SESSION_TTL_SECS),
    );
    r.headers_mut().append(
        header::SET_COOKIE,
        g.set_cookie(g.state_cookie_name(), "", 0),
    );
    r
}

/// Only *open* recommendations with an unused, unexpired token are actionable.
async fn lookup(app: &App, token: &str) -> Option<(i64, String, String)> {
    sqlx::query_as(
        "SELECT t.rec_id, t.repo, t.action FROM action_tokens t JOIN recommendations r ON r.id = t.rec_id
         WHERE t.token_hash=$1 AND t.used_at IS NULL AND t.expires_at > now() AND r.status='open'",
    )
    .bind(db::hash_token(token))
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten()
}

async fn confirm(
    State(app): State<Arc<App>>,
    Extension(sess): Extension<Session>,
    Path(token): Path<String>,
) -> Response {
    if !valid_token(&token) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some((_, repo, action)) = lookup(&app, &token).await else {
        return page(
            "Link expired",
            "<p>This link was already used or has expired.</p>",
        )
        .into_response();
    };
    let verb = match action.as_str() {
        "archive" => "Archive (make read-only on GitHub; reversible from repo settings)",
        "disable_actions" => {
            "Turn off GitHub Actions (no more CI runs; re-enable in repo settings)"
        }
        "test_ping" | "test_archive" | "test_disable_actions" | "test_fail" => {
            "SELF-TEST (nothing real changes): run the sandbox action on"
        }
        _ => "Keep as-is: no change to the repo, and stop flagging this suggestion for",
    };
    page(
        "Confirm",
        &format!(
            "<p>Signed in as <b>{who}</b>.</p><p>{verb} <b>{r}</b>?</p>\
             <form method=post><input type=hidden name=csrf value=\"{csrf}\"><button>Yes, do it</button></form>",
            who = esc(&sess.login),
            r = esc(&repo),
            csrf = esc(&sess.csrf)
        ),
    )
    .into_response()
}

#[derive(Deserialize)]
struct ExecForm {
    csrf: String,
}

async fn execute(
    State(app): State<Arc<App>>,
    Extension(sess): Extension<Session>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(f): Form<ExecForm>,
) -> Response {
    if !valid_token(&token) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    // Synchronizer token bound to this session (defence in depth on top of the origin check).
    if !constant_eq(f.csrf.as_bytes(), sess.csrf.as_bytes()) {
        return (StatusCode::FORBIDDEN, "bad csrf token").into_response();
    }
    // Atomic claim: exactly one caller wins a token, and only while the recommendation is still open.
    let claimed: Option<(i64, String, String)> = sqlx::query_as(
        "UPDATE action_tokens t SET used_at=now(), used_by=$2
         FROM recommendations r
         WHERE t.token_hash=$1 AND t.used_at IS NULL AND t.expires_at > now() AND r.id = t.rec_id AND r.status='open'
         RETURNING t.rec_id, t.repo, t.action",
    )
    .bind(db::hash_token(&token))
    .bind(&sess.login)
    .fetch_optional(&app.pool)
    .await
    .unwrap_or(None);
    let Some((rec_id, repo, action)) = claimed else {
        return page(
            "Link expired",
            "<p>This link was already used or has expired.</p>",
        )
        .into_response();
    };
    // One decision per item: invalidate the sibling buttons.
    // (The sandbox item keeps its other buttons live so each can be tested.)
    if repo != crate::jobs::SELFTEST_REPO {
        let _ = sqlx::query("UPDATE action_tokens SET used_at=now(), used_by='superseded' WHERE rec_id=$1 AND used_at IS NULL")
            .bind(rec_id)
            .execute(&app.pool)
            .await;
    }
    let req = ActionRequest {
        rec_id,
        repo: repo.clone(),
        action,
        actor: sess.login,
        ip: security::client_ip(&headers),
    };
    let queued = match &app.nats {
        Some(js) => match js
            .publish(SUBJECT, serde_json::to_vec(&req).unwrap().into())
            .await
        {
            Ok(ack) => ack.await.is_ok(),
            Err(_) => false,
        },
        None => false,
    };
    if !queued {
        // No NATS (or publish failed): run inline so the click is never silently lost.
        if let Err(e) = perform(&app, &req).await {
            tracing::error!("action failed: {e:#}");
            return page(
                "Failed",
                "<p>The action failed. Check the service logs.</p>",
            )
            .into_response();
        }
        return page(
            "Done",
            &format!("<p>Completed for <b>{}</b>.</p>", esc(&repo)),
        )
        .into_response();
    }
    page(
        "Queued",
        &format!(
            "<p>Request for <b>{}</b> queued; it will run in a moment.</p>",
            esc(&repo)
        ),
    )
    .into_response()
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Do the thing and record it. The recommendation must exist and match the repo.
pub async fn perform(app: &App, req: &ActionRequest) -> Result<()> {
    let ok: Option<i64> =
        sqlx::query_scalar("SELECT id FROM recommendations WHERE id=$1 AND repo=$2")
            .bind(req.rec_id)
            .bind(&req.repo)
            .fetch_optional(&app.pool)
            .await?;
    if ok.is_none() {
        bail!("recommendation {} does not match {}", req.rec_id, req.repo);
    }
    let sandbox = req.repo == crate::jobs::SELFTEST_REPO;
    // Real actions never run on the sandbox item, and test actions never run on real repos.
    if sandbox != req.action.starts_with("test_") && req.action != "dismiss" {
        bail!("action {} not allowed on {}", req.action, req.repo);
    }
    let res = match req.action.as_str() {
        "archive" => app.gh.archive_repo(&req.repo).await,
        "disable_actions" => app.gh.disable_actions(&req.repo).await,
        "test_ping" | "test_archive" | "test_disable_actions" => {
            tracing::info!("selftest {} ok (no GitHub call)", req.action);
            Ok(())
        }
        "test_fail" => Err(anyhow::anyhow!("intentional self-test failure")),
        "dismiss" => Ok(()),
        other => Err(anyhow::anyhow!("unknown action {other}")),
    };
    sqlx::query(
        "INSERT INTO action_log (actor, action, repo, ok, detail, ip) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&req.actor)
    .bind(&req.action)
    .bind(&req.repo)
    .bind(res.is_ok())
    .bind(res.as_ref().err().map(|e| format!("{e:#}")))
    .bind(&req.ip)
    .execute(&app.pool)
    .await?;
    if res.is_ok() && !sandbox {
        let status = if req.action == "dismiss" {
            "dismissed"
        } else {
            "done"
        };
        sqlx::query("UPDATE recommendations SET status=$2 WHERE id=$1")
            .bind(req.rec_id)
            .bind(status)
            .execute(&app.pool)
            .await?;
    }
    if let Some(js) = &app.nats {
        let _ = js
            .publish(
                RESULT_SUBJECT,
                serde_json::to_vec(&serde_json::json!({"req": req, "ok": res.is_ok()}))?.into(),
            )
            .await;
    }
    res
}

/// Durable JetStream consumer that executes queued actions.
pub async fn worker(app: Arc<App>) -> Result<()> {
    let Some(js) = app.nats.clone() else {
        return Ok(());
    };
    let stream = js
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: STREAM.into(),
            subjects: vec!["knock.>".into()],
            max_age: std::time::Duration::from_secs(7 * 86400),
            ..Default::default()
        })
        .await?;
    let consumer = stream
        .get_or_create_consumer(
            "action-worker",
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("action-worker".into()),
                filter_subject: SUBJECT.into(),
                max_deliver: 3,
                ..Default::default()
            },
        )
        .await?;
    let mut msgs = consumer.messages().await?;
    while let Some(m) = msgs.next().await {
        let m = m?;
        match serde_json::from_slice::<ActionRequest>(&m.payload) {
            Ok(req) => match perform(&app, &req).await {
                Ok(()) => {
                    tracing::info!("performed {} on {} for {}", req.action, req.repo, req.actor);
                    m.ack().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                Err(e) => {
                    tracing::error!("action {req:?} failed: {e:#}");
                    let _ = m.ack_with(async_nats::jetstream::AckKind::Nak(None)).await;
                }
            },
            Err(e) => {
                tracing::error!("bad action payload: {e}");
                let _ = m.ack_with(async_nats::jetstream::AckKind::Term).await;
            }
        }
    }
    Ok(())
}
