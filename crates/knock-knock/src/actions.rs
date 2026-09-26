//! Email-button backend: GitHub sign-in, single-use tokens, NATS JetStream work queue.
use crate::{config::Config, db};
use anyhow::{Result, bail};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use futures::StreamExt;
use gh_core::Client;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use std::sync::Arc;

const STREAM: &str = "KNOCK";
const SUBJECT: &str = "knock.actions.requested";
const RESULT_SUBJECT: &str = "knock.actions.result";

pub struct App {
    pub cfg: Config,
    pub gh: Client,
    pub pool: PgPool,
    pub nats: Option<async_nats::jetstream::Context>,
    pub http: reqwest::Client,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ActionRequest {
    pub rec_id: i64,
    pub repo: String,
    pub action: String,
    pub actor: String,
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

// ---- sessions: `login.exp.hmac` -------------------------------------------------------------

fn sign(secret: &str, msg: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    m.update(msg.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

fn verify(secret: &str, msg: &str, sig: &str) -> bool {
    let Ok(sig) = hex::decode(sig) else {
        return false;
    };
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    m.update(msg.as_bytes());
    m.verify_slice(&sig).is_ok()
}

fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| c.trim().strip_prefix(&format!("{name}=")))
}

fn session_login(app: &App, h: &HeaderMap) -> Option<String> {
    let secret = app.cfg.session_secret.as_deref()?;
    let v = cookie(h, "kk_session")?;
    let (msg, sig) = v.rsplit_once('.')?;
    if !verify(secret, msg, sig) {
        return None;
    }
    let (login, exp) = msg.split_once('.')?;
    (exp.parse::<i64>().ok()? > chrono::Utc::now().timestamp()
        && login.eq_ignore_ascii_case(&app.cfg.owner))
    .then(|| login.to_string())
}

fn set_cookie(app: &App, name: &str, value: &str, max_age: i64) -> HeaderValue {
    let secure = if app.cfg.base_url.starts_with("https") {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
    ))
    .unwrap()
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><meta name=viewport content=\"width=device-width\"><title>{t}</title>\
         <body style=\"font-family:sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem\"><h2>{t}</h2>{body}</body>",
        t = esc(title)
    ))
}

// ---- routes ---------------------------------------------------------------------------------

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/a/{token}", get(confirm).post(execute))
        .with_state(app)
}

#[derive(Deserialize)]
struct LoginQ {
    next: Option<String>,
}

async fn login(State(app): State<Arc<App>>, Query(q): Query<LoginQ>) -> Response {
    let (Some(cid), Some(_)) = (&app.cfg.oauth_client_id, &app.cfg.session_secret) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "sign-in not configured").into_response();
    };
    let next = q
        .next
        .filter(|n| n.strip_prefix("/a/").is_some_and(valid_token))
        .unwrap_or_else(|| "/".into());
    let state = db::new_token();
    let mut r = Redirect::to(&format!(
        "https://github.com/login/oauth/authorize?client_id={cid}&redirect_uri={}/callback&state={state}",
        app.cfg.base_url
    ))
    .into_response();
    // state + next travel in a signed cookie so the callback can verify both.
    let msg = format!("{state}|{next}");
    let sig = sign(app.cfg.session_secret.as_deref().unwrap(), &msg);
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(
            &app,
            "kk_state",
            &format!("{}.{sig}", hex::encode(msg)),
            600,
        ),
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
    let (Some(cid), Some(cs), Some(secret)) = (
        &app.cfg.oauth_client_id,
        &app.cfg.oauth_client_secret,
        &app.cfg.session_secret,
    ) else {
        return (StatusCode::SERVICE_UNAVAILABLE, "sign-in not configured").into_response();
    };
    let Some(next) = (|| {
        let (hexmsg, sig) = cookie(&headers, "kk_state")?.rsplit_once('.')?;
        let msg = String::from_utf8(hex::decode(hexmsg).ok()?).ok()?;
        let (state, next) = msg.split_once('|')?;
        (verify(secret, &msg, sig) && state == q.state).then(|| next.to_string())
    })() else {
        return (StatusCode::BAD_REQUEST, "bad state").into_response();
    };
    let res: Result<String> = async {
        let v: serde_json::Value = app
            .http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .json(&serde_json::json!({"client_id": cid, "client_secret": cs, "code": q.code}))
            .send()
            .await?
            .json()
            .await?;
        let Some(tok) = v["access_token"].as_str() else {
            bail!("no access token")
        };
        Client::oauth_login(&app.http, tok).await
    }
    .await;
    let login = match res {
        Ok(l) if l.eq_ignore_ascii_case(&app.cfg.owner) => l,
        Ok(l) => {
            tracing::warn!("sign-in rejected for {l}");
            return (StatusCode::FORBIDDEN, "this account is not allowed").into_response();
        }
        Err(e) => {
            tracing::warn!("oauth: {e:#}");
            return (StatusCode::BAD_GATEWAY, "GitHub sign-in failed").into_response();
        }
    };
    let exp = chrono::Utc::now().timestamp() + 3600;
    let msg = format!("{login}.{exp}");
    let mut r = Redirect::to(&next).into_response();
    r.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(
            &app,
            "kk_session",
            &format!("{msg}.{}", sign(secret, &msg)),
            3600,
        ),
    );
    r.headers_mut()
        .append(header::SET_COOKIE, set_cookie(&app, "kk_state", "", 0));
    r
}

async fn lookup(app: &App, token: &str) -> Option<(i64, String, String)> {
    sqlx::query_as(
        "SELECT rec_id, repo, action FROM action_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()",
    )
    .bind(db::hash_token(token))
    .fetch_optional(&app.pool)
    .await
    .ok()
    .flatten()
}

async fn confirm(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
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
    if session_login(&app, &headers).is_none() {
        return Redirect::to(&format!("/login?next=/a/{token}")).into_response();
    }
    let verb = match action.as_str() {
        "archive" => "Archive",
        "disable_actions" => "Disable GitHub Actions on",
        _ => "Dismiss the recommendation for",
    };
    page(
        "Confirm",
        &format!(
            "<p>{verb} <b>{r}</b>?</p><form method=post><button style=\"padding:8px 16px\">Yes, do it</button></form>",
            r = esc(&repo)
        ),
    )
    .into_response()
}

async fn execute(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if !valid_token(&token) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some(actor) = session_login(&app, &headers) else {
        return (StatusCode::UNAUTHORIZED, "sign in first").into_response();
    };
    // Atomic claim: exactly one caller wins a token.
    let claimed: Option<(i64, String, String)> = sqlx::query_as(
        "UPDATE action_tokens SET used_at=now(), used_by=$2 WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now()
         RETURNING rec_id, repo, action",
    )
    .bind(db::hash_token(&token))
    .bind(&actor)
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
    // Invalidate the sibling buttons for the same recommendation: one decision per item.
    let _ = sqlx::query("UPDATE action_tokens SET used_at=now(), used_by='superseded' WHERE rec_id=$1 AND used_at IS NULL")
        .bind(rec_id)
        .execute(&app.pool)
        .await;
    let req = ActionRequest {
        rec_id,
        repo: repo.clone(),
        action,
        actor,
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
            return page("Failed", &format!("<p>{}</p>", esc(&format!("{e:#}")))).into_response();
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
            "<p>Request for <b>{}</b> queued; you'll see the result on GitHub shortly.</p>",
            esc(&repo)
        ),
    )
    .into_response()
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
    let res = match req.action.as_str() {
        "archive" => app.gh.archive_repo(&req.repo).await,
        "disable_actions" => app.gh.disable_actions(&req.repo).await,
        "dismiss" => Ok(()),
        other => Err(anyhow::anyhow!("unknown action {other}")),
    };
    sqlx::query("INSERT INTO action_log (actor, action, repo, ok, detail) VALUES ($1,$2,$3,$4,$5)")
        .bind(&req.actor)
        .bind(&req.action)
        .bind(&req.repo)
        .bind(res.is_ok())
        .bind(res.as_ref().err().map(|e| format!("{e:#}")))
        .execute(&app.pool)
        .await?;
    if res.is_ok() {
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
