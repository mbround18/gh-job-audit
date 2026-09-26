use crate::config::{Config, MailConfig};
use anyhow::{Context, Result, bail};
use async_nats::jetstream::{self, AckKind, consumer::pull};
use futures::StreamExt;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::MultiPart,
    transport::smtp::authentication::Credentials,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;

async fn transport(cfg: &Config, subject: &str, html: &str, text: &str) -> Result<()> {
    let Some(to) = cfg.mail_to.as_deref() else {
        tracing::warn!("MAIL_TO not set; report logged instead of sent:\n{text}");
        return Ok(());
    };
    match &cfg.mail {
        MailConfig::None => {
            tracing::warn!(
                "no mail transport configured (RESEND_API_KEY or SMTP_HOST); subject={subject}\n{text}"
            );
            Ok(())
        }
        MailConfig::Resend { api_key, from } => {
            let r = reqwest::Client::new()
                .post("https://api.resend.com/emails")
                .bearer_auth(api_key)
                .json(&serde_json::json!({"from": from, "to": [to], "subject": subject, "html": html, "text": text}))
                .send()
                .await?;
            if !r.status().is_success() {
                bail!(
                    "resend {}: {}",
                    r.status(),
                    r.text().await.unwrap_or_default()
                );
            }
            Ok(())
        }
        MailConfig::Smtp {
            host,
            port,
            user,
            pass,
            from,
            starttls,
        } => {
            let msg = Message::builder()
                .from(from.parse().context("MAIL_FROM")?)
                .to(to.parse().context("MAIL_TO")?)
                .subject(subject)
                .multipart(MultiPart::alternative_plain_html(
                    text.to_string(),
                    html.to_string(),
                ))?;
            let mut b = if *starttls {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::relay(host)?
            }
            .port(*port);
            if let (Some(u), Some(p)) = (user, pass) {
                b = b.credentials(Credentials::new(u.clone(), p.clone()));
            }
            b.build().send(msg).await?;
            Ok(())
        }
    }
}

pub const SUBJECT: &str = "knock.mail.send";
const MAX_DELIVER: i64 = 5;
/// Redelivery delays after a failed send (transient provider errors, rate limits).
const BACKOFF: [u64; 4] = [30, 120, 600, 3600];

/// A message any job can hand to the mailer. `dedupe_key` makes re-publishing idempotent.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MailMsg {
    pub subject: String,
    pub html: String,
    pub text: String,
    #[serde(default)]
    pub dedupe_key: Option<String>,
}

impl MailMsg {
    pub fn new(
        subject: impl Into<String>,
        html: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            html: html.into(),
            text: text.into(),
            dedupe_key: None,
        }
    }
    pub fn dedupe(mut self, key: impl Into<String>) -> Self {
        self.dedupe_key = Some(key.into());
        self
    }
}

/// Queue a message for the mailer worker; with no NATS configured, send it directly.
pub async fn deliver(cfg: &Config, nats: Option<&jetstream::Context>, msg: MailMsg) -> Result<()> {
    match nats {
        Some(js) => {
            js.publish(SUBJECT, serde_json::to_vec(&msg)?.into())
                .await
                .context("publish mail")?
                .await
                .context("mail publish not acknowledged")?;
            tracing::info!("queued mail: {}", msg.subject);
            Ok(())
        }
        None => send_direct(cfg, &msg).await,
    }
}

async fn send_direct(cfg: &Config, m: &MailMsg) -> Result<()> {
    transport(cfg, &m.subject, &m.html, &m.text).await
}

/// The mailer: the only thing that talks to Resend/SMTP when NATS is in use.
pub async fn run_worker(cfg: &Config, pool: &PgPool, js: jetstream::Context) -> Result<()> {
    let stream = js
        .get_or_create_stream(jetstream::stream::Config {
            name: crate::actions::STREAM.into(),
            subjects: vec!["knock.>".into()],
            max_age: Duration::from_secs(7 * 86400),
            ..Default::default()
        })
        .await?;
    let consumer = stream
        .get_or_create_consumer(
            "mailer",
            pull::Config {
                durable_name: Some("mailer".into()),
                filter_subject: SUBJECT.into(),
                max_deliver: MAX_DELIVER,
                ..Default::default()
            },
        )
        .await?;
    tracing::info!("mailer ready");
    let mut msgs = consumer.messages().await?;
    while let Some(m) = msgs.next().await {
        let m = m?;
        let msg: MailMsg = match serde_json::from_slice(&m.payload) {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("bad mail payload: {e}");
                let _ = m.ack_with(AckKind::Term).await;
                continue;
            }
        };
        match handle(cfg, pool, &msg).await {
            Ok(()) => {
                let _ = m.ack().await;
            }
            Err(e) => {
                let n = m.info().map(|i| i.delivered).unwrap_or(1).max(1) as usize;
                if n as i64 >= MAX_DELIVER {
                    tracing::error!("mail '{}' dropped after {n} attempts: {e:#}", msg.subject);
                    let _ = m.ack_with(AckKind::Term).await;
                } else {
                    let wait = BACKOFF[(n - 1).min(BACKOFF.len() - 1)];
                    tracing::warn!(
                        "mail '{}' failed (attempt {n}), retry in {wait}s: {e:#}",
                        msg.subject
                    );
                    let _ = m
                        .ack_with(AckKind::Nak(Some(Duration::from_secs(wait))))
                        .await;
                }
            }
        }
    }
    Ok(())
}

async fn handle(cfg: &Config, pool: &PgPool, msg: &MailMsg) -> Result<()> {
    if let Some(k) = &msg.dedupe_key {
        let seen: Option<String> =
            sqlx::query_scalar("SELECT dedupe_key FROM mail_log WHERE dedupe_key=$1")
                .bind(k)
                .fetch_optional(pool)
                .await?;
        if seen.is_some() {
            tracing::info!("skipping duplicate mail {k}");
            return Ok(());
        }
    }
    send_direct(cfg, msg).await?;
    if let Some(k) = &msg.dedupe_key {
        sqlx::query(
            "INSERT INTO mail_log (dedupe_key, subject) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(k)
        .bind(&msg.subject)
        .execute(pool)
        .await?;
    }
    tracing::info!("sent mail: {}", msg.subject);
    Ok(())
}
