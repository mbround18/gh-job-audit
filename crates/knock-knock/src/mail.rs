use crate::config::{Config, MailConfig};
use anyhow::{Context, Result, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::MultiPart,
    transport::smtp::authentication::Credentials,
};

pub async fn send(cfg: &Config, subject: &str, html: &str, text: &str) -> Result<()> {
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
