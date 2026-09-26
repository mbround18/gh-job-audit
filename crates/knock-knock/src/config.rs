use anyhow::{Context, Result};
use gh_core::{Auth, Thresholds};

/// Read `NAME`, or the file named by `NAME_FILE` (for mounted secrets).
pub fn env_or_file(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let path = std::env::var(format!("{name}_FILE")).ok()?;
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn num<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub struct Config {
    pub owner: String,
    pub database_url: String,
    pub base_url: String,
    pub thresholds: Thresholds,
    pub report_min_items: usize,
    pub renotify_days: i64,
    pub usage_alert_pcts: Vec<f64>,
    pub minutes_quota: f64,
    pub action_ttl_hours: i64,
    pub nats_url: Option<String>,
    pub session_secret: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub mail: MailConfig,
    pub mail_to: Option<String>,
}

pub enum MailConfig {
    Resend {
        api_key: String,
        from: String,
    },
    Smtp {
        host: String,
        port: u16,
        user: Option<String>,
        pass: Option<String>,
        from: String,
        starttls: bool,
    },
    /// No mail configured: reports are logged instead of sent.
    None,
}

impl Config {
    /// `lenient` (report-only mode) doesn't require a database.
    pub fn from_env_for(lenient: bool) -> Result<Self> {
        let from = std::env::var("MAIL_FROM").unwrap_or_else(|_| "knock-knock@localhost".into());
        let mail = if let Some(k) = env_or_file("RESEND_API_KEY") {
            MailConfig::Resend { api_key: k, from }
        } else if let Ok(host) = std::env::var("SMTP_HOST") {
            MailConfig::Smtp {
                host,
                port: num("SMTP_PORT", 587),
                user: env_or_file("SMTP_USERNAME"),
                pass: env_or_file("SMTP_PASSWORD"),
                from,
                starttls: num("SMTP_STARTTLS", true),
            }
        } else {
            MailConfig::None
        };
        let d = Thresholds::default();
        Ok(Self {
            owner: std::env::var("GH_OWNER").context("GH_OWNER is required")?,
            database_url: match env_or_file("DATABASE_URL") {
                Some(u) => u,
                None if lenient => String::new(),
                None => anyhow::bail!("DATABASE_URL is required"),
            },
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8080".into())
                .trim_end_matches('/')
                .into(),
            thresholds: Thresholds {
                archive_idle_days: num("ARCHIVE_IDLE_DAYS", d.archive_idle_days),
                archive_popular_score: num("ARCHIVE_POPULAR_SCORE", d.archive_popular_score),
                ci_off_runs_30d: num("CI_OFF_RUNS_30D", d.ci_off_runs_30d),
                private_minutes_30d: num("PRIVATE_MINUTES_30D", d.private_minutes_30d),
                heavy_minutes_30d: num("HEAVY_MINUTES_30D", d.heavy_minutes_30d),
                bot_runs_30d: num("BOT_RUNS_30D", d.bot_runs_30d),
            },
            report_min_items: num("REPORT_MIN_ITEMS", 1),
            renotify_days: num("RENOTIFY_DAYS", 14),
            usage_alert_pcts: std::env::var("USAGE_ALERT_PCTS")
                .unwrap_or_else(|_| "50,75,90".into())
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect(),
            minutes_quota: num("ACTIONS_QUOTA_MINUTES", 2000.0),
            action_ttl_hours: num("ACTION_TTL_HOURS", 72),
            nats_url: std::env::var("NATS_URL").ok().filter(|s| !s.is_empty()),
            session_secret: env_or_file("SESSION_SECRET"),
            oauth_client_id: env_or_file("GITHUB_APP_CLIENT_ID"),
            oauth_client_secret: env_or_file("GITHUB_APP_CLIENT_SECRET"),
            mail,
            mail_to: std::env::var("MAIL_TO").ok().filter(|s| !s.is_empty()),
        })
    }

    /// GitHub App if configured, else a PAT. A PAT is also required for real billing data.
    pub fn github_auth(&self) -> Result<(Auth, Option<Auth>)> {
        let pat = env_or_file("GITHUB_TOKEN").map(Auth::Token);
        let app = match (
            env_or_file("GITHUB_APP_ID"),
            env_or_file("GITHUB_APP_PRIVATE_KEY"),
        ) {
            (Some(app_id), Some(pem)) => Some(Auth::App {
                app_id,
                private_key_pem: pem,
                installation_id: env_or_file("GITHUB_APP_INSTALLATION_ID")
                    .and_then(|s| s.parse().ok()),
            }),
            _ => None,
        };
        match (app, pat) {
            (Some(a), p) => Ok((a, p)),
            (None, Some(p)) => Ok((p.clone(), Some(p))),
            (None, None) => {
                anyhow::bail!("set GITHUB_APP_ID+GITHUB_APP_PRIVATE_KEY (or GITHUB_TOKEN)")
            }
        }
    }
}
