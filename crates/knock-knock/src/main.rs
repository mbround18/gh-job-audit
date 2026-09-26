mod actions;
mod config;
mod db;
mod gov;
mod jobs;
mod mail;
mod security;
mod template;

use anyhow::Result;
use clap::{Parser, Subcommand};
use gh_core::Client;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "knock-knock", about = "GitHub audit + usage watcher")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan repos, store a snapshot, email new recommendations (run daily).
    Daily {
        /// Send even if fewer than REPORT_MIN_ITEMS are due.
        #[arg(long)]
        force: bool,
    },
    /// Email when monthly Actions usage crosses USAGE_ALERT_PCTS (run every few hours).
    Usage,
    /// Serve the email-button web UI and the NATS action worker.
    Serve {
        #[arg(long, env = "LISTEN", default_value = "0.0.0.0:8080")]
        listen: String,
    },
    /// Find unassigned issues/PRs and (per TRIAGE_MODE) assign them to CODEOWNERS or the repo owner.
    Triage {
        /// Assign per TRIAGE_MODE (daily). With neither flag, does both.
        #[arg(long)]
        assign: bool,
        /// Email the weekly unassigned/assigned summary.
        #[arg(long)]
        report: bool,
    },
    /// Email one digest of open issues/PRs with no activity for STALE_DAYS (tracked in `tracked_items`).
    Stale,
    /// Run one governance sweep (security, hygiene, access, workflows, storage, deps, releases, branches, prflow, rollup).
    Gov {
        #[arg(value_enum)]
        job: gov::GovJob,
    },
    /// Render a report JSON (see template.rs) to HTML; `--send` emails it instead. Reads stdin when no file.
    Render {
        file: Option<std::path::PathBuf>,
        #[arg(long)]
        send: bool,
    },
    /// Run the mailer: consumes queued email from NATS and sends it (retries with backoff).
    Mailer,
    /// Email a sandbox item whose buttons test sign-in, tokens and the NATS worker (no repo is touched).
    Selftest,
    /// Print the current recommendations without emailing or writing to the DB.
    Report,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let cli = Cli::parse();
    let cfg = config::Config::from_env_for(matches!(cli.cmd, Cmd::Report))?;
    if let Cmd::Mailer = cli.cmd {
        let url = cfg
            .nats_url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("NATS_URL required for the mailer"))?;
        let pool = db::connect(&cfg.database_url).await?;
        let js = async_nats::jetstream::new(async_nats::connect(url).await?);
        return mail::run_worker(&cfg, &pool, js).await;
    }
    let (auth, billing_auth) = cfg.github_auth()?;
    let gh = Client::new(auth, &cfg.owner)?;

    if let Cmd::Report = cli.cmd {
        let repos = gh.list_repos().await?;
        let mut stats = Vec::new();
        for r in &repos {
            stats.push(gh.repo_stats(r).await?);
        }
        for r in gh_core::evaluate(&stats, &cfg.thresholds, chrono::Utc::now()) {
            println!("{:<15} {:<40} {}", r.kind.as_str(), r.repo, r.reason);
        }
        return Ok(());
    }

    let pool = db::connect(&cfg.database_url).await?;
    let job_nats = match (&cli.cmd, &cfg.nats_url) {
        (
            Cmd::Daily { .. }
            | Cmd::Usage
            | Cmd::Selftest
            | Cmd::Triage { .. }
            | Cmd::Stale
            | Cmd::Gov { .. },
            Some(u),
        ) => Some(async_nats::jetstream::new(async_nats::connect(u).await?)),
        _ => None,
    };
    match cli.cmd {
        Cmd::Daily { force } => jobs::daily(&cfg, &gh, &pool, job_nats.as_ref(), force).await,
        Cmd::Triage { assign, report } => {
            let both = !assign && !report;
            jobs::triage(
                &cfg,
                &gh,
                &pool,
                job_nats.as_ref(),
                assign || both,
                report || both,
            )
            .await
        }
        Cmd::Gov { job } => gov::run(job, &cfg, &gh, &pool, job_nats.as_ref()).await,
        Cmd::Render { file, send } => {
            let raw = match file {
                Some(f) => std::fs::read_to_string(f)?,
                None => std::io::read_to_string(std::io::stdin())?,
            };
            let mut r: template::Report = serde_json::from_str(&raw)?;
            if r.brand.is_none() {
                r.brand = Some(template::Brand::from_github(&gh, &cfg.owner).await);
            }
            let (html, text) = r.render();
            if send {
                mail::deliver(
                    &cfg,
                    job_nats.as_ref(),
                    mail::MailMsg::new(r.title.clone(), html, text),
                )
                .await
            } else {
                println!("{html}");
                Ok(())
            }
        }
        Cmd::Stale => jobs::stale(&cfg, &gh, &pool, job_nats.as_ref()).await,
        Cmd::Selftest => jobs::selftest(&cfg, &pool, job_nats.as_ref()).await,
        Cmd::Usage => {
            let billing = Client::new(
                billing_auth.unwrap_or_else(|| gh_core::Auth::Token(String::new())),
                &cfg.owner,
            )?;
            jobs::usage(&cfg, &billing, &pool, job_nats.as_ref()).await
        }
        Cmd::Serve { listen } => {
            let nats = match &cfg.nats_url {
                Some(u) => Some(async_nats::jetstream::new(async_nats::connect(u).await?)),
                None => None,
            };
            let secret = cfg
                .session_secret
                .clone()
                .filter(|s| s.len() >= 32)
                .ok_or_else(|| {
                    anyhow::anyhow!("SESSION_SECRET (>=32 chars) is required for serve")
                })?;
            anyhow::ensure!(
                cfg.oauth_client_id.is_some() && cfg.oauth_client_secret.is_some(),
                "GITHUB_APP_CLIENT_ID/SECRET required for serve"
            );
            // Pin the owner's immutable numeric id once at startup.
            let owner_id = gh.user_id(&cfg.owner).await?;
            let guard = security::Guard::new(&cfg.base_url, secret, cfg.owner.clone(), owner_id);
            let web_dir = std::env::var("WEB_DIR").unwrap_or_else(|_| "/srv/web".into());
            let app = Arc::new(actions::App {
                cfg,
                gh,
                pool,
                nats,
                http: reqwest::Client::new(),
                guard,
                web_dir,
            });
            let worker = tokio::spawn(actions::worker(app.clone()));
            if let Some(js) = app.nats.clone() {
                tokio::spawn(jobs::assigner(app.gh.clone(), app.pool.clone(), js));
            }
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            tracing::info!("listening on {listen}");
            tokio::select! {
                r = axum::serve(listener, actions::router(app)) => r?,
                r = worker => r??,
            }
            Ok(())
        }
        Cmd::Mailer | Cmd::Report => unreachable!(),
    }
}
