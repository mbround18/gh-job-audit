mod actions;
mod config;
mod db;
mod jobs;
mod mail;

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
    match cli.cmd {
        Cmd::Daily { force } => jobs::daily(&cfg, &gh, &pool, force).await,
        Cmd::Usage => {
            let billing = Client::new(
                billing_auth.unwrap_or_else(|| gh_core::Auth::Token(String::new())),
                &cfg.owner,
            )?;
            jobs::usage(&cfg, &billing, &pool).await
        }
        Cmd::Serve { listen } => {
            let nats = match &cfg.nats_url {
                Some(u) => Some(async_nats::jetstream::new(async_nats::connect(u).await?)),
                None => None,
            };
            let app = Arc::new(actions::App {
                cfg,
                gh,
                pool,
                nats,
                http: reqwest::Client::new(),
            });
            let worker = tokio::spawn(actions::worker(app.clone()));
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            tracing::info!("listening on {listen}");
            tokio::select! {
                r = axum::serve(listener, actions::router(app)) => r?,
                r = worker => r??,
            }
            Ok(())
        }
        Cmd::Report => unreachable!(),
    }
}
