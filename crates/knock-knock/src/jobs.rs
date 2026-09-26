use crate::{config::Config, db, mail};
use anyhow::Result;
use chrono::{Datelike, Utc};
use futures::{StreamExt, stream};
use gh_core::{Client, RepoStats, evaluate};
use sqlx::PgPool;

/// Run `f` only if we get the cluster-wide advisory lock, so two replicas never double-send.
async fn with_lock<F, Fut>(pool: &PgPool, id: i64, f: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut conn = pool.acquire().await?;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    if !got {
        tracing::info!("another instance holds job lock {id}; skipping");
        return Ok(());
    }
    let r = f().await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(id)
        .execute(&mut *conn)
        .await;
    r
}

pub async fn daily(cfg: &Config, gh: &Client, pool: &PgPool, force_send: bool) -> Result<()> {
    with_lock(pool, 0x6b6b01, || async {
        let repos = gh.list_repos().await?;
        tracing::info!("auditing {} repos", repos.len());
        let stats: Vec<RepoStats> = stream::iter(repos)
            .map(|r| async move {
                match gh.repo_stats(&r).await {
                    Ok(s) => Some(s),
                    Err(e) => {
                        tracing::warn!("stats for {}: {e:#}", r["full_name"]);
                        None
                    }
                }
            })
            .buffer_unordered(4)
            .filter_map(|x| async move { x })
            .collect()
            .await;

        for s in &stats {
            sqlx::query("INSERT INTO snapshots (repo, stats) VALUES ($1, $2)")
                .bind(&s.full_name)
                .bind(serde_json::to_value(s)?)
                .execute(pool)
                .await?;
        }

        let recs = evaluate(&stats, &cfg.thresholds, Utc::now());
        // Anything open that stops tripping a threshold has resolved itself.
        let run_start = Utc::now();
        for r in &recs {
            sqlx::query(
                "INSERT INTO recommendations (repo, kind, reason) VALUES ($1,$2,$3)
                 ON CONFLICT (repo, kind) DO UPDATE SET reason=EXCLUDED.reason, last_seen=now(),
                 status = CASE WHEN recommendations.status='done' THEN 'open' ELSE recommendations.status END",
            )
            .bind(&r.repo)
            .bind(r.kind.as_str())
            .bind(&r.reason)
            .execute(pool)
            .await?;
        }
        sqlx::query("UPDATE recommendations SET status='done' WHERE status='open' AND last_seen < $1")
            .bind(run_start)
            .execute(pool)
            .await?;

        let due: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT id, repo, kind, reason FROM recommendations
             WHERE status='open' AND (notified_at IS NULL OR notified_at < now() - make_interval(days => $1::int))
             ORDER BY kind, repo",
        )
        .bind(cfg.renotify_days as i32)
        .fetch_all(pool)
        .await?;

        if due.len() < cfg.report_min_items && !force_send {
            tracing::info!("{} due recommendations < REPORT_MIN_ITEMS={}; no report", due.len(), cfg.report_min_items);
            return Ok(());
        }
        if due.is_empty() {
            return Ok(());
        }
        let total_min: f64 = stats.iter().map(|s| s.minutes_30d).sum();
        let (html, text) = render_report(cfg, pool, &due, stats.len(), total_min).await?;
        mail::send(cfg, &format!("[knock-knock] {} GitHub repos need attention", due.len()), &html, &text).await?;
        let ids: Vec<i64> = due.iter().map(|d| d.0).collect();
        sqlx::query("UPDATE recommendations SET notified_at=now() WHERE id = ANY($1)").bind(&ids).execute(pool).await?;
        Ok(())
    })
    .await
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn mint(
    cfg: &Config,
    pool: &PgPool,
    rec_id: i64,
    repo: &str,
    action: &str,
) -> Result<String> {
    let token = db::new_token();
    sqlx::query(
        "INSERT INTO action_tokens (token_hash, rec_id, action, repo, expires_at)
         VALUES ($1,$2,$3,$4, now() + make_interval(hours => $5::int))",
    )
    .bind(db::hash_token(&token))
    .bind(rec_id)
    .bind(action)
    .bind(repo)
    .bind(cfg.action_ttl_hours as i32)
    .execute(pool)
    .await?;
    Ok(format!("{}/a/{}", cfg.base_url, token))
}

async fn render_report(
    cfg: &Config,
    pool: &PgPool,
    due: &[(i64, String, String, String)],
    repos: usize,
    total_min: f64,
) -> Result<(String, String)> {
    let can_act = cfg.session_secret.is_some() && cfg.oauth_client_id.is_some();
    let mut html = format!(
        "<div style=\"font-family:sans-serif;max-width:760px\"><h2>GitHub audit for {}</h2>\
         <p>{repos} repos scanned, ~{total_min:.0} Actions minutes in the last 30 days.</p>\
         <table cellpadding=\"6\" style=\"border-collapse:collapse;width:100%\">",
        esc(&cfg.owner)
    );
    let mut text = format!(
        "GitHub audit for {}: {repos} repos, ~{total_min:.0} min/30d\n\n",
        cfg.owner
    );
    for (id, repo, kind, reason) in due {
        html += &format!(
            "<tr style=\"border-top:1px solid #ddd\"><td><b><a href=\"https://github.com/{r}\">{r}</a></b><br>\
             <small>{k}: {why}</small></td><td align=\"right\" style=\"white-space:nowrap\">",
            r = esc(repo),
            k = esc(kind),
            why = esc(reason)
        );
        text += &format!("- {repo} [{kind}] {reason}\n");
        if can_act {
            let acts: &[(&str, &str)] = match kind.as_str() {
                "archive" => &[
                    ("archive", "Archive"),
                    ("disable_actions", "Disable CI"),
                    ("dismiss", "Dismiss"),
                ],
                "disable_actions" => &[("disable_actions", "Disable CI"), ("dismiss", "Dismiss")],
                _ => &[("dismiss", "Dismiss")],
            };
            for (a, label) in acts {
                let url = mint(cfg, pool, *id, repo, a).await?;
                let color = if *a == "dismiss" {
                    "#6b7280"
                } else {
                    "#b91c1c"
                };
                html += &format!(
                    "<a href=\"{url}\" style=\"background:{color};color:#fff;padding:6px 10px;border-radius:5px;\
                     text-decoration:none;margin-left:4px;font-size:13px\">{label}</a>"
                );
                text += &format!("    {label}: {url}\n");
            }
        }
        html += "</td></tr>";
    }
    html += "</table><p><small>Buttons are single-use, expire in ";
    html += &format!(
        "{}h and require GitHub sign-in as {}.</small></p></div>",
        cfg.action_ttl_hours,
        esc(&cfg.owner)
    );
    Ok((html, text))
}

/// Email when this month's Actions usage first crosses each configured percentage.
pub async fn usage(cfg: &Config, gh_billing: &Client, pool: &PgPool) -> Result<()> {
    with_lock(pool, 0x6b6b02, || async {
        let (used, source) = match gh_billing.actions_minutes().await {
            Ok(Some(m)) => (m, "GitHub billing API"),
            other => {
                if let Err(e) = other {
                    tracing::warn!("billing API failed: {e:#}");
                }
                // Estimate from the newest snapshot of each private repo (public repos are free).
                let m: Option<f64> = sqlx::query_scalar(
                    "SELECT COALESCE(SUM((s.stats->>'minutes_30d')::float8),0) FROM
                     (SELECT DISTINCT ON (repo) stats FROM snapshots ORDER BY repo, taken_at DESC) s
                     WHERE (s.stats->>'private')::bool",
                )
                .fetch_one(pool)
                .await?;
                (m.unwrap_or(0.0), "estimate from private-repo run history (no billing scope on token)")
            }
        };
        let pct = used / cfg.minutes_quota * 100.0;
        tracing::info!("usage {used:.0}/{:.0} min = {pct:.1}% ({source})", cfg.minutes_quota);
        let now = Utc::now();
        let mut pcts = cfg.usage_alert_pcts.clone();
        pcts.sort_by(|a, b| b.partial_cmp(a).unwrap());
        // Highest crossed threshold not yet alerted this month.
        for p in pcts.into_iter().filter(|p| pct >= *p) {
            let key = format!("usage:{}-{:02}:{p}", now.year(), now.month());
            let fresh = sqlx::query("INSERT INTO alerts (key, detail) VALUES ($1,$2) ON CONFLICT DO NOTHING")
                .bind(&key)
                .bind(serde_json::json!({"used": used, "pct": pct}))
                .execute(pool)
                .await?
                .rows_affected()
                > 0;
            if fresh {
                let text = format!(
                    "You have used {used:.0} of {:.0} GitHub Actions minutes this month ({pct:.0}%).\nSource: {source}.",
                    cfg.minutes_quota
                );
                mail::send(cfg, &format!("[knock-knock] GitHub Actions at {pct:.0}% of monthly quota"), &format!("<p>{}</p>", esc(&text).replace('\n', "<br>")), &text).await?;
                // Mark lower thresholds as covered so we send one mail, not three.
                for q in &cfg.usage_alert_pcts {
                    if *q < p {
                        let k = format!("usage:{}-{:02}:{q}", now.year(), now.month());
                        sqlx::query("INSERT INTO alerts (key) VALUES ($1) ON CONFLICT DO NOTHING").bind(k).execute(pool).await?;
                    }
                }
                break;
            }
        }
        Ok(())
    })
    .await
}
