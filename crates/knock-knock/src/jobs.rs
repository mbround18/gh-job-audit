use crate::{
    config::Config,
    db,
    mail::{self, MailMsg},
};

type Js = async_nats::jetstream::Context;
use anyhow::Result;
use chrono::{Datelike, Utc};
use futures::{StreamExt, stream};
use gh_core::{Client, RepoStats, evaluate};
use sqlx::PgPool;

/// Run `f` only if we get the cluster-wide advisory lock, so two replicas never double-send.
pub(crate) async fn with_lock<F, Fut>(pool: &PgPool, id: i64, f: F) -> Result<()>
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

pub async fn daily(
    cfg: &Config,
    gh: &Client,
    pool: &PgPool,
    nats: Option<&Js>,
    force_send: bool,
) -> Result<()> {
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
        sqlx::query("UPDATE recommendations SET status='done' WHERE status='open' AND repo NOT LIKE 'selftest/%' AND last_seen < $1")
            .bind(run_start)
            .execute(pool)
            .await?;

        let due: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT id, repo, kind, reason FROM recommendations
             WHERE status='open' AND repo NOT LIKE 'selftest/%' AND (notified_at IS NULL OR notified_at < now() - make_interval(days => $1::int))
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
        mail::deliver(cfg, nats, MailMsg::new(format!("[knock-knock] {} GitHub repos need attention", due.len()), html, text)).await?;
        let ids: Vec<i64> = due.iter().map(|d| d.0).collect();
        sqlx::query("UPDATE recommendations SET notified_at=now() WHERE id = ANY($1)").bind(&ids).execute(pool).await?;
        Ok(())
    })
    .await
}

pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub const SELFTEST_REPO: &str = "selftest/sandbox";

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
                    ("archive", "Archive repo"),
                    ("disable_actions", "Turn off Actions"),
                    ("dismiss", "Keep as-is"),
                ],
                "disable_actions" => &[
                    ("disable_actions", "Turn off Actions"),
                    ("dismiss", "Keep as-is"),
                ],
                _ => &[("dismiss", "Got it, stop flagging")],
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
    let legend: [(&str, &str); 3] = [
        (
            "Archive repo",
            "makes the repo read-only on GitHub. Reversible any time in the repo's settings.",
        ),
        (
            "Turn off Actions",
            "stops all workflow runs on the repo. Re-enable in Settings > Actions.",
        ),
        (
            "Keep as-is",
            "changes nothing on GitHub and stops flagging that suggestion.",
        ),
    ];
    html += "</table>";
    if can_act {
        html += "<h4 style=\"margin-bottom:4px\">What the buttons do</h4><ul style=\"margin-top:0;font-size:13px\">";
        text += "\nWhat the buttons do:\n";
        for (name, what) in legend {
            html += &format!("<li><b>{name}</b>: {what}</li>");
            text += &format!("  {name}: {what}\n");
        }
        html += &format!(
            "</ul><p><small>Buttons are single-use, expire in {}h and require GitHub sign-in as {}. Nothing changes until you confirm on the next page.</small></p>",
            cfg.action_ttl_hours,
            esc(&cfg.owner)
        );
    }
    html += "</div>";
    Ok((html, text))
}

/// Email when this month's Actions usage first crosses each configured percentage.
pub async fn usage(
    cfg: &Config,
    gh_billing: &Client,
    pool: &PgPool,
    nats: Option<&Js>,
) -> Result<()> {
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
                let html = format!("<p>{}</p>", esc(&text).replace('\n', "<br>"));
                let msg = MailMsg::new(format!("[knock-knock] GitHub Actions at {pct:.0}% of monthly quota"), html, text)
                    .dedupe(format!("usage:{}:{p}", Utc::now().format("%Y-%m")));
                mail::deliver(cfg, nats, msg).await?;
                usage_breakdown(cfg, pool, nats, used, pct, p).await?;
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

/// Follow-up to a usage alert: where the minutes are going and where the month is headed.
async fn usage_breakdown(
    cfg: &Config,
    pool: &PgPool,
    nats: Option<&Js>,
    used: f64,
    pct: f64,
    p: f64,
) -> Result<()> {
    let now = Utc::now();
    let day = now.day() as f64;
    let days_in_month = (chrono::NaiveDate::from_ymd_opt(
        now.year() + (now.month() / 12) as i32,
        now.month() % 12 + 1,
        1,
    )
    .and_then(|d| d.pred_opt())
    .map(|d| d.day())
    .unwrap_or(30)) as f64;
    let projected = used / day * days_in_month;
    let proj_pct = projected / cfg.minutes_quota * 100.0;
    let top: Vec<(String, f64, i64, i64)> = sqlx::query_as(
        "SELECT repo, (stats->>'minutes_30d')::float8, COALESCE((stats->>'runs_30d')::bigint,0), COALESCE((stats->>'bot_runs_30d')::bigint,0)
         FROM (SELECT DISTINCT ON (repo) repo, stats FROM snapshots ORDER BY repo, taken_at DESC) s
         WHERE (stats->>'private')::bool AND (stats->>'minutes_30d')::float8 > 0
         ORDER BY 2 DESC LIMIT 10",
    )
    .fetch_all(pool)
    .await?;
    let colour = if pct >= 90.0 {
        "#dc2626"
    } else if pct >= 75.0 {
        "#ea580c"
    } else {
        "#ca8a04"
    };
    let bar = |v: f64, max: f64| {
        format!(
            "<div style=\"background:#e5e7eb;border-radius:4px;width:160px\"><div style=\"background:{colour};height:8px;border-radius:4px;width:{:.0}%\"></div></div>",
            (v / max * 100.0).clamp(1.0, 100.0)
        )
    };
    let max = top.first().map(|t| t.1).unwrap_or(1.0).max(1.0);
    let mut html = format!(
        "<h2>Actions usage breakdown</h2><p style=\"font-size:28px;margin:4px 0\"><b style=\"color:{colour}\">{pct:.0}%</b> <small>of {:.0} min used ({used:.0})</small></p>{}\
         <p>At this pace the month ends at <b>~{projected:.0} min ({proj_pct:.0}%)</b>{}.</p>\
         <h3>Heaviest private repos (30 days)</h3><table cellpadding=\"4\" style=\"border-collapse:collapse\"><tr><th align=\"left\">Repo</th><th></th><th align=\"right\">Min</th><th align=\"right\">Runs</th><th align=\"right\">Bot runs</th></tr>",
        cfg.minutes_quota,
        bar(used, cfg.minutes_quota),
        if proj_pct > 100.0 {
            " &mdash; <b>over quota</b>"
        } else {
            ""
        },
    );
    let mut text = format!(
        "Actions usage: {pct:.0}% ({used:.0}/{:.0} min). Projected month end ~{projected:.0} min ({proj_pct:.0}%).\n\nHeaviest private repos (30d):\n",
        cfg.minutes_quota
    );
    for (repo, m, runs, bots) in &top {
        html.push_str(&format!(
            "<tr><td><a href=\"https://github.com/{r}/actions\">{r}</a></td><td>{}</td><td align=\"right\">{m:.0}</td><td align=\"right\">{runs}</td><td align=\"right\">{bots}</td></tr>",
            bar(*m, max), r = esc(repo)
        ));
        text.push_str(&format!(
            "  {repo}: {m:.0} min, {runs} runs, {bots} bot runs\n"
        ));
    }
    html.push_str("</table><p><small>Cut it down: make private repos public or archive them, gate bot CI, cache dependencies, or disable workflows on dormant repos. The weekly report has one-click buttons for the last two.</small></p>");
    if top.is_empty() {
        html.push_str(
            "<p><small>No per-repo data yet; the next daily report will populate it.</small></p>",
        );
    }
    let key = format!("usage-report:{}:{p}", now.format("%Y-%m"));
    mail::deliver(
        cfg,
        nats,
        MailMsg::new(
            format!(
                "[knock-knock] Actions usage report: {pct:.0}% used, on track for {proj_pct:.0}%"
            ),
            html,
            text,
        )
        .dedupe(key),
    )
    .await
}

/// Email a sandbox item whose buttons exercise the whole click path (sign-in, CSRF, single-use
/// token, NATS publish, worker, result subject, action_log) without touching any real repo.
pub async fn selftest(cfg: &Config, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let rec_id: i64 = sqlx::query_scalar(
        "INSERT INTO recommendations (repo, kind, reason) VALUES ($1,'selftest','sandbox item for testing the email buttons')
         ON CONFLICT (repo, kind) DO UPDATE SET status='open', last_seen=now() RETURNING id",
    )
    .bind(SELFTEST_REPO)
    .fetch_one(pool)
    .await?;
    // Drop any tokens from a previous run so only this email's links work.
    sqlx::query("DELETE FROM action_tokens WHERE rec_id=$1")
        .bind(rec_id)
        .execute(pool)
        .await?;
    let buttons = [
        (
            "test_ping",
            "Ping (full NATS round trip)",
            "Should say Queued, then log ok=true.",
        ),
        (
            "test_archive",
            "Archive (dry run)",
            "Same path as the real archive button; no GitHub call is made.",
        ),
        (
            "test_disable_actions",
            "Turn off Actions (dry run)",
            "Same path as the real button; no GitHub call is made.",
        ),
        (
            "test_fail",
            "Fail on purpose",
            "Worker should log ok=false and keep running.",
        ),
    ];
    let (mut html, mut text) = (String::new(), String::new());
    for (action, label, note) in buttons {
        let url = mint(cfg, pool, rec_id, SELFTEST_REPO, action).await?;
        html.push_str(&format!(
            "<p><a href=\"{url}\" style=\"display:inline-block;padding:8px 14px;background:#374151;color:#fff;border-radius:6px;text-decoration:none\">{}</a><br><small>{}</small></p>",
            esc(label), esc(note)
        ));
        text.push_str(&format!("{label}: {url}\n  {note}\n"));
    }
    let html = format!(
        "<h2>gh-job-audit self-test</h2><p>Hello, are you there? These buttons only touch a sandbox item; nothing on your real repos changes. Each works once. Check <code>action_log</code> or the pod logs to see the results.</p>{html}"
    );
    mail::deliver(
        cfg,
        nats,
        MailMsg::new(
            "gh-job-audit self-test",
            html,
            format!(
                "Self-test

{text}"
            ),
        ),
    )
    .await
}

const ASSIGN_SUBJECT: &str = "knock.triage.assign";

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct AssignReq {
    repo: String,
    number: i64,
    assignees: Vec<String>,
}

/// Discover unassigned issues/PRs into `tracked_items`, plan who owns each (CODEOWNERS, else the
/// repo owner) once, then in `apply` mode hand a batch to the assigner over NATS. Progress lives in
/// the table, so a big backlog drains across runs without rescanning. `--report` emails a summary.
pub async fn triage(
    cfg: &Config,
    gh: &Client,
    pool: &PgPool,
    nats: Option<&Js>,
    do_assign: bool,
    do_report: bool,
) -> Result<()> {
    if cfg.triage_mode == "off" {
        tracing::info!("triage disabled (TRIAGE_MODE=off)");
        return Ok(());
    }
    with_lock(pool, 0x6b6b03, || async {
        use gh_core::triage::{default_owners, owners_for_paths};
        // 1. discover
        let (items, truncated) = gh.unassigned_items().await?;
        let started: chrono::DateTime<Utc> = Utc::now();
        let bots = items.iter().filter(|i| i.author_is_bot).count();
        for i in &items {
            sqlx::query(
                "INSERT INTO tracked_items (repo, number, kind, title, url, author, author_is_bot, unassigned, last_seen_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,true,now())
                 ON CONFLICT (repo, number) DO UPDATE SET title=$4, url=$5, author_is_bot=$7,
                   unassigned=true, last_seen_at=now()",
            )
            .bind(&i.repo).bind(i.number).bind(if i.is_pr { "pr" } else { "issue" })
            .bind(&i.title).bind(&i.url).bind(&i.author).bind(i.author_is_bot)
            .execute(pool)
            .await?;
        }
        if !truncated {
            // Anything we track as unassigned but the search no longer returns was assigned or closed.
            sqlx::query("UPDATE tracked_items SET unassigned=false WHERE unassigned AND last_seen_at < $1")
                .bind(started)
                .execute(pool)
                .await?;
        }
        // Unassignable items get another look after a week (permissions/CODEOWNERS may change).
        sqlx::query("UPDATE tracked_items SET plan_state='new' WHERE plan_state='unassignable' AND planned_at < now() - interval '7 days'")
            .execute(pool).await?;

        // 2. plan (only items never planned; resolved once, reused by later runs)
        let todo: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT repo, number, kind FROM tracked_items
             WHERE unassigned AND plan_state='new' AND ($1 OR NOT author_is_bot)
             ORDER BY first_seen_at LIMIT 200",
        )
        .bind(cfg.triage_include_bots)
        .fetch_all(pool)
        .await?;
        let mut rules = std::collections::HashMap::new();
        let mut can = std::collections::HashMap::<(String, String), bool>::new();
        for (repo, number, kind) in &todo {
            if !rules.contains_key(repo) {
                rules.insert(repo.clone(), gh.codeowners(repo).await?);
            }
            let r = &rules[repo];
            let mut owners = if kind == "pr" {
                owners_for_paths(r, &gh.pr_files(repo, *number).await?)
            } else {
                default_owners(r)
            };
            let source = if owners.is_empty() { "repo owner" } else { "CODEOWNERS" };
            if owners.is_empty() {
                owners.push(cfg.owner.clone());
            }
            let mut ok = Vec::new();
            for o in owners {
                let k = (repo.clone(), o.to_ascii_lowercase());
                if !can.contains_key(&k) {
                    can.insert(k.clone(), gh.can_assign(repo, &o).await?);
                }
                if can[&k] {
                    ok.push(o);
                }
            }
            let (state, who) = if ok.is_empty() { ("unassignable", None) } else { ("planned", Some(ok.join(","))) };
            sqlx::query("UPDATE tracked_items SET plan_state=$3, planned_assignees=$4, plan_source=$5, planned_at=now() WHERE repo=$1 AND number=$2")
                .bind(repo).bind(number).bind(state).bind(who).bind(source)
                .execute(pool).await?;
        }
        let (planned, unassignable): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE plan_state='planned'), count(*) FILTER (WHERE plan_state='unassignable')
             FROM tracked_items WHERE unassigned",
        )
        .fetch_one(pool)
        .await?;
        tracing::info!(
            "triage: {} unassigned ({bots} bot-authored{}), {planned} planned, {unassignable} unassignable, {} newly planned this run",
            items.len(),
            if cfg.triage_include_bots { "" } else { ", skipped" },
            todo.len()
        );
        let apply = cfg.triage_mode == "apply";

        // 3. assign one batch (a retry cooldown keeps failing items from being re-queued every run)
        if do_assign {
            let batch: Vec<(String, i64, String)> = sqlx::query_as(
                "SELECT repo, number, planned_assignees FROM tracked_items
                 WHERE unassigned AND plan_state='planned'
                   AND (last_attempt_at IS NULL OR last_attempt_at < now() - interval '6 hours')
                 ORDER BY first_seen_at LIMIT $1",
            )
            .bind(cfg.triage_max as i64)
            .fetch_all(pool)
            .await?;
            if apply {
                for (repo, number, who) in &batch {
                    sqlx::query("UPDATE tracked_items SET last_attempt_at=now() WHERE repo=$1 AND number=$2")
                        .bind(repo).bind(number).execute(pool).await?;
                    let req = AssignReq {
                        repo: repo.clone(),
                        number: *number,
                        assignees: who.split(',').map(String::from).collect(),
                    };
                    match nats {
                        Some(js) => {
                            js.publish(ASSIGN_SUBJECT, serde_json::to_vec(&req)?.into()).await?.await?;
                        }
                        None => assign_one(gh, pool, &req).await?,
                    }
                }
                tracing::info!("triage: queued {} of {planned} planned assignments", batch.len());
            } else {
                tracing::info!("triage: dry run, would assign {} of {planned} (TRIAGE_MODE={})", batch.len(), cfg.triage_mode);
            }
        }
        if !do_report {
            return Ok(());
        }

        // 4. weekly report from the table
        let pending: Vec<(String, i64, String, String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT repo, number, kind, title, url, author, planned_assignees, plan_source FROM tracked_items
             WHERE unassigned AND ($1 OR NOT author_is_bot) ORDER BY first_seen_at LIMIT 100",
        )
        .bind(cfg.triage_include_bots)
        .fetch_all(pool)
        .await?;
        let done: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT repo, number, assignees FROM assignments WHERE ok AND at > now() - interval '7 days' ORDER BY at",
        )
        .fetch_all(pool)
        .await?;
        let verb = if apply { "Still waiting to be assigned" } else { "Unassigned, would assign (dry run)" };
        let mut html = format!("<h2>{} unassigned items</h2><p>{verb}. {bots} bot-authored items are {}.</p><ul>", pending.len(), if cfg.triage_include_bots { "included" } else { "skipped" });
        let mut text = format!("{} unassigned items: {verb}\n\n", pending.len());
        for (repo, number, kind, title, url, _author, who, source) in &pending {
            let who = who.clone().map(|w| w.split(',').map(|a| format!("@{a}")).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "no assignable owner".into());
            let source = source.clone().unwrap_or_default();
            html.push_str(&format!(
                "<li><a href=\"{}\">{}#{number}</a> {} <small>({kind})</small> &rarr; {} <small>via {}</small></li>",
                esc(url), esc(repo), esc(title), esc(&who), esc(&source)
            ));
            text.push_str(&format!("{repo}#{number} {title} -> {who} ({source})\n"));
        }
        html.push_str(&format!("</ul><p>Assigned automatically in the last 7 days: {}.</p>", done.len()));
        for (r, n, a) in done.iter().take(50) {
            text.push_str(&format!("assigned {r}#{n} -> {a}\n"));
        }
        let key = format!("triage-report:{}", Utc::now().format("%G-W%V"));
        mail::deliver(cfg, nats, MailMsg::new(format!("[knock-knock] weekly triage: {} unassigned", pending.len()), html, text).dedupe(key)).await
    })
    .await
}

/// One consolidated email of open issues/PRs (not by you or a bot) with no activity for
/// `STALE_DAYS`. "Activity" is GitHub's `updated_at`, so this is an approximation of "you haven't
/// responded". Each item is re-emailed at most every `STALE_RENOTIFY_DAYS`, and skipped while snoozed.
pub async fn stale(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    with_lock(pool, 0x6b6b04, || async {
        let started = Utc::now();
        let cutoff = (started - chrono::Duration::days(cfg.stale_days)).format("%Y-%m-%d").to_string();
        let (items, truncated) = gh.stale_items(&cutoff).await?;
        let mut kept = 0;
        for i in items.iter().filter(|i| !i.author_is_bot && !i.author.eq_ignore_ascii_case(&cfg.owner)) {
            kept += 1;
            sqlx::query(
                "INSERT INTO tracked_items (repo, number, kind, title, url, author, author_is_bot, stale, last_activity_at, first_flagged_at, last_seen_at)
                 VALUES ($1,$2,$3,$4,$5,$6,false,true,$7::timestamptz,now(),now())
                 ON CONFLICT (repo, number) DO UPDATE SET title=$4, url=$5, stale=true, last_seen_at=now(),
                   first_flagged_at=COALESCE(tracked_items.first_flagged_at, now()),
                   -- new activity resets the email cooldown
                   last_emailed_at = CASE WHEN tracked_items.last_activity_at IS DISTINCT FROM $7::timestamptz THEN NULL ELSE tracked_items.last_emailed_at END,
                   last_activity_at=$7::timestamptz",
            )
            .bind(&i.repo).bind(i.number).bind(if i.is_pr { "pr" } else { "issue" })
            .bind(&i.title).bind(&i.url).bind(&i.author).bind(&i.updated_at)
            .execute(pool)
            .await?;
        }
        if !truncated {
            sqlx::query("UPDATE tracked_items SET stale=false WHERE stale AND last_seen_at < $1")
                .bind(started)
                .execute(pool)
                .await?;
        }
        let due: Vec<(String, i64, String, String, String, String, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT repo, number, kind, title, url, author, last_activity_at FROM tracked_items
             WHERE stale AND (snoozed_until IS NULL OR snoozed_until < now())
               AND (last_emailed_at IS NULL OR last_emailed_at < now() - make_interval(days => $1::int))
             ORDER BY last_activity_at LIMIT 100",
        )
        .bind(cfg.stale_renotify_days as i32)
        .fetch_all(pool)
        .await?;
        tracing::info!("stale: {kept} items idle >{}d, {} due for the digest", cfg.stale_days, due.len());
        if due.is_empty() {
            return Ok(());
        }
        let mut html = format!("<h2>{} open items idle for {}+ days</h2><ul>", due.len(), cfg.stale_days);
        let mut text = format!("{} open items idle for {}+ days\n\n", due.len(), cfg.stale_days);
        for (repo, number, kind, title, url, author, at) in &due {
            let days = (started - *at).num_days();
            html.push_str(&format!(
                "<li><a href=\"{}\">{}#{number}</a> {} <small>({kind} by {}, idle {days}d)</small></li>",
                esc(url), esc(repo), esc(title), esc(author)
            ));
            text.push_str(&format!("{repo}#{number} {title} ({kind} by {author}, idle {days}d)\n{url}\n"));
        }
        html.push_str("</ul>");
        let key = format!("stale:{}", started.format("%G-W%V"));
        mail::deliver(cfg, nats, MailMsg::new(format!("[knock-knock] {} stale issues/PRs", due.len()), html, text).dedupe(key)).await?;
        for (repo, number, ..) in &due {
            sqlx::query("UPDATE tracked_items SET last_emailed_at=now() WHERE repo=$1 AND number=$2")
                .bind(repo).bind(number).execute(pool).await?;
        }
        Ok(())
    })
    .await
}

async fn assign_one(gh: &Client, pool: &PgPool, req: &AssignReq) -> Result<()> {
    let res = gh.assign(&req.repo, req.number, &req.assignees).await;
    sqlx::query(
        "INSERT INTO assignments (repo, number, assignees, ok, detail) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(&req.repo)
    .bind(req.number)
    .bind(req.assignees.join(","))
    .bind(res.is_ok())
    .bind(res.as_ref().err().map(|e| format!("{e:#}")))
    .execute(pool)
    .await?;
    if res.is_ok() {
        sqlx::query("UPDATE tracked_items SET unassigned=false WHERE repo=$1 AND number=$2")
            .bind(&req.repo)
            .bind(req.number)
            .execute(pool)
            .await?;
    }
    res
}

/// Consumes `knock.triage.assign` and performs the assignments (runs inside `serve`).
pub async fn assigner(gh: Client, pool: PgPool, js: Js) -> Result<()> {
    use async_nats::jetstream::{AckKind, consumer::pull};
    use futures::StreamExt;
    let stream = js
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: crate::actions::STREAM.into(),
            subjects: vec!["knock.>".into()],
            max_age: std::time::Duration::from_secs(7 * 86400),
            ..Default::default()
        })
        .await?;
    let consumer = stream
        .get_or_create_consumer(
            "assigner",
            pull::Config {
                durable_name: Some("assigner".into()),
                filter_subject: ASSIGN_SUBJECT.into(),
                max_deliver: 3,
                ..Default::default()
            },
        )
        .await?;
    let mut msgs = consumer.messages().await?;
    while let Some(m) = msgs.next().await {
        let m = m?;
        match serde_json::from_slice::<AssignReq>(&m.payload) {
            Ok(req) => match assign_one(&gh, &pool, &req).await {
                Ok(()) => {
                    tracing::info!(
                        "assigned {} to {}#{}",
                        req.assignees.join(","),
                        req.repo,
                        req.number
                    );
                    let _ = m.ack().await;
                }
                Err(e) => {
                    tracing::warn!("assign {}#{} failed: {e:#}", req.repo, req.number);
                    let _ = m
                        .ack_with(AckKind::Nak(Some(std::time::Duration::from_secs(60))))
                        .await;
                }
            },
            Err(_) => {
                let _ = m.ack_with(AckKind::Term).await;
            }
        }
    }
    Ok(())
}
