//! Governance jobs: read-only GitHub API sweeps that store findings; `rollup` emails one digest.
#![allow(unused_variables)]
//! They cost no Actions minutes; the only budget is the API rate limit, so each job walks repos
//! with low concurrency and the chart staggers their schedules.
use crate::{
    config::Config,
    jobs::{esc, with_lock},
    mail::{self, MailMsg},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use futures::{StreamExt, stream};
use gh_core::Client;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

type Js = async_nats::jetstream::Context;

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum GovJob {
    Security,
    Hygiene,
    Access,
    Workflows,
    Storage,
    Deps,
    Releases,
    Branches,
    Prflow,
    Rollup,
}

pub async fn run(
    job: GovJob,
    cfg: &Config,
    gh: &Client,
    pool: &PgPool,
    nats: Option<&Js>,
) -> Result<()> {
    let lock = 0x6b6b10 + job as i64;
    with_lock(pool, lock, || async {
        match job {
            GovJob::Security => security(cfg, gh, pool, nats).await,
            GovJob::Hygiene => hygiene(cfg, gh, pool, nats).await,
            GovJob::Access => access(cfg, gh, pool, nats).await,
            GovJob::Workflows => workflows(cfg, gh, pool, nats).await,
            GovJob::Storage => storage(cfg, gh, pool, nats).await,
            GovJob::Deps => deps(cfg, gh, pool, nats).await,
            GovJob::Releases => releases(cfg, gh, pool, nats).await,
            GovJob::Branches => branches(cfg, gh, pool, nats).await,
            GovJob::Prflow => prflow(cfg, gh, pool, nats).await,
            GovJob::Rollup => rollup(cfg, gh, pool, nats).await,
        }
    })
    .await
}

// ---------- plumbing ----------

fn envn<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Finding {
    kind: &'static str,
    sev: u8,
    label: String,
    url: String,
    detail: String,
}

fn finding(
    kind: &'static str,
    sev: u8,
    label: impl Into<String>,
    url: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        kind,
        sev,
        label: label.into(),
        url: url.into(),
        detail: detail.into(),
    }
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" | "error" => 3,
        "medium" | "moderate" | "warning" => 2,
        _ => 1,
    }
}

fn age_days(ts: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| (Utc::now() - t.with_timezone(&Utc)).num_days())
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// Non-archived, non-fork repos.
async fn repos(gh: &Client) -> Result<Vec<Value>> {
    let mut r = gh.list_repos().await?;
    r.retain(|x| {
        !x["archived"].as_bool().unwrap_or(false) && !x["fork"].as_bool().unwrap_or(false)
    });
    Ok(r)
}

/// Run `f` for every repo, three at a time; a repo that errors is logged and skipped.
async fn sweep<F, Fut>(repos: Vec<Value>, f: F) -> Vec<Finding>
where
    F: Fn(Value) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<Finding>>>,
{
    stream::iter(repos)
        .map(|r| {
            let name = s(&r["full_name"]).to_string();
            let fut = f(r);
            async move {
                match fut.await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("{name}: {e:#}");
                        vec![]
                    }
                }
            }
        })
        .buffer_unordered(3)
        .flat_map(stream::iter)
        .collect()
        .await
}

async fn metric(pool: &PgPool, job: &str, key: &str, v: f64) -> Result<()> {
    sqlx::query("INSERT INTO gov_metrics (job, key, value) VALUES ($1,$2,$3)")
        .bind(job)
        .bind(key)
        .bind(v)
        .execute(pool)
        .await?;
    Ok(())
}

/// Latest value from at least 4 days ago, for week-over-week comparison.
async fn prev_metric(pool: &PgPool, job: &str, key: &str) -> Result<Option<f64>> {
    Ok(sqlx::query_scalar(
        "SELECT value FROM gov_metrics WHERE job=$1 AND key=$2 AND at < now() - interval '4 days' ORDER BY at DESC LIMIT 1",
    )
    .bind(job).bind(key).fetch_optional(pool).await?)
}

/// Persist this run's findings (replacing the job's previous set) and per-kind counts. Nothing is
/// emailed here; the Monday `rollup` composes every job's latest findings into one digest.
async fn finish(pool: &PgPool, job: &str, intro: &str, mut found: Vec<Finding>) -> Result<()> {
    found.sort_by(|a, b| b.sev.cmp(&a.sev).then(a.label.cmp(&b.label)));
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM gov_findings WHERE job=$1")
        .bind(job)
        .execute(&mut *tx)
        .await?;
    for f in &found {
        sqlx::query(
            "INSERT INTO gov_findings (job,kind,sev,label,url,detail) VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(job)
        .bind(f.kind)
        .bind(f.sev as i16)
        .bind(&f.label)
        .bind(&f.url)
        .bind(&f.detail)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("INSERT INTO gov_notes (job,note) VALUES ($1,$2) ON CONFLICT (job) DO UPDATE SET note=$2, at=now()")
        .bind(job).bind(intro).execute(&mut *tx).await?;
    tx.commit().await?;
    for (kind, _, _, _, _) in KINDS.iter().filter(|k| k.0 != "") {
        let n = found.iter().filter(|f| f.kind == *kind).count();
        // Only record kinds this job can produce, so other jobs' metrics are not zero-filled.
        if found.iter().any(|f| f.kind == *kind) || KINDS.iter().any(|k| k.0 == *kind && k.4 == job)
        {
            metric(pool, job, kind, n as f64).await?;
        }
    }
    tracing::info!("{job}: {} findings stored", found.len());
    Ok(())
}

/// kind -> (kind, group, title, note, job). Order is the order sections appear in the digest.
const KINDS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "secret",
        "Security",
        "Exposed secrets",
        "Rotate the credential first, then resolve the alert.",
        "security",
    ),
    (
        "dependabot",
        "Security",
        "Dependabot alerts",
        "Open vulnerable dependencies, worst first.",
        "security",
    ),
    (
        "code",
        "Security",
        "Code scanning alerts",
        "Open code scanning results.",
        "security",
    ),
    (
        "keys",
        "Access",
        "Old deploy keys",
        "Deploy keys past the age threshold.",
        "access",
    ),
    (
        "outside",
        "Access",
        "Outside collaborators",
        "People with repo access who are not org/owner members.",
        "access",
    ),
    (
        "unprotected",
        "Repo hygiene",
        "Unprotected default branch",
        "No branch protection on an active repo.",
        "hygiene",
    ),
    (
        "alerts_off",
        "Repo hygiene",
        "Dependabot alerts disabled",
        "Turn on vulnerability alerts.",
        "hygiene",
    ),
    (
        "security_md",
        "Repo hygiene",
        "Missing SECURITY.md",
        "No vulnerability reporting policy.",
        "hygiene",
    ),
    (
        "codeowners",
        "Repo hygiene",
        "Missing CODEOWNERS",
        "Reviews and auto-assign have no owner to use.",
        "hygiene",
    ),
    (
        "license",
        "Repo hygiene",
        "Missing license",
        "No license file detected.",
        "hygiene",
    ),
    (
        "surge",
        "Workflows",
        "Minutes surge",
        "Actions minutes up sharply versus last week.",
        "workflows",
    ),
    (
        "failing",
        "Workflows",
        "Failing workflows",
        "Mostly failing over the last 30 days.",
        "workflows",
    ),
    (
        "reruns",
        "Workflows",
        "Re-run churn",
        "Workflows re-run many times.",
        "workflows",
    ),
    (
        "idle",
        "Workflows",
        "Idle workflows",
        "Enabled but no runs for a long time.",
        "workflows",
    ),
    (
        "cache",
        "Storage",
        "Large Actions caches",
        "Caches over the size threshold.",
        "storage",
    ),
    (
        "artifacts",
        "Storage",
        "Large artifacts",
        "Artifacts over the size threshold.",
        "storage",
    ),
    (
        "stale_bot",
        "Maintenance",
        "Stale bot PRs",
        "Dependency PRs open longer than the threshold.",
        "deps",
    ),
    (
        "unreleased",
        "Maintenance",
        "Unreleased commits",
        "Repos well ahead of their latest release.",
        "releases",
    ),
    (
        "merged",
        "Maintenance",
        "Merged branches to delete",
        "Branches already merged into the default branch.",
        "branches",
    ),
    (
        "stale",
        "Maintenance",
        "Stale branches",
        "No commits for a long time.",
        "branches",
    ),
    (
        "waiting",
        "PR flow",
        "PRs waiting for review",
        "Open human PRs with no review yet.",
        "prflow",
    ),
    (
        "slow",
        "PR flow",
        "Slow merges",
        "PRs that took longest to merge.",
        "prflow",
    ),
];

fn tone_for(sev: u8) -> &'static str {
    match sev {
        4 => "critical",
        3 => "high",
        2 => "medium",
        _ => "low",
    }
}

fn week() -> String {
    Utc::now().format("%G-W%V").to_string()
}

fn enc(b: &str) -> String {
    b.replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('?', "%3F")
}

// ---------- 1. security alerts ----------

async fn security(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let na = AtomicUsize::new(0);
    let na = &na;
    let found = sweep(repos(gh).await?, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let mut out = vec![];
        match gh
            .paged(
                &format!("/repos/{full}/dependabot/alerts?state=open"),
                None,
                3,
            )
            .await?
        {
            None => {
                na.fetch_add(1, Ordering::Relaxed);
            }
            Some(a) => {
                for x in a {
                    let sev = s(&x["security_advisory"]["severity"]);
                    out.push(finding(
                        "dependabot",
                        sev_rank(sev),
                        &full,
                        s(&x["html_url"]),
                        format!(
                            "{sev}: {} ({})",
                            s(&x["security_advisory"]["summary"]),
                            s(&x["dependency"]["package"]["name"])
                        ),
                    ));
                }
            }
        }
        if let Some(a) = gh
            .paged(
                &format!("/repos/{full}/code-scanning/alerts?state=open"),
                None,
                3,
            )
            .await?
        {
            for x in a {
                let sev = x["rule"]["security_severity_level"]
                    .as_str()
                    .unwrap_or_else(|| s(&x["rule"]["severity"]));
                out.push(finding(
                    "code",
                    sev_rank(sev),
                    &full,
                    s(&x["html_url"]),
                    format!("{sev}: {}", s(&x["rule"]["description"])),
                ));
            }
        }
        if let Some(a) = gh
            .paged(
                &format!("/repos/{full}/secret-scanning/alerts?state=open"),
                None,
                3,
            )
            .await?
        {
            for x in a {
                out.push(finding(
                    "secret",
                    9,
                    &full,
                    s(&x["html_url"]),
                    format!("exposed {}", s(&x["secret_type_display_name"])),
                ));
            }
        }
        Ok(out)
    })
    .await;

    // Exposed secrets are urgent: email as soon as a new set appears, not with the weekly digest.
    let mut urls: Vec<&str> = found
        .iter()
        .filter(|f| f.kind == "secret")
        .map(|f| f.url.as_str())
        .collect();
    if !urls.is_empty() {
        urls.sort();
        use sha2::{Digest, Sha256};
        let key = format!(
            "gov-secret:{}",
            hex::encode(Sha256::digest(urls.join(",").as_bytes()))
        );
        let (mut html, mut text) = (
            String::from("<h2>Exposed secrets</h2><ul>"),
            String::from("Exposed secrets\n"),
        );
        for f in found.iter().filter(|f| f.kind == "secret") {
            html.push_str(&format!(
                "<li><a href=\"{}\">{}</a> {}</li>",
                esc(&f.url),
                esc(&f.label),
                esc(&f.detail)
            ));
            text.push_str(&format!("- {} {} {}\n", f.label, f.detail, f.url));
        }
        html.push_str("</ul><p>Rotate the credential first, then resolve the alert.</p>");
        mail::deliver(
            cfg,
            nats,
            MailMsg::new(
                format!("[gh-job-audit] URGENT: {} exposed secret(s)", urls.len()),
                html,
                text,
            )
            .dedupe(key),
        )
        .await?;
    }
    let unavailable = na.load(Ordering::Relaxed);
    let intro = format!(
        "Open security alerts across your repos, worst first.{}",
        if unavailable > 0 {
            format!(
                " {unavailable} repos returned no Dependabot data (feature off or the App lacks Dependabot alerts read)."
            )
        } else {
            String::new()
        }
    );
    // Weekly digest; the daily run only re-sends if this week's digest has not gone out.
    finish(pool, "security", &intro, found).await
}

// ---------- 2. repo hygiene drift ----------

async fn hygiene(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let mut rs = repos(gh).await?;
    // Only repos touched in the last year; dormant ones are the archive report's business.
    rs.retain(|r| age_days(s(&r["pushed_at"])).is_some_and(|d| d < 365));
    let found = sweep(rs, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let def = s(&r["default_branch"]).to_string();
        let url = s(&r["html_url"]).to_string();
        let private = r["private"].as_bool().unwrap_or(false);
        let mut out = vec![];
        let rules = gh
            .json_opt(&format!("/repos/{full}/rules/branches/{}", enc(&def)))
            .await?;
        let ruled = rules
            .as_ref()
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
        // Classic protection is only knowable on public repos (private is plan-gated).
        if !private
            && !ruled
            && gh
                .json_opt(&format!("/repos/{full}/branches/{}/protection", enc(&def)))
                .await?
                .is_none()
        {
            out.push(finding(
                "unprotected",
                3,
                &full,
                format!("{url}/settings/rules"),
                format!("no ruleset or branch protection on {def}"),
            ));
        }
        if r["license"].is_null() && !private {
            out.push(finding(
                "license",
                1,
                &full,
                &url,
                "public repo without a license",
            ));
        }
        let sec = gh
            .json_opt(&format!("/repos/{full}/contents/SECURITY.md"))
            .await?
            .is_some()
            || gh
                .json_opt(&format!("/repos/{full}/contents/.github/SECURITY.md"))
                .await?
                .is_some();
        if !sec && !private {
            out.push(finding(
                "security_md",
                1,
                &full,
                format!("{url}/security/policy"),
                "no SECURITY.md",
            ));
        }
        if gh.codeowners(&full).await?.is_empty() {
            out.push(finding(
                "codeowners",
                1,
                &full,
                &url,
                "no CODEOWNERS with individual owners (triage falls back to the repo owner)",
            ));
        }
        if gh
            .status(&format!("/repos/{full}/vulnerability-alerts"))
            .await?
            == 404
        {
            out.push(finding(
                "alerts_off",
                3,
                &full,
                format!("{url}/settings/security_analysis"),
                "Dependabot alerts are disabled",
            ));
        }
        Ok(out)
    })
    .await;
    finish(
        pool,
        "hygiene",
        "Active repos (pushed in the last year) that are missing baseline settings.",
        found,
    )
    .await
}

// ---------- 3. access review ----------

async fn access(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let max_age: i64 = envn("GOV_KEY_MAX_AGE_DAYS", 365);
    let found = sweep(repos(gh).await?, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let url = s(&r["html_url"]).to_string();
        let mut out = vec![];
        for k in gh
            .paged(&format!("/repos/{full}/keys"), None, 1)
            .await?
            .unwrap_or_default()
        {
            let title = s(&k["title"]);
            let age = age_days(s(&k["created_at"])).unwrap_or(0);
            let write = !k["read_only"].as_bool().unwrap_or(true);
            let unused = k["last_used"].is_null();
            if write || age > max_age || unused {
                let mut why = vec![];
                if write {
                    why.push("WRITE access".to_string());
                }
                if age > max_age {
                    why.push(format!("{age}d old"));
                }
                if unused {
                    why.push("never used".into());
                }
                out.push(finding(
                    "keys",
                    if write { 3 } else { 2 },
                    &full,
                    format!("{url}/settings/keys"),
                    format!("deploy key \"{title}\": {}", why.join(", ")),
                ));
            }
        }
        for c in gh
            .paged(
                &format!("/repos/{full}/collaborators?affiliation=outside"),
                None,
                1,
            )
            .await?
            .unwrap_or_default()
        {
            let role = c["role_name"].as_str().unwrap_or("?");
            out.push(finding(
                "outside",
                if role == "admin" { 3 } else { 2 },
                &full,
                format!("{url}/settings/access"),
                format!("outside collaborator @{} ({role})", s(&c["login"])),
            ));
        }
        Ok(out)
    })
    .await;
    let intro = "Access to review. Needs the App's Administration (read) permission; personal tokens and SSH keys are not visible to a GitHub App.";
    finish(pool, "access", intro, found).await
}

// ---------- 4. workflow health + minutes trend ----------

async fn workflows(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let idle: i64 = envn("GOV_WORKFLOW_IDLE_DAYS", 90);
    let since = (Utc::now() - chrono::Duration::days(30))
        .format("%Y-%m-%d")
        .to_string();
    let mins: Mutex<Vec<(String, f64)>> = Mutex::new(vec![]);
    let mins_ref = &mins;
    let since = &since;
    let mut found = sweep(repos(gh).await?, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let url = s(&r["html_url"]).to_string();
        let mut out = vec![];
        let Some(wfs) = gh
            .paged(
                &format!("/repos/{full}/actions/workflows"),
                Some("workflows"),
                2,
            )
            .await?
        else {
            return Ok(out);
        };
        for w in wfs.iter().filter(|w| w["state"] == "active") {
            let runs = gh
                .json_opt(&format!(
                    "/repos/{full}/actions/workflows/{}/runs?per_page=1",
                    w["id"]
                ))
                .await?;
            let last = runs
                .as_ref()
                .map(|v| s(&v["workflow_runs"][0]["created_at"]).to_string())
                .unwrap_or_default();
            let label = format!("{full} / {}", s(&w["name"]));
            let wurl = format!(
                "{url}/actions/workflows/{}",
                s(&w["path"]).rsplit('/').next().unwrap_or("")
            );
            match age_days(&last) {
                None => out.push(finding(
                    "idle",
                    1,
                    label,
                    wurl,
                    "active workflow that has never run",
                )),
                Some(d) if d > idle => out.push(finding(
                    "idle",
                    1,
                    label,
                    wurl,
                    format!("last ran {d}d ago"),
                )),
                _ => {}
            }
        }
        let Some(v) = gh
            .json_opt(&format!(
                "/repos/{full}/actions/runs?created=%3E%3D{since}&per_page=100"
            ))
            .await?
        else {
            return Ok(out);
        };
        let runs = v["workflow_runs"].as_array().cloned().unwrap_or_default();
        let mut by: std::collections::HashMap<String, (u32, u32, u32)> = Default::default();
        let mut minutes = 0f64;
        for r in &runs {
            let e = by.entry(s(&r["name"]).to_string()).or_default();
            e.0 += 1;
            if r["conclusion"] == "failure" {
                e.1 += 1;
            }
            if r["run_attempt"].as_i64().unwrap_or(1) > 1 {
                e.2 += 1;
            }
            let t = |k: &str| DateTime::parse_from_rfc3339(s(&r[k])).ok();
            if let (Some(a), Some(b)) = (t("run_started_at"), t("updated_at")) {
                minutes += ((b - a).num_seconds().max(0) as f64 / 60.0).ceil().max(1.0);
            }
        }
        let total = v["total_count"].as_f64().unwrap_or(0.0);
        if !runs.is_empty() && total > runs.len() as f64 {
            minutes *= total / runs.len() as f64;
        }
        if minutes > 0.0 {
            mins_ref.lock().unwrap().push((full.clone(), minutes));
        }
        for (name, (n, failed, reruns)) in by {
            let a = format!("{url}/actions");
            if n >= 5 && failed * 2 >= n {
                out.push(finding(
                    "failing",
                    3,
                    format!("{full} / {name}"),
                    &a,
                    format!("{failed} of {n} recent runs failed"),
                ));
            }
            if reruns >= 5 {
                out.push(finding(
                    "reruns",
                    2,
                    format!("{full} / {name}"),
                    &a,
                    format!("{reruns} of {n} runs were re-runs (flaky?)"),
                ));
            }
        }
        Ok(out)
    })
    .await;
    let mut total = 0.0;
    for (repo, m) in mins.into_inner().unwrap() {
        total += m;
        let key = format!("minutes:{repo}");
        if let Some(prev) = prev_metric(pool, "workflows", &key).await? {
            if m >= 60.0 && m >= prev * 2.0 {
                found.push(finding(
                    "surge",
                    3,
                    &repo,
                    format!("https://github.com/{repo}/actions"),
                    format!("~{m:.0} min in 30d, up from ~{prev:.0} last week"),
                ));
            }
        }
        metric(pool, "workflows", &key, m).await?;
    }
    metric(pool, "workflows", "total_minutes_30d", total).await?;
    finish(
        pool,
        "workflows",
        "Workflow health over the last 30 days (sampled from the newest 100 runs per repo).",
        found,
    )
    .await
}

// ---------- 5. storage watch ----------

async fn storage(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let cache_mb: f64 = envn("GOV_CACHE_MB", 1024.0);
    let art_mb: f64 = envn("GOV_ARTIFACT_MB", 512.0);
    let tot = Mutex::new((0f64, 0f64));
    let tot_ref = &tot;
    let found = sweep(repos(gh).await?, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let url = s(&r["html_url"]).to_string();
        let mut out = vec![];
        let mb = 1024.0 * 1024.0;
        let cache = gh
            .json_opt(&format!("/repos/{full}/actions/cache/usage"))
            .await?
            .map(|v| v["active_caches_size_in_bytes"].as_f64().unwrap_or(0.0) / mb)
            .unwrap_or(0.0);
        let arts = gh
            .paged(
                &format!("/repos/{full}/actions/artifacts"),
                Some("artifacts"),
                3,
            )
            .await?
            .unwrap_or_default();
        let art: f64 = arts
            .iter()
            .filter(|a| a["expired"] == false)
            .map(|a| a["size_in_bytes"].as_f64().unwrap_or(0.0))
            .sum::<f64>()
            / mb;
        {
            let mut t = tot_ref.lock().unwrap();
            t.0 += cache;
            t.1 += art;
        }
        if cache >= cache_mb {
            out.push(finding(
                "cache",
                2,
                &full,
                format!("{url}/actions/caches"),
                format!("{cache:.0} MB of Actions caches"),
            ));
        }
        if art >= art_mb {
            out.push(finding(
                "artifacts",
                2,
                &full,
                format!("{url}/actions"),
                format!("{art:.0} MB of artifacts (first {} listed)", arts.len()),
            ));
        }
        Ok(out)
    })
    .await;
    let (c, a) = *tot.lock().unwrap();
    metric(pool, "storage", "total_cache_mb", c).await?;
    metric(pool, "storage", "total_artifact_mb", a).await?;
    let intro =
        format!("Actions storage: ~{c:.0} MB caches and ~{a:.0} MB artifacts across all repos.");
    finish(pool, "storage", &intro, found).await
}

// ---------- 6. dependency freshness ----------

async fn deps(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let days: i64 = envn("GOV_DEPS_STALE_DAYS", 30);
    let cutoff = (Utc::now() - chrono::Duration::days(days))
        .format("%Y-%m-%d")
        .to_string();
    let mut found = vec![];
    for bot in ["dependabot", "renovate"] {
        for page in 1..=3 {
            let q = format!(
                "/search/issues?q=user:{}+is:open+is:pr+archived:false+author:app/{bot}+created:%3C{cutoff}&sort=created&order=asc&per_page=100&page={page}",
                cfg.owner
            );
            let Some(v) = gh.search_json(&q).await? else {
                break;
            };
            let items = v["items"].as_array().cloned().unwrap_or_default();
            for i in &items {
                let repo = s(&i["repository_url"])
                    .trim_start_matches("https://api.github.com/repos/")
                    .to_string();
                let age = age_days(s(&i["created_at"])).unwrap_or(0);
                found.push(finding(
                    "stale_bot",
                    2,
                    format!("{repo}#{}", i["number"]),
                    s(&i["html_url"]),
                    format!("{bot}: {} ({age}d old)", s(&i["title"])),
                ));
            }
            if items.len() < 100 {
                break;
            }
        }
    }
    let intro = format!("Dependabot/Renovate PRs open for more than {days} days.");
    finish(pool, "deps", &intro, found).await
}

// ---------- 7. release hygiene ----------

async fn releases(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let ahead_min: i64 = envn("GOV_RELEASE_AHEAD", 10);
    let days_min: i64 = envn("GOV_RELEASE_DAYS", 30);
    let found = sweep(repos(gh).await?, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let def = s(&r["default_branch"]).to_string();
        let Some(rel) = gh
            .json_opt(&format!("/repos/{full}/releases/latest"))
            .await?
        else {
            return Ok(vec![]);
        };
        let tag = s(&rel["tag_name"]).to_string();
        let age = age_days(s(&rel["published_at"])).unwrap_or(0);
        let Some(c) = gh
            .json_opt(&format!(
                "/repos/{full}/compare/{}...{}",
                enc(&tag),
                enc(&def)
            ))
            .await?
        else {
            return Ok(vec![]);
        };
        let ahead = c["ahead_by"].as_i64().unwrap_or(0);
        Ok(if ahead >= ahead_min && age >= days_min {
            vec![finding(
                "unreleased",
                2,
                &full,
                s(&c["html_url"]),
                format!("{ahead} commits since {tag} ({age}d ago)"),
            )]
        } else {
            vec![]
        })
    })
    .await;
    let intro = format!(
        "Repos with a release that are {ahead_min}+ commits ahead of it and {days_min}+ days past it."
    );
    finish(pool, "releases", &intro, found).await
}

// ---------- 8. branch cleanup ----------

async fn branches(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let stale_days: i64 = envn("GOV_BRANCH_STALE_DAYS", 90);
    let found = sweep(repos(gh).await?, |r| async move {
        let full = s(&r["full_name"]).to_string();
        let def = s(&r["default_branch"]).to_string();
        let mut out = vec![];
        let Some(bs) = gh
            .paged(&format!("/repos/{full}/branches"), None, 2)
            .await?
        else {
            return Ok(out);
        };
        for b in bs
            .iter()
            .filter(|b| s(&b["name"]) != def && b["protected"] != true)
            .take(30)
        {
            let name = s(&b["name"]);
            let url = format!("https://github.com/{full}/tree/{name}");
            let Some(c) = gh
                .json_opt(&format!(
                    "/repos/{full}/compare/{}...{}",
                    enc(&def),
                    enc(name)
                ))
                .await?
            else {
                continue;
            };
            if c["ahead_by"].as_i64().unwrap_or(1) == 0 {
                out.push(finding(
                    "merged",
                    1,
                    format!("{full}:{name}"),
                    url,
                    "fully merged into the default branch; safe to delete",
                ));
                continue;
            }
            let sha = s(&b["commit"]["sha"]);
            if let Some(cm) = gh.json_opt(&format!("/repos/{full}/commits/{sha}")).await? {
                if let Some(d) =
                    age_days(s(&cm["commit"]["committer"]["date"])).filter(|d| *d > stale_days)
                {
                    out.push(finding(
                        "stale",
                        1,
                        format!("{full}:{name}"),
                        url,
                        format!("unmerged, last commit {d}d ago"),
                    ));
                }
            }
        }
        Ok(out)
    })
    .await;
    let intro = format!(
        "Branch clutter (up to 30 non-default branches per repo; stale means {stale_days}+ days)."
    );
    finish(pool, "branches", &intro, found).await
}

// ---------- 9. PR flow ----------

async fn prflow(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    let since = (Utc::now() - chrono::Duration::days(30))
        .format("%Y-%m-%d")
        .to_string();
    let human = "-author:app/dependabot+-author:app/renovate+archived:false";
    let mut found = vec![];

    let mut hours: Vec<(f64, String, String, String)> = vec![];
    for page in 1..=3 {
        let q = format!(
            "/search/issues?q=user:{}+is:pr+is:merged+merged:%3E%3D{since}+{human}&per_page=100&page={page}",
            cfg.owner
        );
        let Some(v) = gh.search_json(&q).await? else {
            break;
        };
        let items = v["items"].as_array().cloned().unwrap_or_default();
        for i in &items {
            let (a, b) = (
                DateTime::parse_from_rfc3339(s(&i["created_at"])),
                DateTime::parse_from_rfc3339(s(&i["closed_at"])),
            );
            if let (Ok(a), Ok(b)) = (a, b) {
                let repo = s(&i["repository_url"])
                    .trim_start_matches("https://api.github.com/repos/")
                    .to_string();
                hours.push((
                    (b - a).num_minutes() as f64 / 60.0,
                    format!("{repo}#{}", i["number"]),
                    s(&i["html_url"]).into(),
                    s(&i["title"]).into(),
                ));
            }
        }
        if items.len() < 100 {
            break;
        }
    }
    hours.sort_by(|a, b| a.0.total_cmp(&b.0));
    let pct = |p: f64| {
        hours
            .get(((hours.len() as f64 - 1.0) * p).round() as usize)
            .map(|h| h.0)
            .unwrap_or(0.0)
    };
    let (median, p90) = (pct(0.5), pct(0.9));
    for (h, label, url, title) in hours.iter().rev().take(10) {
        found.push(finding(
            "slow",
            1,
            label,
            url,
            format!("{title}: {:.1} days to merge", h / 24.0),
        ));
    }

    let q = format!(
        "/search/issues?q=user:{}+is:pr+is:open+draft:false+review:none+{human}&sort=created&order=asc&per_page=100",
        cfg.owner
    );
    let mut waiting = 0;
    if let Some(v) = gh.search_json(&q).await? {
        for i in v["items"].as_array().into_iter().flatten() {
            let age = age_days(s(&i["created_at"])).unwrap_or(0);
            if age >= 3 {
                waiting += 1;
                let repo = s(&i["repository_url"])
                    .trim_start_matches("https://api.github.com/repos/")
                    .to_string();
                found.push(finding(
                    "waiting",
                    3,
                    format!("{repo}#{}", i["number"]),
                    s(&i["html_url"]),
                    format!("{}: no review after {age}d", s(&i["title"])),
                ));
            }
        }
    }
    let prev = prev_metric(pool, "prflow", "median_hours_to_merge").await?;
    metric(pool, "prflow", "merged_30d", hours.len() as f64).await?;
    metric(pool, "prflow", "median_hours_to_merge", median).await?;
    metric(pool, "prflow", "p90_hours_to_merge", p90).await?;
    metric(pool, "prflow", "waiting_for_review", waiting as f64).await?;
    let trend = prev
        .map(|p| format!(" (last week {p:.1}h)"))
        .unwrap_or_default();
    let intro = format!(
        "{} human-authored PRs merged in 30 days. Median time to merge {median:.1}h{trend}, p90 {p90:.1}h. Bots are excluded.",
        hours.len()
    );
    finish(pool, "prflow", &intro, found).await
}

// ---------- 10. weekly rollup ----------

async fn rollup(cfg: &Config, gh: &Client, pool: &PgPool, nats: Option<&Js>) -> Result<()> {
    use crate::template::{Brand, Report, Row, Section, Stat};
    let brand = Brand::from_github(gh, &cfg.owner).await;
    let mut sections = vec![];
    let mut kpis: Vec<Stat> = vec![];

    let all: Vec<(String, String, i16, String, String, String)> = sqlx::query_as(
        "SELECT job, kind, sev, label, url, detail FROM gov_findings ORDER BY sev DESC, label",
    )
    .fetch_all(pool)
    .await?;
    let mut counts = std::collections::HashMap::new();
    for (group, title, note, _job, kind) in KINDS.iter().map(|k| (k.1, k.2, k.3, k.4, k.0)) {
        let rows: Vec<Row> = all
            .iter()
            .filter(|f| f.1 == kind)
            .map(|f| Row {
                label: f.3.clone(),
                url: (!f.4.is_empty()).then(|| f.4.clone()),
                detail: Some(f.5.clone()),
                badge: (f.2 >= 3).then(|| tone_for(f.2 as u8).to_string()),
            })
            .collect();
        counts.insert(kind, rows.len());
        if rows.is_empty() {
            continue;
        }
        let worst = all
            .iter()
            .filter(|f| f.1 == kind)
            .map(|f| f.2)
            .max()
            .unwrap_or(1) as u8;
        sections.push(Section {
            group: Some(group.to_string()),
            title: title.to_string(),
            note: Some(note.to_string()),
            tone: Some(tone_for(worst).to_string()),
            rows,
        });
    }
    let n = |k: &str| *counts.get(k).unwrap_or(&0);

    // Triage and stale items come from the tracker rather than a gov job.
    let (unassigned, planned): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE unassigned AND NOT author_is_bot),
                count(*) FILTER (WHERE unassigned AND plan_state='planned') FROM tracked_items",
    )
    .fetch_one(pool)
    .await?;
    let assigned: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM assignments WHERE ok AND at > now() - interval '7 days'",
    )
    .fetch_one(pool)
    .await?;
    let stale: Vec<(String, i64, String, String, String)> = sqlx::query_as(
        "SELECT repo, number, title, url, to_char(last_activity_at,'YYYY-MM-DD') FROM tracked_items
         WHERE stale AND NOT author_is_bot AND (snoozed_until IS NULL OR snoozed_until < now())
         ORDER BY last_activity_at NULLS FIRST",
    )
    .fetch_all(pool)
    .await?;
    if !stale.is_empty() {
        sections.push(Section {
            group: Some("Triage".into()),
            title: "Stale issues and PRs".into(),
            note: Some("No activity for a while; comment, close or snooze.".into()),
            tone: Some("medium".into()),
            rows: stale
                .iter()
                .map(|s| Row {
                    label: format!("{}#{}", s.0, s.1),
                    url: Some(s.3.clone()),
                    detail: Some(format!("{} (last activity {})", s.2, s.4)),
                    badge: None,
                })
                .collect(),
        });
    }

    let notes: Vec<(String, String)> =
        sqlx::query_as("SELECT job, note FROM gov_notes ORDER BY job")
            .fetch_all(pool)
            .await?;
    let note_of = |j: &str| notes.iter().find(|x| x.0 == j).map(|x| x.1.clone());
    let mut intro_lines: Vec<String> = ["prflow", "storage", "deps", "releases"]
        .iter()
        .filter_map(|j| note_of(j))
        .collect();
    intro_lines.dedup();

    // KPI cards with week-over-week deltas from gov_metrics.
    let kpi = |label: &str, job: &str, keys: &[&str], bad_if_up: bool| {
        let cur: f64 = keys.iter().map(|k| n(k) as f64).sum();
        (
            label.to_string(),
            job.to_string(),
            keys.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
            cur,
            bad_if_up,
        )
    };
    let defs = [
        kpi(
            "Security alerts",
            "security",
            &["secret", "dependabot", "code"],
            true,
        ),
        kpi(
            "Hygiene gaps",
            "hygiene",
            &[
                "unprotected",
                "alerts_off",
                "security_md",
                "codeowners",
                "license",
            ],
            true,
        ),
        kpi(
            "Workflow issues",
            "workflows",
            &["surge", "failing", "reruns", "idle"],
            true,
        ),
        kpi("Branch cleanup", "branches", &["merged", "stale"], true),
        kpi("PRs awaiting review", "prflow", &["waiting"], true),
    ];
    for (label, job, keys, cur, bad_if_up) in defs {
        let mut prev_sum = 0.0;
        let mut have = false;
        for k in &keys {
            if let Some(p) = prev_metric(pool, &job, k).await? {
                prev_sum += p;
                have = true;
            }
        }
        let delta = have.then(|| {
            let d = cur - prev_sum;
            if d == 0.0 {
                "no change vs last week".to_string()
            } else {
                format!("{}{:.0} vs last week", if d > 0.0 { "+" } else { "" }, d)
            }
        });
        let tone = match (have, cur - prev_sum) {
            _ if cur == 0.0 => "good",
            (true, d) if (d > 0.0) == bad_if_up && d != 0.0 => "high",
            _ => "neutral",
        };
        kpis.push(Stat {
            label,
            value: format!("{cur:.0}"),
            delta,
            tone: Some(tone.into()),
        });
    }
    kpis.push(Stat {
        label: "Auto-assigned (7d)".into(),
        value: assigned.to_string(),
        delta: Some(format!("{unassigned} still unassigned, {planned} planned")),
        tone: Some("good".into()),
    });
    kpis.push(Stat {
        label: "Stale items".into(),
        value: stale.len().to_string(),
        delta: None,
        tone: Some(if stale.is_empty() { "good" } else { "medium" }.into()),
    });

    let total: usize = sections.iter().map(|s| s.rows.len()).sum();
    let report = Report {
        preheader: Some(format!("{total} items across {} sections", sections.len())),
        title: "GitHub, this week".into(),
        subtitle: Some(Utc::now().format("Week %V, %Y").to_string()),
        intro: (!intro_lines.is_empty()).then(|| intro_lines.join(" ")),
        stats: kpis,
        sections,
        brand: Some(brand),
        footer: None,
    };
    let (html, text) = report.render();
    tracing::info!("rollup: {total} rows, {} KB html", html.len() / 1024);
    mail::deliver(
        cfg,
        nats,
        MailMsg::new(
            format!("[gh-job-audit] GitHub this week: {total} items"),
            html,
            text,
        )
        .dedupe(format!("gov-rollup:{}", week())),
    )
    .await
}
