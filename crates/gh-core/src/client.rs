use crate::analysis::RepoStats;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;

const API: &str = "https://api.github.com";

#[derive(Clone)]
pub enum Auth {
    /// GitHub App: JWT -> installation token (auto-refreshed).
    App {
        app_id: String,
        private_key_pem: String,
        installation_id: Option<u64>,
    },
    /// Personal access token (needed for billing endpoints, which Apps cannot call).
    Token(String),
}

struct Cached {
    token: String,
    expires: DateTime<Utc>,
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    auth: Auth,
    cache: Arc<Mutex<Option<Cached>>>,
    /// Search API allows 30 req/min; space calls out.
    search_gate: Arc<Mutex<std::time::Instant>>,
    /// Owner whose repos we audit (user or org login).
    pub owner: String,
}

#[derive(Serialize)]
struct Claims {
    iat: i64,
    exp: i64,
    iss: String,
}

impl Client {
    pub fn new(auth: Auth, owner: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("knock-knock/gh-audit")
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            auth,
            cache: Default::default(),
            search_gate: Arc::new(Mutex::new(std::time::Instant::now())),
            owner: owner.into(),
        })
    }

    async fn token(&self) -> Result<String> {
        let (app_id, pem, inst) = match &self.auth {
            Auth::Token(t) => return Ok(t.clone()),
            Auth::App {
                app_id,
                private_key_pem,
                installation_id,
            } => (app_id, private_key_pem, installation_id),
        };
        let mut guard = self.cache.lock().await;
        if let Some(c) = guard.as_ref() {
            if c.expires - Duration::minutes(5) > Utc::now() {
                return Ok(c.token.clone());
            }
        }
        let now = Utc::now().timestamp();
        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims {
                iat: now - 60,
                exp: now + 540,
                iss: app_id.clone(),
            },
            &EncodingKey::from_rsa_pem(pem.as_bytes()).context("invalid GitHub App private key")?,
        )?;
        let inst_id = match inst {
            Some(i) => *i,
            None => {
                let v: Vec<Value> = self
                    .http
                    .get(format!("{API}/app/installations"))
                    .bearer_auth(&jwt)
                    .header("Accept", "application/vnd.github+json")
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                let mine = v
                    .iter()
                    .find(|i| {
                        i["account"]["login"]
                            .as_str()
                            .is_some_and(|l| l.eq_ignore_ascii_case(&self.owner))
                    })
                    .or(v.first())
                    .context("GitHub App has no installations")?;
                mine["id"].as_u64().context("installation id")?
            }
        };
        let r: Value = self
            .http
            .post(format!("{API}/app/installations/{inst_id}/access_tokens"))
            .bearer_auth(&jwt)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let token = r["token"].as_str().context("token")?.to_string();
        let expires = r["expires_at"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(Utc::now() + Duration::minutes(50));
        *guard = Some(Cached {
            token: token.clone(),
            expires,
        });
        Ok(token)
    }

    pub(crate) async fn req(
        &self,
        m: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<reqwest::Response> {
        let mut rb = self
            .http
            .request(m, format!("{API}{path}"))
            .bearer_auth(self.token().await?)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        Ok(rb.send().await?)
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        let r = self.req(reqwest::Method::GET, path, None).await?;
        let s = r.status();
        if !s.is_success() {
            bail!("GET {path} -> {s}: {}", r.text().await.unwrap_or_default());
        }
        Ok(r.json().await?)
    }

    /// GET that maps 404/403/409 (feature off, empty repo, no access) to None.
    pub(crate) async fn get_opt(&self, path: &str) -> Result<Option<Value>> {
        let r = self.req(reqwest::Method::GET, path, None).await?;
        let remaining = r
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        match r.status().as_u16() {
            // A 403/429 from rate limiting must never look like "feature off": fail the repo instead.
            403 | 429
                if remaining.as_deref() == Some("0") || r.headers().contains_key("retry-after") =>
            {
                bail!("GET {path}: rate limited")
            }
            404 | 403 | 409 | 451 => Ok(None),
            s if (200..300).contains(&s) => Ok(Some(r.json().await?)),
            s => bail!("GET {path} -> {s}"),
        }
    }

    /// GET returning None for 404/403/409 (feature off, no access), for governance checks.
    pub async fn json_opt(&self, path: &str) -> Result<Option<Value>> {
        self.get_opt(path).await
    }

    /// Rate-gated search API GET (None when unavailable).
    pub async fn search_json(&self, path: &str) -> Result<Option<Value>> {
        self.search(path).await
    }

    /// Bare HTTP status of a GET (for 204/404 style feature toggles).
    pub async fn status(&self, path: &str) -> Result<u16> {
        Ok(self
            .req(reqwest::Method::GET, path, None)
            .await?
            .status()
            .as_u16())
    }

    /// Follow `page=` pagination (100 per page, at most `max_pages`). `key` names the array inside
    /// an object response (e.g. "workflows"); None when the endpoint is unavailable.
    pub async fn paged(
        &self,
        path: &str,
        key: Option<&str>,
        max_pages: u32,
    ) -> Result<Option<Vec<Value>>> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut out = Vec::new();
        for page in 1..=max_pages {
            let Some(v) = self
                .get_opt(&format!("{path}{sep}per_page=100&page={page}"))
                .await?
            else {
                return Ok(if page == 1 { None } else { Some(out) });
            };
            let arr = match key {
                Some(k) => v[k].as_array().cloned().unwrap_or_default(),
                None => v.as_array().cloned().unwrap_or_default(),
            };
            let n = arr.len();
            out.extend(arr);
            if n < 100 {
                break;
            }
        }
        Ok(Some(out))
    }

    pub async fn list_repos(&self) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        for page in 1.. {
            let v = match &self.auth {
                Auth::App { .. } => {
                    let v = self
                        .get(&format!(
                            "/installation/repositories?per_page=100&page={page}"
                        ))
                        .await?;
                    v["repositories"].as_array().cloned().unwrap_or_default()
                }
                Auth::Token(_) => {
                    let v = self
                        .get(&format!(
                            "/user/repos?per_page=100&page={page}&affiliation=owner"
                        ))
                        .await?;
                    v.as_array().cloned().unwrap_or_default()
                }
            };
            let n = v.len();
            out.extend(v);
            if n < 100 {
                break;
            }
        }
        out.retain(|r| {
            r["owner"]["login"]
                .as_str()
                .is_some_and(|l| l.eq_ignore_ascii_case(&self.owner))
        });
        Ok(out)
    }

    pub(crate) async fn search(&self, path: &str) -> Result<Option<Value>> {
        let mut last = self.search_gate.lock().await;
        let wait = std::time::Duration::from_millis(2200).saturating_sub(last.elapsed());
        tokio::time::sleep(wait).await;
        let r = self.get_opt(path).await;
        *last = std::time::Instant::now();
        r
    }

    /// Gather everything `analysis::evaluate` needs for one repo.
    pub async fn repo_stats(&self, repo: &Value) -> Result<RepoStats> {
        let full = repo["full_name"].as_str().unwrap_or_default().to_string();
        let since = (Utc::now() - Duration::days(30))
            .format("%Y-%m-%d")
            .to_string();
        let ts = |v: &Value| v.as_str().and_then(|s| s.parse::<DateTime<Utc>>().ok());

        let actions_enabled = self
            .get_opt(&format!("/repos/{full}/actions/permissions"))
            .await?
            .map(|v| v["enabled"].as_bool().unwrap_or(false))
            .unwrap_or(false);

        let (mut runs, mut bot_runs, mut minutes) = (0i64, 0i64, 0f64);
        if actions_enabled {
            if let Some(v) = self
                .get_opt(&format!(
                    "/repos/{full}/actions/runs?created=%3E%3D{since}&per_page=100"
                ))
                .await?
            {
                runs = v["total_count"].as_i64().unwrap_or(0);
                for r in v["workflow_runs"].as_array().into_iter().flatten() {
                    let actor = r["actor"]["login"].as_str().unwrap_or("");
                    if actor.ends_with("[bot]") {
                        bot_runs += 1;
                    }
                    if let (Some(a), Some(b)) = (ts(&r["run_started_at"]), ts(&r["updated_at"])) {
                        // Per-run wall clock, min 1 min; sampled from the newest 100 then scaled.
                        minutes += ((b - a).num_seconds().max(0) as f64 / 60.0).ceil().max(1.0);
                    }
                }
                let sampled = v["workflow_runs"].as_array().map(|a| a.len()).unwrap_or(0) as f64;
                if sampled > 0.0 && (runs as f64) > sampled {
                    let scale = runs as f64 / sampled;
                    minutes *= scale;
                    bot_runs = (bot_runs as f64 * scale) as i64;
                }
            }
        }

        let commit = self
            .get_opt(&format!(
                "/repos/{full}/commits?author={}&per_page=1",
                self.owner
            ))
            .await?
            .and_then(|v| ts(&v[0]["commit"]["author"]["date"]));
        // Search is expensive (30/min): only look for PRs when commits alone don't show recent activity.
        let stale = commit.is_none_or(|c| (Utc::now() - c).num_days() > 180);
        let (mut pr, mut open_prs) = (None, 0);
        if stale {
            pr = self
                .search(&format!(
                    "/search/issues?q=repo:{full}+type:pr+author:{}&sort=created&per_page=1",
                    self.owner
                ))
                .await?
                .and_then(|v| ts(&v["items"][0]["created_at"]));
            open_prs = self
                .search(&format!(
                    "/search/issues?q=repo:{full}+type:pr+state:open&per_page=1"
                ))
                .await?
                .and_then(|v| v["total_count"].as_i64())
                .unwrap_or(0);
        }

        Ok(RepoStats {
            full_name: full,
            private: repo["private"].as_bool().unwrap_or(false),
            fork: repo["fork"].as_bool().unwrap_or(false),
            archived: repo["archived"].as_bool().unwrap_or(false),
            stars: repo["stargazers_count"].as_i64().unwrap_or(0),
            forks: repo["forks_count"].as_i64().unwrap_or(0),
            open_issues: (repo["open_issues_count"].as_i64().unwrap_or(0) - open_prs).max(0),
            open_prs,
            actions_enabled,
            runs_30d: runs,
            minutes_30d: minutes,
            bot_runs_30d: bot_runs,
            last_owner_commit: commit,
            last_owner_pr: pr,
            pushed_at: ts(&repo["pushed_at"]),
        })
    }

    pub async fn archive_repo(&self, full: &str) -> Result<()> {
        self.check_owned(full)?;
        let r = self
            .req(
                reqwest::Method::PATCH,
                &format!("/repos/{full}"),
                Some(serde_json::json!({"archived": true})),
            )
            .await?;
        if !r.status().is_success() {
            bail!("archive {full}: {}", r.status());
        }
        Ok(())
    }

    pub async fn disable_actions(&self, full: &str) -> Result<()> {
        self.check_owned(full)?;
        let r = self
            .req(
                reqwest::Method::PUT,
                &format!("/repos/{full}/actions/permissions"),
                Some(serde_json::json!({"enabled": false})),
            )
            .await?;
        if !r.status().is_success() {
            bail!("disable actions {full}: {}", r.status());
        }
        Ok(())
    }

    /// Never act outside the configured owner, whatever a token says.
    pub(crate) fn check_owned(&self, full: &str) -> Result<()> {
        match full.split_once('/') {
            Some((o, r))
                if o.eq_ignore_ascii_case(&self.owner) && !r.is_empty() && !r.contains('/') =>
            {
                Ok(())
            }
            _ => bail!("refusing to act on {full}: not owned by {}", self.owner),
        }
    }

    /// Billing usage (needs a classic PAT with `user` scope; Apps get 403/404).
    /// Returns gross Actions minutes used this month, if available.
    pub async fn actions_minutes(&self) -> Result<Option<f64>> {
        let Auth::Token(_) = self.auth else {
            return Ok(None);
        };
        let now = Utc::now();
        let v = self
            .get_opt(&format!(
                "/users/{}/settings/billing/usage?year={}&month={}",
                self.owner,
                now.format("%Y"),
                now.format("%-m")
            ))
            .await?;
        let Some(v) = v else { return Ok(None) };
        let mut used = 0.0;
        for i in v["usageItems"].as_array().into_iter().flatten() {
            if i["product"].as_str() == Some("actions") && i["unitType"].as_str() == Some("Minutes")
            {
                used += i["quantity"].as_f64().unwrap_or(0.0);
            }
        }
        Ok(Some(used))
    }

    /// Login + immutable numeric id of the user behind an OAuth user token.
    pub async fn oauth_user(http: &reqwest::Client, user_token: &str) -> Result<(String, i64)> {
        let v: Value = http
            .get(format!("{API}/user"))
            .bearer_auth(user_token)
            .header("User-Agent", "knock-knock/gh-audit")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok((
            v["login"].as_str().context("login")?.to_string(),
            v["id"].as_i64().context("id")?,
        ))
    }

    /// Numeric id of a public account (used to pin the owner's identity at startup).
    pub async fn user_id(&self, login: &str) -> Result<i64> {
        let v = self.get(&format!("/users/{login}")).await?;
        v["id"].as_i64().context("user id")
    }
}
