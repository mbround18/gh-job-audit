//! Unassigned issue/PR discovery and CODEOWNERS-based assignee resolution.
use crate::client::Client;
use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub repo: String,
    pub number: i64,
    pub is_pr: bool,
    pub title: String,
    pub url: String,
    pub author: String,
    pub author_is_bot: bool,
    pub updated_at: String,
}

/// One CODEOWNERS line: a compiled path pattern and its individual (non-team) owners.
pub struct Rule {
    re: Regex,
    is_global: bool,
    owners: Vec<String>,
}

fn pattern_regex(p: &str) -> Option<Regex> {
    let dir = p.ends_with('/');
    let core = p.trim_end_matches('/');
    let anchored = core.starts_with('/') || core.contains('/');
    let core = core.trim_start_matches('/');
    let mut re = String::new();
    let cs: Vec<char> = core.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '*' if cs.get(i + 1) == Some(&'*') => {
                if cs.get(i + 2) == Some(&'/') {
                    re.push_str("(?:.*/)?");
                    i += 3;
                } else {
                    re.push_str(".*");
                    i += 2;
                }
                continue;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    let head = if anchored { "^" } else { "^(?:.*/)?" };
    let tail = if dir { "/.*$" } else { "(?:/.*)?$" };
    Regex::new(&format!("{head}{re}{tail}")).ok()
}

/// Parse a CODEOWNERS file. Only individual `@user` owners are kept: teams (`@org/team`) and
/// e-mail owners are skipped, since assigning them needs different permissions.
pub fn parse_codeowners(text: &str) -> Vec<Rule> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let mut it = l.split_whitespace();
            let pat = it.next()?;
            let owners: Vec<String> = it
                .filter_map(|o| o.strip_prefix('@'))
                .filter(|o| !o.contains('/'))
                .map(str::to_string)
                .collect();
            Some(Rule {
                re: pattern_regex(pat)?,
                is_global: pat == "*",
                owners,
            })
        })
        .collect()
}

/// Repo-wide owners (the last `*` rule) - what an issue, which touches no paths, falls back on.
pub fn default_owners(rules: &[Rule]) -> Vec<String> {
    rules
        .iter()
        .rev()
        .find(|r| r.is_global)
        .map(|r| r.owners.clone())
        .unwrap_or_default()
}

/// For each path the *last* matching rule wins (CODEOWNERS semantics); union across paths.
pub fn owners_for_paths(rules: &[Rule], paths: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in paths {
        if let Some(r) = rules.iter().rev().find(|r| r.re.is_match(p)) {
            for o in &r.owners {
                if !out.iter().any(|x| x.eq_ignore_ascii_case(o)) {
                    out.push(o.clone());
                }
            }
        }
    }
    out
}

impl Client {
    /// Open issues and PRs with no assignee in the owner's repos (private ones included when the
    /// credential can see them). Capped at 500 to bound a first run.
    pub async fn unassigned_items(&self) -> Result<(Vec<Item>, bool)> {
        self.items("no:assignee", "created").await
    }

    /// Open items with no update since `date` (YYYY-MM-DD), oldest first.
    pub async fn stale_items(&self, date: &str) -> Result<(Vec<Item>, bool)> {
        self.items(&format!("updated:<{date}"), "updated").await
    }

    /// Search the owner's open, non-archived issues/PRs. Returns the items and whether the
    /// result was cut off at the page cap (so absence from it proves nothing).
    async fn items(&self, qualifiers: &str, sort: &str) -> Result<(Vec<Item>, bool)> {
        let mut out = Vec::new();
        let mut truncated = false;
        for page in 1..=5 {
            let q = format!(
                "/search/issues?q=user:{}+is:open+archived:false+{qualifiers}&sort={sort}&order=asc&per_page=100&page={page}",
                self.owner
            );
            let Some(v) = self.search(&q).await? else {
                break;
            };
            let items = v["items"].as_array().cloned().unwrap_or_default();
            let n = items.len();
            for i in items {
                let Some(repo) = i["repository_url"]
                    .as_str()
                    .and_then(|u| u.strip_prefix("https://api.github.com/repos/"))
                else {
                    continue;
                };
                let login = i["user"]["login"].as_str().unwrap_or("").to_string();
                out.push(Item {
                    repo: repo.to_string(),
                    number: i["number"].as_i64().unwrap_or(0),
                    is_pr: i.get("pull_request").is_some(),
                    title: i["title"].as_str().unwrap_or("").to_string(),
                    url: i["html_url"].as_str().unwrap_or("").to_string(),
                    author_is_bot: i["user"]["type"] == "Bot" || login.ends_with("[bot]"),
                    author: login,
                    updated_at: i["updated_at"].as_str().unwrap_or("").to_string(),
                });
            }
            if n < 100 {
                break;
            }
            truncated = page == 5;
        }
        Ok((out, truncated))
    }

    /// CODEOWNERS from the default branch (GitHub's three lookup locations), if any.
    pub async fn codeowners(&self, repo: &str) -> Result<Vec<Rule>> {
        use base64::Engine;
        for p in [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"] {
            if let Some(v) = self.get_opt(&format!("/repos/{repo}/contents/{p}")).await? {
                if let Some(b) = v["content"].as_str() {
                    let raw = base64::engine::general_purpose::STANDARD
                        .decode(b.replace('\n', ""))
                        .unwrap_or_default();
                    return Ok(parse_codeowners(&String::from_utf8_lossy(&raw)));
                }
            }
        }
        Ok(Vec::new())
    }

    pub async fn pr_files(&self, repo: &str, number: i64) -> Result<Vec<String>> {
        let v = self
            .get_opt(&format!("/repos/{repo}/pulls/{number}/files?per_page=100"))
            .await?;
        Ok(v.and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|f| f["filename"].as_str().map(str::to_string))
            .collect())
    }

    /// GitHub only accepts assignees who are collaborators; check before trying.
    pub async fn can_assign(&self, repo: &str, user: &str) -> Result<bool> {
        let r = self
            .req(
                reqwest::Method::GET,
                &format!("/repos/{repo}/assignees/{user}"),
                None,
            )
            .await?;
        Ok(r.status().as_u16() == 204)
    }

    pub async fn assign(&self, repo: &str, number: i64, assignees: &[String]) -> Result<()> {
        self.check_owned(repo)?;
        let r = self
            .req(
                reqwest::Method::POST,
                &format!("/repos/{repo}/issues/{number}/assignees"),
                Some(serde_json::json!({ "assignees": assignees })),
            )
            .await?;
        if !r.status().is_success() {
            bail!(
                "assign {repo}#{number}: {} {}",
                r.status(),
                r.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CO: &str = "# owners\n* @alice @org/team\n/docs/ @bob\n*.rs @carol # rust\n/src/**/gen/ @dave\nweb/* someone@example.com\n";

    fn p(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn issue_uses_global_rule_and_skips_teams() {
        assert_eq!(default_owners(&parse_codeowners(CO)), vec!["alice"]);
    }

    #[test]
    fn last_match_wins_per_path_and_unions() {
        let r = parse_codeowners(CO);
        assert_eq!(owners_for_paths(&r, &p(&["docs/a.md"])), vec!["bob"]);
        assert_eq!(owners_for_paths(&r, &p(&["src/x/y.rs"])), vec!["carol"]);
        assert_eq!(
            owners_for_paths(&r, &p(&["docs/a.md", "src/lib.rs"])),
            vec!["bob", "carol"]
        );
        assert_eq!(owners_for_paths(&r, &p(&["README.md"])), vec!["alice"]);
        assert_eq!(
            owners_for_paths(&r, &p(&["src/a/b/gen/z.txt"])),
            vec!["dave"]
        );
    }

    #[test]
    fn email_owner_yields_none_and_no_file_means_empty() {
        let r = parse_codeowners(CO);
        assert!(owners_for_paths(&r, &p(&["web/index.html"])).is_empty());
        assert!(default_owners(&parse_codeowners("")).is_empty());
    }
}
