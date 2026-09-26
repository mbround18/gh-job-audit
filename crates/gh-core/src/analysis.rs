use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Per-repo facts gathered from GitHub. Mirrors the columns we analysed by hand.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoStats {
    pub full_name: String,
    pub private: bool,
    pub fork: bool,
    pub archived: bool,
    pub stars: i64,
    pub forks: i64,
    pub open_issues: i64,
    pub open_prs: i64,
    pub actions_enabled: bool,
    /// Workflow runs started in the trailing 30 days.
    pub runs_30d: i64,
    /// Estimated billable minutes over those runs (sampled, rounded up per job).
    pub minutes_30d: f64,
    /// Runs triggered by renovate/dependabot in the trailing 30 days.
    pub bot_runs_30d: i64,
    pub last_owner_commit: Option<DateTime<Utc>>,
    pub last_owner_pr: Option<DateTime<Utc>>,
    pub pushed_at: Option<DateTime<Utc>>,
}

/// Configurable knobs. Every field has an env override in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    /// No owner commit or PR for this many days => archive candidate.
    pub archive_idle_days: i64,
    /// Stars+forks at or above this => only "review", never a straight archive.
    pub archive_popular_score: i64,
    /// Repo is dormant (idle) yet still burning at least this many runs/30d => disable CI.
    pub ci_off_runs_30d: i64,
    /// Private repos: any Actions minutes above this in 30d => flag (they cost money).
    pub private_minutes_30d: f64,
    /// Any repo above this many minutes/30d => flag as a heavy hitter.
    pub heavy_minutes_30d: f64,
    /// Bot-driven runs above this on a repo => suggest gating/grouping bot CI.
    pub bot_runs_30d: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            archive_idle_days: 365,
            archive_popular_score: 5,
            ci_off_runs_30d: 5,
            private_minutes_30d: 60.0,
            heavy_minutes_30d: 500.0,
            bot_runs_30d: 40,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Archive,
    ReviewArchive,
    DisableActions,
    HeavyCi,
    PrivateCost,
    BotChurn,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Archive => "archive",
            Kind::ReviewArchive => "review_archive",
            Kind::DisableActions => "disable_actions",
            Kind::HeavyCi => "heavy_ci",
            Kind::PrivateCost => "private_cost",
            Kind::BotChurn => "bot_churn",
        }
    }
    /// Only these can be executed from an email button.
    pub fn actionable(self) -> bool {
        matches!(self, Kind::Archive | Kind::DisableActions)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub repo: String,
    pub kind: Kind,
    pub reason: String,
}

fn idle_days(s: &RepoStats, now: DateTime<Utc>) -> Option<i64> {
    // Last *owner* signal; fall back to pushed_at so bot-only repos still count as idle.
    let last = [s.last_owner_commit, s.last_owner_pr]
        .into_iter()
        .flatten()
        .max();
    last.map(|t| (now - t).num_days())
        .or_else(|| s.pushed_at.map(|t| (now - t).num_days()))
}

pub fn evaluate(stats: &[RepoStats], t: &Thresholds, now: DateTime<Utc>) -> Vec<Recommendation> {
    let mut out = Vec::new();
    for s in stats.iter().filter(|s| !s.archived) {
        let idle = idle_days(s, now);
        let dormant = idle.is_some_and(|d| d >= t.archive_idle_days);
        let idle_txt = idle
            .map(|d| format!("{d}d idle"))
            .unwrap_or_else(|| "no activity".into());
        let popular = s.stars + s.forks >= t.archive_popular_score;

        if dormant {
            if popular || s.open_prs > 0 {
                out.push(Recommendation {
                    repo: s.full_name.clone(),
                    kind: Kind::ReviewArchive,
                    reason: format!(
                        "{idle_txt}, but {} stars / {} forks / {} open PRs",
                        s.stars, s.forks, s.open_prs
                    ),
                });
            } else {
                out.push(Recommendation {
                    repo: s.full_name.clone(),
                    kind: Kind::Archive,
                    reason: format!(
                        "{idle_txt}, {} stars, {} forks{}",
                        s.stars,
                        s.forks,
                        if s.fork { ", fork" } else { "" }
                    ),
                });
            }
        }
        // CI on a dormant repo (or a fork) is pure waste.
        if s.actions_enabled && (dormant || s.fork) && s.runs_30d >= t.ci_off_runs_30d {
            out.push(Recommendation {
                repo: s.full_name.clone(),
                kind: Kind::DisableActions,
                reason: format!(
                    "{} runs / ~{:.0} min in 30d on a {} repo",
                    s.runs_30d,
                    s.minutes_30d,
                    if dormant { "dormant" } else { "fork" }
                ),
            });
        }
        if s.private && s.minutes_30d >= t.private_minutes_30d {
            out.push(Recommendation {
                repo: s.full_name.clone(),
                kind: Kind::PrivateCost,
                reason: format!(
                    "private repo used ~{:.0} min in 30d (billable)",
                    s.minutes_30d
                ),
            });
        }
        if !s.private && s.minutes_30d >= t.heavy_minutes_30d {
            out.push(Recommendation {
                repo: s.full_name.clone(),
                kind: Kind::HeavyCi,
                reason: format!("~{:.0} min / {} runs in 30d", s.minutes_30d, s.runs_30d),
            });
        }
        if s.bot_runs_30d >= t.bot_runs_30d {
            out.push(Recommendation {
                repo: s.full_name.clone(),
                kind: Kind::BotChurn,
                reason: format!(
                    "{} bot-triggered runs in 30d; group updates or gate bot CI",
                    s.bot_runs_30d
                ),
            });
        }
    }
    out
}

#[allow(dead_code)]
fn _days(n: i64) -> Duration {
    Duration::days(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(name: &str) -> RepoStats {
        RepoStats {
            full_name: name.into(),
            actions_enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn dead_repo_is_archive_and_ci_off() {
        let now = Utc::now();
        let mut s = base("o/dead");
        s.last_owner_commit = Some(now - Duration::days(800));
        s.runs_30d = 12;
        let r = evaluate(&[s], &Thresholds::default(), now);
        assert!(r.iter().any(|x| x.kind == Kind::Archive));
        assert!(r.iter().any(|x| x.kind == Kind::DisableActions));
    }

    #[test]
    fn popular_dead_repo_only_reviewed() {
        let now = Utc::now();
        let mut s = base("o/pop");
        s.last_owner_commit = Some(now - Duration::days(800));
        s.stars = 50;
        let r = evaluate(&[s], &Thresholds::default(), now);
        assert!(r.iter().any(|x| x.kind == Kind::ReviewArchive));
        assert!(!r.iter().any(|x| x.kind == Kind::Archive));
    }

    #[test]
    fn active_repo_is_quiet_and_archived_skipped() {
        let now = Utc::now();
        let mut s = base("o/live");
        s.last_owner_commit = Some(now - Duration::days(3));
        let mut a = base("o/old");
        a.archived = true;
        assert!(evaluate(&[s, a], &Thresholds::default(), now).is_empty());
    }

    #[test]
    fn private_minutes_flagged() {
        let now = Utc::now();
        let mut s = base("o/priv");
        s.private = true;
        s.minutes_30d = 200.0;
        s.last_owner_commit = Some(now);
        let r = evaluate(&[s], &Thresholds::default(), now);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, Kind::PrivateCost);
    }
}
