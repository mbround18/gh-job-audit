//! GitHub client + repo analysis shared by every gh-audit binary.
pub mod analysis;
pub mod client;
pub mod triage;

pub use analysis::{Kind, Recommendation, RepoStats, Thresholds, evaluate};
pub use client::{Auth, Client};
