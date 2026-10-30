//! Explicit local experiment protocol. None of these fields grants CPU credit.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const SCHEMA: &str = "native-public-v3-identity-churn-supplement-v1";
pub const JOB_SCHEMA: &str = "native-public-v3-identity-actor-job-v1";
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    HonestOnly,
    ReplayOnly,
    FreshIdentities,
}
impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Self::HonestOnly => "honest-only",
            Self::ReplayOnly => "replay-only",
            Self::FreshIdentities => "fresh-identities",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub actors: usize,
    pub prefix_calls_per_actor: usize,
    pub pressure_calls_per_actor: usize,
    pub prefix_seconds: u64,
    pub pressure_seconds: u64,
    pub readiness_seconds: u64,
    pub cleanup_seconds: u64,
    pub call_seconds: u64,
    pub actor_total_call_cap: usize,
    pub honest_submission_cap: usize,
    pub honest_history_cap: usize,
    pub rounds: usize,
    pub pressure_schedule: String,
    pub qualification: bool,
}
impl Plan {
    pub fn full() -> Self {
        Self {
            actors: 24,
            prefix_calls_per_actor: 192,
            pressure_calls_per_actor: 288,
            prefix_seconds: 1800,
            pressure_seconds: 30,
            readiness_seconds: 180,
            cleanup_seconds: 5,
            call_seconds: 2,
            actor_total_call_cap: 480,
            honest_submission_cap: 128,
            honest_history_cap: 64,
            rounds: 3,
            pressure_schedule: "closed-loop-one-in-flight-per-actor".into(),
            qualification: true,
        }
    }
    pub fn control() -> Self {
        Self {
            actors: 2,
            prefix_calls_per_actor: 1,
            pressure_calls_per_actor: 2,
            prefix_seconds: 30,
            pressure_seconds: 2,
            rounds: 0,
            qualification: false,
            ..Self::full()
        }
    }
    pub fn validate(&self) {
        assert!(self.actors > 0 && self.actors <= 24 && self.call_seconds == 2);
        assert!(
            self.prefix_calls_per_actor + self.pressure_calls_per_actor
                <= self.actor_total_call_cap
        );
        assert_eq!(self.actor_total_call_cap, 480);
        assert_eq!(
            self.pressure_schedule,
            "closed-loop-one-in-flight-per-actor"
        );
        if self.qualification {
            assert_eq!(
                serde_json::to_value(self).unwrap(),
                serde_json::to_value(Self::full()).unwrap()
            );
        }
    }
    pub fn index(&self, worker: usize, slot: usize) -> usize {
        slot.checked_mul(self.actors)
            .unwrap()
            .checked_add(worker)
            .unwrap()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub schema: String,
    pub plan: Plan,
    pub mode: Mode,
    pub worker: usize,
    pub address: String,
    pub template_packet: String,
    pub output: PathBuf,
    pub prefix_marker: PathBuf,
    pub pressure_marker: PathBuf,
    pub source_commit: String,
    pub source_tree: String,
    pub binary_sha256: String,
}
