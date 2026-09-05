use std::path::{Path, PathBuf};

use serde::Serialize;

use super::arguments::EvidenceMode;
use super::evidence::EnvironmentSnapshot;
use super::paired::{Comparison, Control, Measurement, RunRecord};
use crate::process::ProcessRecord;

#[derive(Serialize)]
pub(super) struct SetupProcesses<'a> {
    pub(super) source: &'a [ProcessRecord],
    pub(super) lock: &'a ProcessRecord,
    pub(super) build: &'a ProcessRecord,
}

#[derive(Serialize)]
pub(super) struct SetupFailureReport<'a> {
    pub(super) decision: &'static str,
    pub(super) environment: EnvironmentSnapshot,
    pub(super) baseline_source: &'a str,
    pub(super) candidate_source: &'a str,
    pub(super) fixture: &'a Path,
    pub(super) harness_source: PathBuf,
    pub(super) harness_source_sha256: String,
    pub(super) paired_core_source: PathBuf,
    pub(super) paired_core_source_sha256: String,
    pub(super) paired_protocol_source: PathBuf,
    pub(super) paired_protocol_source_sha256: String,
    pub(super) paired_stats_protocol_source: PathBuf,
    pub(super) paired_stats_protocol_source_sha256: String,
    pub(super) manifest: PathBuf,
    pub(super) manifest_sha256: String,
    pub(super) policy: &'a Path,
    pub(super) policy_sha256: String,
    pub(super) logs: &'a Path,
    pub(super) processes: SetupProcesses<'a>,
}

#[derive(Serialize)]
pub(super) struct StatsMethod {
    pub(super) name: &'static str,
    pub(super) reason: &'static str,
    pub(super) non_regression_margin: f64,
    pub(super) confidence: f64,
    pub(super) process_replicates: usize,
    pub(super) sample_size: usize,
    pub(super) warm_up_seconds: f64,
    pub(super) measurement_seconds: f64,
    pub(super) cooldown_seconds: f64,
    pub(super) aa_control: bool,
    pub(super) first_invocation_policy: &'static str,
    pub(super) prime_timings_used: bool,
    pub(super) inference: &'static str,
    pub(super) source_identity: &'static str,
}

#[derive(Serialize)]
pub(super) struct StatsArtifacts<'a> {
    pub(super) harness_source: PathBuf,
    pub(super) harness_source_sha256: String,
    pub(super) paired_core_source: PathBuf,
    pub(super) paired_core_source_sha256: String,
    pub(super) paired_protocol_source: PathBuf,
    pub(super) paired_protocol_source_sha256: String,
    pub(super) paired_stats_protocol_source: PathBuf,
    pub(super) paired_stats_protocol_source_sha256: String,
    pub(super) policy: &'a Path,
    pub(super) policy_sha256: String,
    pub(super) manifest: PathBuf,
    pub(super) manifest_sha256: String,
    pub(super) baseline_repository: PathBuf,
    pub(super) baseline_repository_sha256: String,
    pub(super) candidate_repository: PathBuf,
    pub(super) candidate_repository_sha256: String,
    pub(super) cargo_lock: PathBuf,
    pub(super) cargo_lock_sha256: String,
    pub(super) binary: PathBuf,
    pub(super) binary_sha256: String,
    pub(super) logs: &'a Path,
}

#[derive(Serialize)]
pub(super) struct StatsProcesses<'a> {
    pub(super) source: &'a [ProcessRecord],
    pub(super) lock: &'a ProcessRecord,
    pub(super) build: &'a ProcessRecord,
    pub(super) runs: &'a [RunRecord],
}

#[derive(Serialize)]
pub(super) struct StatsReport<'a> {
    pub(super) decision: &'static str,
    pub(super) strict_configuration: bool,
    pub(super) evidence_mode: &'a EvidenceMode,
    pub(super) baseline_source: &'a str,
    pub(super) candidate_source: &'a str,
    pub(super) environment: EnvironmentSnapshot,
    pub(super) completed_environment: EnvironmentSnapshot,
    pub(super) fixture: &'a Path,
    pub(super) method: StatsMethod,
    pub(super) artifacts: StatsArtifacts<'a>,
    pub(super) processes: StatsProcesses<'a>,
    pub(super) anomalies: &'a [String],
    pub(super) ab: Comparison<'a>,
    pub(super) aa_control: Control<'a>,
    pub(super) records: &'a [Measurement],
    pub(super) completed_unix_ms: u128,
}

#[derive(Serialize)]
pub(super) struct StatsInvalidContext<'a> {
    pub(super) decision: &'static str,
    pub(super) environment: Option<EnvironmentSnapshot>,
    pub(super) baseline_ref: &'a str,
    pub(super) candidate_ref: &'a str,
    pub(super) baseline_source: Option<String>,
    pub(super) candidate_source: Option<String>,
    pub(super) fixture: &'a Path,
    pub(super) harness_source_sha256: Option<String>,
    pub(super) policy_sha256: Option<String>,
}
