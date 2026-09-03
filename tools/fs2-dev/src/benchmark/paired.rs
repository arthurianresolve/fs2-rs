use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use clap::ArgMatches;
use serde::Serialize;

use super::arguments::{EvidenceMode, require_exploratory};
use super::common;
use super::statistics;
use crate::policy;
use crate::process::{self, ProcessRecord};
use crate::{Result, invalid_data};

#[path = "../../../../benchmarks/paired_protocol.rs"]
mod protocol;

use protocol::{HEADER, PROTOCOL};

const MAX_REPLICATES: usize = policy::MAX_PAIRED_REPLICATES as usize;
const MAX_SAMPLE_SIZE: usize = policy::MAX_SAMPLE_SIZE as usize;
const MAX_DURATION_SECONDS: f64 = policy::MAX_DURATION_SECONDS;
const MAX_COOLDOWN_SECONDS: f64 = policy::MAX_DURATION_SECONDS;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Measurement {
    pub(super) run: String,
    pub(super) mode: String,
    pub(super) metric: String,
    pub(super) baseline_ns: f64,
    pub(super) candidate_ns: f64,
    pub(super) ratio: f64,
    pub(super) aggregate_ratio: f64,
    pub(super) ratio_mad: f64,
    pub(super) samples: u64,
    pub(super) iterations: u64,
    pub(super) outliers: u64,
    pub(super) warm_up_failures: u64,
    pub(super) failures: u64,
    pub(super) prime_baseline_ns: u128,
    pub(super) prime_candidate_ns: u128,
    pub(super) prime_failures: u64,
    pub(super) ratio_samples: Vec<f64>,
}

#[derive(Debug, Serialize)]
pub(super) struct RunRecord {
    pub(super) run: String,
    pub(super) mode: String,
    pub(super) replicate: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) rotation: Option<usize>,
    pub(super) process: ProcessRecord,
}

#[derive(Debug, Serialize)]
pub(super) struct Summary {
    pub(super) metric: String,
    pub(super) ratios: Vec<f64>,
    pub(super) median_ratio: f64,
    pub(super) process_ratio_mad: f64,
    pub(super) exact_lower_ratio: f64,
    pub(super) exact_upper_ratio: f64,
    pub(super) confidence_requested: f64,
    pub(super) confidence_achieved: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) simultaneous_confidence_at_least: Option<f64>,
    pub(super) disposition: &'static str,
}

#[derive(Serialize)]
pub(super) struct Comparison<'a> {
    pub(super) passed: bool,
    pub(super) summary: &'a [Summary],
}

#[derive(Serialize)]
pub(super) struct Control<'a> {
    pub(super) enabled: bool,
    pub(super) passed: bool,
    pub(super) summary: &'a [Summary],
}

pub(super) struct Settings {
    pub(super) replicates: usize,
    pub(super) sample_size: usize,
    pub(super) warm_up: f64,
    pub(super) measurement: f64,
    pub(super) cooldown: f64,
    pub(super) aa_control: bool,
    pub(super) max_outlier_fraction: f64,
    pub(super) evidence_mode: EvidenceMode,
}

pub(super) struct JobOutput {
    pub(super) records: Vec<Measurement>,
    pub(super) process: ProcessRecord,
    pub(super) rotation: Option<usize>,
    pub(super) anomalies: Vec<String>,
}

pub(super) struct MeasurementRuns {
    pub(super) records: Vec<Measurement>,
    pub(super) runs: Vec<RunRecord>,
    pub(super) anomalies: Vec<String>,
}

pub(super) struct BinaryJobSpec<'a> {
    pub(super) working_directory: &'a Path,
    pub(super) fixture_argument: Option<&'a Path>,
    pub(super) binary: &'a Path,
    pub(super) logs: &'a Path,
    pub(super) metrics: &'a [&'a str],
    pub(super) replicates: usize,
    pub(super) sample_size: usize,
    pub(super) warm_up_ms: u64,
    pub(super) measurement_ms: u64,
    pub(super) cooldown: f64,
    pub(super) aa_control: bool,
    pub(super) max_outlier_fraction: f64,
    pub(super) minimum_free_bytes: u64,
    pub(super) rotation_count: Option<usize>,
}

pub(super) struct GateDecision {
    pub(super) valid: bool,
    pub(super) decision: &'static str,
}

pub(super) fn settings(
    arguments: &ArgMatches,
    policy: &policy::MeasurementPolicy,
) -> Result<Settings> {
    let replicates = arguments
        .get_one::<usize>("replicates")
        .copied()
        .unwrap_or(usize::try_from(policy.paired_process.process_replicates)?);
    let sample_size = arguments
        .get_one::<usize>("sample-size")
        .copied()
        .unwrap_or(usize::try_from(policy.criterion.sample_size)?);
    let warm_up = arguments
        .get_one::<f64>("warm-up-seconds")
        .copied()
        .unwrap_or(policy.criterion.warm_up_seconds);
    let measurement = arguments
        .get_one::<f64>("measurement-seconds")
        .copied()
        .unwrap_or(policy.criterion.measurement_seconds);
    let cooldown = arguments
        .get_one::<f64>("cooldown-seconds")
        .copied()
        .unwrap_or(policy.paired_process.cooldown_seconds);
    let aa_control = policy.paired_process.aa_control && !arguments.get_flag("skip-aa-control");
    validate_settings(replicates, sample_size, warm_up, measurement, cooldown)?;
    validate_replicate_confidence(replicates, policy.paired_process.confidence, aa_control)?;
    let explicitly_exploratory = arguments.get_flag("exploratory");
    let mut evidence_mode = if explicitly_exploratory {
        EvidenceMode::exploratory("explicit --exploratory request")
    } else {
        EvidenceMode::strict()
    };
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        !policy.meets_strict_paired_profile(),
        "measurement policy does not meet the strict paired profile",
    )?;
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        replicates != usize::try_from(policy.paired_process.process_replicates)?,
        "replicate count differs from the measurement policy",
    )?;
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        sample_size != usize::try_from(policy.criterion.sample_size)?,
        "sample size differs from the measurement policy",
    )?;
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        warm_up != policy.criterion.warm_up_seconds,
        "warm-up duration differs from the measurement policy",
    )?;
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        measurement != policy.criterion.measurement_seconds,
        "measurement duration differs from the measurement policy",
    )?;
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        cooldown != policy.paired_process.cooldown_seconds,
        "cooldown differs from the measurement policy",
    )?;
    require_exploratory(
        &mut evidence_mode,
        explicitly_exploratory,
        aa_control != policy.paired_process.aa_control,
        "A/A control differs from the measurement policy",
    )?;
    Ok(Settings {
        replicates,
        sample_size,
        warm_up,
        measurement,
        cooldown,
        aa_control,
        max_outlier_fraction: policy.criterion.max_outlier_fraction,
        evidence_mode,
    })
}

fn validate_replicate_confidence(
    replicates: usize,
    confidence: f64,
    aa_control: bool,
) -> Result<()> {
    let confidence = if aa_control {
        (1.0 + confidence) / 2.0
    } else {
        confidence
    };
    statistics::exact_median_bounds(&vec![1.0; replicates], confidence)
        .map(|_| ())
        .map_err(|_| {
            invalid_data("replicate count is too small for the requested exact confidence")
        })
}

pub(super) fn duration_millis(seconds: f64) -> Result<u64> {
    let value = (seconds * 1000.0).round();
    if !value.is_finite() || !(1.0..=MAX_DURATION_SECONDS * 1000.0).contains(&value) {
        Err(invalid_data(
            "duration must be between one millisecond and one hour",
        ))
    } else {
        Ok(value as u64)
    }
}

pub(super) fn validate_settings(
    replicates: usize,
    sample_size: usize,
    warm_up: f64,
    measurement: f64,
    cooldown: f64,
) -> Result<()> {
    if !(1..=MAX_REPLICATES).contains(&replicates)
        || !(10..=MAX_SAMPLE_SIZE).contains(&sample_size)
        || !(0.0..=MAX_DURATION_SECONDS).contains(&warm_up)
        || warm_up == 0.0
        || !(0.0..=MAX_DURATION_SECONDS).contains(&measurement)
        || measurement == 0.0
        || !(0.0..=MAX_COOLDOWN_SECONDS).contains(&cooldown)
        || !warm_up.is_finite()
        || !measurement.is_finite()
        || !cooldown.is_finite()
    {
        Err(invalid_data("invalid paired-process settings"))
    } else {
        Ok(())
    }
}

pub(super) fn parse_measurements(
    text: &str,
    run: &str,
    mode: &str,
    expected_metrics: &[&str],
    expected_samples: usize,
    max_outlier_fraction: f64,
) -> Result<Vec<Measurement>> {
    let mut lines = text.lines();
    if lines.next() != Some(PROTOCOL) || lines.next() != Some(HEADER) {
        return Err(invalid_data(format!("{run} emitted an unexpected header")));
    }
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 15 || !expected_metrics.contains(&fields[0]) || !seen.insert(fields[0]) {
            return Err(invalid_data(format!(
                "{run} emitted an unexpected or duplicate metric"
            )));
        }
        let record = Measurement {
            run: run.to_owned(),
            mode: mode.to_owned(),
            metric: fields[0].to_owned(),
            baseline_ns: fields[1].parse()?,
            candidate_ns: fields[2].parse()?,
            ratio: fields[3].parse()?,
            aggregate_ratio: fields[4].parse()?,
            ratio_mad: fields[5].parse()?,
            samples: fields[6].parse()?,
            iterations: fields[7].parse()?,
            outliers: fields[8].parse()?,
            warm_up_failures: fields[9].parse()?,
            failures: fields[10].parse()?,
            prime_baseline_ns: fields[11].parse()?,
            prime_candidate_ns: fields[12].parse()?,
            prime_failures: fields[13].parse()?,
            ratio_samples: parse_ratio_samples(fields[14])?,
        };
        let mut ratio_samples = record.ratio_samples.clone();
        let recomputed_ratio = statistics::median(&mut ratio_samples)?;
        let recomputed_mad = statistics::median_absolute_deviation(&record.ratio_samples)?;
        let recomputed_outliers = if recomputed_mad == 0.0 {
            let tolerance = f64::EPSILON * recomputed_ratio.abs().max(1.0);
            record
                .ratio_samples
                .iter()
                .filter(|sample| (*sample - recomputed_ratio).abs() > tolerance)
                .count()
        } else {
            record
                .ratio_samples
                .iter()
                .filter(|sample| (*sample - recomputed_ratio).abs() > 3.0 * recomputed_mad)
                .count()
        };
        let expected_ratio = record.candidate_ns / record.baseline_ns;
        let ratio_tolerance = expected_ratio.abs().max(1.0) * 1.0e-6;
        let sample_tolerance = recomputed_ratio.abs().max(1.0) * 1.0e-6;
        if ![
            record.baseline_ns,
            record.candidate_ns,
            record.ratio,
            record.aggregate_ratio,
            record.ratio_mad,
        ]
        .iter()
        .all(|value| value.is_finite())
            || record.baseline_ns <= 0.0
            || record.candidate_ns <= 0.0
            || record.ratio <= 0.0
            || record.aggregate_ratio <= 0.0
            || record.ratio_mad < 0.0
            || record.samples != u64::try_from(expected_samples)?
            || record.ratio_samples.len() != expected_samples
            || record.iterations == 0
            || record.outliers > record.samples
            || record.outliers as f64 / record.samples as f64 > max_outlier_fraction
            || (record.aggregate_ratio - expected_ratio).abs() > ratio_tolerance
            || (record.ratio - recomputed_ratio).abs() > sample_tolerance
            || (record.ratio_mad - recomputed_mad).abs() > sample_tolerance
            || usize::try_from(record.outliers)? != recomputed_outliers
        {
            return Err(invalid_data(format!(
                "{run} emitted an invalid measurement"
            )));
        }
        records.push(record);
    }
    if seen.len() != expected_metrics.len() {
        return Err(invalid_data(format!(
            "{run} did not emit every expected metric"
        )));
    }
    Ok(records)
}

fn parse_ratio_samples(encoded: &str) -> Result<Vec<f64>> {
    if encoded.is_empty() {
        return Err(invalid_data("ratio samples are empty"));
    }
    encoded
        .split(',')
        .map(|sample| {
            let sample = sample
                .parse::<f64>()
                .map_err(|_| invalid_data("ratio sample is not a number"))?;
            if sample.is_finite() && sample > 0.0 {
                Ok(sample)
            } else {
                Err(invalid_data("ratio sample must be finite and positive"))
            }
        })
        .collect()
}

pub(super) fn summarize(
    records: &[Measurement],
    mode: &str,
    metrics: &[&str],
    replicates: usize,
    confidence: f64,
    margin: f64,
) -> Result<(Vec<Summary>, bool)> {
    let limit = 1.0 + margin;
    let lower_limit = 1.0 / limit;
    let mut result = Vec::new();
    let mut passed = true;
    for metric in metrics {
        let ratios = records
            .iter()
            .filter(|record| record.mode == mode && record.metric == *metric)
            .map(|record| record.ratio)
            .collect::<Vec<_>>();
        if ratios.len() != replicates {
            return Err(invalid_data(format!(
                "{mode} {metric} has {} replicates; expected {replicates}",
                ratios.len()
            )));
        }
        let bound_confidence = if mode == "aa" {
            (1.0 + confidence) / 2.0
        } else {
            confidence
        };
        let (lower, upper, one_sided_achieved) =
            statistics::exact_median_bounds(&ratios, bound_confidence)?;
        let achieved = if mode == "aa" {
            (2.0 * one_sided_achieved - 1.0).max(0.0)
        } else {
            one_sided_achieved
        };
        let metric_passed = if mode == "aa" {
            lower >= lower_limit && upper <= limit
        } else {
            upper <= limit
        };
        passed &= metric_passed;
        let mut median_values = ratios.clone();
        result.push(Summary {
            metric: (*metric).to_owned(),
            ratios: ratios.clone(),
            median_ratio: statistics::median(&mut median_values)?,
            process_ratio_mad: statistics::median_absolute_deviation(&ratios)?,
            exact_lower_ratio: lower,
            exact_upper_ratio: upper,
            confidence_requested: confidence,
            confidence_achieved: achieved,
            simultaneous_confidence_at_least: (mode == "aa").then_some(achieved),
            disposition: if mode == "aa" {
                if metric_passed { "balanced" } else { "biased" }
            } else if metric_passed {
                "non-inferior"
            } else {
                "regression"
            },
        });
    }
    Ok((result, passed))
}

pub(super) fn gate_decision(
    anomalies_empty: bool,
    aa_control: bool,
    aa_passed: bool,
    strict: bool,
    ab_passed: bool,
) -> GateDecision {
    if strict && !aa_control {
        return GateDecision {
            valid: false,
            decision: "invalid-strict-configuration",
        };
    }
    let valid = anomalies_empty && (!aa_control || aa_passed);
    let decision = if !anomalies_empty {
        "invalid"
    } else if aa_control && !aa_passed {
        "invalid-aa-control"
    } else if !strict {
        if ab_passed {
            "exploratory-non-inferior"
        } else {
            "exploratory-regression"
        }
    } else if ab_passed {
        "strict-non-regression-pass"
    } else {
        "regression"
    };
    GateDecision { valid, decision }
}

pub(super) fn run_jobs<F>(
    replicates: usize,
    aa_control: bool,
    cooldown: f64,
    mut run_job: F,
) -> Result<MeasurementRuns>
where
    F: FnMut(&str, usize, &str) -> JobOutput,
{
    let total_jobs = replicates
        .checked_mul(if aa_control { 2 } else { 1 })
        .ok_or_else(|| invalid_data("paired-process job count overflowed"))?;
    let mut completed = 0usize;
    let mut records = Vec::new();
    let mut runs = Vec::new();
    let mut anomalies = Vec::new();
    for replicate in 0..replicates {
        let modes: &[&str] = if aa_control && !replicate.is_multiple_of(2) {
            &["aa", "ab"]
        } else if aa_control {
            &["ab", "aa"]
        } else {
            &["ab"]
        };
        for mode in modes {
            let run_name = format!("{mode}-run{:02}", replicate + 1);
            let mut output = run_job(mode, replicate, &run_name);
            let failures = output.records.iter().fold(0u64, |total, record| {
                total.saturating_add(
                    record
                        .warm_up_failures
                        .saturating_add(record.failures)
                        .saturating_add(record.prime_failures),
                )
            });
            if failures > 0 {
                output
                    .anomalies
                    .push(format!("{run_name} reported {failures} operation failures"));
            }
            if !output.process.succeeded() {
                output.anomalies.push(format!(
                    "{run_name}: {}",
                    output.process.failure_description()
                ));
            }
            let unsafe_to_continue = output.process.may_still_be_running();
            records.append(&mut output.records);
            anomalies.append(&mut output.anomalies);
            if unsafe_to_continue {
                anomalies.push(format!(
                    "{run_name}: process cleanup was incomplete; remaining runs were aborted"
                ));
            }
            runs.push(RunRecord {
                run: run_name,
                mode: (*mode).to_owned(),
                replicate: replicate + 1,
                rotation: output.rotation,
                process: output.process,
            });
            completed += 1;
            if unsafe_to_continue {
                return Ok(MeasurementRuns {
                    records,
                    runs,
                    anomalies,
                });
            }
            if completed < total_jobs && cooldown > 0.0 {
                thread::sleep(Duration::from_secs_f64(cooldown));
            }
        }
    }
    Ok(MeasurementRuns {
        records,
        runs,
        anomalies,
    })
}

pub(super) fn run_binary_jobs(spec: BinaryJobSpec<'_>) -> Result<MeasurementRuns> {
    if spec.rotation_count == Some(0) {
        return Err(invalid_data("workload rotation count must be positive"));
    }
    run_jobs(
        spec.replicates,
        spec.aa_control,
        spec.cooldown,
        |mode, replicate, run_name| {
            let stdout = spec.logs.join(format!("{run_name}.stdout.tsv"));
            let stderr = spec.logs.join(format!("{run_name}.stderr.log"));
            let rotation = spec.rotation_count.map(|count| replicate % count);
            let sample_size = spec.sample_size.to_string();
            let warm_up_ms = spec.warm_up_ms.to_string();
            let measurement_ms = spec.measurement_ms.to_string();
            let mut command = Command::new(spec.binary);
            command.current_dir(spec.working_directory);
            if let Some(fixture) = spec.fixture_argument {
                command.arg(fixture);
            }
            command
                .arg(mode)
                .arg(&sample_size)
                .arg(&warm_up_ms)
                .arg(&measurement_ms);
            if let Some(rotation) = rotation {
                command.arg(rotation.to_string());
            }

            let mut anomalies = Vec::new();
            let process = if let Err(error) =
                common::ensure_disk_headroom(spec.logs, spec.minimum_free_bytes)
            {
                anomalies.push(error.to_string());
                ProcessRecord::skipped(
                    &command,
                    format!("run {run_name}"),
                    stdout.clone(),
                    stderr.clone(),
                    "insufficient benchmark disk headroom",
                )
            } else {
                process::run_logged_attempt(
                    &mut command,
                    format!("run {run_name}"),
                    &stdout,
                    &stderr,
                )
            };
            let (records, mut parse_anomalies) = read_job_output(
                &stdout,
                run_name,
                mode,
                spec.metrics,
                spec.sample_size,
                spec.max_outlier_fraction,
            );
            anomalies.append(&mut parse_anomalies);
            JobOutput {
                records,
                process,
                rotation,
                anomalies,
            }
        },
    )
}

pub(super) fn read_job_output(
    stdout: &Path,
    run: &str,
    mode: &str,
    metrics: &[&str],
    expected_samples: usize,
    max_outlier_fraction: f64,
) -> (Vec<Measurement>, Vec<String>) {
    match fs::read_to_string(stdout) {
        Ok(output) => match parse_measurements(
            &output,
            run,
            mode,
            metrics,
            expected_samples,
            max_outlier_fraction,
        ) {
            Ok(records) => (records, Vec::new()),
            Err(error) => (Vec::new(), vec![error.to_string()]),
        },
        Err(error) => (
            Vec::new(),
            vec![format!(
                "{run}: unable to read {}: {error}",
                stdout.display()
            )],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_decisions_require_the_aa_control() {
        let decision = gate_decision(true, false, true, true, true);
        assert!(!decision.valid);
        assert_eq!(decision.decision, "invalid-strict-configuration");
    }

    #[test]
    fn rejects_unbounded_settings() {
        assert!(validate_settings(MAX_REPLICATES + 1, 50, 2.0, 5.0, 10.0).is_err());
        assert!(validate_settings(8, MAX_SAMPLE_SIZE + 1, 2.0, 5.0, 10.0).is_err());
        assert!(duration_millis(MAX_DURATION_SECONDS + 1.0).is_err());
        assert!(validate_replicate_confidence(1, 0.95, false).is_err());
        assert!(validate_replicate_confidence(5, 0.95, false).is_ok());
        assert!(validate_replicate_confidence(5, 0.95, true).is_err());
        assert!(validate_replicate_confidence(6, 0.95, true).is_ok());
    }

    #[test]
    fn parses_complete_measurements_in_any_order() {
        let ratios = ["1.1"; 50].join(",");
        let text = format!(
            "{PROTOCOL}\n{HEADER}\nsecond\t10\t11\t1.1\t1.1\t0\t50\t5\t0\t0\t0\t12\t13\t0\t{ratios}\nfirst\t10\t11\t1.1\t1.1\t0\t50\t5\t0\t0\t0\t12\t13\t0\t{ratios}\n"
        );
        assert_eq!(
            parse_measurements(&text, "ab-run01", "ab", &["first", "second"], 50, 0.5)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn rejects_summary_statistics_that_disagree_with_raw_samples() {
        let ratios = ["1.1"; 50].join(",");
        let text = format!(
            "{PROTOCOL}\n{HEADER}\nmetric\t10\t11\t1.2\t1.1\t0\t50\t5\t0\t0\t0\t12\t13\t0\t{ratios}\n"
        );
        assert!(parse_measurements(&text, "ab-run01", "ab", &["metric"], 50, 0.5).is_err());
    }

    #[test]
    fn aa_summary_uses_simultaneous_two_sided_confidence() {
        let ratios = [0.99, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.01];
        let records = ratios
            .into_iter()
            .map(|ratio| Measurement {
                run: "aa".to_owned(),
                mode: "aa".to_owned(),
                metric: "metric".to_owned(),
                baseline_ns: 10.0,
                candidate_ns: 10.0 * ratio,
                ratio,
                aggregate_ratio: ratio,
                ratio_mad: 0.0,
                samples: 50,
                iterations: 1,
                outliers: 0,
                warm_up_failures: 0,
                failures: 0,
                prime_baseline_ns: 1,
                prime_candidate_ns: 1,
                prime_failures: 0,
                ratio_samples: vec![ratio; 50],
            })
            .collect::<Vec<_>>();
        let (summary, passed) = summarize(&records, "aa", &["metric"], 8, 0.95, 0.02).unwrap();
        assert!(passed);
        assert!(summary[0].confidence_achieved >= 0.95);
        assert_eq!(
            summary[0].simultaneous_confidence_at_least,
            Some(summary[0].confidence_achieved)
        );
    }
}
