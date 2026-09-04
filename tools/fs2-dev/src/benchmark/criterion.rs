use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use super::statistics;
use crate::process::{self, ProcessRecord};
use crate::{Result, invalid_data};

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub(crate) struct CriterionSettings {
    pub(crate) sample_size: usize,
    pub(crate) warm_up_seconds: f64,
    pub(crate) measurement_seconds: f64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", content = "settings", rename_all = "kebab-case")]
pub(crate) enum CriterionMode {
    Prime,
    Measure(CriterionSettings),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Estimate {
    pub(crate) metric: String,
    pub(crate) median_ns: f64,
    pub(crate) mad_ns: f64,
    pub(crate) std_dev_ns: f64,
    pub(crate) ci_lower_ns: f64,
    pub(crate) ci_upper_ns: f64,
    pub(crate) sample_count: usize,
    pub(crate) outliers: usize,
    pub(crate) outlier_fraction: f64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FailureRecord {
    pub(crate) label: String,
    pub(crate) count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PrimeRecord {
    pub(crate) label: String,
    pub(crate) duration_ns: u128,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CriterionRun {
    pub(crate) mode: CriterionMode,
    pub(crate) process: ProcessRecord,
    pub(crate) prime_observations: Vec<PrimeRecord>,
    pub(crate) estimates: Vec<Estimate>,
    pub(crate) failures: Vec<FailureRecord>,
    pub(crate) criterion_artifact: PathBuf,
}

pub(super) struct CriterionInvocation<'a> {
    pub(super) root: &'a Path,
    pub(super) executable: &'a Path,
    pub(super) benchmark: &'a str,
    pub(super) filter: Option<&'a str>,
    pub(super) mode: CriterionMode,
    pub(super) stats_fixture: Option<&'a Path>,
    pub(super) run_root: &'a Path,
    pub(super) label: &'a str,
    pub(super) max_outlier_fraction: f64,
}

impl CriterionRun {
    pub(crate) fn valid(&self) -> bool {
        self.process.succeeded()
            && self.failures.is_empty()
            && workload_coverage_valid(self.mode, &self.prime_observations, &self.estimates)
    }

    pub(crate) fn matches_priming(&self, priming: &Self) -> bool {
        matches!(self.mode, CriterionMode::Measure(_))
            && matches!(priming.mode, CriterionMode::Prime)
            && self.valid()
            && priming.valid()
            && prime_workloads(&self.prime_observations)
                == prime_workloads(&priming.prime_observations)
    }

    pub(crate) fn estimates_by_metric(&self) -> BTreeMap<String, f64> {
        self.estimates
            .iter()
            .map(|estimate| (estimate.metric.clone(), estimate.median_ns))
            .collect()
    }

    pub(crate) fn workload_ids(&self) -> Option<BTreeSet<String>> {
        prime_workloads(&self.prime_observations)
            .map(|workloads| workloads.into_iter().map(str::to_owned).collect())
    }
}

fn prime_workloads(observations: &[PrimeRecord]) -> Option<BTreeSet<&str>> {
    let workloads = observations
        .iter()
        .map(|record| record.label.as_str())
        .collect::<BTreeSet<_>>();
    (!workloads.is_empty() && workloads.len() == observations.len()).then_some(workloads)
}

fn estimate_workloads(estimates: &[Estimate]) -> Option<BTreeSet<&str>> {
    let workloads = estimates
        .iter()
        .map(|estimate| estimate.metric.as_str())
        .collect::<BTreeSet<_>>();
    (!workloads.is_empty() && workloads.len() == estimates.len()).then_some(workloads)
}

fn workload_coverage_valid(
    mode: CriterionMode,
    observations: &[PrimeRecord],
    estimates: &[Estimate],
) -> bool {
    let Some(primes) = prime_workloads(observations) else {
        return false;
    };
    match mode {
        CriterionMode::Prime => estimates.is_empty(),
        CriterionMode::Measure(settings) => {
            estimate_workloads(estimates).is_some_and(|ids| ids == primes)
                && estimates
                    .iter()
                    .all(|estimate| estimate.sample_count == settings.sample_size)
        }
    }
}

#[derive(Deserialize)]
struct CriterionEstimates {
    median: EstimateValue,
    median_abs_dev: EstimateValue,
    std_dev: EstimateValue,
}

#[derive(Deserialize)]
struct EstimateValue {
    point_estimate: f64,
    confidence_interval: ConfidenceInterval,
}

#[derive(Deserialize)]
struct ConfidenceInterval {
    lower_bound: f64,
    upper_bound: f64,
}

#[derive(Deserialize)]
struct CriterionBenchmark {
    full_id: String,
    directory_name: String,
}

pub(crate) fn run(invocation: CriterionInvocation<'_>) -> Result<CriterionRun> {
    let CriterionInvocation {
        root,
        executable,
        benchmark,
        filter,
        mode,
        stats_fixture,
        run_root,
        label,
        max_outlier_fraction,
    } = invocation;
    let criterion_root = run_root.join(format!("{label}-{benchmark}-criterion"));
    let stdout = run_root.join(format!("{label}-{benchmark}.stdout.log"));
    let stderr = run_root.join(format!("{label}-{benchmark}.stderr.log"));
    let mut command = std::process::Command::new(executable);
    command
        .current_dir(root)
        .env("CRITERION_HOME", &criterion_root)
        .env("FS2_BENCH_REPORT_ERRORS", "0");
    if let Some(filter) = filter.filter(|filter| !filter.is_empty()) {
        command.arg(filter);
    }
    match mode {
        CriterionMode::Prime => {
            command.arg("--test");
        }
        CriterionMode::Measure(settings) => {
            command.args([
                "--bench",
                "--sample-size",
                &settings.sample_size.to_string(),
                "--warm-up-time",
                &settings.warm_up_seconds.to_string(),
                "--measurement-time",
                &settings.measurement_seconds.to_string(),
            ]);
        }
    }
    if let Some(path) = stats_fixture {
        command.env("FS2_BENCH_STATS_PATH", path);
    }
    let process = process::run_logged_attempt(
        &mut command,
        format!("run {label} {benchmark}"),
        &stdout,
        &stderr,
    );
    let mut failures = Vec::new();
    let stdout_text = read_benchmark_log(&stdout, "stdout", &mut failures);
    let stderr_text = read_benchmark_log(&stderr, "stderr", &mut failures);
    failures.extend(parse_failure_records(&stdout_text));
    failures.extend(parse_failure_records(&stderr_text));
    let mut prime_observations = parse_prime_records(&stdout_text, &mut failures);
    prime_observations.extend(parse_prime_records(&stderr_text, &mut failures));
    if !process.succeeded() {
        failures.push(FailureRecord {
            label: "benchmark_command".to_owned(),
            count: 1,
            error: Some(process.failure_description()),
        });
    }
    let estimates = match mode {
        CriterionMode::Measure(_) => match collect_estimates(&criterion_root, max_outlier_fraction)
        {
            Ok(estimates) => estimates,
            Err(error) => {
                failures.push(FailureRecord {
                    label: "criterion_estimates".to_owned(),
                    count: 1,
                    error: Some(error.to_string()),
                });
                Vec::new()
            }
        },
        CriterionMode::Prime => Vec::new(),
    };
    Ok(CriterionRun {
        mode,
        process,
        prime_observations,
        estimates,
        failures,
        criterion_artifact: criterion_root,
    })
}

fn read_benchmark_log(
    path: &Path,
    stream: &'static str,
    failures: &mut Vec<FailureRecord>,
) -> String {
    match fs::read_to_string(path) {
        Ok(output) => output,
        Err(error) => {
            failures.push(FailureRecord {
                label: format!("benchmark_{stream}_log"),
                count: 1,
                error: Some(error.to_string()),
            });
            String::new()
        }
    }
}

fn collect_estimates(root: &Path, max_outlier_fraction: f64) -> Result<Vec<Estimate>> {
    let mut estimates = Vec::new();
    if !root.is_dir() {
        return Err(invalid_data(format!(
            "Criterion produced no output under {}",
            root.display()
        )));
    }
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.file_name() != OsStr::new("estimates.json")
            || entry.path().parent().and_then(Path::file_name) != Some(OsStr::new("new"))
        {
            continue;
        }
        let data: CriterionEstimates = serde_json::from_str(&fs::read_to_string(entry.path())?)?;
        let samples: CriterionSamples = serde_json::from_str(&fs::read_to_string(
            entry.path().with_file_name("sample.json"),
        )?)?;
        let (sample_count, outliers, outlier_fraction) = sample_outliers(&samples)?;
        let metric_root = entry
            .path()
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid_data("invalid Criterion estimate path"))?;
        let benchmark: CriterionBenchmark = serde_json::from_str(&fs::read_to_string(
            entry.path().with_file_name("benchmark.json"),
        )?)?;
        if metric_root.file_name().and_then(OsStr::to_str)
            != Some(benchmark.directory_name.as_str())
            || benchmark.full_id.is_empty()
        {
            return Err(invalid_data("Criterion benchmark identity is inconsistent"));
        }
        let estimate = Estimate {
            metric: benchmark.full_id,
            median_ns: data.median.point_estimate,
            mad_ns: data.median_abs_dev.point_estimate,
            std_dev_ns: data.std_dev.point_estimate,
            ci_lower_ns: data.median.confidence_interval.lower_bound,
            ci_upper_ns: data.median.confidence_interval.upper_bound,
            sample_count,
            outliers,
            outlier_fraction,
        };
        validate_estimate(&estimate)?;
        if estimate.outlier_fraction > max_outlier_fraction {
            return Err(invalid_data(format!(
                "Criterion outlier fraction for {} is {:.3}; maximum is {max_outlier_fraction:.3}",
                estimate.metric, estimate.outlier_fraction
            )));
        }
        estimates.push(estimate);
    }
    estimates.sort_by(|left, right| left.metric.cmp(&right.metric));
    if estimates.is_empty() {
        Err(invalid_data(format!(
            "Criterion produced no estimates under {}",
            root.display()
        )))
    } else {
        Ok(estimates)
    }
}

#[derive(Deserialize)]
struct CriterionSamples {
    iters: Vec<f64>,
    times: Vec<f64>,
}

fn sample_outliers(samples: &CriterionSamples) -> Result<(usize, usize, f64)> {
    if samples.iters.is_empty() || samples.iters.len() != samples.times.len() {
        return Err(invalid_data(
            "Criterion sample arrays are empty or mismatched",
        ));
    }
    let values = samples
        .times
        .iter()
        .zip(&samples.iters)
        .map(|(time, iterations)| {
            if !time.is_finite() || !iterations.is_finite() || *time <= 0.0 || *iterations <= 0.0 {
                Err(invalid_data("Criterion sample is not finite and positive"))
            } else {
                Ok(time / iterations)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let mut sorted = values.clone();
    let sample_median = statistics::median(&mut sorted)?;
    let mut deviations = values
        .iter()
        .map(|value| (value - sample_median).abs())
        .collect::<Vec<_>>();
    let mad = statistics::median(&mut deviations)?;
    let outliers = if mad == 0.0 {
        let tolerance = f64::EPSILON * sample_median.abs().max(1.0);
        values
            .iter()
            .filter(|value| (*value - sample_median).abs() > tolerance)
            .count()
    } else {
        values
            .iter()
            .filter(|value| (*value - sample_median).abs() > 3.0 * mad)
            .count()
    };
    let fraction = outliers as f64 / values.len() as f64;
    Ok((values.len(), outliers, fraction))
}

fn validate_estimate(estimate: &Estimate) -> Result<()> {
    if ![
        estimate.median_ns,
        estimate.mad_ns,
        estimate.std_dev_ns,
        estimate.ci_lower_ns,
        estimate.ci_upper_ns,
    ]
    .iter()
    .all(|value| value.is_finite())
        || estimate.median_ns <= 0.0
        || estimate.mad_ns < 0.0
        || estimate.std_dev_ns < 0.0
        || estimate.ci_lower_ns <= 0.0
        || estimate.ci_lower_ns > estimate.ci_upper_ns
        || estimate.median_ns < estimate.ci_lower_ns
        || estimate.median_ns > estimate.ci_upper_ns
    {
        Err(invalid_data(format!(
            "Criterion emitted invalid estimates for {}",
            estimate.metric
        )))
    } else {
        Ok(())
    }
}

fn parse_failure_records(output: &str) -> Vec<FailureRecord> {
    const PREFIX: &str = "[fs2-bench] FS2_BENCH_FAILURE\t";
    let mut records = Vec::new();
    for line in output.lines() {
        let Some(value) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let parsed = value
            .rsplit_once('\t')
            .filter(|(label, _)| !label.is_empty())
            .and_then(|(label, count)| count.parse::<u64>().ok().map(|count| (label, count)));
        match parsed {
            Some((label, count)) if count > 0 => match unescape_label(label) {
                Ok(label) => records.push(FailureRecord {
                    label,
                    count,
                    error: None,
                }),
                Err(error) => records.push(FailureRecord {
                    label: "malformed_failure_record".to_owned(),
                    count: 1,
                    error: Some(error.to_string()),
                }),
            },
            Some((label, _)) => records.push(FailureRecord {
                label: "malformed_failure_record".to_owned(),
                count: 1,
                error: Some(format!("failure record for {label:?} has a zero count")),
            }),
            None => records.push(FailureRecord {
                label: "malformed_failure_record".to_owned(),
                count: 1,
                error: Some(line.to_owned()),
            }),
        }
    }
    records
}

fn parse_prime_records(output: &str, failures: &mut Vec<FailureRecord>) -> Vec<PrimeRecord> {
    const PREFIX: &str = "[fs2-bench] FS2_BENCH_PRIME\t";
    let mut records = Vec::new();
    for line in output.lines() {
        let Some(value) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let parsed = value
            .rsplit_once('\t')
            .filter(|(label, _)| !label.is_empty())
            .and_then(|(label, duration)| {
                duration
                    .parse::<u128>()
                    .ok()
                    .map(|duration| (label, duration))
            });
        match parsed {
            Some((label, duration_ns)) => match unescape_label(label) {
                Ok(label) => records.push(PrimeRecord { label, duration_ns }),
                Err(error) => failures.push(FailureRecord {
                    label: "malformed_prime_record".to_owned(),
                    count: 1,
                    error: Some(error.to_string()),
                }),
            },
            None => failures.push(FailureRecord {
                label: "malformed_prime_record".to_owned(),
                count: 1,
                error: Some(line.to_owned()),
            }),
        }
    }
    records
}

fn unescape_label(value: &str) -> Result<String> {
    let mut result = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.next() {
                Some('\\') => result.push('\\'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('n') => result.push('\n'),
                Some(other) => {
                    return Err(invalid_data(format!(
                        "unknown benchmark-label escape: \\{other}"
                    )));
                }
                None => return Err(invalid_data("trailing benchmark-label escape")),
            }
        } else {
            result.push(character);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prime(label: &str) -> PrimeRecord {
        PrimeRecord {
            label: label.to_owned(),
            duration_ns: 1,
        }
    }

    fn estimate(metric: &str) -> Estimate {
        Estimate {
            metric: metric.to_owned(),
            median_ns: 1.0,
            mad_ns: 0.0,
            std_dev_ns: 0.0,
            ci_lower_ns: 1.0,
            ci_upper_ns: 1.0,
            sample_count: 50,
            outliers: 0,
            outlier_fraction: 0.0,
        }
    }

    #[test]
    fn parses_and_unescapes_failure_records() {
        let records = parse_failure_records("[fs2-bench] FS2_BENCH_FAILURE\ta\\tb\\n\\\\c\t3\n");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "a\tb\n\\c");
        assert_eq!(records[0].count, 3);
    }

    #[test]
    fn malformed_failure_records_remain_observable() {
        let records = parse_failure_records(
            "[fs2-bench] FS2_BENCH_FAILURE\tmissing-count\n[fs2-bench] FS2_BENCH_FAILURE\tlabel\tnot-a-count\n",
        );
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.label == "malformed_failure_record")
        );
    }

    #[test]
    fn parses_prime_records_and_rejects_malformed_records() {
        let mut failures = Vec::new();
        let records = parse_prime_records(
            "[fs2-bench] FS2_BENCH_PRIME\ta\\tb\t17\n[fs2-bench] FS2_BENCH_PRIME\tbroken\n",
            &mut failures,
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].label, "a\tb");
        assert_eq!(records[0].duration_ns, 17);
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn workload_coverage_requires_exact_unique_ids() {
        let settings = CriterionSettings {
            sample_size: 50,
            warm_up_seconds: 2.0,
            measurement_seconds: 5.0,
        };
        let primes = [prime("first"), prime("second")];
        let estimates = [estimate("first"), estimate("second")];
        assert!(workload_coverage_valid(
            CriterionMode::Measure(settings),
            &primes,
            &estimates
        ));
        assert!(!workload_coverage_valid(
            CriterionMode::Measure(settings),
            &primes,
            &[estimate("first"), estimate("other")]
        ));
        assert!(!workload_coverage_valid(
            CriterionMode::Measure(settings),
            &[prime("first"), prime("first")],
            &estimates
        ));
        let mut incomplete = [estimate("first"), estimate("second")];
        incomplete[0].sample_count = 49;
        assert!(!workload_coverage_valid(
            CriterionMode::Measure(settings),
            &primes,
            &incomplete
        ));
    }

    #[test]
    fn criterion_outliers_are_computed_from_structured_samples() {
        let samples = CriterionSamples {
            iters: vec![1.0; 5],
            times: vec![10.0, 10.0, 10.0, 10.0, 100.0],
        };
        let (count, outliers, fraction) = sample_outliers(&samples).unwrap();
        assert_eq!(count, 5);
        assert_eq!(outliers, 1);
        assert_eq!(fraction, 0.2);
    }
}
