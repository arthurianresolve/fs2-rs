use std::io::{self, Error, ErrorKind};
use std::time::{Duration, Instant};

#[path = "paired_protocol.rs"]
mod paired_protocol;

pub(crate) use paired_protocol::{HEADER, PROTOCOL};

const CALIBRATION_PAIRS: usize = 32;
const MIN_SAMPLE_SIZE: usize = 10;
const MAX_SAMPLE_SIZE: usize = 10_000;
const MAX_DURATION_MILLIS: u64 = 3_600_000;
const MAX_ITERATIONS_PER_SAMPLE: u128 = 100_000_000;

pub(crate) struct PairObservation {
    pub(crate) baseline_ns: u128,
    pub(crate) candidate_ns: u128,
    pub(crate) failures: u64,
}

pub(crate) struct Measurement {
    pub(crate) baseline_ns: f64,
    pub(crate) candidate_ns: f64,
    pub(crate) ratio: f64,
    pub(crate) aggregate_ratio: f64,
    pub(crate) ratio_mad: f64,
    pub(crate) samples: usize,
    pub(crate) iterations: usize,
    pub(crate) outliers: usize,
    pub(crate) warm_up_failures: u64,
    pub(crate) failures: u64,
    pub(crate) prime_baseline_ns: u128,
    pub(crate) prime_candidate_ns: u128,
    pub(crate) prime_failures: u64,
    pub(crate) ratio_samples: Vec<f64>,
}

pub(crate) fn encode_ratio_samples(samples: &[f64]) -> String {
    samples
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn measure<F>(
    sample_size: usize,
    warm_up: Duration,
    measurement: Duration,
    prime: PairObservation,
    mut observe_pair: F,
) -> io::Result<Measurement>
where
    F: FnMut(bool) -> io::Result<PairObservation>,
{
    validate_inputs(sample_size, warm_up, measurement)?;
    let mut sequence = 0usize;
    let mut failures = 0u64;
    let mut warm_up_failures = 0u64;
    let warm_up_start = Instant::now();
    while warm_up_start.elapsed() < warm_up {
        let observation = observe_pair(sequence.is_multiple_of(2))?;
        warm_up_failures = warm_up_failures.saturating_add(observation.failures);
        sequence = sequence.wrapping_add(1);
    }

    let calibration_start = Instant::now();
    for _ in 0..CALIBRATION_PAIRS {
        let observation = observe_pair(sequence.is_multiple_of(2))?;
        failures = failures.saturating_add(observation.failures);
        sequence = sequence.wrapping_add(1);
    }
    let pair_ns = (calibration_start.elapsed().as_nanos() / CALIBRATION_PAIRS as u128).max(1);
    let target_sample_ns = measurement.as_nanos() / sample_size as u128;
    let iterations = (target_sample_ns / pair_ns).max(1);
    if iterations > MAX_ITERATIONS_PER_SAMPLE {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "calibrated iteration count exceeds the safety limit",
        ));
    }
    let iterations = usize::try_from(iterations).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            "calibrated iteration count is not representable",
        )
    })?;

    let mut baseline_samples = Vec::with_capacity(sample_size);
    let mut candidate_samples = Vec::with_capacity(sample_size);
    let mut ratios = Vec::with_capacity(sample_size);
    for _ in 0..sample_size {
        let mut baseline_ns = 0u128;
        let mut candidate_ns = 0u128;
        for _ in 0..iterations {
            let observation = observe_pair(sequence.is_multiple_of(2))?;
            sequence = sequence.wrapping_add(1);
            baseline_ns += observation.baseline_ns;
            candidate_ns += observation.candidate_ns;
            failures = failures.saturating_add(observation.failures);
        }
        let baseline_average = baseline_ns as f64 / iterations as f64;
        let candidate_average = candidate_ns as f64 / iterations as f64;
        if baseline_average <= 0.0 || candidate_average <= 0.0 {
            return Err(Error::other("timer resolution produced an empty sample"));
        }
        baseline_samples.push(baseline_average);
        candidate_samples.push(candidate_average);
        ratios.push(candidate_average / baseline_average);
    }

    let baseline_ns = median(&mut baseline_samples);
    let candidate_ns = median(&mut candidate_samples);
    let ratio = median(&mut ratios.clone());
    let aggregate_ratio = candidate_ns / baseline_ns;
    let mut deviations = ratios
        .iter()
        .map(|sample_ratio| (sample_ratio - ratio).abs())
        .collect::<Vec<_>>();
    let ratio_mad = median(&mut deviations);
    let outliers = if ratio_mad == 0.0 {
        let tolerance = f64::EPSILON * ratio.abs().max(1.0);
        ratios
            .iter()
            .filter(|sample_ratio| (*sample_ratio - ratio).abs() > tolerance)
            .count()
    } else {
        ratios
            .iter()
            .filter(|sample_ratio| (*sample_ratio - ratio).abs() > 3.0 * ratio_mad)
            .count()
    };

    Ok(Measurement {
        baseline_ns,
        candidate_ns,
        ratio,
        aggregate_ratio,
        ratio_mad,
        samples: sample_size,
        iterations,
        outliers,
        warm_up_failures,
        failures,
        prime_baseline_ns: prime.baseline_ns,
        prime_candidate_ns: prime.candidate_ns,
        prime_failures: prime.failures,
        ratio_samples: ratios,
    })
}

pub(crate) fn parse_sample_size(value: Option<String>) -> io::Result<usize> {
    parse_bounded(value, "sample size", MIN_SAMPLE_SIZE, MAX_SAMPLE_SIZE)
}

pub(crate) fn parse_duration_millis(value: Option<String>, name: &str) -> io::Result<u64> {
    parse_bounded(value, name, 1, MAX_DURATION_MILLIS)
}

fn parse_bounded<T>(value: Option<String>, name: &str, minimum: T, maximum: T) -> io::Result<T>
where
    T: std::str::FromStr + PartialOrd + Copy,
{
    let value = value
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("missing {name} argument")))?;
    let parsed = value
        .parse::<T>()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, format!("invalid {name} argument")))?;
    if parsed < minimum || parsed > maximum {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{name} is outside the supported range"),
        ));
    }
    Ok(parsed)
}

fn validate_inputs(sample_size: usize, warm_up: Duration, measurement: Duration) -> io::Result<()> {
    if !(MIN_SAMPLE_SIZE..=MAX_SAMPLE_SIZE).contains(&sample_size)
        || warm_up.is_zero()
        || measurement.is_zero()
        || warm_up > Duration::from_millis(MAX_DURATION_MILLIS)
        || measurement > Duration::from_millis(MAX_DURATION_MILLIS)
    {
        Err(Error::new(
            ErrorKind::InvalidInput,
            "paired measurement settings are outside the supported range",
        ))
    } else {
        Ok(())
    }
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_unstable_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_handles_even_and_odd_samples() {
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&mut [4.0, 1.0, 3.0, 2.0]), 2.5);
    }

    #[test]
    fn direct_arguments_are_bounded() {
        assert!(parse_sample_size(Some("9".into())).is_err());
        assert!(parse_sample_size(Some((MAX_SAMPLE_SIZE + 1).to_string())).is_err());
        assert!(
            parse_duration_millis(Some((MAX_DURATION_MILLIS + 1).to_string()), "duration").is_err()
        );
    }
}
