use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::process;
use crate::{Result, invalid_data};

const MATRIX_TARGET_EXPRESSION: &str = "${{ matrix.target }}";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum EvidenceLevel {
    Runtime,
    Compile,
    NotCovered,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum AllocationCapability {
    PhysicalReservation,
    Unsupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize)]
enum Runner {
    #[serde(rename = "macos-15-intel")]
    MacOsIntel,
    #[serde(rename = "macos-latest")]
    MacOs,
    #[serde(rename = "ubuntu-latest")]
    Ubuntu,
    #[serde(rename = "windows-latest")]
    Windows,
}

impl Runner {
    const fn as_str(self) -> &'static str {
        match self {
            Self::MacOsIntel => "macos-15-intel",
            Self::MacOs => "macos-latest",
            Self::Ubuntu => "ubuntu-latest",
            Self::Windows => "windows-latest",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupportRegistry {
    version: u64,
    evidence_levels: Vec<EvidenceLevel>,
    targets: Vec<TargetSpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetSpec {
    target: String,
    platform: String,
    evidence: EvidenceLevel,
    allocation: AllocationCapability,
    ci: Option<CiSpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CiSpec {
    job: String,
    runner: Runner,
    toolchains: Vec<String>,
    #[serde(default)]
    coverage: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Matrix {
    include: Vec<MatrixEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct MatrixEntry {
    os: String,
    target: String,
    toolchain: String,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    rust_version: Option<String>,
}

pub(crate) fn run(root: &Path, github_output: Option<&Path>) -> Result<()> {
    let rust_version = package_rust_version(root)?;
    let registry = load_registry(&root.join("support-matrix.json"))?;
    validate_registry(&registry, &rust_version)?;
    let workflow = load_workflow(&root.join(".github/workflows/ci.yml"))?;
    validate_workflow(&registry, &workflow)?;
    let release_gates = load_workflow(&root.join(".github/workflows/release-gates.yml"))?;
    validate_workflow_policy(&release_gates)?;
    let generated = matrices(&registry);
    if let Some(path) = github_output {
        write_github_output(path, &generated, &rust_version)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&generated)?);
    }
    Ok(())
}

fn load_registry(path: &Path) -> Result<SupportRegistry> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn load_workflow(path: &Path) -> Result<Value> {
    Ok(serde_yaml_ng::from_str(&fs::read_to_string(path)?)?)
}

fn package_rust_version(root: &Path) -> Result<String> {
    let mut command = process::cargo();
    command
        .current_dir(root)
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"]);
    let output = process::capture(&mut command, "read fs2 package metadata")?;
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)?;
    metadata
        .packages
        .into_iter()
        .find(|package| package.name == "fs2")
        .and_then(|package| package.rust_version)
        .ok_or_else(|| invalid_data("cargo metadata did not provide fs2 rust-version"))
}

fn validate_registry(registry: &SupportRegistry, rust_version: &str) -> Result<()> {
    if registry.version != 5 {
        return Err(invalid_data("support matrix version must be 5"));
    }
    let levels = registry
        .evidence_levels
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if levels
        != [
            EvidenceLevel::Runtime,
            EvidenceLevel::Compile,
            EvidenceLevel::NotCovered,
        ]
        .into_iter()
        .collect()
    {
        return Err(invalid_data(
            "evidence_levels must contain runtime, compile, and not-covered",
        ));
    }
    if registry.targets.is_empty() {
        return Err(invalid_data("targets must be a non-empty list"));
    }

    let mut targets = HashSet::new();
    let mut has_runtime = false;
    let mut has_coverage = false;
    for entry in &registry.targets {
        if !is_target_triple(&entry.target) {
            return Err(invalid_data(format!(
                "target is not approved: {:?}",
                entry.target
            )));
        }
        if !targets.insert(entry.target.as_str()) {
            return Err(invalid_data(format!(
                "target must be unique: {:?}",
                entry.target
            )));
        }
        if entry.platform.is_empty() {
            return Err(invalid_data(format!(
                "platform must be non-empty for {}",
                entry.target
            )));
        }
        has_runtime |= entry.evidence == EvidenceLevel::Runtime;
        if entry.evidence == EvidenceLevel::NotCovered {
            if entry.allocation != AllocationCapability::Unknown || entry.ci.is_some() {
                return Err(invalid_data(format!(
                    "not-covered target {} must use unknown allocation and no CI",
                    entry.target
                )));
            }
            continue;
        }
        if entry.allocation == AllocationCapability::Unknown {
            return Err(invalid_data(format!(
                "covered target {} must declare allocation capability",
                entry.target
            )));
        }
        let ci = entry
            .ci
            .as_ref()
            .ok_or_else(|| invalid_data(format!("CI metadata missing for {}", entry.target)))?;
        if !is_ci_job_name(&ci.job) {
            return Err(invalid_data(format!(
                "invalid CI job name for {}",
                entry.target
            )));
        }
        if ci.toolchains.is_empty() {
            return Err(invalid_data(format!(
                "toolchains missing for {}",
                entry.target
            )));
        }
        if entry.evidence == EvidenceLevel::Runtime
            && ci.toolchains != [rust_version.to_owned(), "stable".to_owned()]
        {
            return Err(invalid_data(format!(
                "runtime target {} must use Rust {rust_version} and stable",
                entry.target
            )));
        }
        if entry.evidence == EvidenceLevel::Compile
            && ci.toolchains != [rust_version.to_owned()]
            && ci.toolchains != ["nightly".to_owned()]
        {
            return Err(invalid_data(format!(
                "compile target {} must use Rust {rust_version} or nightly",
                entry.target
            )));
        }
        if ci.coverage && entry.evidence != EvidenceLevel::Runtime {
            return Err(invalid_data(format!(
                "compile target {} cannot provide native coverage",
                entry.target
            )));
        }
        has_coverage |= ci.coverage;
    }
    if !has_runtime {
        return Err(invalid_data("at least one runtime target is required"));
    }
    if !has_coverage {
        return Err(invalid_data(
            "at least one native coverage target is required",
        ));
    }
    Ok(())
}

fn matrices(registry: &SupportRegistry) -> BTreeMap<String, Matrix> {
    let mut generated = BTreeMap::<String, Matrix>::new();
    for entry in &registry.targets {
        let Some(ci) = &entry.ci else { continue };
        let matrix = generated.entry(ci.job.clone()).or_insert_with(|| Matrix {
            include: Vec::new(),
        });
        for toolchain in &ci.toolchains {
            matrix.include.push(MatrixEntry {
                os: ci.runner.as_str().to_owned(),
                target: entry.target.clone(),
                toolchain: toolchain.clone(),
            });
        }
    }
    generated.insert(
        "coverage".to_owned(),
        Matrix {
            include: registry
                .targets
                .iter()
                .filter_map(|entry| {
                    let ci = entry.ci.as_ref()?;
                    ci.coverage.then(|| MatrixEntry {
                        os: ci.runner.as_str().to_owned(),
                        target: entry.target.clone(),
                        toolchain: ci.toolchains[0].clone(),
                    })
                })
                .collect(),
        },
    );
    generated
}

fn validate_workflow(registry: &SupportRegistry, workflow: &Value) -> Result<()> {
    validate_workflow_policy(workflow)?;
    let jobs = workflow
        .get("jobs")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data("workflow must define a jobs object"))?;
    let generated = matrices(registry);
    let declared = generated.keys().map(String::as_str).collect::<HashSet<_>>();

    for (job_name, job) in jobs {
        let job = job
            .as_object()
            .ok_or_else(|| invalid_data(format!("workflow job {job_name} must be an object")))?;
        let configured = job
            .get("strategy")
            .and_then(Value::as_object)
            .and_then(|strategy| strategy.get("matrix"));
        match configured {
            Some(Value::String(expression)) if expression.contains("fromJSON") => {
                return Err(invalid_data(format!(
                    "workflow must not consume a runtime-generated matrix: {expression}"
                )));
            }
            Some(configured) if declared.contains(job_name.as_str()) => {
                let expected = serde_json::to_value(&generated[job_name])?;
                if configured != &expected {
                    return Err(invalid_data(format!(
                        "workflow job {job_name} literal matrix drifted from support data"
                    )));
                }
            }
            None if declared.contains(job_name.as_str()) => {
                return Err(invalid_data(format!(
                    "workflow job {job_name} must define a literal support matrix"
                )));
            }
            _ => {}
        }
    }
    let missing = declared
        .into_iter()
        .filter(|job| !jobs.contains_key(*job))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(invalid_data(format!(
            "workflow support jobs are missing: {missing:?}"
        )));
    }

    let triggers = workflow
        .get("on")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data("workflow must define triggers"))?;
    if !triggers.contains_key("workflow_dispatch") {
        return Err(invalid_data("workflow must retain a manual trigger"));
    }
    if triggers.get("schedule") != Some(&serde_json::json!([{ "cron": "17 1 1 * *" }])) {
        return Err(invalid_data("workflow must retain the monthly canary"));
    }
    Ok(())
}

fn validate_workflow_policy(workflow: &Value) -> Result<()> {
    let jobs = workflow
        .get("jobs")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data("workflow must define a jobs object"))?;
    for (job_name, job) in jobs {
        let job = job
            .as_object()
            .ok_or_else(|| invalid_data(format!("workflow job {job_name} must be an object")))?;
        if let Some(action) = job.get("uses").and_then(Value::as_str) {
            validate_action(action)?;
        }
        let Some(steps) = job.get("steps") else {
            continue;
        };
        let steps = steps
            .as_array()
            .ok_or_else(|| invalid_data(format!("workflow job {job_name} steps must be a list")))?;
        for step in steps {
            let step = step.as_object().ok_or_else(|| {
                invalid_data(format!("workflow job {job_name} contains an invalid step"))
            })?;
            if let Some(action) = step.get("uses").and_then(Value::as_str) {
                validate_action(action)?;
            }
            if let Some(command) = step.get("run").and_then(Value::as_str) {
                if has_unquoted_matrix_target(command) {
                    return Err(invalid_data(format!(
                        "workflow job {job_name} uses an unquoted matrix target"
                    )));
                }
                validate_locked_cargo(job_name, command)?;
            }
        }
    }
    Ok(())
}

fn validate_action(action: &str) -> Result<()> {
    if action.starts_with("./") || pinned_action(action) {
        Ok(())
    } else {
        Err(invalid_data(format!(
            "workflow action is not pinned to a commit: {action}"
        )))
    }
}

fn validate_locked_cargo(job_name: &str, command: &str) -> Result<()> {
    for invocation in shell_segments(command)? {
        for cargo_index in invocation
            .iter()
            .enumerate()
            .filter_map(|(index, token)| cargo_executable(token).then_some(index))
        {
            let mut words = invocation[cargo_index + 1..].iter().map(String::as_str);
            let mut subcommand = words.next().unwrap_or_default();
            if subcommand.starts_with('+') {
                subcommand = words.next().unwrap_or_default();
            }
            let exempt = matches!(subcommand, "audit" | "deny" | "fmt" | "xtask");
            let locked = invocation[cargo_index + 1..]
                .iter()
                .any(|argument| argument == "--locked");
            if !exempt && !locked {
                return Err(invalid_data(format!(
                    "workflow cargo command is not locked in {job_name}: {}",
                    invocation.join(" ")
                )));
            }
        }
    }
    Ok(())
}

fn cargo_executable(token: &str) -> bool {
    token.rsplit(['/', '\\']).next().is_some_and(|name| {
        name.eq_ignore_ascii_case("cargo") || name.eq_ignore_ascii_case("cargo.exe")
    })
}

fn shell_segments(command: &str) -> Result<Vec<Vec<String>>> {
    let mut segments = Vec::new();
    let mut segment = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            segment.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            segment.push(character);
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            segment.push(character);
            continue;
        }
        if quote.is_none() && matches!(character, '&' | '|' | ';' | '\n' | '\r') {
            if !segment.trim().is_empty() {
                segments.push(shell_words(segment.trim())?);
            }
            segment.clear();
        } else {
            segment.push(character);
        }
    }
    if quote.is_some() || escaped {
        return Err(invalid_data(
            "workflow command contains unterminated quoting",
        ));
    }
    if !segment.trim().is_empty() {
        segments.push(shell_words(segment.trim())?);
    }
    Ok(segments)
}

fn shell_words(segment: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in segment.chars() {
        if escaped {
            word.push(character);
            escaped = false;
        } else if character == '\\' && quote != Some('\'') {
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                word.push(character);
            }
        } else if character.is_whitespace() && quote.is_none() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(character);
        }
    }
    if quote.is_some() || escaped {
        return Err(invalid_data(
            "workflow command contains unterminated quoting",
        ));
    }
    if !word.is_empty() {
        words.push(word);
    }
    Ok(words)
}

fn is_target_triple(value: &str) -> bool {
    value.is_ascii()
        && value.split('-').count() >= 3
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn pinned_action(action: &str) -> bool {
    action.rsplit_once('@').is_some_and(|(_, revision)| {
        revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn is_ci_job_name(value: &str) -> bool {
    value.is_ascii()
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn has_unquoted_matrix_target(command: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index < command.len() {
        if command[index..].starts_with(MATRIX_TARGET_EXPRESSION) {
            if quote.is_none() {
                return true;
            }
            index += MATRIX_TARGET_EXPRESSION.len();
            escaped = false;
            continue;
        }
        let byte = command.as_bytes()[index];
        if matches!(byte, b'\'' | b'"') && !escaped {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
        }
        escaped = byte == b'\\' && quote != Some(b'\'') && !escaped;
        index += 1;
    }
    false
}

fn write_github_output(
    path: &Path,
    generated: &BTreeMap<String, Matrix>,
    rust_version: &str,
) -> Result<()> {
    let mut output = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(output, "matrices={}", serde_json::to_string(generated)?)?;
    writeln!(output, "rust_version={rust_version}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_registry() -> SupportRegistry {
        load_registry(&crate::repository_root().join("support-matrix.json")).unwrap()
    }

    #[test]
    fn repository_registry_and_workflow_agree() {
        let registry = repository_registry();
        validate_registry(&registry, "1.88").unwrap();
        let workflow =
            load_workflow(&crate::repository_root().join(".github/workflows/ci.yml")).unwrap();
        validate_workflow(&registry, &workflow).unwrap();
        let release_gates =
            load_workflow(&crate::repository_root().join(".github/workflows/release-gates.yml"))
                .unwrap();
        validate_workflow_policy(&release_gates).unwrap();
    }

    #[test]
    fn rejects_duplicate_or_unapproved_targets() {
        let mut registry = repository_registry();
        registry.targets[1].target = registry.targets[0].target.clone();
        assert!(validate_registry(&registry, "1.88").is_err());
        registry.targets[1].target = "$(echo injected)".to_owned();
        assert!(validate_registry(&registry, "1.88").is_err());
    }

    #[test]
    fn rejects_mutable_actions_and_unquoted_targets() {
        assert!(!pinned_action("actions/checkout@v4"));
        assert!(pinned_action(
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
        ));
        assert!(has_unquoted_matrix_target(
            "cargo check --target ${{ matrix.target }}"
        ));
        assert!(!has_unquoted_matrix_target(
            "cargo check --target \"${{ matrix.target }}\""
        ));
        assert!(validate_locked_cargo("test", "echo preparing\ncargo test").is_err());
        assert!(validate_locked_cargo("test", "cargo check --locked && cargo test").is_err());
        assert!(validate_locked_cargo("test", "cargo.exe test").is_err());
        assert!(validate_locked_cargo("test", "cargo\ttest").is_err());
        assert!(validate_locked_cargo("test", "/opt/rust/bin/cargo test").is_err());
        assert!(
            validate_locked_cargo("test", "cargo check --locked && cargo test --locked").is_ok()
        );
    }

    #[test]
    fn generates_every_declared_matrix() {
        let registry = repository_registry();
        let generated = matrices(&registry);
        assert!(generated.contains_key("check"));
        assert!(generated.contains_key("cross_check"));
        assert!(generated.contains_key("mingw"));
        assert!(generated.contains_key("uclibc"));
        assert_eq!(generated["coverage"].include.len(), 3);
    }
}
