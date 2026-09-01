use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::process;
use crate::{Result, invalid_data, lower_hex};

const EXPECTED_CONSUMER_SHA256: &str =
    "3f3b5ea95f12828437a8e851baad8cc58eee3a6206f5957748248195f6ceab29";
const LEGACY_CHECKSUM: &str = "9564fc758e15025b46aa6643b1b77d047d1a56a1aea6e01002ac0c7026876213";
const SUBJECTS: [&str; 2] = ["legacy", "current"];
const REQUIRED_EDITIONS: [&str; 4] = ["2015", "2018", "2021", "2024"];

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    edition: String,
    source: Option<String>,
    manifest_path: PathBuf,
    dependencies: Vec<CargoDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    name: String,
    req: String,
    source: Option<String>,
    path: Option<PathBuf>,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let compatibility = root.join("compatibility");
    let manifest = compatibility.join("Cargo.toml");
    let consumer = compatibility.join("v04_consumer.rs");
    let digest = consumer_digest(&consumer)?;
    if digest != EXPECTED_CONSUMER_SHA256 {
        return Err(invalid_data(
            "frozen v0.4 consumer changed; update its digest only after an intentional API review",
        ));
    }
    println!("v0.4 consumer sha256={digest}");
    validate_lockfile(&compatibility.join("Cargo.lock"))?;
    let target = root
        .join("target/xtask/compatibility")
        .join(process::toolchain_key()?);
    let mut format = process::cargo();
    format
        .current_dir(root)
        .args(["fmt", "--manifest-path"])
        .arg(&manifest)
        .args(["--all", "--", "--check"]);
    process::run(&mut format, "format compatibility fixtures")?;

    let packages = compatibility_packages(root, &manifest, &target)?;
    validate_dependencies(root, &packages)?;

    for subject in SUBJECTS {
        let mut check = process::cargo();
        check
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &target)
            .args(["check", "--workspace", "--manifest-path"])
            .arg(&manifest)
            .args(["--no-default-features", "--features", subject, "--locked"]);
        process::run(
            &mut check,
            &format!("check {subject} compatibility surface"),
        )?;
    }

    for package in &packages {
        for subject in SUBJECTS {
            let mut run = process::cargo();
            run.current_dir(root)
                .env("CARGO_TARGET_DIR", &target)
                .args(["run", "--manifest-path"])
                .arg(&manifest)
                .args([
                    "--package",
                    package.name.as_str(),
                    "--no-default-features",
                    "--features",
                    subject,
                    "--locked",
                ]);
            process::run(
                &mut run,
                &format!("run {subject} v0.4 consumer in edition {}", package.edition),
            )?;
        }
    }
    Ok(())
}

fn validate_resolved_fs2(root: &Path, packages: &[CargoPackage]) -> Result<()> {
    let resolved = packages
        .iter()
        .filter(|package| package.name == "fs2")
        .collect::<Vec<_>>();
    let legacy = resolved.iter().any(|package| {
        package.version == "0.4.3"
            && package.source.as_deref()
                == Some("registry+https://github.com/rust-lang/crates.io-index")
    });
    let current_manifest = root.join("Cargo.toml").canonicalize()?;
    let current = resolved.iter().any(|package| {
        package.source.is_none()
            && package
                .manifest_path
                .canonicalize()
                .is_ok_and(|path| path == current_manifest)
    });
    if resolved.len() != 2 || !legacy || !current {
        return Err(invalid_data(
            "resolved compatibility graph must contain only approved fs2 0.4.3 and the current checkout",
        ));
    }
    Ok(())
}

fn validate_lockfile(path: &Path) -> Result<()> {
    let contents = fs::read_to_string(path)?;
    let legacy = format!(
        "name = \"fs2\"\nversion = \"0.4.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{LEGACY_CHECKSUM}\""
    );
    if !contents.replace("\r\n", "\n").contains(&legacy)
        || contents.matches("name = \"fs2\"").count() != 2
    {
        return Err(invalid_data(
            "compatibility lockfile does not contain exactly the approved legacy and current fs2 packages",
        ));
    }
    Ok(())
}

fn validate_dependencies(root: &Path, packages: &[CargoPackage]) -> Result<()> {
    let current = root.canonicalize()?;
    for package in packages {
        let fs2_dependencies = package
            .dependencies
            .iter()
            .filter(|dependency| dependency.name == "fs2")
            .collect::<Vec<_>>();
        let legacy = fs2_dependencies.iter().any(|dependency| {
            dependency.req == "=0.4.3"
                && dependency.path.is_none()
                && dependency.source.as_deref()
                    == Some("registry+https://github.com/rust-lang/crates.io-index")
        });
        let current_path = fs2_dependencies.iter().any(|dependency| {
            dependency.source.is_none()
                && dependency
                    .path
                    .as_deref()
                    .and_then(|path| path.canonicalize().ok())
                    .is_some_and(|path| path == current)
        });
        if fs2_dependencies.len() != 2 || !legacy || !current_path {
            return Err(invalid_data(format!(
                "{} must depend on exact fs2 0.4.3 and the current checkout",
                package.name
            )));
        }
    }
    Ok(())
}

fn consumer_digest(path: &Path) -> Result<String> {
    let contents = fs::read_to_string(path)?;
    Ok(digest_contents(&contents))
}

fn digest_contents(contents: &str) -> String {
    let normalized = contents.replace("\r\n", "\n").replace('\r', "\n");
    lower_hex(Sha256::digest(normalized.as_bytes()))
}

fn compatibility_packages(
    root: &Path,
    manifest: &Path,
    target: &Path,
) -> Result<Vec<CargoPackage>> {
    let mut command = process::cargo();
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target)
        .args(["metadata", "--manifest-path"])
        .arg(manifest)
        .args(["--format-version", "1", "--locked", "--all-features"]);
    let output = process::capture(&mut command, "read compatibility metadata")?;
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)?;
    validate_resolved_fs2(root, &metadata.packages)?;
    let mut packages = metadata
        .packages
        .into_iter()
        .filter(|package| package.name.starts_with("fs2-compat-edition-"))
        .collect::<Vec<_>>();
    packages.sort_by(|left, right| left.edition.cmp(&right.edition));
    if packages.is_empty() {
        return Err(invalid_data(
            "compatibility workspace has no edition packages",
        ));
    }
    let editions = packages
        .iter()
        .map(|package| package.edition.as_str())
        .collect::<HashSet<_>>();
    if editions.len() != packages.len() {
        return Err(invalid_data(
            "compatibility workspace has duplicate Rust editions",
        ));
    }
    let required = REQUIRED_EDITIONS.into_iter().collect::<HashSet<_>>();
    if editions != required {
        return Err(invalid_data(
            "compatibility workspace must cover editions 2015, 2018, 2021, and 2024 exactly",
        ));
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_consumer_digest_matches() {
        let consumer = crate::repository_root().join("compatibility/v04_consumer.rs");
        assert_eq!(
            consumer_digest(&consumer).unwrap(),
            EXPECTED_CONSUMER_SHA256
        );
    }

    #[test]
    fn changed_consumer_has_a_different_digest() {
        assert_ne!(
            digest_contents("original\n"),
            digest_contents("original\n\n")
        );
    }
}
