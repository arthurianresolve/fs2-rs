use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

use crate::process::{self, ProcessRecord};
use crate::{Result, invalid_data, lower_hex};

pub(crate) fn default_output(root: &Path, prefix: &str) -> Result<PathBuf> {
    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(root
        .join("target/measurement-runs")
        .join(format!("{prefix}-{epoch}")))
}

pub(crate) fn hash_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(lower_hex(digest.finalize()))
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    lower_hex(Sha256::digest(bytes))
}

pub(crate) fn normalized_text_hash(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    Ok(lower_hex(Sha256::digest(normalized.as_bytes())))
}

pub(crate) fn retain_artifact(source: &Path, destination: &Path) -> Result<PathBuf> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)?;
    Ok(destination.to_owned())
}

pub(crate) fn retain_bytes(bytes: &[u8], destination: &Path) -> Result<PathBuf> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    destination_file.write_all(bytes)?;
    Ok(destination.to_owned())
}

#[derive(Deserialize)]
struct CargoArtifactMessage {
    reason: String,
    target: Option<CargoTarget>,
    executable: Option<PathBuf>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoMetadataPackage>,
}

#[derive(Deserialize)]
struct CargoMetadataPackage {
    name: String,
    manifest_path: PathBuf,
    source: Option<String>,
    targets: Vec<CargoMetadataTarget>,
}

#[derive(Deserialize)]
struct CargoMetadataTarget {
    src_path: PathBuf,
}

pub(crate) fn cargo_executable(message_log: &Path, target_name: &str) -> Result<PathBuf> {
    let contents = fs::read_to_string(message_log)?;
    let mut executable = None;
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let message = serde_json::from_str::<CargoArtifactMessage>(line).map_err(|error| {
            invalid_data(format!(
                "malformed Cargo JSON message on line {}: {error}",
                index + 1
            ))
        })?;
        if message.reason == "compiler-artifact"
            && message
                .target
                .as_ref()
                .is_some_and(|target| target.name == target_name)
            && let Some(path) = message.executable
        {
            executable = Some(path);
        }
    }
    executable.filter(|path| path.is_file()).ok_or_else(|| {
        invalid_data(format!(
            "Cargo did not report an executable artifact for {target_name}"
        ))
    })
}

pub(crate) struct TemporaryWorkspace {
    #[cfg(unix)]
    _guard: Vec<std::os::fd::OwnedFd>,
    #[cfg(windows)]
    _guard: Vec<fs::File>,
    temporary: tempfile::TempDir,
}

#[cfg(windows)]
pub(crate) type DirectoryGuard = Vec<fs::File>;
#[cfg(unix)]
pub(crate) type DirectoryGuard = Vec<std::os::fd::OwnedFd>;
#[cfg(not(any(unix, windows)))]
pub(crate) type DirectoryGuard = ();

#[cfg(windows)]
pub(crate) fn retain_directory_ancestry(path: &Path, label: &str) -> Result<DirectoryGuard> {
    if !path.is_dir() {
        return Err(invalid_data(format!(
            "{label} must be an existing directory: {}",
            path.display()
        )));
    }
    super::windows_security::guard_directory_ancestry(path)
}

#[cfg(unix)]
pub(crate) fn retain_directory_ancestry(path: &Path, label: &str) -> Result<DirectoryGuard> {
    if !path.is_dir() {
        return Err(invalid_data(format!(
            "{label} must be an existing directory: {}",
            path.display()
        )));
    }
    Ok(super::unix_security::prepare_directory(
        path, label, false, false,
    )?)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn retain_directory_ancestry(_path: &Path, label: &str) -> Result<DirectoryGuard> {
    Err(invalid_data(format!(
        "{label} ancestry retention is unavailable on this platform"
    )))
}

impl TemporaryWorkspace {
    pub(crate) fn path(&self) -> &Path {
        self.temporary.path()
    }
}

pub(crate) fn temporary_workspace(root: &Path, prefix: &str) -> Result<TemporaryWorkspace> {
    let configured = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let target = if configured.is_absolute() {
        configured
    } else {
        root.join(configured)
    };
    #[cfg(all(not(unix), not(windows)))]
    fs::create_dir_all(&target)?;
    #[cfg(unix)]
    let mut guard =
        super::unix_security::prepare_directory(&target, "benchmark workspace target", true, true)?;
    #[cfg(windows)]
    {
        let parent = target.join(".fs2-secure-workspaces");
        let mut guard =
            super::windows_security::create_or_open_trusted_directory_ancestry(&target)?;
        guard.push(super::windows_security::create_or_open_private_directory(
            &parent,
        )?);
        let temporary = tempfile::Builder::new().prefix(prefix).tempdir_in(parent)?;
        guard.push(super::windows_security::harden_new_private_directory(
            temporary.path(),
        )?);
        Ok(TemporaryWorkspace {
            _guard: guard,
            temporary,
        })
    }
    #[cfg(unix)]
    {
        let temporary = tempfile::Builder::new().prefix(prefix).tempdir_in(target)?;
        guard.extend(super::unix_security::prepare_directory(
            temporary.path(),
            "benchmark temporary workspace",
            false,
            false,
        )?);
        Ok(TemporaryWorkspace {
            _guard: guard,
            temporary,
        })
    }

    #[cfg(all(not(windows), not(unix)))]
    {
        let temporary = tempfile::Builder::new().prefix(prefix).tempdir_in(target)?;
        Ok(TemporaryWorkspace { temporary })
    }
}

pub(crate) fn repository_state(path: &Path, label: &str) -> Result<(PathBuf, String)> {
    let path = path.canonicalize()?;
    if !path.join("Cargo.toml").is_file() {
        return Err(invalid_data(format!(
            "{label} is not a crate checkout: {}",
            path.display()
        )));
    }
    let commit = git_text(&path, ["rev-parse", "HEAD"], "resolve checkout commit")?;
    let ignored = git_output(
        &path,
        ["status", "--porcelain=v1", "-z", "--ignored=matching"],
        "inspect ignored checkout material",
    )?;
    if ignored
        .stdout
        .split(|byte| *byte == 0)
        .any(repository_state_record_is_dirty)
    {
        return Err(invalid_data(format!(
            "{label} checkout contains ignored material that copy_tree would stage: {}",
            path.display()
        )));
    }
    Ok((path, commit.trim().to_owned()))
}

pub(crate) fn resolve_ref(repo: &Path, revision: &str) -> Result<String> {
    git_text(
        repo,
        ["rev-parse", "--verify", &format!("{revision}^{{commit}}")],
        "resolve Git revision",
    )
    .map(|value| value.trim().to_owned())
}

pub(crate) fn clone_revision(
    repo: &Path,
    destination: &Path,
    revision: &str,
    log_root: &Path,
    label: &str,
) -> Result<Vec<ProcessRecord>> {
    let mut clone = Command::new("git");
    enable_git_long_paths(&mut clone);
    clone
        .args(["clone", "--shared", "--no-checkout", "--quiet"])
        .arg(git_local_path(repo)?)
        .arg(destination);
    let clone_record = process::run_logged_attempt(
        &mut clone,
        format!("clone {label} benchmark source"),
        &log_root.join(format!("{label}.clone.stdout.log")),
        &log_root.join(format!("{label}.clone.stderr.log")),
    );
    let mut checkout = Command::new("git");
    enable_git_long_paths(&mut checkout);
    checkout
        .current_dir(destination)
        .args(["checkout", "--detach", "--quiet", revision]);
    let checkout_record = if clone_record.succeeded() {
        process::run_logged_attempt(
            &mut checkout,
            format!("checkout {label} benchmark revision"),
            &log_root.join(format!("{label}.checkout.stdout.log")),
            &log_root.join(format!("{label}.checkout.stderr.log")),
        )
    } else {
        ProcessRecord::skipped(
            &checkout,
            format!("checkout {label} benchmark revision"),
            log_root.join(format!("{label}.checkout.stdout.log")),
            log_root.join(format!("{label}.checkout.stderr.log")),
            "clone failed",
        )
    };
    Ok(vec![clone_record, checkout_record])
}

#[cfg(windows)]
fn enable_git_long_paths(command: &mut Command) {
    command.args(["-c", "core.longpaths=true"]);
}

#[cfg(not(windows))]
fn enable_git_long_paths(_command: &mut Command) {}

fn git_local_path(path: &Path) -> Result<std::ffi::OsString> {
    let path = path.canonicalize()?;
    #[cfg(unix)]
    let path = path.into_os_string();
    #[cfg(windows)]
    let path = {
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

        const VERBATIM: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
        const UNC: &[u16] = &[b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
        let encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if let Some(path) = encoded
            .strip_prefix(VERBATIM)
            .and_then(|path| path.strip_prefix(UNC))
        {
            let mut native = vec![b'\\' as u16, b'\\' as u16];
            native.extend_from_slice(path);
            std::ffi::OsString::from_wide(&native)
        } else {
            std::ffi::OsString::from_wide(encoded.strip_prefix(VERBATIM).unwrap_or(&encoded))
        }
    };
    Ok(path)
}

pub(crate) fn tree_digest(path: &Path) -> Result<String> {
    let mut entries = Vec::new();
    let mut walker = WalkDir::new(path).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        let entry = entry?;
        if !included_entry(path, &entry) {
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        if entry.file_type().is_symlink() || tree_entry_is_windows_reparse_point(entry.path())? {
            return Err(invalid_data(format!(
                "tree digest rejects links and reparse points: {}",
                entry.path().display()
            )));
        }
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.path().to_owned());
    let mut digest = Sha256::new();
    digest.update(b"fs2-tree-digest-v2\0");
    for entry in entries {
        let relative = entry.path().strip_prefix(path)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if entry.file_type().is_dir() {
            digest.update(b"D");
            update_path_digest(&mut digest, relative)?;
            update_metadata_digest(&mut digest, entry.path())?;
            continue;
        }
        if !entry.file_type().is_file() || entry.path().extension() == Some(OsStr::new("pyc")) {
            continue;
        }
        digest.update(b"F");
        update_path_digest(&mut digest, relative)?;
        update_metadata_digest(&mut digest, entry.path())?;
        let metadata = fs::metadata(entry.path())?;
        digest.update(metadata.len().to_le_bytes());
        let mut reader = BufReader::new(File::open(entry.path())?);
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
    }
    Ok(lower_hex(digest.finalize()))
}

#[cfg(windows)]
fn tree_entry_is_windows_reparse_point(path: &Path) -> Result<bool> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    Ok(fs::symlink_metadata(path)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(not(windows))]
fn tree_entry_is_windows_reparse_point(_path: &Path) -> Result<bool> {
    Ok(false)
}

fn update_metadata_digest(digest: &mut Sha256, path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        digest.update(metadata.mode().to_le_bytes());
    }
    #[cfg(not(unix))]
    digest.update([u8::from(metadata.permissions().readonly())]);
    Ok(())
}

fn update_path_digest(digest: &mut Sha256, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        digest.update(b"unix\0");
        let bytes = path.as_os_str().as_bytes();
        digest.update(
            u64::try_from(bytes.len())
                .map_err(|_| invalid_data("tree path is too long to hash"))?
                .to_le_bytes(),
        );
        digest.update(bytes);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        digest.update(b"windows-utf16le\0");
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        let byte_len = units
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|length| u64::try_from(length).ok())
            .ok_or_else(|| invalid_data("tree path is too long to hash"))?;
        digest.update(byte_len.to_le_bytes());
        for unit in units {
            digest.update(unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        digest.update(b"portable\0");
        let path = path.to_string_lossy();
        digest.update(
            u64::try_from(path.len())
                .map_err(|_| invalid_data("tree path is too long to hash"))?
                .to_le_bytes(),
        );
        digest.update(path.as_bytes());
    }
    Ok(())
}

pub(crate) fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        return Err(invalid_data(format!(
            "copy destination already exists: {}",
            destination.display()
        )));
    }
    for entry in WalkDir::new(source)
        .into_iter()
        .filter_entry(|entry| included_entry(source, entry))
    {
        let entry = entry?;
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() && entry.path().extension() != Some(OsStr::new("pyc"))
        {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
            fs::set_permissions(&target, fs::metadata(entry.path())?.permissions())?;
        } else if entry.file_type().is_symlink() {
            return Err(invalid_data(format!(
                "benchmark staging does not follow symlinks: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn included_entry(root: &Path, entry: &DirEntry) -> bool {
    let Ok(relative) = entry.path().strip_prefix(root) else {
        return false;
    };
    let Some(first) = relative.components().next() else {
        return true;
    };
    !matches!(
        first.as_os_str().to_str(),
        Some(".git" | "target" | "__pycache__")
    )
}

pub(crate) fn prepare_harness(
    root: &Path,
    name: &str,
    repository: &Path,
    package_name: &str,
    benchmark_inputs: &Path,
    lockfile: &Path,
) -> Result<PathBuf> {
    let package = root.join(name);
    copy_tree(benchmark_inputs, &package)?;
    fs::copy(lockfile, package.join("Cargo.lock"))?;
    let manifest = package.join("Cargo.toml");
    let text = fs::read_to_string(&manifest)?;
    let repository = repository
        .to_str()
        .ok_or_else(|| invalid_data("benchmark repository path is not valid Unicode"))?
        .replace('\\', "/");
    let replacement = match package_name {
        "fs2" => format!("fs2 = {{ path = {repository:?} }}"),
        "fs4" => format!(
            "fs2 = {{ package = \"fs4\", path = {repository:?}, default-features = false, features = [\"sync\"] }}"
        ),
        _ => {
            return Err(invalid_data(format!(
                "unsupported subject package: {package_name}"
            )));
        }
    };
    let rewritten = rewrite_subject_dependency(&text, &replacement)?;
    fs::write(&manifest, format!("{rewritten}\n[workspace]\n"))?;
    Ok(manifest)
}

fn rewrite_subject_dependency(manifest: &str, replacement: &str) -> Result<String> {
    const SUBJECT_DEPENDENCY: &str = "fs2 = { path = \"..\" }";
    if manifest
        .lines()
        .filter(|line| line.trim() == SUBJECT_DEPENDENCY)
        .count()
        != 1
    {
        return Err(invalid_data(
            "benchmark manifest must contain exactly one canonical fs2 dependency",
        ));
    }
    if manifest.lines().any(|line| line.trim() == "[workspace]") {
        return Err(invalid_data(
            "benchmark manifest already declares a workspace",
        ));
    }

    let mut output = String::with_capacity(manifest.len() + replacement.len());
    for line in manifest.lines() {
        if line.trim() == SUBJECT_DEPENDENCY {
            output.push_str(replacement);
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    Ok(output.trim_end().to_owned())
}

pub(crate) fn processes_succeeded(processes: &[ProcessRecord]) -> bool {
    processes.iter().all(ProcessRecord::succeeded)
}

pub(crate) fn subject_features(benchmark: &str, package_name: &str) -> Result<Vec<String>> {
    if benchmark == "fs_compat" {
        Ok(vec![
            "--no-default-features".to_owned(),
            "--features".to_owned(),
            format!("subject-{package_name}"),
        ])
    } else if package_name == "fs2" {
        Ok(Vec::new())
    } else {
        Err(invalid_data(format!(
            "benchmark {benchmark} does not support package {package_name}"
        )))
    }
}

pub(crate) fn generate_lockfile(
    root: &Path,
    manifest: &Path,
    target: &Path,
    log_root: &Path,
    label: &str,
) -> Result<ProcessRecord> {
    let mut command = process::cargo();
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target)
        .args(["generate-lockfile", "--manifest-path"])
        .arg(manifest)
        .arg("--offline");
    Ok(process::run_logged_attempt(
        &mut command,
        format!("generate {label} lockfile"),
        &log_root.join(format!("{label}.lock.stdout.log")),
        &log_root.join(format!("{label}.lock.stderr.log")),
    ))
}

pub(crate) fn prebuild(
    root: &Path,
    manifest: &Path,
    target: &Path,
    benchmark: &str,
    features: &[String],
    log_root: &Path,
    label: &str,
) -> Result<ProcessRecord> {
    let mut command = process::cargo();
    command
        .current_dir(root)
        .args(["bench", "--manifest-path"])
        .arg(manifest)
        .args([
            "--bench",
            benchmark,
            "--no-run",
            "--locked",
            "--offline",
            "--message-format=json-render-diagnostics",
            "--target-dir",
        ])
        .arg(target)
        .args(features);
    Ok(process::run_logged_attempt(
        &mut command,
        format!("prebuild {label} {benchmark}"),
        &log_root.join(format!("{label}-{benchmark}.stdout.log")),
        &log_root.join(format!("{label}-{benchmark}.stderr.log")),
    ))
}

pub(crate) fn validate_path_dependencies(
    working_directory: &Path,
    manifest: &Path,
    features: &[String],
    source_roots: &[&Path],
) -> Result<()> {
    let harness_root = manifest
        .parent()
        .ok_or_else(|| invalid_data("benchmark manifest has no parent"))?
        .canonicalize()?;
    let mut digested_roots = Vec::with_capacity(source_roots.len() + 1);
    digested_roots.push(harness_root);
    for root in source_roots {
        digested_roots.push(root.canonicalize()?);
    }
    digested_roots.sort();
    digested_roots.dedup();

    let mut command = process::cargo();
    command
        .current_dir(working_directory)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--manifest-path",
        ])
        .arg(manifest)
        .args(features);
    let output = process::capture(&mut command, "resolve strict benchmark dependency closure")?;
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)?;
    validate_metadata_path_dependencies(&metadata, &digested_roots)
}

fn validate_metadata_path_dependencies(
    metadata: &CargoMetadata,
    digested_roots: &[PathBuf],
) -> Result<()> {
    if metadata.packages.is_empty() {
        return Err(invalid_data(
            "Cargo metadata returned an empty package graph",
        ));
    }
    for package in metadata
        .packages
        .iter()
        .filter(|package| package.source.is_none())
    {
        let manifest = package.manifest_path.canonicalize()?;
        let package_root = manifest
            .parent()
            .ok_or_else(|| invalid_data("Cargo package manifest has no parent"))?;
        if !digested_roots
            .iter()
            .any(|root| tree_digest_covers(root, package_root))
        {
            return Err(invalid_data(format!(
                "strict benchmark dependency {} resolves outside the recorded source trees: {}",
                package.name,
                manifest.display()
            )));
        }
        for target in &package.targets {
            let source = target.src_path.canonicalize()?;
            if !digested_roots
                .iter()
                .any(|root| tree_digest_covers(root, &source))
            {
                return Err(invalid_data(format!(
                    "strict benchmark target for {} resolves outside the recorded source trees: {}",
                    package.name,
                    source.display()
                )));
            }
        }
    }
    Ok(())
}

fn tree_digest_covers(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    relative.components().next().is_none_or(|component| {
        !matches!(
            component.as_os_str().to_str(),
            Some(".git" | "target" | "__pycache__")
        )
    })
}

pub(crate) fn ensure_disk_headroom(path: &Path, minimum_free_bytes: u64) -> Result<()> {
    let stats = fs2::statvfs(path)?;
    if stats.available_space() < minimum_free_bytes {
        Err(invalid_data(format!(
            "benchmark workspace has {} available bytes; at least {minimum_free_bytes} are required",
            stats.available_space()
        )))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_output_headroom(output: &Path, minimum_free_bytes: u64) -> Result<()> {
    let mut probe = output;
    while !probe.exists() {
        probe = probe
            .parent()
            .ok_or_else(|| invalid_data("benchmark output has no existing ancestor"))?;
    }
    ensure_disk_headroom(probe, minimum_free_bytes)
}

fn git_text<const N: usize>(repo: &Path, arguments: [&str; N], label: &str) -> Result<String> {
    let output = git_output(repo, arguments, label)?;
    Ok(String::from_utf8(output.stdout)?)
}

fn git_output<const N: usize>(
    repo: &Path,
    arguments: [&str; N],
    label: &str,
) -> Result<std::process::Output> {
    let output = process::capture(
        Command::new("git")
            .current_dir(repo)
            .arg("-C")
            .arg(repo)
            .args(arguments),
        label,
    )?;
    Ok(output)
}

pub(crate) fn repository_state_record_is_dirty(record: &[u8]) -> bool {
    if record.is_empty() {
        return false;
    }
    if let Some(path) = record.strip_prefix(b"!! ") {
        return copy_tree_would_stage_ignored_entry(path);
    }
    true
}

fn copy_tree_would_stage_ignored_entry(path: &[u8]) -> bool {
    let Some(first_component) = path.split(|byte| *byte == b'/').next() else {
        return false;
    };
    if first_component == b".git"
        || first_component == b"target"
        || first_component == b"__pycache__"
    {
        return false;
    }
    let Some(file_name) = path.rsplit(|byte| *byte == b'/').next() else {
        return false;
    };
    let has_pyc_extension = file_name
        .iter()
        .rposition(|byte| *byte == b'.')
        .is_some_and(|dot| dot != 0 && &file_name[dot + 1..] == b"pyc");
    !has_pyc_extension
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn subject_features_reject_incompatible_workloads() {
        assert!(subject_features("fs2_legacy", "fs4").is_err());
        assert_eq!(
            subject_features("fs_compat", "fs4").unwrap(),
            ["--no-default-features", "--features", "subject-fs4"]
        );
    }

    #[test]
    fn cargo_executable_uses_the_reported_target_path() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("custom-target/release/probe.exe");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, []).unwrap();
        let log = directory.path().join("cargo.json");
        fs::write(
            &log,
            format!(
                "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"probe\"}},\"executable\":{}}}\n",
                serde_json::to_string(&executable).unwrap()
            ),
        )
        .unwrap();

        assert_eq!(cargo_executable(&log, "probe").unwrap(), executable);
    }

    #[test]
    fn tree_digest_includes_directory_topology() {
        let left = tempfile::tempdir().unwrap();
        let right = tempfile::tempdir().unwrap();
        fs::write(left.path().join("file"), b"same").unwrap();
        fs::write(right.path().join("file"), b"same").unwrap();
        fs::create_dir(left.path().join("empty")).unwrap();

        assert_ne!(
            tree_digest(left.path()).unwrap(),
            tree_digest(right.path()).unwrap()
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn tree_digest_rejects_links_and_reparse_points() {
        let tree = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(external.path(), tree.path().join("link")).unwrap();
        #[cfg(windows)]
        {
            let status = Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(tree.path().join("link"))
                .arg(external.path())
                .status()
                .unwrap();
            assert!(status.success());
        }

        assert!(tree_digest(tree.path()).is_err());
    }

    #[test]
    fn subject_dependency_rewrite_requires_the_canonical_manifest_line() {
        assert!(rewrite_subject_dependency("[dependencies]\nfs2=\"1\"", "replacement").is_err());
        assert_eq!(
            rewrite_subject_dependency(
                "[dependencies]\nfs2 = { path = \"..\" }\n",
                "fs2 = { path = \"subject\" }",
            )
            .unwrap(),
            "[dependencies]\nfs2 = { path = \"subject\" }"
        );
    }

    #[test]
    fn strict_dependency_closure_stays_inside_digested_trees() {
        let workspace = tempfile::tempdir().unwrap();
        let trusted = workspace.path().join("trusted");
        let external = workspace.path().join("external");
        let excluded = trusted.join("target/generated");
        for package in [&trusted, &external, &excluded] {
            fs::create_dir_all(package).unwrap();
            fs::write(
                package.join("Cargo.toml"),
                "[package]\nname='fixture'\nversion='0.0.0'\n",
            )
            .unwrap();
        }
        let roots = [trusted.canonicalize().unwrap()];
        let package = |name: &str, root: &Path| CargoMetadataPackage {
            name: name.to_owned(),
            manifest_path: root.join("Cargo.toml"),
            source: None,
            targets: Vec::new(),
        };

        let inside = CargoMetadata {
            packages: vec![package("inside", &trusted)],
        };
        assert!(validate_metadata_path_dependencies(&inside, &roots).is_ok());

        let outside = CargoMetadata {
            packages: vec![package("outside", &external)],
        };
        assert!(validate_metadata_path_dependencies(&outside, &roots).is_err());

        let ignored = CargoMetadata {
            packages: vec![package("ignored", &excluded)],
        };
        assert!(validate_metadata_path_dependencies(&ignored, &roots).is_err());

        let external_source = external.join("entry.rs");
        fs::write(&external_source, "pub fn external() {}\n").unwrap();
        let external_target = CargoMetadata {
            packages: vec![CargoMetadataPackage {
                name: "external-target".to_owned(),
                manifest_path: trusted.join("Cargo.toml"),
                source: None,
                targets: vec![CargoMetadataTarget {
                    src_path: external_source,
                }],
            }],
        };
        assert!(validate_metadata_path_dependencies(&external_target, &roots).is_err());
    }

    #[test]
    fn repository_state_matches_copy_tree_ignored_boundaries() {
        assert!(!copy_tree_would_stage_ignored_entry(b"target/debug/file"));
        assert!(!copy_tree_would_stage_ignored_entry(
            b"__pycache__/module.py"
        ));
        assert!(!copy_tree_would_stage_ignored_entry(b"module.pyc"));
        assert!(copy_tree_would_stage_ignored_entry(b".pyc"));
        assert!(copy_tree_would_stage_ignored_entry(b"build.rs"));
        assert!(copy_tree_would_stage_ignored_entry(b"nested/target/file"));

        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        fs::write(
            repo.path().join("Cargo.toml"),
            "[package]\nname = \"fs2-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(repo.path().join(".gitignore"), "").unwrap();
        git(repo.path(), &["add", "Cargo.toml", ".gitignore"]);
        git(
            repo.path(),
            &[
                "-c",
                "user.name=Codex",
                "-c",
                "user.email=codex@example.com",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
        );

        let clean_state = repository_state(repo.path(), "repo");
        assert!(clean_state.is_ok(), "{clean_state:?}");
        fs::write(repo.path().join("notes.txt"), "dirty\n").unwrap();
        assert!(repository_state(repo.path(), "repo").is_err());

        let ignored_build = tempfile::tempdir().unwrap();
        git(ignored_build.path(), &["init", "--quiet"]);
        fs::write(
            ignored_build.path().join("Cargo.toml"),
            "[package]\nname = \"fs2-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(ignored_build.path().join(".gitignore"), "build.rs\n").unwrap();
        git(ignored_build.path(), &["add", "Cargo.toml", ".gitignore"]);
        git(
            ignored_build.path(),
            &[
                "-c",
                "user.name=Codex",
                "-c",
                "user.email=codex@example.com",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
        );
        fs::write(ignored_build.path().join("build.rs"), "fn main() {}\n").unwrap();
        assert!(repository_state(ignored_build.path(), "repo").is_err());

        let ignored_target = tempfile::tempdir().unwrap();
        git(ignored_target.path(), &["init", "--quiet"]);
        fs::write(
            ignored_target.path().join("Cargo.toml"),
            "[package]\nname = \"fs2-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(ignored_target.path().join(".gitignore"), "target/\n").unwrap();
        git(ignored_target.path(), &["add", "Cargo.toml", ".gitignore"]);
        git(
            ignored_target.path(),
            &[
                "-c",
                "user.name=Codex",
                "-c",
                "user.email=codex@example.com",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
        );
        fs::create_dir_all(ignored_target.path().join("target/debug")).unwrap();
        fs::write(
            ignored_target.path().join("target/debug/output.txt"),
            "ignored\n",
        )
        .unwrap();
        assert!(repository_state(ignored_target.path(), "repo").is_ok());

        let ignored_pycache = tempfile::tempdir().unwrap();
        git(ignored_pycache.path(), &["init", "--quiet"]);
        fs::write(
            ignored_pycache.path().join("Cargo.toml"),
            "[package]\nname = \"fs2-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(ignored_pycache.path().join(".gitignore"), "__pycache__/\n").unwrap();
        git(ignored_pycache.path(), &["add", "Cargo.toml", ".gitignore"]);
        git(
            ignored_pycache.path(),
            &[
                "-c",
                "user.name=Codex",
                "-c",
                "user.email=codex@example.com",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
        );
        fs::create_dir_all(ignored_pycache.path().join("__pycache__")).unwrap();
        fs::write(
            ignored_pycache.path().join("__pycache__/module.pyc"),
            "ignored\n",
        )
        .unwrap();
        assert!(repository_state(ignored_pycache.path(), "repo").is_ok());

        let ignored_pyc = tempfile::tempdir().unwrap();
        git(ignored_pyc.path(), &["init", "--quiet"]);
        fs::write(
            ignored_pyc.path().join("Cargo.toml"),
            "[package]\nname = \"fs2-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(ignored_pyc.path().join(".gitignore"), "*.pyc\n").unwrap();
        git(ignored_pyc.path(), &["add", "Cargo.toml", ".gitignore"]);
        git(
            ignored_pyc.path(),
            &[
                "-c",
                "user.name=Codex",
                "-c",
                "user.email=codex@example.com",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
        );
        fs::write(ignored_pyc.path().join("module.pyc"), "ignored\n").unwrap();
        assert!(repository_state(ignored_pyc.path(), "repo").is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn benchmark_git_commands_enable_long_paths_on_windows() {
        let mut command = Command::new("git");
        enable_git_long_paths(&mut command);

        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["-c", "core.longpaths=true"]
        );
    }

    #[test]
    fn clone_revision_materializes_only_recorded_commit_bytes() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "--quiet"]);
        fs::write(
            repo.path().join("Cargo.toml"),
            "[package]\nname = \"fs2-test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(repo.path().join(".gitignore"), "build.rs\n").unwrap();
        git(repo.path(), &["add", "Cargo.toml", ".gitignore"]);
        git(
            repo.path(),
            &[
                "-c",
                "user.name=Codex",
                "-c",
                "user.email=codex@example.com",
                "commit",
                "--quiet",
                "-m",
                "init",
            ],
        );
        fs::write(
            repo.path().join("build.rs"),
            "fn main() { panic!(\"ignored input executed\") }\n",
        )
        .unwrap();
        let revision = resolve_ref(repo.path(), "HEAD").unwrap();
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("materialized");
        let logs = work.path().join("logs");

        let records =
            clone_revision(repo.path(), &destination, &revision, &logs, "subject").unwrap();

        assert!(processes_succeeded(&records));
        assert_eq!(resolve_ref(&destination, "HEAD").unwrap(), revision);
        assert!(!destination.join("build.rs").exists());
    }
}
