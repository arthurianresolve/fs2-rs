use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::process;
use crate::{Result, invalid_data};

#[derive(Clone, Debug, Serialize)]
pub(super) struct DiskSnapshot {
    path: PathBuf,
    filesystem_id: Option<String>,
    free_space: u64,
    available_space: u64,
    total_space: u64,
    allocation_granularity: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct EnvironmentSnapshot {
    captured_unix_ms: u128,
    host_os: &'static str,
    host_arch: &'static str,
    hostname: Option<String>,
    cpu_identifier: Option<String>,
    logical_processors: Option<String>,
    process_affinity: Option<String>,
    power_plan: Option<String>,
    rustc_host: String,
    cargo_build_target: Option<String>,
    rustc_verbose_version: String,
    cargo_verbose_version: String,
    environment: BTreeMap<String, String>,
    disk: DiskSnapshot,
    observation_failures: Vec<String>,
}

impl EnvironmentSnapshot {
    pub(super) fn capture(disk_path: &Path) -> Result<Self> {
        let mut rustc = rustc_command();
        rustc.arg("-vV");
        let rustc_verbose_version = command_text(rustc, "capture rustc version")?;
        let rustc_host = rustc_verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .map(str::to_owned)
            .ok_or_else(|| invalid_data("rustc -vV did not report a host target"))?;
        let mut cargo = process::cargo();
        cargo.arg("-vV");
        let cargo_verbose_version = command_text(cargo, "capture Cargo version")?;
        let selected = [
            "PATH",
            "CARGO_HOME",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
            "CARGO_TARGET_DIR",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
            "RUSTDOCFLAGS",
            "RUSTFLAGS",
            "TEMP",
            "TMP",
            "TMPDIR",
            "CC",
            "CFLAGS",
            "CXX",
            "CXXFLAGS",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_IDENTIFIER",
            "FS2_DEV_PROCESS_TIMEOUT_SECONDS",
        ];
        let environment = env::vars_os()
            .filter_map(|(name, value)| {
                let encoded_name = process::display_os(&name);
                (selected.contains(&encoded_name.as_str())
                    || encoded_name.starts_with("CARGO_TARGET_")
                    || encoded_name.starts_with("CC_")
                    || encoded_name.starts_with("CFLAGS_")
                    || encoded_name.starts_with("CXXFLAGS_"))
                .then(|| (encoded_name, process::display_os(&value)))
            })
            .collect();

        let cpu_identifier = cpu_identifier();
        let logical_processors = env::var("NUMBER_OF_PROCESSORS").ok().or_else(|| {
            std::thread::available_parallelism()
                .ok()
                .map(|count| count.get().to_string())
        });
        let process_affinity = process_affinity();
        let power_plan = power_plan();
        let disk = DiskSnapshot::capture(disk_path)?;
        let mut observation_failures = Vec::new();
        if cpu_identifier.is_none() {
            observation_failures.push("CPU identity unavailable".to_owned());
        }
        if logical_processors.is_none() {
            observation_failures.push("logical processor count unavailable".to_owned());
        }
        if disk.filesystem_id.is_none() {
            observation_failures.push("filesystem identity unavailable".to_owned());
        }
        #[cfg(any(target_os = "linux", windows))]
        if process_affinity.is_none() {
            observation_failures.push("process affinity unavailable".to_owned());
        }
        #[cfg(windows)]
        if power_plan.is_none() {
            observation_failures.push("Windows power plan unavailable".to_owned());
        }

        Ok(Self {
            captured_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
            host_os: env::consts::OS,
            host_arch: env::consts::ARCH,
            hostname: env::var("COMPUTERNAME")
                .or_else(|_| env::var("HOSTNAME"))
                .ok(),
            cpu_identifier,
            logical_processors,
            process_affinity,
            power_plan,
            rustc_host,
            cargo_build_target: env::var("CARGO_BUILD_TARGET").ok(),
            rustc_verbose_version,
            cargo_verbose_version,
            environment,
            disk,
            observation_failures,
        })
    }

    pub(super) fn strict_failure_reason(&self) -> Option<String> {
        (!self.observation_failures.is_empty()).then(|| {
            format!(
                "required environment observations failed: {}",
                self.observation_failures.join("; ")
            )
        })
    }

    pub(super) fn drift_reasons(&self, completed: &Self) -> Vec<String> {
        let mut reasons = Vec::new();
        let mut compare = |name: &str, unchanged: bool| {
            if !unchanged {
                reasons.push(format!("environment changed during measurement: {name}"));
            }
        };
        compare("host OS", self.host_os == completed.host_os);
        compare("host architecture", self.host_arch == completed.host_arch);
        compare("host name", self.hostname == completed.hostname);
        compare(
            "CPU identifier",
            self.cpu_identifier == completed.cpu_identifier,
        );
        compare(
            "logical processor count",
            self.logical_processors == completed.logical_processors,
        );
        compare(
            "process affinity",
            self.process_affinity == completed.process_affinity,
        );
        compare("power plan", self.power_plan == completed.power_plan);
        compare("rustc host", self.rustc_host == completed.rustc_host);
        compare(
            "Cargo build target",
            self.cargo_build_target == completed.cargo_build_target,
        );
        compare(
            "rustc version",
            self.rustc_verbose_version == completed.rustc_verbose_version,
        );
        compare(
            "Cargo version",
            self.cargo_verbose_version == completed.cargo_verbose_version,
        );
        compare(
            "selected environment",
            self.environment == completed.environment,
        );
        compare(
            "filesystem identity",
            self.disk.filesystem_id == completed.disk.filesystem_id,
        );
        compare(
            "environment observation failures",
            self.observation_failures == completed.observation_failures,
        );
        reasons
    }
}

impl DiskSnapshot {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        let path = path.canonicalize()?;
        let stats = fs2::statvfs(&path)?;
        Ok(Self {
            filesystem_id: filesystem_id(&path),
            path,
            free_space: stats.free_space(),
            available_space: stats.available_space(),
            total_space: stats.total_space(),
            allocation_granularity: stats.allocation_granularity(),
        })
    }
}

#[cfg(unix)]
fn filesystem_id(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt as _;

    fs::metadata(path)
        .ok()
        .map(|metadata| metadata.dev().to_string())
}

#[cfg(windows)]
fn filesystem_id(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr::null_mut;

    use windows_sys::Win32::Storage::FileSystem::{GetVolumeInformationW, GetVolumePathNameW};

    let mut encoded_path: Vec<_> = path.as_os_str().encode_wide().collect();
    encoded_path.push(0);
    let mut volume_path = vec![0u16; 32_768];
    // SAFETY: both buffers are writable, nul-terminated UTF-16 buffers with the
    // lengths passed to the Windows APIs.
    if unsafe {
        GetVolumePathNameW(
            encoded_path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    } == 0
    {
        return None;
    }

    let mut serial = 0;
    let mut maximum_component_length = 0;
    let mut filesystem_flags = 0;
    // SAFETY: volume_path was initialized by GetVolumePathNameW and the output
    // pointers refer to live u32 values. Optional name buffers are null.
    if unsafe {
        GetVolumeInformationW(
            volume_path.as_ptr(),
            null_mut(),
            0,
            &mut serial,
            &mut maximum_component_length,
            &mut filesystem_flags,
            null_mut(),
            0,
        )
    } == 0
    {
        None
    } else {
        Some(format!("{serial:08x}"))
    }
}

#[cfg(not(any(unix, windows)))]
fn filesystem_id(_path: &Path) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn process_affinity() -> Option<String> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t").map(str::to_owned))
}

#[cfg(windows)]
fn process_affinity() -> Option<String> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessAffinityMask};

    let mut process_mask = 0usize;
    let mut system_mask = 0usize;
    // SAFETY: the pseudo-handle is valid in this process and both output
    // pointers refer to initialized writable values.
    let succeeded =
        unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process_mask, &mut system_mask) };
    (succeeded != 0).then(|| format!("{process_mask:x}/{system_mask:x}"))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn process_affinity() -> Option<String> {
    None
}

#[cfg(windows)]
fn power_plan() -> Option<String> {
    let mut command = Command::new("powercfg");
    command.arg("/getactivescheme");
    process::capture(&mut command, "capture active Windows power plan")
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_owned())
        .filter(|output| !output.is_empty())
}

#[cfg(not(windows))]
fn power_plan() -> Option<String> {
    None
}

fn cpu_identifier() -> Option<String> {
    if let Ok(value) = env::var("PROCESSOR_IDENTIFIER") {
        return Some(value);
    }
    let linux_identifier = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| matches!(name.trim(), "model name" | "Hardware"))
                    .map(|(_, value)| value.trim().to_owned())
            })
        });
    if linux_identifier.is_some() {
        return linux_identifier;
    }
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("sysctl");
        command.args(["-n", "machdep.cpu.brand_string"]);
        return process::capture(&mut command, "capture macOS CPU identity")
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|output| output.trim().to_owned())
            .filter(|output| !output.is_empty());
    }
    #[cfg(not(target_os = "macos"))]
    None
}

fn rustc_command() -> Command {
    Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
}

fn command_text(mut command: Command, label: &str) -> Result<String> {
    let output = process::capture(&mut command, label)?;
    Ok(String::from_utf8(output.stdout)?)
}
