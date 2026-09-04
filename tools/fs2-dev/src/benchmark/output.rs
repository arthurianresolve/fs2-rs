use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{Result, invalid_data};

pub(super) struct StagedDirectory {
    staging: PrivateStaging,
    work: PathBuf,
    root: PathBuf,
    destination: PathBuf,
}

pub(super) fn prepare_output_root(path: &Path) -> Result<()> {
    prepare_output_root_platform(path)
}

#[cfg(windows)]
fn prepare_output_root_platform(path: &Path) -> Result<()> {
    drop(super::windows_security::create_or_open_private_directory(
        path,
    )?);
    Ok(())
}

#[cfg(unix)]
fn prepare_output_root_platform(path: &Path) -> Result<()> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt as _;

    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    drop(super::unix_security::prepare_directory(
        path,
        "trusted benchmark output root",
        false,
        false,
    )?);
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn prepare_output_root_platform(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

impl StagedDirectory {
    pub(super) fn new(root: &Path, destination: &Path, prefix: &str) -> Result<Self> {
        let staging = private_staging(root, prefix)?;
        let work = staging.path().join("output");
        create_staged_directory(&work)?;
        Ok(Self {
            staging,
            work,
            root: root.to_owned(),
            destination: destination.to_owned(),
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.work
    }

    pub(super) fn publish(self) -> Result<()> {
        reject_staged_links(&self.work)?;
        rebase_report_paths(
            &self.work.join("report.json"),
            &[(&self.work, &self.destination)],
        )?;
        harden_staged_permissions(&self.work)?;
        publish_noclobber(&self.work, &self.destination, Some(&self.root))?;
        drop(self.staging);
        Ok(())
    }
}

pub(super) struct StagedBundle {
    staging: PrivateStaging,
    anchor: PathBuf,
    root: PathBuf,
}

impl StagedBundle {
    pub(super) fn new(root: &Path, prefix: &str) -> Result<Self> {
        let staging = private_staging(root, prefix)?;
        let bundle = staging.path().join("bundle");
        create_staged_directory(&bundle)?;
        Ok(Self {
            staging,
            anchor: root.to_owned(),
            root: bundle,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.root
    }

    pub(super) fn publish(
        self,
        staged_report: &Path,
        report: &Path,
        staged_artifacts: &Path,
        artifacts: &Path,
    ) -> Result<()> {
        reject_staged_links(staged_artifacts)?;
        reject_staged_file_link(staged_report)?;
        rebase_report_paths(
            staged_report,
            &[(staged_artifacts, artifacts), (staged_report, report)],
        )?;
        harden_staged_permissions(&self.root)?;
        publish_noclobber(staged_artifacts, artifacts, Some(&self.anchor))?;
        // The report is the commit marker: sibling artifacts are only a
        // completed publication when the no-clobber report move succeeds.
        if let Err(error) = publish_noclobber(staged_report, report, Some(&self.anchor)) {
            let rollback = rollback_published_artifacts(artifacts);
            let rollback = match rollback {
                Ok(()) => "published artifacts were rolled back".to_owned(),
                Err(rollback_error) => {
                    format!("artifact rollback also failed: {rollback_error}")
                }
            };
            return Err(invalid_data(format!(
                "artifacts were published but the report commit marker failed: {error}; {rollback}"
            )));
        }
        drop(self.staging);
        Ok(())
    }
}

struct PrivateStaging {
    _guard: StagingGuard,
    temporary: tempfile::TempDir,
}

impl PrivateStaging {
    fn path(&self) -> &Path {
        self.temporary.path()
    }
}

#[cfg(unix)]
fn create_staged_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_staged_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn harden_staged_permissions(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_dir() && !entry.file_type().is_file() {
            return Err(invalid_data(format!(
                "staged benchmark output contains a non-regular entry: {}",
                entry.path().display()
            )));
        }
        super::unix_security::harden_publication_path(
            entry.path(),
            "staged benchmark publication",
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_staged_permissions(_root: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
type StagingGuard = Vec<fs::File>;

#[cfg(unix)]
type StagingGuard = Vec<std::os::fd::OwnedFd>;

#[cfg(not(any(unix, windows)))]
type StagingGuard = ();

fn private_staging(root: &Path, prefix: &str) -> Result<PrivateStaging> {
    let parent = root.join("target").join(".fs2-secure-staging");
    let mut guard = prepare_private_staging_parent(root, &parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    }
    let temporary = tempfile::Builder::new().prefix(prefix).tempdir_in(parent)?;
    guard_private_staging_directory(temporary.path(), &mut guard)?;
    Ok(PrivateStaging {
        _guard: guard,
        temporary,
    })
}

#[cfg(windows)]
fn prepare_private_staging_parent(root: &Path, parent: &Path) -> Result<StagingGuard> {
    let mut held = Vec::new();
    held.push(
        open_windows_directory_no_reparse(root, false).map_err(|error| {
            invalid_data(format!(
                "unable to retain benchmark staging root {}: {error}",
                root.display()
            ))
        })?,
    );
    let target = root.join("target");
    create_directory_no_reparse(&target).map_err(|error| {
        invalid_data(format!(
            "unable to create benchmark staging target {}: {error}",
            target.display()
        ))
    })?;
    held.push(
        open_windows_directory_no_reparse(&target, false).map_err(|error| {
            invalid_data(format!(
                "unable to retain benchmark staging target {}: {error}",
                target.display()
            ))
        })?,
    );
    held.push(
        super::windows_security::create_or_open_private_directory(parent).map_err(|error| {
            invalid_data(format!(
                "unable to secure benchmark staging parent {}: {error}",
                parent.display()
            ))
        })?,
    );
    Ok(held)
}

#[cfg(unix)]
fn prepare_private_staging_parent(root: &Path, parent: &Path) -> Result<StagingGuard> {
    let target = root.join("target");
    if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(invalid_data(format!(
            "benchmark staging target is a link: {}",
            target.display()
        )));
    }
    Ok(super::unix_security::prepare_directory(
        parent,
        "benchmark private staging parent",
        false,
        true,
    )?)
}

#[cfg(not(any(unix, windows)))]
fn prepare_private_staging_parent(_root: &Path, parent: &Path) -> Result<StagingGuard> {
    create_directory_no_reparse(parent)?;
    Ok(())
}

#[cfg(windows)]
fn guard_private_staging_directory(path: &Path, held: &mut StagingGuard) -> Result<()> {
    held.push(super::windows_security::harden_new_private_directory(path)?);
    Ok(())
}

#[cfg(unix)]
fn guard_private_staging_directory(path: &Path, held: &mut StagingGuard) -> Result<()> {
    held.extend(super::unix_security::prepare_directory(
        path,
        "benchmark private staging directory",
        false,
        false,
    )?);
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn guard_private_staging_directory(_path: &Path, _held: &mut StagingGuard) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn create_directory_no_reparse(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || is_windows_reparse_point(path)? {
                return Err(invalid_data(format!(
                    "benchmark staging ancestry is a link or reparse point: {}",
                    path.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(invalid_data(format!(
                    "benchmark staging ancestry is not a directory: {}",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            reject_link_or_reparse(path, "benchmark staging ancestry")?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_link_or_reparse(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_windows_reparse_point(path)? {
        return Err(invalid_data(format!(
            "{label} is a link or reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

fn reject_staged_links(root: &Path) -> Result<()> {
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() || is_windows_reparse_point(entry.path())? {
            return Err(invalid_data(format!(
                "staged benchmark output contains a link or reparse point: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn reject_staged_file_link(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() || is_windows_reparse_point(path)? {
        return Err(invalid_data(format!(
            "staged benchmark report is a link or reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

fn rebase_report_paths(report: &Path, replacements: &[(&Path, &Path)]) -> Result<()> {
    if !report.exists() {
        return Ok(());
    }
    let mut value = serde_json::from_slice::<serde_json::Value>(&fs::read(report)?)?;
    rebase_json_value(&mut value, replacements);
    let mut output = serde_json::to_vec_pretty(&value)?;
    output.push(b'\n');
    fs::write(report, output)?;
    Ok(())
}

fn rebase_json_value(value: &mut serde_json::Value, replacements: &[(&Path, &Path)]) {
    match value {
        serde_json::Value::String(text) => {
            for (from, to) in replacements {
                if let Some(rebased) = rebase_path_string(text, from, to) {
                    *text = rebased;
                    break;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                rebase_json_value(item, replacements);
            }
        }
        serde_json::Value::Object(entries) => {
            for item in entries.values_mut() {
                rebase_json_value(item, replacements);
            }
        }
        _ => {}
    }
}

fn rebase_path_string(text: &str, from: &Path, to: &Path) -> Option<String> {
    let from = from.to_string_lossy();
    let to = to.to_string_lossy();
    let suffix = text.strip_prefix(from.as_ref())?;
    if suffix.is_empty()
        || suffix
            .as_bytes()
            .first()
            .is_some_and(|byte| *byte == b'/' || *byte == b'\\')
    {
        Some(format!("{to}{suffix}"))
    } else {
        None
    }
}

fn rollback_published_artifacts(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || is_windows_reparse_point(path)? {
        return Err(invalid_data(format!(
            "published artifact rollback refused link or reparse point: {}",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(invalid_data(format!(
            "published artifact rollback refused non-directory path: {}",
            path.display()
        )));
    }
    reject_staged_links(path)?;
    fs::remove_dir_all(path)?;
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(path: &Path) -> Result<bool> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    Ok(fs::symlink_metadata(path)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_path: &Path) -> Result<bool> {
    Ok(false)
}

#[cfg(unix)]
fn publish_noclobber(source: &Path, destination: &Path, anchor: Option<&Path>) -> Result<()> {
    let (source_parent, source_name) = secure_parent(source, false, anchor)?;
    let (destination_parent, destination_name) = secure_parent(destination, true, anchor)?;
    atomic_rename_noclobber(
        &source_parent,
        &source_name,
        &destination_parent,
        &destination_name,
    )?;
    Ok(())
}

#[cfg(unix)]
fn secure_parent(
    path: &Path,
    create_missing: bool,
    anchor: Option<&Path>,
) -> Result<(std::os::fd::OwnedFd, std::ffi::OsString)> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::path::Component;

    if !path.is_absolute() {
        return Err(invalid_data("publication path must be absolute"));
    }
    let name = path
        .file_name()
        .ok_or_else(|| invalid_data("publication path has no final component"))?
        .to_owned();
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("publication path has no parent"))?;
    let relative_parent = if let Some(anchor) = anchor {
        Some(parent.strip_prefix(anchor).map_err(|_| {
            invalid_data(format!(
                "publication destination must remain beneath the trusted benchmark root: {}",
                anchor.display()
            ))
        })?)
    } else {
        None
    };
    let _authority_guard = super::unix_security::prepare_directory(
        parent,
        "benchmark publication parent",
        false,
        create_missing,
    )?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if let (Some(anchor), Some(relative_parent)) = (anchor, relative_parent) {
        // Starting at the validated benchmark root avoids traversing platform
        // aliases such as macOS `/var` while keeping all descendants no-follow.
        let mut directory = open(anchor, flags, Mode::empty())?;
        for component in relative_parent.components() {
            let Component::Normal(component) = component else {
                if component == Component::CurDir {
                    continue;
                }
                return Err(invalid_data(
                    "publication path escaped the benchmark output anchor",
                ));
            };
            match openat(&directory, component, flags, Mode::empty()) {
                Ok(next) => directory = next,
                Err(error) if create_missing && error == rustix::io::Errno::NOENT => {
                    mkdirat(&directory, component, Mode::from_raw_mode(0o700))?;
                    directory = openat(&directory, component, flags, Mode::empty())?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        return Ok((directory, name));
    }
    let mut directory = open("/", flags, Mode::empty())?;
    for component in parent.components() {
        let component = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(component) => component,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid_data(
                    "publication path may not contain parent-directory components",
                ));
            }
        };
        match openat(&directory, component, flags, Mode::empty()) {
            Ok(next) => directory = next,
            Err(error) if create_missing && error == rustix::io::Errno::NOENT => {
                mkdirat(&directory, component, Mode::from_raw_mode(0o700))?;
                directory = openat(&directory, component, flags, Mode::empty())?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok((directory, name))
}

#[cfg(all(
    unix,
    any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "redox",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    )
))]
fn atomic_rename_noclobber(
    source_parent: &std::os::fd::OwnedFd,
    source_name: &std::ffi::OsStr,
    destination_parent: &std::os::fd::OwnedFd,
    destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    rustix::fs::renameat_with(
        source_parent,
        source_name,
        destination_parent,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "redox",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos"
    ))
))]
fn atomic_rename_noclobber(
    _source_parent: &std::os::fd::OwnedFd,
    _source_name: &std::ffi::OsStr,
    _destination_parent: &std::os::fd::OwnedFd,
    _destination_name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace output publication is unavailable on this Unix target",
    ))
}

#[cfg(windows)]
fn publish_noclobber(source: &Path, destination: &Path, anchor: Option<&Path>) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, MoveFileW, OPEN_EXISTING,
    };

    super::windows_security::reject_ambiguous_path(destination)?;
    if let Some(anchor) = anchor {
        super::windows_security::reject_ambiguous_path(anchor)?;
    }
    let held_parents =
        hold_windows_parent_ancestry(destination, true, anchor).map_err(|error| {
            invalid_data(format!(
                "unable to bind publication destination ancestry: {error}"
            ))
        })?;
    let _destination_parent = held_parents
        .last()
        .ok_or_else(|| invalid_data("publication destination has no opened parent"))?;
    let source_path = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let source_handle = unsafe {
        // SAFETY: `source_path` is terminated. DELETE is the access required
        // for rename, and the validated staging entry is not traversed through
        // a reparse point.
        CreateFileW(
            source_path.as_ptr(),
            DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if source_handle == INVALID_HANDLE_VALUE {
        return Err(invalid_data(format!(
            "unable to open staged output for publication: {}",
            std::io::Error::last_os_error()
        )));
    }
    let source_handle = unsafe {
        // SAFETY: ownership of the newly opened source handle transfers to File.
        fs::File::from_raw_handle(source_handle)
    };
    let destination_path = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // MoveFileW requires the source handle to be closed. The source remains
    // protected by the private staging directory while destination ancestry
    // handles prevent namespace replacement through the move.
    drop(source_handle);
    let result = unsafe {
        // SAFETY: both paths are terminated and remain alive for the call.
        // MoveFileW fails when the destination already exists.
        MoveFileW(source_path.as_ptr(), destination_path.as_ptr())
    };
    if result == 0 {
        Err(invalid_data(format!(
            "no-clobber publication rename failed: {}",
            std::io::Error::last_os_error()
        )))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn hold_windows_parent_ancestry(
    path: &Path,
    create_missing: bool,
    anchor: Option<&Path>,
) -> Result<Vec<fs::File>> {
    use std::path::Component;

    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("publication path has no parent"))?;
    if let Some(anchor) = anchor {
        let relative_parent = parent.strip_prefix(anchor).map_err(|_| {
            invalid_data(format!(
                "publication destination must remain beneath the trusted benchmark root: {}",
                anchor.display()
            ))
        })?;
        let mut current = anchor.to_owned();
        let mut held = vec![hold_windows_ancestry_component(
            anchor,
            current == parent,
            create_missing,
        )?];
        for component in relative_parent.components() {
            match component {
                Component::CurDir => continue,
                Component::Normal(component) => current.push(component),
                _ => {
                    return Err(invalid_data(
                        "publication path escaped the benchmark output anchor",
                    ));
                }
            }
            held.push(hold_windows_ancestry_component(
                &current,
                current == parent,
                create_missing,
            )?);
        }
        return Ok(held);
    }
    let mut current = PathBuf::new();
    let mut held = Vec::new();
    for component in parent.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(invalid_data(
                    "publication path may not contain parent-directory components",
                ));
            }
            Component::Normal(component) => current.push(component),
        }
        if current == parent {
            held.push(
                hold_windows_ancestry_component(&current, true, create_missing).map_err(
                    |error| {
                        invalid_data(format!(
                            "unable to secure publication parent {}: {error}",
                            current.display()
                        ))
                    },
                )?,
            );
        } else {
            held.push(
                hold_windows_ancestry_component(&current, false, create_missing).map_err(
                    |error| {
                        invalid_data(format!(
                            "unable to secure publication ancestry {}: {error}",
                            current.display()
                        ))
                    },
                )?,
            );
        }
    }
    Ok(held)
}

#[cfg(windows)]
fn hold_windows_ancestry_component(
    path: &Path,
    publication_parent: bool,
    create_missing: bool,
) -> Result<fs::File> {
    if publication_parent {
        if create_missing {
            super::windows_security::create_or_open_private_directory(path)
        } else {
            super::windows_security::open_private_directory(path)
        }
    } else {
        create_windows_ancestry_directory(path, create_missing)?;
        super::windows_security::open_trusted_ancestor(path)
    }
}

#[cfg(windows)]
fn create_windows_ancestry_directory(path: &Path, create_missing: bool) -> Result<()> {
    if path.parent().is_some() && !path.exists() {
        if !create_missing {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound).into());
        }
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_directory_no_reparse(path: &Path, publication_parent: bool) -> Result<fs::File> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        FileAttributeTagInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let desired_access = FILE_READ_ATTRIBUTES
        | FILE_TRAVERSE
        | if publication_parent {
            FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
        } else {
            0
        };
    let handle = unsafe {
        // SAFETY: `encoded` is a terminated path. Keeping every ancestry
        // handle open without delete sharing prevents namespace replacement
        // while the final no-clobber rename resolves its absolute destination.
        CreateFileW(
            encoded.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut information = FILE_ATTRIBUTE_TAG_INFO::default();
    let result = unsafe {
        // SAFETY: `handle` is valid and `information` is correctly sized output.
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            std::ptr::from_mut(&mut information).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if result == 0 || information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        let error = if result == 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "publication ancestry is a reparse point: {}",
                    path.display()
                ),
            )
        };
        unsafe { CloseHandle(handle) };
        return Err(error.into());
    }
    Ok(unsafe {
        // SAFETY: ownership of the validated directory handle transfers to File.
        fs::File::from_raw_handle(handle)
    })
}

#[cfg(not(any(unix, windows)))]
fn publish_noclobber(_source: &Path, _destination: &Path, _anchor: Option<&Path>) -> Result<()> {
    Err(invalid_data(
        "atomic no-replace output publication is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    fn protect_publication_parent(path: &Path) {
        drop(super::super::windows_security::harden_new_private_directory(path).unwrap());
    }

    #[cfg(not(windows))]
    fn protect_publication_parent(_path: &Path) {}

    #[test]
    fn publication_never_replaces_existing_file() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let destination = root.path().join("report.json");
        fs::write(&destination, b"victim").unwrap();
        let staged = private_staging(root.path(), "publish-file-").unwrap();
        let source = staged.path().join("report.json");
        fs::write(&source, b"replacement").unwrap();

        assert!(publish_noclobber(&source, &destination, Some(root.path())).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"victim");
    }

    #[test]
    fn publication_rejects_destination_outside_trusted_anchor() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let external = tempfile::tempdir().unwrap();
        protect_publication_parent(external.path());
        let staged = private_staging(root.path(), "publish-outside-").unwrap();
        let source = staged.path().join("report.json");
        fs::write(&source, b"result").unwrap();
        let destination = external.path().join("report.json");

        assert!(publish_noclobber(&source, &destination, Some(root.path())).is_err());
        assert!(!destination.exists());
    }

    #[cfg(windows)]
    #[test]
    fn publication_rejects_win32_normalization_aliases() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let staged = private_staging(root.path(), "publish-alias-").unwrap();
        let source = staged.path().join("report.json");
        fs::write(&source, b"result").unwrap();
        let destination = root.path().join(".. ").join("report.json");

        assert!(publish_noclobber(&source, &destination, Some(root.path())).is_err());
    }

    #[test]
    fn publication_moves_a_new_directory() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let destination = root.path().join("output");
        let staged = StagedDirectory::new(root.path(), &destination, "publish-new-").unwrap();
        fs::write(staged.path().join("result"), b"result").unwrap();

        staged.publish().unwrap();

        assert_eq!(fs::read(destination.join("result")).unwrap(), b"result");
    }

    #[test]
    fn explicit_output_root_supports_secure_publication() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("trusted-output");
        prepare_output_root(&root).unwrap();
        let destination = root.join("result");
        let staged = StagedDirectory::new(&root, &destination, "publish-explicit-").unwrap();
        fs::write(staged.path().join("result"), b"result").unwrap();

        staged.publish().unwrap();

        assert_eq!(fs::read(destination.join("result")).unwrap(), b"result");
    }

    #[test]
    fn publication_never_replaces_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let destination = root.path().join("output");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("victim"), b"victim").unwrap();
        let staged = StagedDirectory::new(root.path(), &destination, "publish-dir-").unwrap();
        fs::write(staged.path().join("result"), b"result").unwrap();

        assert!(staged.publish().is_err());
        assert_eq!(fs::read(destination.join("victim")).unwrap(), b"victim");
    }

    #[test]
    fn staged_links_are_rejected_before_publication() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let destination = root.path().join("output");
        let staged = StagedDirectory::new(root.path(), &destination, "publish-link-").unwrap();
        let external = root.path().join("external");
        #[cfg(unix)]
        {
            fs::write(&external, b"victim").unwrap();
            std::os::unix::fs::symlink(&external, staged.path().join("link")).unwrap();
        }
        #[cfg(windows)]
        {
            fs::create_dir(&external).unwrap();
            fs::write(external.join("victim"), b"victim").unwrap();
            let status = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(staged.path().join("link"))
                .arg(&external)
                .status()
                .unwrap();
            assert!(status.success());
        }

        assert!(staged.publish().is_err());
        #[cfg(unix)]
        assert_eq!(fs::read(external).unwrap(), b"victim");
        #[cfg(windows)]
        assert_eq!(fs::read(external.join("victim")).unwrap(), b"victim");
        assert!(!destination.exists());
    }

    #[test]
    fn private_staging_rejects_target_link_ancestry() {
        let root = tempfile::tempdir().unwrap();
        let external = root.path().join("external");
        fs::create_dir(&external).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external, root.path().join("target")).unwrap();
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(root.path().join("target"))
                .arg(&external)
                .status()
                .unwrap();
            assert!(status.success());
        }

        assert!(private_staging(root.path(), "publish-target-link-").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn held_publication_ancestry_cannot_be_renamed() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let parent = root.path().join("results");
        fs::create_dir(&parent).unwrap();
        protect_publication_parent(&parent);
        let destination = parent.join("report.json");
        let held = hold_windows_parent_ancestry(&destination, false, Some(root.path())).unwrap();

        assert!(fs::rename(&parent, root.path().join("replacement")).is_err());
        drop(held);
    }

    #[test]
    fn concurrent_publishers_have_one_winner() {
        let root = tempfile::tempdir().unwrap();
        protect_publication_parent(root.path());
        let destination = root.path().join("output");
        let first = StagedDirectory::new(root.path(), &destination, "publish-a-").unwrap();
        let second = StagedDirectory::new(root.path(), &destination, "publish-b-").unwrap();
        fs::write(first.path().join("winner"), b"a").unwrap();
        fs::write(second.path().join("winner"), b"b").unwrap();

        let first = std::thread::spawn(move || first.publish());
        let second = std::thread::spawn(move || second.publish());
        let results = [first.join().unwrap(), second.join().unwrap()];

        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            1,
            "{results:?}"
        );
        let winner = fs::read(destination.join("winner")).unwrap();
        assert!(winner == b"a" || winner == b"b");
    }
}
