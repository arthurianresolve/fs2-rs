use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Wdk::Storage::FileSystem::{
    FileFsFullSizeInformation, NtQueryVolumeInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, E_NOTIMPL, ERROR_BAD_NETPATH, ERROR_BAD_PATHNAME,
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_DIRECTORY, ERROR_INVALID_DRIVE, ERROR_INVALID_FUNCTION,
    ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER, ERROR_LOCK_VIOLATION, ERROR_NOT_SUPPORTED,
    ERROR_PATH_NOT_FOUND, HANDLE, HMODULE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError, S_OK, TRUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DISK_SPACE_INFORMATION, FILE_ALLOCATION_INFO, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAllocationInfo,
    FileStandardInfo, GetDiskFreeSpaceExW, GetDiskFreeSpaceW, GetFileAttributesW,
    GetFileInformationByHandleEx, GetVolumePathNameW, INVALID_FILE_ATTRIBUTES,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_EXISTING,
    SetFileInformationByHandle, UnlockFile,
};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::allocation::AllocationState;
use crate::lock::{LockMode, LockOperation};
use crate::stats::{FsStats, validate_granularity};
use crate::{FilesystemCounters, SpaceKind};

const VOLUME_PATH_CAPACITY: usize = 261;
const FACILITY_NT_BIT: u32 = 0x1000_0000;
const FACILITY_WIN32: u32 = 7;
type GetDiskSpaceInformation = unsafe extern "system" fn(
    *const u16,
    *mut DISK_SPACE_INFORMATION,
) -> windows_sys::core::HRESULT;

static GET_DISK_SPACE_INFORMATION: OnceLock<(bool, Option<GetDiskSpaceInformation>)> =
    OnceLock::new();

#[derive(Debug)]
pub(crate) struct StatsQuery {
    root_path: [u16; VOLUME_PATH_CAPACITY],
}

impl StatsQuery {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        let path = wide_path(path)?;
        let mut root_path = [0; VOLUME_PATH_CAPACITY];
        if !copy_exact_drive_root(&path, &mut root_path) {
            volume_path(&path, &mut root_path)?;
        }
        Ok(Self { root_path })
    }

    pub(crate) fn counters(&self) -> Result<FilesystemCounters> {
        statvfs_root(&self.root_path)
    }
}

#[inline]
pub(crate) fn duplicate(file: &File) -> Result<File> {
    let mut duplicate = std::ptr::null_mut();
    let process = unsafe {
        // SAFETY: `GetCurrentProcess` returns the calling process's pseudo-handle.
        GetCurrentProcess()
    };
    let result = unsafe {
        // SAFETY: `file` owns a valid handle, `process` identifies the calling
        // process, and `duplicate` is writable output storage. On success the
        // returned handle is newly owned by the caller.
        DuplicateHandle(
            process,
            file.as_raw_handle(),
            process,
            &mut duplicate,
            0,
            TRUE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    duplicate_result(result, duplicate)
}

fn duplicate_result(result: i32, duplicate: HANDLE) -> Result<File> {
    win32_bool_result(result)?;
    // SAFETY: a successful `DuplicateHandle` call returned one newly owned handle.
    let owned = unsafe { OwnedHandle::from_raw_handle(duplicate) };
    Ok(File::from(owned))
}

#[inline(always)]
pub(crate) fn allocation_state(file: &File) -> Result<AllocationState> {
    let handle = file.as_raw_handle();
    let mut info = FILE_STANDARD_INFO::default();
    let ret = unsafe {
        // SAFETY: `file` owns a valid handle and `info` is properly sized and aligned.
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };

    allocation_state_result(ret, info)
}

pub(crate) const ALLOCATE_SPACE_EXTENDS_LENGTH: bool = false;

fn allocation_state_result(result: i32, info: FILE_STANDARD_INFO) -> Result<AllocationState> {
    win32_bool_result(result)?;
    Ok(AllocationState {
        allocated_size: info.AllocationSize as u64,
        file_size: info.EndOfFile as u64,
    })
}

pub(crate) fn allocate_space(file: &File, len: u64) -> Result<()> {
    let len = i64::try_from(len)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "allocation length is too large"))?;
    let info = FILE_ALLOCATION_INFO {
        AllocationSize: len,
    };
    let ret = unsafe {
        // SAFETY: `file` owns a valid handle and `info` is properly sized and aligned.
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileAllocationInfo,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        )
    };
    win32_bool_result(ret)?;
    Ok(())
}

pub(crate) fn lock(file: &File, operation: LockOperation) -> Result<()> {
    match operation {
        LockOperation::Acquire { mode, nonblocking } => {
            let mut flags = match mode {
                LockMode::Shared => 0,
                LockMode::Exclusive => LOCKFILE_EXCLUSIVE_LOCK,
            };
            if nonblocking {
                flags |= LOCKFILE_FAIL_IMMEDIATELY;
            }
            lock_file(file, flags)
        }
        LockOperation::Release => {
            let ret = unsafe {
                // SAFETY: `file` owns a valid handle for the duration of this call.
                UnlockFile(file.as_raw_handle(), 0, 0, u32::MAX, u32::MAX)
            };
            win32_bool_result(ret)
        }
    }
}

pub(crate) fn lock_error() -> Error {
    Error::from_raw_os_error(ERROR_LOCK_VIOLATION as i32)
}

fn lock_file(file: &File, flags: u32) -> Result<()> {
    let mut overlapped = OVERLAPPED::default();
    let ret = unsafe {
        // SAFETY: `file` owns a valid handle and `overlapped` is a valid zeroed structure.
        LockFileEx(
            file.as_raw_handle(),
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    volume_path_result(ret)
}

fn volume_path_result(result: i32) -> Result<()> {
    win32_bool_result(result)
}

#[inline]
fn win32_bool_result(result: i32) -> Result<()> {
    if result == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let path = path.as_os_str();
    let mut encoded = Vec::with_capacity(path.len().saturating_add(1));
    for code_unit in path.encode_wide() {
        if code_unit == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "path contained a null"));
        }
        encoded.push(code_unit);
    }
    encoded.push(0);
    Ok(encoded)
}

fn copy_exact_drive_root(path: &[u16], root_path: &mut [u16; VOLUME_PATH_CAPACITY]) -> bool {
    let [drive, colon, separator, terminator] = path else {
        return false;
    };
    if !valid_drive_root_components(*drive, *colon, *separator, *terminator) {
        return false;
    }

    root_path[..path.len()].copy_from_slice(path);
    root_path[2] = u16::from(b'\\');
    true
}

fn valid_drive_root_components(drive: u16, colon: u16, separator: u16, terminator: u16) -> bool {
    let is_uppercase_drive = (u16::from(b'A')..=u16::from(b'Z')).contains(&drive);
    let is_lowercase_drive = (u16::from(b'a')..=u16::from(b'z')).contains(&drive);
    let is_drive_letter = is_uppercase_drive | is_lowercase_drive;
    let is_backslash = separator == u16::from(b'\\');
    let is_forward_slash = separator == u16::from(b'/');
    let is_separator = is_backslash | is_forward_slash;
    is_drive_letter && colon == u16::from(b':') && is_separator && terminator == 0
}

fn volume_path(path: &[u16], volume_path: &mut [u16]) -> Result<()> {
    let ret = unsafe {
        // SAFETY: `path` is null-terminated and `volume_path` is valid output storage.
        GetVolumePathNameW(
            path.as_ptr(),
            volume_path.as_mut_ptr(),
            volume_path.len() as u32,
        )
    };
    win32_bool_result(ret)
}

pub(crate) fn statvfs(path: &Path) -> Result<FilesystemCounters> {
    StatsQuery::new(path)?.counters()
}

fn statvfs_root(root_path: &[u16]) -> Result<FilesystemCounters> {
    statvfs_root_with(root_path, modern_statvfs(root_path)?)
}

#[inline(always)]
fn statvfs_root_with(
    root_path: &[u16],
    modern: Option<FilesystemCounters>,
) -> Result<FilesystemCounters> {
    match modern {
        Some(counters) => Ok(counters),
        None => legacy_statvfs(root_path),
    }
}

fn modern_statvfs(root_path: &[u16]) -> Result<Option<FilesystemCounters>> {
    let get_disk_space_information = disk_space_information_provider().1;

    modern_statvfs_with(root_path, get_disk_space_information)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderOutcome {
    Available,
    Unavailable,
    Error,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProviderProbe {
    pub(crate) module_present: bool,
    pub(crate) symbol_present: bool,
    pub(crate) outcome: ProviderOutcome,
    pub(crate) error_raw_os: Option<i32>,
}

fn disk_space_information_provider() -> (bool, Option<GetDiskSpaceInformation>) {
    *GET_DISK_SPACE_INFORMATION.get_or_init(|| unsafe {
        // SAFETY: kernel32 is loaded in every Windows process and both string literals are
        // null-terminated. The resolved symbol is cast to its documented Windows ABI.
        let module = GetModuleHandleA(windows_sys::core::s!("kernel32.dll"));
        (
            !module.is_null(),
            resolve_module_symbol(module, get_disk_space_information),
        )
    })
}

#[cfg(test)]
pub(crate) fn provider_probe(root_path: &[u16]) -> ProviderProbe {
    let (module_present, provider) = disk_space_information_provider();
    provider_probe_with(module_present, provider, root_path)
}

#[cfg(test)]
fn provider_probe_with(
    module_present: bool,
    provider: Option<GetDiskSpaceInformation>,
    root_path: &[u16],
) -> ProviderProbe {
    let symbol_present = provider.is_some();
    let Some(provider) = provider else {
        return ProviderProbe {
            module_present,
            symbol_present,
            outcome: ProviderOutcome::Unavailable,
            error_raw_os: None,
        };
    };

    match modern_statvfs_with(root_path, Some(provider)) {
        Ok(Some(_)) => ProviderProbe {
            module_present,
            symbol_present,
            outcome: ProviderOutcome::Available,
            error_raw_os: None,
        },
        Ok(None) => ProviderProbe {
            module_present,
            symbol_present,
            outcome: ProviderOutcome::Unavailable,
            error_raw_os: None,
        },
        Err(error) => ProviderProbe {
            module_present,
            symbol_present,
            outcome: ProviderOutcome::Error,
            error_raw_os: error.raw_os_error(),
        },
    }
}

fn get_disk_space_information(module: HMODULE) -> Option<GetDiskSpaceInformation> {
    unsafe {
        GetProcAddress(module, windows_sys::core::s!("GetDiskSpaceInformationW"))
            .map(|function| std::mem::transmute(function))
    }
}

fn resolve_module_symbol<T>(module: HMODULE, symbol: fn(HMODULE) -> Option<T>) -> Option<T> {
    if module.is_null() {
        None
    } else {
        symbol(module)
    }
}

fn modern_statvfs_with(
    root_path: &[u16],
    get_disk_space_information: Option<GetDiskSpaceInformation>,
) -> Result<Option<FilesystemCounters>> {
    let Some(get_disk_space_information) = get_disk_space_information else {
        return Ok(None);
    };
    let mut info = DISK_SPACE_INFORMATION::default();
    let result = unsafe {
        // SAFETY: `root_path` is null-terminated UTF-16 and `info` is valid output storage.
        get_disk_space_information(root_path.as_ptr(), &mut info)
    };
    if result != S_OK {
        if modern_statvfs_unavailable(result) {
            return Ok(None);
        }
        return Err(io_error_from_hresult(result));
    }

    counters_from_disk_space_information(info).map(Some)
}

const fn hresult_from_win32(error: u32) -> windows_sys::core::HRESULT {
    ((error & 0xffff) | 0x8007_0000) as windows_sys::core::HRESULT
}

fn io_error_from_hresult(result: windows_sys::core::HRESULT) -> Error {
    let encoded = result as u32;
    let facility = (encoded >> 16) & 0x1fff;
    let error = if encoded & FACILITY_NT_BIT != 0 {
        let status = (encoded & !FACILITY_NT_BIT) as i32;
        unsafe {
            // SAFETY: this converts an integer NTSTATUS value and dereferences no pointers.
            RtlNtStatusToDosError(status)
        }
    } else if facility == FACILITY_WIN32 {
        encoded & 0xffff
    } else {
        return Error::from_raw_os_error(result);
    };
    Error::from_raw_os_error(error as i32)
}

fn modern_statvfs_unavailable(result: windows_sys::core::HRESULT) -> bool {
    let not_implemented = result == E_NOTIMPL;
    let call_not_implemented = result == hresult_from_win32(ERROR_CALL_NOT_IMPLEMENTED);
    let invalid_function = result == hresult_from_win32(ERROR_INVALID_FUNCTION);
    let not_supported = result == hresult_from_win32(ERROR_NOT_SUPPORTED);
    not_implemented | call_not_implemented | invalid_function | not_supported
}

fn counters_from_disk_space_information(
    info: DISK_SPACE_INFORMATION,
) -> Result<FilesystemCounters> {
    let allocation_granularity =
        u64::from(info.SectorsPerAllocationUnit) * u64::from(info.BytesPerSector);
    let checked_bytes = |units: u64| {
        allocation_granularity
            .checked_mul(units)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "filesystem space overflowed"))
    };

    Ok(FilesystemCounters::windows_modern_bytes(
        allocation_granularity,
        checked_bytes(info.ActualAvailableAllocationUnits)?,
        checked_bytes(info.CallerAvailableAllocationUnits)?,
        checked_bytes(info.ActualTotalAllocationUnits)?,
    ))
}

fn legacy_statvfs(root_path: &[u16]) -> Result<FilesystemCounters> {
    legacy_statvfs_after_geometry(root_path, cluster_geometry(root_path))
}

fn legacy_statvfs_after_geometry(
    root_path: &[u16],
    geometry: Result<u64>,
) -> Result<FilesystemCounters> {
    let geometry = geometry?;
    let bytes = byte_space(root_path)?;

    Ok(FilesystemCounters::windows_legacy_bytes(
        geometry,
        bytes.actual_free,
        bytes.caller_available,
        bytes.caller_total,
    ))
}

pub(crate) fn space(path: &Path, kind: SpaceKind) -> Result<u64> {
    let path_utf16 = wide_path(path)?;
    if path.is_absolute() {
        match direct_space(&path_utf16, kind) {
            DirectSpace::Hit(value) => return Ok(value),
            DirectSpace::Unavailable => match handle_space(&path_utf16, kind) {
                DirectSpace::Hit(value) => return Ok(value),
                DirectSpace::Unavailable => {}
            },
        }
    }

    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    if copy_exact_drive_root(&path_utf16, &mut root_path) {
        let exact_root = root_space(&root_path, kind);
        return space_after_exact_root(&path_utf16, kind, &mut root_path, exact_root, root_space);
    }

    root_path.fill(0);
    volume_path(&path_utf16, &mut root_path)?;

    root_space(&root_path, kind)
}

fn space_after_exact_root(
    path: &[u16],
    kind: SpaceKind,
    root_path: &mut [u16; VOLUME_PATH_CAPACITY],
    exact_root: Result<u64>,
    root_query: fn(&[u16], SpaceKind) -> Result<u64>,
) -> Result<u64> {
    if let Some(value) = exact_root_value(exact_root)? {
        return Ok(value);
    }

    root_path.fill(0);
    volume_path(path, root_path)?;
    root_query(root_path, kind)
}

const UNSUITABLE_HANDLE_SPACE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_DEVICE
    | FILE_ATTRIBUTE_DIRECTORY
    | FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    | FILE_ATTRIBUTE_RECALL_ON_OPEN;

const fn handle_space_attributes_eligible(attributes: u32) -> bool {
    let valid_attributes = attributes != INVALID_FILE_ATTRIBUTES;
    let suitable_attributes = attributes & UNSUITABLE_HANDLE_SPACE_ATTRIBUTES == 0;
    handle_space_attributes_decision(valid_attributes, suitable_attributes)
}

const fn handle_space_attributes_decision(
    valid_attributes: bool,
    suitable_attributes: bool,
) -> bool {
    valid_attributes && suitable_attributes
}

fn handle_space(path: &[u16], kind: SpaceKind) -> DirectSpace {
    if matches!(kind, SpaceKind::Total | SpaceKind::AllocationGranularity) {
        return DirectSpace::Unavailable;
    }

    let attributes = unsafe {
        // SAFETY: `path` is null-terminated for the duration of the call.
        GetFileAttributesW(path.as_ptr())
    };
    if !handle_space_attributes_eligible(attributes) {
        return DirectSpace::Unavailable;
    }

    let handle = unsafe {
        // SAFETY: `path` is null-terminated. The null security-attributes and
        // template pointers are permitted, and no data access is requested.
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL,
            std::ptr::null_mut(),
        )
    };
    with_owned_handle(handle, |handle| {
        let mut status = IO_STATUS_BLOCK::default();
        let mut info = FILE_FS_FULL_SIZE_INFORMATION::default();
        let result = unsafe {
            // SAFETY: `handle` remains valid, and `status` and `info` are writable,
            // correctly sized output storage for this query class.
            NtQueryVolumeInformationFile(
                handle.as_raw_handle(),
                &mut status,
                std::ptr::from_mut(&mut info).cast(),
                std::mem::size_of::<FILE_FS_FULL_SIZE_INFORMATION>() as u32,
                FileFsFullSizeInformation,
            )
        };
        handle_space_query_result(result, info, kind)
    })
    .unwrap_or(DirectSpace::Unavailable)
}

fn with_owned_handle<T>(handle: HANDLE, operation: impl FnOnce(OwnedHandle) -> T) -> Option<T> {
    owned_handle(handle).map(operation)
}

fn owned_handle(handle: HANDLE) -> Option<OwnedHandle> {
    if handle == INVALID_HANDLE_VALUE {
        None
    } else {
        // SAFETY: the caller obtained `handle` from a successful CreateFileW call
        // and transfers ownership to this function.
        Some(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

fn handle_space_query_result(
    result: i32,
    info: FILE_FS_FULL_SIZE_INFORMATION,
    kind: SpaceKind,
) -> DirectSpace {
    if result != 0 {
        DirectSpace::Unavailable
    } else {
        handle_space_from_info(info, kind)
    }
}

fn handle_space_from_info(info: FILE_FS_FULL_SIZE_INFORMATION, kind: SpaceKind) -> DirectSpace {
    let granularity = u64::from(info.SectorsPerAllocationUnit) * u64::from(info.BytesPerSector);
    if granularity == 0 {
        return DirectSpace::Unavailable;
    }
    let Ok(actual_units) = u64::try_from(info.ActualAvailableAllocationUnits) else {
        return DirectSpace::Unavailable;
    };
    let Ok(caller_units) = u64::try_from(info.CallerAvailableAllocationUnits) else {
        return DirectSpace::Unavailable;
    };
    let Some(actual_free) = granularity.checked_mul(actual_units) else {
        return DirectSpace::Unavailable;
    };
    let Some(caller_available) = granularity.checked_mul(caller_units) else {
        return DirectSpace::Unavailable;
    };
    if caller_available > actual_free {
        return DirectSpace::Unavailable;
    }

    match kind {
        SpaceKind::Free => DirectSpace::Hit(actual_free),
        SpaceKind::Available => DirectSpace::Hit(caller_available),
        SpaceKind::Total | SpaceKind::AllocationGranularity => DirectSpace::Unavailable,
    }
}

fn exact_root_value(result: Result<u64>) -> Result<Option<u64>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_volume_resolution_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn is_volume_resolution_error(error: &Error) -> bool {
    let Some(code) = error.raw_os_error() else {
        return false;
    };
    [
        ERROR_BAD_NETPATH,
        ERROR_BAD_PATHNAME,
        ERROR_DIRECTORY,
        ERROR_INVALID_DRIVE,
        ERROR_INVALID_NAME,
        ERROR_INVALID_PARAMETER,
        ERROR_PATH_NOT_FOUND,
    ]
    .into_iter()
    .any(|win32_error| code == win32_error as i32)
}

fn root_space(root_path: &[u16], kind: SpaceKind) -> Result<u64> {
    root_space_with(root_path, kind, modern_statvfs(root_path))
}

#[inline(always)]
fn root_space_with(
    root_path: &[u16],
    kind: SpaceKind,
    modern: Result<Option<FilesystemCounters>>,
) -> Result<u64> {
    match modern? {
        Some(counters) => FsStats::from_counters(counters).map(|stats| stats.value(kind)),
        None => legacy_space(root_path, kind),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DirectSpace {
    Hit(u64),
    Unavailable,
}

fn direct_space(path: &[u16], kind: SpaceKind) -> DirectSpace {
    if matches!(kind, SpaceKind::Total | SpaceKind::AllocationGranularity) {
        return DirectSpace::Unavailable;
    }
    let mut caller_available = 0;
    let mut actual_free = 0;
    let ret = unsafe {
        // SAFETY: `path` is null-terminated and both output pointers are valid.
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut caller_available,
            std::ptr::null_mut(),
            &mut actual_free,
        )
    };
    direct_space_result(ret, caller_available, actual_free, kind)
}

#[inline(always)]
fn direct_space_result(
    result: i32,
    caller_available: u64,
    actual_free: u64,
    kind: SpaceKind,
) -> DirectSpace {
    let query_failed = result == 0;
    let domain_invalid = caller_available > actual_free;
    if query_failed || domain_invalid {
        DirectSpace::Unavailable
    } else {
        match kind {
            SpaceKind::Free => DirectSpace::Hit(actual_free),
            SpaceKind::Available => DirectSpace::Hit(caller_available),
            SpaceKind::Total | SpaceKind::AllocationGranularity => DirectSpace::Unavailable,
        }
    }
}

fn legacy_space(root_path: &[u16], kind: SpaceKind) -> Result<u64> {
    legacy_space_with(
        kind,
        || byte_space(root_path),
        || cluster_geometry(root_path),
    )
}

fn legacy_space_with(
    kind: SpaceKind,
    byte_query: impl FnOnce() -> Result<ByteSpace>,
    geometry_query: impl FnOnce() -> Result<u64>,
) -> Result<u64> {
    match kind {
        SpaceKind::Free => byte_query().map(|space| space.actual_free),
        SpaceKind::Available => byte_query().map(|space| space.caller_available),
        SpaceKind::Total => byte_query().map(|space| space.caller_total),
        SpaceKind::AllocationGranularity => geometry_query(),
    }
}

fn cluster_geometry(root_path: &[u16]) -> Result<u64> {
    let mut sectors_per_cluster = 0;
    let mut bytes_per_sector = 0;
    let mut free_clusters = 0;
    let mut total_clusters = 0;
    let ret = unsafe {
        // SAFETY: `root_path` is null-terminated UTF-16 and all output pointers are valid.
        GetDiskFreeSpaceW(
            root_path.as_ptr(),
            &mut sectors_per_cluster,
            &mut bytes_per_sector,
            &mut free_clusters,
            &mut total_clusters,
        )
    };
    cluster_geometry_result(ret, sectors_per_cluster, bytes_per_sector)
}

fn cluster_geometry_result(
    result: i32,
    sectors_per_cluster: u32,
    bytes_per_sector: u32,
) -> Result<u64> {
    win32_bool_result(result)?;
    let allocation_granularity = u64::from(sectors_per_cluster) * u64::from(bytes_per_sector);
    validate_granularity(allocation_granularity)
}

struct ByteSpace {
    actual_free: u64,
    caller_available: u64,
    caller_total: u64,
}

fn byte_space(root_path: &[u16]) -> Result<ByteSpace> {
    let mut free_bytes_available_to_caller = 0;
    let mut total_number_of_bytes = 0;
    let mut total_number_of_free_bytes = 0;
    let ret = unsafe {
        // SAFETY: `root_path` is null-terminated UTF-16 and all output pointers are valid.
        GetDiskFreeSpaceExW(
            root_path.as_ptr(),
            &mut free_bytes_available_to_caller,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    };
    byte_space_result(
        ret,
        free_bytes_available_to_caller,
        total_number_of_bytes,
        total_number_of_free_bytes,
    )
}

fn byte_space_result(
    result: i32,
    caller_available: u64,
    caller_total: u64,
    actual_free: u64,
) -> Result<ByteSpace> {
    win32_bool_result(result)?;
    Ok(ByteSpace {
        actual_free,
        caller_available,
        caller_total,
    })
}

#[cfg(test)]
#[path = "windows/tests.rs"]
mod test;
