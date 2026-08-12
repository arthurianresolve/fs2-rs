use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    E_NOTIMPL, ERROR_BAD_NETPATH, ERROR_BAD_PATHNAME, ERROR_CALL_NOT_IMPLEMENTED, ERROR_DIRECTORY,
    ERROR_INVALID_DRIVE, ERROR_INVALID_FUNCTION, ERROR_INVALID_NAME, ERROR_INVALID_PARAMETER,
    ERROR_LOCK_VIOLATION, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND, S_OK,
};
use windows_sys::Win32::Storage::FileSystem::{
    DISK_SPACE_INFORMATION, FILE_ALLOCATION_INFO, FILE_STANDARD_INFO, FileAllocationInfo,
    FileStandardInfo, GetDiskFreeSpaceExW, GetDiskFreeSpaceW, GetFileInformationByHandleEx,
    GetVolumePathNameW, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    SetFileInformationByHandle, UnlockFile,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use crate::allocation::AllocationState;
use crate::lock::{LockMode, LockOperation};
use crate::stats::{FsStats, validate_granularity};
use crate::{FilesystemCounters, SpaceKind};

const VOLUME_PATH_CAPACITY: usize = 261;
// `GetDiskSpaceInformationW` can return this NTSTATUS-derived value for an
// unavailable drive instead of a Win32 HRESULT.
const VOLUME_PATH_NOT_FOUND_STATUS: i32 = 0xd000_003a_u32 as i32;
type GetDiskSpaceInformation = unsafe extern "system" fn(
    *const u16,
    *mut DISK_SPACE_INFORMATION,
) -> windows_sys::core::HRESULT;

static GET_DISK_SPACE_INFORMATION: OnceLock<Option<GetDiskSpaceInformation>> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct StatsQuery {
    root_path: [u16; VOLUME_PATH_CAPACITY],
}

impl StatsQuery {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        let mut root_path = [0; VOLUME_PATH_CAPACITY];
        if let Some(drive_root) = exact_drive_root(path) {
            root_path[..drive_root.len()].copy_from_slice(&drive_root);
        } else {
            volume_path(&wide_path(path), &mut root_path)?;
        }
        Ok(Self { root_path })
    }

    pub(crate) fn counters(&self) -> Result<FilesystemCounters> {
        statvfs_root(&self.root_path)
    }
}

#[inline]
pub(crate) fn duplicate(file: &File) -> Result<File> {
    let owned = file.as_handle().try_clone_to_owned()?;
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

    if ret == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(AllocationState {
            allocated_size: info.AllocationSize as u64,
            file_size: info.EndOfFile as u64,
        })
    }
}

pub(crate) const ALLOCATE_SPACE_EXTENDS_LENGTH: bool = false;

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
    if ret == 0 {
        return Err(Error::last_os_error());
    }
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
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
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
    if ret == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn exact_drive_root(path: &Path) -> Option<[u16; 4]> {
    if path.as_os_str().len() != 3 {
        return None;
    }
    let mut units = path.as_os_str().encode_wide();
    let (Some(drive), Some(colon), Some(separator), None) =
        (units.next(), units.next(), units.next(), units.next())
    else {
        return None;
    };
    let is_drive_letter = (u16::from(b'A')..=u16::from(b'Z')).contains(&drive)
        || (u16::from(b'a')..=u16::from(b'z')).contains(&drive);
    let is_separator = separator == u16::from(b'\\') || separator == u16::from(b'/');
    if !is_drive_letter || colon != u16::from(b':') || !is_separator {
        return None;
    }

    Some([drive, colon, u16::from(b'\\'), 0])
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
    if ret == 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn statvfs(path: &Path) -> Result<FilesystemCounters> {
    StatsQuery::new(path)?.counters()
}

fn statvfs_root(root_path: &[u16]) -> Result<FilesystemCounters> {
    query_root(root_path, Ok, legacy_statvfs)
}

#[inline(always)]
fn query_root<T>(
    root_path: &[u16],
    modern: impl FnOnce(FilesystemCounters) -> Result<T>,
    legacy: impl FnOnce(&[u16]) -> Result<T>,
) -> Result<T> {
    match modern_statvfs(root_path)? {
        Some(counters) => modern(counters),
        None => legacy(root_path),
    }
}

fn modern_statvfs(root_path: &[u16]) -> Result<Option<FilesystemCounters>> {
    let get_disk_space_information = *GET_DISK_SPACE_INFORMATION.get_or_init(|| unsafe {
        // SAFETY: kernel32 is loaded in every Windows process and both string literals are
        // null-terminated. The resolved symbol is cast to its documented Windows ABI.
        let module = GetModuleHandleA(windows_sys::core::s!("kernel32.dll"));
        if module.is_null() {
            return None;
        }
        GetProcAddress(module, windows_sys::core::s!("GetDiskSpaceInformationW"))
            .map(|function| std::mem::transmute(function))
    });

    modern_statvfs_with(root_path, get_disk_space_information)
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
        return Err(Error::from_raw_os_error(result));
    }

    counters_from_disk_space_information(info).map(Some)
}

const fn hresult_from_win32(error: u32) -> windows_sys::core::HRESULT {
    ((error & 0xffff) | 0x8007_0000) as windows_sys::core::HRESULT
}

fn modern_statvfs_unavailable(result: windows_sys::core::HRESULT) -> bool {
    result == E_NOTIMPL
        || result == hresult_from_win32(ERROR_CALL_NOT_IMPLEMENTED)
        || result == hresult_from_win32(ERROR_INVALID_FUNCTION)
        || result == hresult_from_win32(ERROR_NOT_SUPPORTED)
}

fn counters_from_disk_space_information(
    info: DISK_SPACE_INFORMATION,
) -> Result<FilesystemCounters> {
    let allocation_granularity = (info.SectorsPerAllocationUnit as u64)
        .checked_mul(info.BytesPerSector as u64)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "filesystem cluster size overflowed"))?;
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
    let geometry = cluster_geometry(root_path)?;
    let bytes = byte_space(root_path)?;

    Ok(FilesystemCounters::windows_legacy_bytes(
        geometry,
        bytes.actual_free,
        bytes.caller_available,
        bytes.caller_total,
    ))
}

pub(crate) fn space(path: &Path, kind: SpaceKind) -> Result<u64> {
    let drive_root = exact_drive_root(path);
    if let Some(drive_root) = drive_root {
        if let Some(value) = direct_space(&drive_root, kind) {
            return Ok(value);
        }
        match root_space(&drive_root, kind) {
            Ok(value) => return Ok(value),
            Err(error) if is_volume_resolution_error(&error) => {}
            Err(error) => return Err(error),
        }
    }

    let path_utf16 = wide_path(path);
    if drive_root.is_none() && path.is_absolute() {
        if let Some(value) = direct_space(&path_utf16, kind) {
            return Ok(value);
        }
    }

    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(&path_utf16, &mut root_path)?;

    root_space(&root_path, kind)
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
    .any(|win32_error| code == win32_error as i32 || code == hresult_from_win32(win32_error) as i32)
        || code == VOLUME_PATH_NOT_FOUND_STATUS
}

fn root_space(root_path: &[u16], kind: SpaceKind) -> Result<u64> {
    query_root(
        root_path,
        |counters| FsStats::from_counters(counters).map(|stats| stats.value(kind)),
        |root_path| legacy_space(root_path, kind),
    )
}

fn direct_space(path: &[u16], kind: SpaceKind) -> Option<u64> {
    if matches!(kind, SpaceKind::Total | SpaceKind::AllocationGranularity) {
        return None;
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
    if ret == 0 || caller_available > actual_free {
        None
    } else {
        match kind {
            SpaceKind::Free => Some(actual_free),
            SpaceKind::Available => Some(caller_available),
            SpaceKind::Total | SpaceKind::AllocationGranularity => None,
        }
    }
}

fn legacy_space(root_path: &[u16], kind: SpaceKind) -> Result<u64> {
    match kind {
        SpaceKind::Free => byte_space(root_path).map(|space| space.actual_free),
        SpaceKind::Available => byte_space(root_path).map(|space| space.caller_available),
        SpaceKind::Total => byte_space(root_path).map(|space| space.caller_total),
        SpaceKind::AllocationGranularity => cluster_geometry(root_path),
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
    if ret == 0 {
        return Err(Error::last_os_error());
    }

    let allocation_granularity = (sectors_per_cluster as u64)
        .checked_mul(bytes_per_sector as u64)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "filesystem cluster size overflowed"))?;
    let allocation_granularity = validate_granularity(allocation_granularity)?;

    Ok(allocation_granularity)
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
    if ret == 0 {
        return Err(Error::last_os_error());
    }

    Ok(ByteSpace {
        actual_free: total_number_of_free_bytes,
        caller_available: free_bytes_available_to_caller,
        caller_total: total_number_of_bytes,
    })
}

#[cfg(test)]
#[path = "windows/tests.rs"]
mod test;
