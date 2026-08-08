use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    E_NOTIMPL, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_FUNCTION, ERROR_LOCK_VIOLATION,
    ERROR_NOT_SUPPORTED, S_OK,
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
use crate::stats::{WindowsCounterSource, validate_granularity};
use crate::{FilesystemCounters, SpaceKind};

const VOLUME_PATH_CAPACITY: usize = 261;
type GetDiskSpaceInformation = unsafe extern "system" fn(
    *const u16,
    *mut DISK_SPACE_INFORMATION,
) -> windows_sys::core::HRESULT;

static GET_DISK_SPACE_INFORMATION: OnceLock<Option<GetDiskSpaceInformation>> = OnceLock::new();

#[inline]
pub(crate) fn duplicate(file: &File) -> Result<File> {
    let owned = file.as_handle().try_clone_to_owned()?;
    Ok(File::from(owned))
}

pub(crate) fn allocation_state(file: &File) -> Result<AllocationState> {
    let mut info = FILE_STANDARD_INFO::default();
    let ret = unsafe {
        // SAFETY: `file` owns a valid handle and `info` is properly sized and aligned.
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
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

pub(crate) fn allocated_size(file: &File) -> Result<u64> {
    allocation_state(file).map(|state| state.allocated_size)
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

fn volume_path(path: &Path, volume_path: &mut [u16]) -> Result<()> {
    let path_utf16: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let ret = unsafe {
        // SAFETY: `path_utf16` is null-terminated and `volume_path` is valid output storage.
        GetVolumePathNameW(
            path_utf16.as_ptr(),
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
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(path, &mut root_path)?;

    if let Some(counters) = modern_statvfs(&root_path)? {
        return Ok(counters);
    }

    legacy_statvfs(&root_path)
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
        return Err(Error::last_os_error());
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

    Ok(FilesystemCounters {
        allocation_granularity,
        free_space: checked_bytes(info.ActualAvailableAllocationUnits)?,
        available_space: checked_bytes(info.CallerAvailableAllocationUnits)?,
        total_space: checked_bytes(info.ActualTotalAllocationUnits)?,
        source: WindowsCounterSource::Modern,
    })
}

fn legacy_statvfs(root_path: &[u16]) -> Result<FilesystemCounters> {
    let geometry = cluster_geometry(root_path)?;
    let bytes = byte_space(root_path)?;

    Ok(FilesystemCounters {
        allocation_granularity: geometry.allocation_granularity,
        free_space: bytes.actual_free,
        available_space: bytes.caller_available,
        total_space: bytes.caller_total,
        source: WindowsCounterSource::Legacy,
    })
}

pub(crate) fn space(path: &Path, kind: SpaceKind) -> Result<u64> {
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(path, &mut root_path)?;

    if let Some(counters) = modern_statvfs(&root_path)? {
        return counter_value(counters, kind);
    }

    legacy_space(&root_path, kind)
}

fn counter_value(counters: FilesystemCounters, kind: SpaceKind) -> Result<u64> {
    match kind {
        SpaceKind::Free => Ok(counters.free_space),
        SpaceKind::Available => Ok(counters.available_space),
        SpaceKind::Total => Ok(counters.total_space),
        SpaceKind::AllocationGranularity => validate_granularity(counters.allocation_granularity),
    }
}

fn legacy_space(root_path: &[u16], kind: SpaceKind) -> Result<u64> {
    match kind {
        SpaceKind::Free => byte_space(root_path).map(|space| space.actual_free),
        SpaceKind::Available => byte_space(root_path).map(|space| space.caller_available),
        SpaceKind::Total => byte_space(root_path).map(|space| space.caller_total),
        SpaceKind::AllocationGranularity => {
            cluster_geometry(root_path).map(|geometry| geometry.allocation_granularity)
        }
    }
}

struct ClusterGeometry {
    allocation_granularity: u64,
}

fn cluster_geometry(root_path: &[u16]) -> Result<ClusterGeometry> {
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

    Ok(ClusterGeometry {
        allocation_granularity,
    })
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
mod test {

    use std::fs;
    use std::io::ErrorKind;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::DISK_SPACE_INFORMATION;

    use super::{
        E_NOTIMPL, VOLUME_PATH_CAPACITY, counter_value, counters_from_disk_space_information,
        legacy_statvfs, modern_statvfs, modern_statvfs_with, space, volume_path,
    };
    use crate::stats::WindowsCounterSource;
    use crate::{FileExt, FilesystemCounters, SpaceKind, lock_contended_error};
    use tempfile::tempdir;

    #[test]
    fn maps_modern_disk_space_information() {
        let info = DISK_SPACE_INFORMATION {
            ActualAvailableAllocationUnits: 8,
            ActualTotalAllocationUnits: 10,
            CallerTotalAllocationUnits: 6,
            CallerAvailableAllocationUnits: 6,
            SectorsPerAllocationUnit: 2,
            BytesPerSector: 512,
            ..Default::default()
        };

        let counters = counters_from_disk_space_information(info).unwrap();
        assert_eq!(counters.allocation_granularity, 1024);
        assert_eq!(counters.free_space, 8192);
        assert_eq!(counters.available_space, 6144);
        assert_eq!(counters.total_space, 10_240);
    }

    #[test]
    fn projects_modern_scalar_without_full_snapshot_validation() {
        let counters = FilesystemCounters {
            allocation_granularity: 4096,
            free_space: 100,
            available_space: 101,
            total_space: 100,
            source: WindowsCounterSource::Modern,
        };

        assert_eq!(counter_value(counters, SpaceKind::Free).unwrap(), 100);
    }

    #[test]
    fn rejects_invalid_modern_snapshot_stats() {
        let counters = FilesystemCounters {
            allocation_granularity: 4096,
            free_space: 101,
            available_space: 100,
            total_space: 100,
            source: WindowsCounterSource::Modern,
        };

        assert_eq!(
            crate::FsStats::from_counters(counters).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_modern_disk_space_overflow() {
        let info = DISK_SPACE_INFORMATION {
            ActualAvailableAllocationUnits: u64::MAX,
            CallerTotalAllocationUnits: u64::MAX,
            CallerAvailableAllocationUnits: u64::MAX,
            SectorsPerAllocationUnit: 8,
            BytesPerSector: 512,
            ..Default::default()
        };

        assert_eq!(
            counters_from_disk_space_information(info)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn modern_and_legacy_stats_have_valid_domains() {
        let tempdir = tempdir().unwrap();
        let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
        volume_path(tempdir.path(), &mut root_path).unwrap();

        let legacy = legacy_statvfs(&root_path).unwrap();
        assert!(legacy.allocation_granularity > 0);
        assert!(legacy.available_space <= legacy.free_space);
        assert!(legacy.total_space > 0);

        if let Some(modern) = modern_statvfs(&root_path).unwrap() {
            assert_eq!(modern.allocation_granularity, legacy.allocation_granularity);
            assert!(modern.available_space <= modern.free_space);
            assert!(modern.free_space <= modern.total_space);

            // Each scalar query acquires a fresh snapshot; space counters can
            // change between calls while the test is running.
            for kind in [
                SpaceKind::Free,
                SpaceKind::Available,
                SpaceKind::Total,
                SpaceKind::AllocationGranularity,
            ] {
                assert!(
                    space(tempdir.path(), kind).is_ok(),
                    "scalar query failed for {kind:?}"
                );
            }
        }
    }

    #[test]
    fn distinguishes_unavailable_and_failed_modern_api() {
        unsafe extern "system" fn unavailable_api(
            _root_path: *const u16,
            _info: *mut DISK_SPACE_INFORMATION,
        ) -> windows_sys::core::HRESULT {
            E_NOTIMPL
        }

        unsafe extern "system" fn failed_api(
            _root_path: *const u16,
            _info: *mut DISK_SPACE_INFORMATION,
        ) -> windows_sys::core::HRESULT {
            -1
        }

        let root_path = [0u16; VOLUME_PATH_CAPACITY];
        assert!(modern_statvfs_with(&root_path, None).unwrap().is_none());
        assert!(
            modern_statvfs_with(&root_path, Some(unavailable_api))
                .unwrap()
                .is_none()
        );
        assert!(modern_statvfs_with(&root_path, Some(failed_api)).is_err());
    }

    /// The duplicate method returns a file with a new file handle.
    #[test]
    fn duplicate_new_handle() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = file1.duplicate().unwrap();
        assert!(file1.as_raw_handle() != file2.as_raw_handle());
    }

    /// A duplicated file handle does not have access to the original handle's locks.
    #[test]
    fn lock_duplicate_handle_independence() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = file1.duplicate().unwrap();

        // Locking the original file handle will block the duplicate file handle from opening a lock.
        file1.fs2_lock_shared().unwrap();
        assert_eq!(
            file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );

        // Once the original file handle is unlocked, the duplicate handle can proceed with a lock.
        file1.fs2_unlock().unwrap();
        file2.fs2_lock_exclusive().unwrap();
    }

    /// A file handle may not be exclusively locked multiple times, or exclusively locked and then
    /// shared locked.
    #[test]
    fn lock_non_reentrant() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Multiple exclusive locks fails.
        file.fs2_lock_exclusive().unwrap();
        assert_eq!(
            file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );
        file.fs2_unlock().unwrap();

        // Shared then Exclusive locks fails.
        file.fs2_lock_shared().unwrap();
        assert_eq!(
            file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );
    }

    /// A file handle can hold an exclusive lock and any number of shared locks, all of which must
    /// be unlocked independently.
    #[test]
    fn lock_layering() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Open two shared locks on the file, and then try and fail to open an exclusive lock.
        file.fs2_lock_exclusive().unwrap();
        file.fs2_lock_shared().unwrap();
        file.fs2_lock_shared().unwrap();
        assert_eq!(
            file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );

        // Pop one of the shared locks and try again.
        file.fs2_unlock().unwrap();
        assert_eq!(
            file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );

        // Pop the second shared lock and try again.
        file.fs2_unlock().unwrap();
        assert_eq!(
            file.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );

        // Pop the exclusive lock and finally succeed.
        file.fs2_unlock().unwrap();
        file.fs2_lock_exclusive().unwrap();
    }

    /// A file handle with multiple open locks will have all locks closed on drop.
    #[test]
    fn lock_layering_cleanup() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();

        // Open two shared locks on the file, and then try and fail to open an exclusive lock.
        file1.fs2_lock_shared().unwrap();
        assert_eq!(
            file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );

        drop(file1);
        file2.fs2_lock_exclusive().unwrap();
    }

    /// A file handle's locks will not be released until the original handle and all of its
    /// duplicates have been closed. This on really smells like a bug in Windows.
    #[test]
    fn lock_duplicate_cleanup() {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("fs2");
        let file1 = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        let file2 = file1.duplicate().unwrap();

        // Open a lock on the original handle, then close it.
        file1.fs2_lock_shared().unwrap();
        drop(file1);

        // Attempting to create a lock on the file with the duplicate handle will fail.
        assert_eq!(
            file2.fs2_try_lock_exclusive().unwrap_err().raw_os_error(),
            lock_contended_error().raw_os_error()
        );
    }
}
