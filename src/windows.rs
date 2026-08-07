use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, S_OK};
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

    if let Some(result) = modern_statvfs(&root_path) {
        return result;
    }

    legacy_statvfs(&root_path)
}

fn modern_statvfs(root_path: &[u16]) -> Option<Result<FilesystemCounters>> {
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

    let get_disk_space_information = get_disk_space_information?;
    let mut info = DISK_SPACE_INFORMATION::default();
    let result = unsafe {
        // SAFETY: `root_path` is null-terminated UTF-16 and `info` is valid output storage.
        get_disk_space_information(root_path.as_ptr(), &mut info)
    };
    if result != S_OK {
        return None;
    }

    Some(counters_from_disk_space_information(info))
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
        total_space: checked_bytes(info.CallerTotalAllocationUnits)?,
    })
}

fn legacy_statvfs(root_path: &[u16]) -> Result<FilesystemCounters> {
    let caller = caller_space(root_path)?;
    let bytes = byte_space(root_path)?;

    Ok(FilesystemCounters {
        allocation_granularity: caller.allocation_granularity,
        free_space: bytes.free,
        available_space: bytes.available,
        total_space: bytes.total,
    })
}

pub(crate) fn space(path: &Path, kind: SpaceKind) -> Result<u64> {
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(path, &mut root_path)?;

    let counters = match kind {
        SpaceKind::Free => {
            let bytes = byte_space(&root_path)?;
            FilesystemCounters {
                allocation_granularity: 1,
                free_space: bytes.free,
                available_space: bytes.available,
                total_space: bytes.total,
            }
        }
        SpaceKind::Available | SpaceKind::Total | SpaceKind::AllocationGranularity => {
            let caller = caller_space(&root_path)?;
            FilesystemCounters {
                allocation_granularity: caller.allocation_granularity,
                free_space: caller.available,
                available_space: caller.available,
                total_space: caller.total,
            }
        }
    };

    counters.value(kind)
}

struct CallerSpace {
    allocation_granularity: u64,
    available: u64,
    total: u64,
}

fn caller_space(root_path: &[u16]) -> Result<CallerSpace> {
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

    Ok(CallerSpace {
        allocation_granularity,
        available: allocation_granularity
            .checked_mul(free_clusters as u64)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "filesystem space overflowed"))?,
        total: allocation_granularity
            .checked_mul(total_clusters as u64)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "filesystem space overflowed"))?,
    })
}

struct ByteSpace {
    free: u64,
    available: u64,
    total: u64,
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
        free: total_number_of_free_bytes,
        available: free_bytes_available_to_caller,
        total: total_number_of_bytes,
    })
}

#[cfg(test)]
mod test {

    use std::fs;
    use std::io::ErrorKind;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::DISK_SPACE_INFORMATION;

    use super::{
        VOLUME_PATH_CAPACITY, counters_from_disk_space_information, legacy_statvfs, modern_statvfs,
        volume_path,
    };
    use crate::{FileExt, lock_contended_error};
    use tempfile::tempdir;

    #[test]
    fn maps_modern_disk_space_information() {
        let info = DISK_SPACE_INFORMATION {
            ActualAvailableAllocationUnits: 8,
            CallerTotalAllocationUnits: 10,
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
    fn modern_and_legacy_stats_are_consistent() {
        let tempdir = tempdir().unwrap();
        let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
        volume_path(tempdir.path(), &mut root_path).unwrap();

        let legacy = legacy_statvfs(&root_path).unwrap();
        assert!(legacy.allocation_granularity > 0);
        assert!(legacy.available_space <= legacy.free_space);
        assert!(legacy.free_space <= legacy.total_space);

        if let Some(modern) = modern_statvfs(&root_path) {
            let modern = modern.unwrap();
            assert_eq!(modern.allocation_granularity, legacy.allocation_granularity);
            assert!(modern.available_space <= modern.free_space);
            assert!(modern.free_space <= modern.total_space);
        }
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
