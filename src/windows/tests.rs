use std::fs;
use std::io::ErrorKind;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_NETPATH, ERROR_BAD_PATHNAME, ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_DIRECTORY, ERROR_INVALID_DRIVE, ERROR_INVALID_FUNCTION, ERROR_INVALID_NAME,
    ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND,
};
use windows_sys::Win32::Storage::FileSystem::DISK_SPACE_INFORMATION;

use super::{
    DirectSpace, E_NOTIMPL, ExactRootSpace, VOLUME_PATH_CAPACITY, VOLUME_PATH_NOT_FOUND_STATUS,
    copy_exact_drive_root, counters_from_disk_space_information, direct_space, exact_root_space,
    hresult_from_win32, legacy_statvfs, modern_statvfs, modern_statvfs_unavailable,
    modern_statvfs_with, space, volume_path, wide_path,
};
use crate::{FileExt, FilesystemCounters, SpaceKind, lock_contended_error};
use tempfile::tempdir;

const HRESULT_ACCESS_DENIED: i32 = 0x8007_0005_u32 as i32;
const HRESULT_E_NOTIMPL: i32 = 0x8000_4001_u32 as i32;
const HRESULT_OBJECT_PATH_NOT_FOUND: i32 = 0xd000_003a_u32 as i32;
const PATH_ERROR_ENCODINGS: [(u32, i32); 7] = [
    (ERROR_BAD_NETPATH, 0x8007_0035_u32 as i32),
    (ERROR_BAD_PATHNAME, 0x8007_00a1_u32 as i32),
    (ERROR_DIRECTORY, 0x8007_010b_u32 as i32),
    (ERROR_INVALID_DRIVE, 0x8007_000f_u32 as i32),
    (ERROR_INVALID_NAME, 0x8007_007b_u32 as i32),
    (ERROR_INVALID_PARAMETER, 0x8007_0057_u32 as i32),
    (ERROR_PATH_NOT_FOUND, 0x8007_0003_u32 as i32),
];
const UNAVAILABLE_ERROR_ENCODINGS: [(u32, i32); 3] = [
    (ERROR_CALL_NOT_IMPLEMENTED, 0x8007_0078_u32 as i32),
    (ERROR_INVALID_FUNCTION, 0x8007_0001_u32 as i32),
    (ERROR_NOT_SUPPORTED, 0x8007_0032_u32 as i32),
];

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
    let stats = crate::FsStats::from_counters(counters).unwrap();
    assert_eq!(stats.allocation_granularity(), 1024);
    assert_eq!(stats.free_space(), 8192);
    assert_eq!(stats.available_space(), 6144);
    assert_eq!(stats.total_space(), 10_240);
}

#[test]
fn rejects_invalid_modern_scalar_snapshot() {
    let counters = FilesystemCounters::windows_modern_bytes(4096, 100, 101, 100);

    assert_eq!(
        crate::FsStats::from_counters(counters).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

#[test]
fn rejects_invalid_modern_snapshot_stats() {
    let counters = FilesystemCounters::windows_modern_bytes(4096, 101, 100, 100);

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
    volume_path(&wide_path(tempdir.path()), &mut root_path).unwrap();

    let legacy = crate::FsStats::from_counters(legacy_statvfs(&root_path).unwrap()).unwrap();
    assert!(legacy.allocation_granularity() > 0);
    assert!(legacy.available_space() <= legacy.free_space());
    assert!(legacy.total_space() > 0);

    if let Some(modern) = modern_statvfs(&root_path).unwrap() {
        let modern = crate::FsStats::from_counters(modern).unwrap();
        assert_eq!(
            modern.allocation_granularity(),
            legacy.allocation_granularity()
        );
        assert!(modern.available_space() <= modern.free_space());
        assert!(modern.free_space() <= modern.total_space());

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
fn filesystem_counters_retain_compact_layout() {
    assert_eq!(
        std::mem::size_of::<FilesystemCounters>(),
        std::mem::size_of::<[u64; 5]>()
    );
}

#[test]
fn direct_directory_space_uses_narrow_queries() {
    let tempdir = tempdir().unwrap();
    let path = wide_path(tempdir.path());

    let DirectSpace::Hit(_) = direct_space(&path, SpaceKind::Free) else {
        panic!("direct free-space query unexpectedly required fallback");
    };
    let DirectSpace::Hit(_) = direct_space(&path, SpaceKind::Available) else {
        panic!("direct available-space query unexpectedly required fallback");
    };

    assert!(matches!(
        direct_space(&path, SpaceKind::Total),
        DirectSpace::Unavailable
    ));
}

#[test]
fn direct_file_space_falls_back_to_canonical_provider() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    fs::write(&path, []).unwrap();

    assert_eq!(
        direct_space(&wide_path(&path), SpaceKind::Free),
        DirectSpace::Unavailable
    );
    assert!(space(&path, SpaceKind::Free).is_ok());
}

#[test]
fn copies_only_exact_drive_roots() {
    let mut root_path = [0; VOLUME_PATH_CAPACITY];
    assert!(copy_exact_drive_root(
        &wide_path(std::path::Path::new("c:/")),
        &mut root_path
    ));
    assert_eq!(
        &root_path[..4],
        &[u16::from(b'c'), u16::from(b':'), u16::from(b'\\'), 0]
    );

    for path in ["C:", r"C:\directory", r"\", r"\\server\share\"] {
        root_path.fill(0);
        assert!(!copy_exact_drive_root(
            &wide_path(std::path::Path::new(path)),
            &mut root_path
        ));
    }
}

#[test]
fn exact_drive_root_matches_canonical_resolution() {
    let current = std::env::current_dir().unwrap();
    let root = current.ancestors().last().unwrap();
    let query = super::StatsQuery::new(root).unwrap();
    let mut canonical = [0; VOLUME_PATH_CAPACITY];
    volume_path(&wide_path(root), &mut canonical).unwrap();

    assert_eq!(query.root_path, canonical);
}

#[test]
fn exact_drive_root_scalars_match_snapshot() {
    let current = std::env::current_dir().unwrap();
    let root = current.ancestors().last().unwrap();
    let stats = crate::statvfs(root).unwrap();

    assert_eq!(space(root, SpaceKind::Total).unwrap(), stats.total_space());
    assert_eq!(
        space(root, SpaceKind::AllocationGranularity).unwrap(),
        stats.allocation_granularity()
    );
}

#[test]
fn exact_drive_root_scalar_errors_match_canonical_resolution() {
    let missing_root = (b'A'..=b'Z').find_map(|drive| {
        let root = PathBuf::from(format!("{}:\\", char::from(drive)));
        let mut canonical = [0; VOLUME_PATH_CAPACITY];
        volume_path(&wide_path(&root), &mut canonical)
            .err()
            .map(|error| (root, error))
    });
    let Some((root, expected)) = missing_root else {
        return;
    };

    for kind in [
        SpaceKind::Free,
        SpaceKind::Available,
        SpaceKind::Total,
        SpaceKind::AllocationGranularity,
    ] {
        let actual = space(&root, kind).unwrap_err();
        assert_eq!(actual.kind(), expected.kind(), "{kind:?}");
        assert_eq!(actual.raw_os_error(), expected.raw_os_error(), "{kind:?}");
    }
}

#[test]
fn exact_drive_root_preserves_provider_errors() {
    for code in [ERROR_ACCESS_DENIED as i32, HRESULT_ACCESS_DENIED] {
        let error = std::io::Error::from_raw_os_error(code);

        assert!(matches!(
            exact_root_space(Err(error)),
            ExactRootSpace::Failed(error) if error.raw_os_error() == Some(code)
        ));
    }
}

#[test]
fn windows_errors_map_to_documented_hresult_values() {
    assert_eq!(E_NOTIMPL, HRESULT_E_NOTIMPL);
    assert_eq!(VOLUME_PATH_NOT_FOUND_STATUS, HRESULT_OBJECT_PATH_NOT_FOUND);
    assert_eq!(
        hresult_from_win32(ERROR_ACCESS_DENIED),
        HRESULT_ACCESS_DENIED
    );
    for (win32_error, hresult) in PATH_ERROR_ENCODINGS {
        assert_eq!(hresult_from_win32(win32_error), hresult);
    }
    for (win32_error, hresult) in UNAVAILABLE_ERROR_ENCODINGS {
        assert_eq!(hresult_from_win32(win32_error), hresult);
    }
}

#[test]
fn modern_provider_only_falls_back_for_unavailable_errors() {
    assert!(modern_statvfs_unavailable(HRESULT_E_NOTIMPL));
    for (_, hresult) in UNAVAILABLE_ERROR_ENCODINGS {
        assert!(modern_statvfs_unavailable(hresult));
    }
    assert!(!modern_statvfs_unavailable(HRESULT_ACCESS_DENIED));
}

#[test]
fn exact_drive_root_only_resolves_volume_for_path_errors() {
    for (win32_error, hresult) in PATH_ERROR_ENCODINGS {
        for code in [win32_error as i32, hresult] {
            let error = std::io::Error::from_raw_os_error(code);
            assert!(matches!(
                exact_root_space(Err(error)),
                ExactRootSpace::ResolveVolume
            ));
        }
    }

    let error = std::io::Error::from_raw_os_error(HRESULT_OBJECT_PATH_NOT_FOUND);
    assert!(matches!(
        exact_root_space(Err(error)),
        ExactRootSpace::ResolveVolume
    ));
}

#[test]
fn distinguishes_unavailable_and_failed_modern_api() {
    unsafe extern "system" fn unavailable_api(
        _root_path: *const u16,
        _info: *mut DISK_SPACE_INFORMATION,
    ) -> windows_sys::core::HRESULT {
        HRESULT_E_NOTIMPL
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
    assert_eq!(
        modern_statvfs_with(&root_path, Some(failed_api))
            .unwrap_err()
            .raw_os_error(),
        Some(-1)
    );
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
