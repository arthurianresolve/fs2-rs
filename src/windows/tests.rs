use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{Error, ErrorKind};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, IntoRawHandle};
use std::path::{Path, PathBuf};

use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BAD_NETPATH, ERROR_BAD_PATHNAME, ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_DIRECTORY, ERROR_INVALID_DRIVE, ERROR_INVALID_FUNCTION, ERROR_INVALID_NAME,
    ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND, GetHandleInformation,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    DISK_SPACE_INFORMATION, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_STANDARD_INFO, INVALID_FILE_ATTRIBUTES,
};

use super::{
    ByteSpace, DirectSpace, E_NOTIMPL, ProviderOutcome, ProviderProbe, StatsQuery,
    VOLUME_PATH_CAPACITY, allocation_state_result, byte_space_result, cluster_geometry_result,
    copy_exact_drive_root, counters_from_disk_space_information, direct_space, direct_space_result,
    duplicate_result, exact_root_value, get_disk_space_information, handle_space,
    handle_space_attributes_decision, handle_space_attributes_eligible, handle_space_from_info,
    handle_space_query_result, hresult_from_win32, is_volume_resolution_error, legacy_space,
    legacy_space_with, legacy_statvfs, legacy_statvfs_after_geometry, modern_statvfs,
    modern_statvfs_unavailable, modern_statvfs_with, provider_probe, provider_probe_with,
    resolve_module_symbol, root_space_with, space, space_after_exact_root, statvfs_root_with,
    valid_drive_root_components, volume_path, volume_path_result, wide_path, win32_bool_result,
    with_owned_handle,
};
use crate::{FileExt, FilesystemCounters, SpaceKind, lock_contended_error};
use tempfile::tempdir;

const HRESULT_ACCESS_DENIED: i32 = 0x8007_0005_u32 as i32;
const HRESULT_E_FAIL: i32 = 0x8000_4005_u32 as i32;
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
fn maps_win32_boolean_results() {
    assert!(win32_bool_result(1).is_ok());
    assert!(win32_bool_result(-1).is_ok());
    assert!(win32_bool_result(0).is_err());
}

#[test]
fn maps_native_result_seams_without_faulting_the_os() {
    assert!(duplicate_result(0, std::ptr::null_mut()).is_err());
    assert!(allocation_state_result(0, FILE_STANDARD_INFO::default()).is_err());
    assert!(volume_path_result(0).is_err());

    let info = FILE_STANDARD_INFO {
        AllocationSize: 8,
        EndOfFile: 6,
        ..Default::default()
    };
    let state = allocation_state_result(1, info).unwrap();
    assert_eq!(state.allocated_size, 8);
    assert_eq!(state.file_size, 6);

    assert_eq!(cluster_geometry_result(1, 2, 512).unwrap(), 1024);
    assert_eq!(
        cluster_geometry_result(1, u32::MAX, u32::MAX).unwrap(),
        u64::from(u32::MAX) * u64::from(u32::MAX)
    );
    assert!(cluster_geometry_result(0, 2, 512).is_err());

    assert!(byte_space_result(0, 1, 2, 3).is_err());
    let bytes = byte_space_result(1, 1, 2, 3).unwrap();
    assert_eq!(bytes.actual_free, 3);
    assert_eq!(bytes.caller_available, 1);
    assert_eq!(bytes.caller_total, 2);
}

#[test]
fn injects_native_failures_at_result_adapters() {
    assert!(allocation_state_result(0, FILE_STANDARD_INFO::default()).is_err());
    assert!(byte_space_result(0, 0, 0, 0).is_err());
    assert!(cluster_geometry_result(0, 0, 0).is_err());
    assert!(volume_path_result(0).is_err());
    assert_eq!(
        direct_space_result(0, 0, 0, SpaceKind::Free),
        DirectSpace::Unavailable
    );
    assert_eq!(
        handle_space_query_result(1, FILE_FS_FULL_SIZE_INFORMATION::default(), SpaceKind::Free),
        DirectSpace::Unavailable
    );
    assert!(duplicate_result(0, std::ptr::null_mut()).is_err());
}

#[test]
fn selects_modern_or_legacy_query_without_native_provider_state() {
    let counters = FilesystemCounters::windows_modern_bytes(4096, 8, 6, 10);
    let tempdir = tempdir().unwrap();
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(&wide_path(tempdir.path()).unwrap(), &mut root_path).unwrap();

    assert_eq!(
        crate::FsStats::from_counters(statvfs_root_with(&root_path, Some(counters)).unwrap())
            .unwrap()
            .total_space(),
        10
    );
    assert!(statvfs_root_with(&root_path, None).is_ok());
    let legacy = crate::FsStats::from_counters(legacy_statvfs(&root_path).unwrap()).unwrap();
    assert_eq!(
        root_space_with(&root_path, SpaceKind::AllocationGranularity, Ok(None)).unwrap(),
        legacy.allocation_granularity()
    );
}

#[test]
fn maps_legacy_space_kinds_without_native_queries() {
    for (kind, expected) in [
        (SpaceKind::Free, 3),
        (SpaceKind::Available, 1),
        (SpaceKind::Total, 2),
        (SpaceKind::AllocationGranularity, 4096),
    ] {
        let actual = legacy_space_with(
            kind,
            || {
                Ok(ByteSpace {
                    actual_free: 3,
                    caller_available: 1,
                    caller_total: 2,
                })
            },
            || Ok(4096),
        )
        .unwrap();
        assert_eq!(actual, expected, "{kind:?}");
    }
}

#[test]
fn relative_space_queries_resolve_the_volume_path() {
    assert!(space(Path::new("."), SpaceKind::Free).is_ok());
}

#[test]
fn rejects_unresolvable_volume_paths() {
    let unavailable_drive = (b'A'..=b'Z')
        .map(char::from)
        .find(|letter| {
            let root = format!("{}:\\", letter);
            let mut canonical = [0; VOLUME_PATH_CAPACITY];
            volume_path(&wide_path(Path::new(&root)).unwrap(), &mut canonical).is_err()
        })
        .expect("Windows should expose at least one unavailable drive letter");
    let unavailable_root = format!("{}:\\missing", unavailable_drive);

    assert!(StatsQuery::new(Path::new(&unavailable_root)).is_err());
}

#[test]
fn space_rejects_unresolvable_volume_paths() {
    let unavailable_drive = (b'A'..=b'Z')
        .map(char::from)
        .find(|letter| {
            let root = format!("{}:\\", letter);
            let mut canonical = [0; VOLUME_PATH_CAPACITY];
            volume_path(&wide_path(Path::new(&root)).unwrap(), &mut canonical).is_err()
        })
        .expect("Windows should expose at least one unavailable drive letter");
    let unavailable_root = format!("{}:\\missing", unavailable_drive);

    assert!(space(Path::new(&unavailable_root), SpaceKind::Free).is_err());
}

#[test]
fn allocation_preserves_readonly_native_errors() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    fs::write(&path, []).unwrap();

    let readonly = fs::OpenOptions::new().read(true).open(path).unwrap();
    assert!(readonly.allocate(4096).is_err());
}

#[test]
fn resolves_module_symbols_only_when_the_module_is_available() {
    assert!(resolve_module_symbol(std::ptr::null_mut(), get_disk_space_information).is_none());
    let module = unsafe {
        // SAFETY: the module name is a null-terminated static string.
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(windows_sys::core::s!(
            "kernel32.dll"
        ))
    };
    assert!(!module.is_null());
    assert!(resolve_module_symbol(module, get_disk_space_information).is_some());
}

#[test]
fn records_provider_availability() {
    let tempdir = tempdir().unwrap();
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(&wide_path(tempdir.path()).unwrap(), &mut root_path).unwrap();

    let probe = provider_probe(&root_path);
    assert!(
        probe.module_present,
        "kernel32.dll must be loaded on Windows"
    );

    if let Some(output_path) = env::var_os("FS2_WINDOWS_PROVIDER_PROBE") {
        write_provider_probe(Path::new(&output_path), probe).unwrap();
    }
}

#[test]
fn classifies_provider_faults_without_mutating_the_os() {
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
        HRESULT_E_FAIL
    }

    let root_path = [0u16; VOLUME_PATH_CAPACITY];
    assert_eq!(
        provider_probe_with(false, None, &root_path),
        ProviderProbe {
            module_present: false,
            symbol_present: false,
            outcome: ProviderOutcome::Unavailable,
            error_raw_os: None,
        }
    );
    assert_eq!(
        provider_probe_with(true, Some(unavailable_api), &root_path).outcome,
        ProviderOutcome::Unavailable
    );
    assert_eq!(
        provider_probe_with(true, Some(failed_api), &root_path),
        ProviderProbe {
            module_present: true,
            symbol_present: true,
            outcome: ProviderOutcome::Error,
            error_raw_os: Some(HRESULT_E_FAIL),
        }
    );
}

fn write_provider_probe(path: &Path, probe: ProviderProbe) -> std::io::Result<()> {
    let outcome = match probe.outcome {
        ProviderOutcome::Available => "available",
        ProviderOutcome::Unavailable => "unavailable",
        ProviderOutcome::Error => "error",
    };
    let error = probe
        .error_raw_os
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    let contents = format!(
        "{{\n  \"schema_version\": 1,\n  \"api\": \"GetDiskSpaceInformationW\",\n  \"library\": \"kernel32.dll\",\n  \"module_present\": {},\n  \"symbol_present\": {},\n  \"outcome\": \"{}\",\n  \"error_raw_os\": {}\n}}\n",
        probe.module_present, probe.symbol_present, outcome, error
    );
    fs::write(path, contents)
}

#[test]
fn owns_only_valid_windows_handles() {
    assert_eq!(with_owned_handle(INVALID_HANDLE_VALUE, |_| 7_u8), None);

    let tempdir = tempdir().unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(tempdir.path().join("fs2"))
        .unwrap();
    let handle = file.into_raw_handle();
    assert_eq!(with_owned_handle(handle, |_| 7_u8), Some(7));
}

#[test]
fn maps_handle_query_results_before_projecting_counters() {
    let info = FILE_FS_FULL_SIZE_INFORMATION {
        ActualAvailableAllocationUnits: 8,
        CallerAvailableAllocationUnits: 6,
        SectorsPerAllocationUnit: 2,
        BytesPerSector: 512,
        ..Default::default()
    };

    assert_eq!(
        handle_space_query_result(1, info, SpaceKind::Free),
        DirectSpace::Unavailable
    );
    assert_eq!(
        handle_space_query_result(0, info, SpaceKind::Free),
        DirectSpace::Hit(8192)
    );
}

#[test]
fn evaluates_handle_attribute_decision_independently() {
    assert!(handle_space_attributes_decision(true, true));
    assert!(!handle_space_attributes_decision(false, true));
    assert!(!handle_space_attributes_decision(true, false));
    assert!(!handle_space_attributes_decision(false, false));
}

#[test]
fn maps_direct_space_results_and_rejects_invalid_domains() {
    assert_eq!(
        direct_space_result(1, 6, 8, SpaceKind::Free),
        DirectSpace::Hit(8)
    );
    assert_eq!(
        direct_space_result(1, 6, 8, SpaceKind::Available),
        DirectSpace::Hit(6)
    );
    assert_eq!(
        direct_space_result(1, 6, 8, SpaceKind::Total),
        DirectSpace::Unavailable
    );
    assert_eq!(
        direct_space_result(1, 6, 8, SpaceKind::AllocationGranularity),
        DirectSpace::Unavailable
    );
    assert_eq!(
        direct_space_result(0, 6, 8, SpaceKind::Free),
        DirectSpace::Unavailable
    );
    assert_eq!(
        direct_space_result(1, 9, 8, SpaceKind::Free),
        DirectSpace::Unavailable
    );
}

#[test]
fn recognizes_only_volume_resolution_errors() {
    assert!(!is_volume_resolution_error(&Error::other(
        "provider failure"
    )));
    assert!(!is_volume_resolution_error(&Error::from_raw_os_error(
        ERROR_ACCESS_DENIED as i32
    )));
}

#[test]
fn evaluates_drive_root_components_independently() {
    let upper = u16::from(b'C');
    let lower = u16::from(b'c');
    let colon = u16::from(b':');
    let slash = u16::from(b'/');
    let backslash = u16::from(b'\\');

    assert!(valid_drive_root_components(upper, colon, backslash, 0));
    assert!(valid_drive_root_components(lower, colon, slash, 0));
    assert!(!valid_drive_root_components(
        u16::from(b'1'),
        colon,
        backslash,
        0
    ));
    assert!(!valid_drive_root_components(
        upper,
        u16::from(b'x'),
        backslash,
        0
    ));
    assert!(!valid_drive_root_components(
        upper,
        colon,
        u16::from(b'x'),
        0
    ));
    assert!(!valid_drive_root_components(
        upper,
        colon,
        backslash,
        u16::from(b'x')
    ));
}

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
fn rejects_modern_total_space_overflow_after_valid_free_counters() {
    let info = DISK_SPACE_INFORMATION {
        ActualAvailableAllocationUnits: 1,
        CallerAvailableAllocationUnits: 1,
        ActualTotalAllocationUnits: u64::MAX,
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
fn rejects_modern_available_space_overflow_after_valid_free_counters() {
    let info = DISK_SPACE_INFORMATION {
        ActualAvailableAllocationUnits: 1,
        CallerAvailableAllocationUnits: u64::MAX,
        ActualTotalAllocationUnits: 1,
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
    volume_path(&wide_path(tempdir.path()).unwrap(), &mut root_path).unwrap();

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
fn legacy_space_queries_cover_native_fallback_kinds() {
    let tempdir = tempdir().unwrap();
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    volume_path(&wide_path(tempdir.path()).unwrap(), &mut root_path).unwrap();

    for kind in [
        SpaceKind::Free,
        SpaceKind::Available,
        SpaceKind::Total,
        SpaceKind::AllocationGranularity,
    ] {
        assert!(
            legacy_space(&root_path, kind).is_ok(),
            "legacy native query failed for {kind:?}"
        );
    }
}

#[test]
fn propagates_legacy_provider_errors_without_cross_querying() {
    let geometry_error = Error::other("cluster geometry failed");
    assert!(legacy_statvfs_after_geometry(&[0], Err(geometry_error)).is_err());
    assert!(legacy_statvfs_after_geometry(&[0], Ok(1)).is_err());
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
    let path = wide_path(tempdir.path()).unwrap();

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
fn direct_file_space_defers_to_an_alternate_provider() {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("fs2");
    fs::write(&path, []).unwrap();

    assert_eq!(
        direct_space(&wide_path(&path).unwrap(), SpaceKind::Free),
        DirectSpace::Unavailable
    );
    assert!(space(&path, SpaceKind::Free).is_ok());
}

#[test]
fn handle_space_only_resolves_online_files() {
    let tempdir = tempdir().unwrap();
    let file = tempdir.path().join("fs2");
    fs::write(&file, []).unwrap();

    let path = wide_path(&file).unwrap();
    assert!(matches!(
        handle_space(&path, SpaceKind::Free),
        DirectSpace::Hit(_)
    ));
    assert!(matches!(
        handle_space(&path, SpaceKind::Available),
        DirectSpace::Hit(_)
    ));
    assert_eq!(
        handle_space(&path, SpaceKind::Total),
        DirectSpace::Unavailable
    );
    assert_eq!(
        handle_space(&wide_path(tempdir.path()).unwrap(), SpaceKind::Free),
        DirectSpace::Unavailable
    );
}

#[test]
fn handle_space_attributes_only_accept_online_regular_files() {
    assert!(handle_space_attributes_eligible(FILE_ATTRIBUTE_ARCHIVE));
    for attributes in [
        INVALID_FILE_ATTRIBUTES,
        FILE_ATTRIBUTE_DEVICE,
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN,
    ] {
        assert!(!handle_space_attributes_eligible(attributes));
    }
}

#[test]
fn handle_space_projects_valid_file_counters() {
    let info = FILE_FS_FULL_SIZE_INFORMATION {
        ActualAvailableAllocationUnits: 8,
        CallerAvailableAllocationUnits: 6,
        SectorsPerAllocationUnit: 2,
        BytesPerSector: 512,
        ..Default::default()
    };

    assert_eq!(
        handle_space_from_info(info, SpaceKind::Free),
        DirectSpace::Hit(8192)
    );
    assert_eq!(
        handle_space_from_info(info, SpaceKind::Available),
        DirectSpace::Hit(6144)
    );
    assert_eq!(
        handle_space_from_info(info, SpaceKind::Total),
        DirectSpace::Unavailable
    );
}

#[test]
fn handle_space_rejects_invalid_file_counters() {
    let valid = FILE_FS_FULL_SIZE_INFORMATION {
        ActualAvailableAllocationUnits: 8,
        CallerAvailableAllocationUnits: 6,
        SectorsPerAllocationUnit: 2,
        BytesPerSector: 512,
        ..Default::default()
    };
    let invalid = [
        FILE_FS_FULL_SIZE_INFORMATION {
            SectorsPerAllocationUnit: 0,
            ..valid
        },
        FILE_FS_FULL_SIZE_INFORMATION {
            ActualAvailableAllocationUnits: -1,
            ..valid
        },
        FILE_FS_FULL_SIZE_INFORMATION {
            CallerAvailableAllocationUnits: -1,
            ..valid
        },
        FILE_FS_FULL_SIZE_INFORMATION {
            ActualAvailableAllocationUnits: 5,
            CallerAvailableAllocationUnits: 6,
            ..valid
        },
        FILE_FS_FULL_SIZE_INFORMATION {
            ActualAvailableAllocationUnits: i64::MAX,
            CallerAvailableAllocationUnits: i64::MAX,
            ..valid
        },
        FILE_FS_FULL_SIZE_INFORMATION {
            ActualAvailableAllocationUnits: 1,
            CallerAvailableAllocationUnits: i64::MAX,
            ..valid
        },
    ];

    for info in invalid {
        assert_eq!(
            handle_space_from_info(info, SpaceKind::Free),
            DirectSpace::Unavailable
        );
    }
}

#[test]
fn copies_only_exact_drive_roots() {
    let mut root_path = [0; VOLUME_PATH_CAPACITY];
    assert!(copy_exact_drive_root(
        &wide_path(std::path::Path::new("c:/")).unwrap(),
        &mut root_path
    ));
    assert_eq!(
        &root_path[..4],
        &[u16::from(b'c'), u16::from(b':'), u16::from(b'\\'), 0]
    );

    for path in ["C:", r"C:\directory", r"\", r"\\server\share\"] {
        root_path.fill(0);
        assert!(!copy_exact_drive_root(
            &wide_path(std::path::Path::new(path)).unwrap(),
            &mut root_path
        ));
    }

    for path in [
        vec![],
        vec![u16::from(b'1'), u16::from(b':'), u16::from(b'\\'), 0],
        vec![u16::from(b'C'), u16::from(b'x'), u16::from(b'\\'), 0],
        vec![u16::from(b'C'), u16::from(b':'), u16::from(b'x'), 0],
        vec![
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            u16::from(b'x'),
        ],
    ] {
        root_path.fill(0);
        assert!(!copy_exact_drive_root(&path, &mut root_path));
    }
}

#[test]
fn exact_drive_root_matches_canonical_resolution() {
    let current = std::env::current_dir().unwrap();
    let root = current.ancestors().last().unwrap();
    let query = super::StatsQuery::new(root).unwrap();
    let mut canonical = [0; VOLUME_PATH_CAPACITY];
    volume_path(&wide_path(root).unwrap(), &mut canonical).unwrap();

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
        volume_path(&wide_path(&root).unwrap(), &mut canonical)
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
    let code = ERROR_ACCESS_DENIED as i32;
    let error = std::io::Error::from_raw_os_error(code);

    assert!(matches!(
        exact_root_value(Err(error)),
        Err(error) if error.raw_os_error() == Some(code)
    ));
}

#[test]
fn exact_drive_root_returns_provider_error_for_unavailable_drive() {
    let unavailable_root = (b'A'..=b'Z')
        .map(|letter| format!("{}:\\", char::from(letter)))
        .find(|root| !Path::new(root).exists())
        .expect("Windows should expose at least one unavailable drive letter");

    let error = space(Path::new(&unavailable_root), SpaceKind::Free).unwrap_err();
    assert!(error.raw_os_error().is_some());
}

#[test]
fn propagates_exact_root_query_errors_without_volume_fallback() {
    let mut root_path = [0u16; VOLUME_PATH_CAPACITY];
    let error = Error::other("exact root query failed");

    assert!(
        space_after_exact_root(
            &[0],
            SpaceKind::Free,
            &mut root_path,
            Err(error),
            failing_root_space,
        )
        .is_err()
    );

    let tempdir = tempdir().unwrap();
    let path = wide_path(tempdir.path()).unwrap();
    assert!(
        space_after_exact_root(
            &path,
            SpaceKind::Free,
            &mut root_path,
            Err(Error::from_raw_os_error(ERROR_PATH_NOT_FOUND as i32)),
            failing_root_space,
        )
        .is_err()
    );

    let unavailable_root = (b'A'..=b'Z')
        .map(|letter| format!("{}:\\missing", char::from(letter)))
        .find(|root| !Path::new(root).exists())
        .expect("Windows should expose at least one unavailable drive letter");
    let path = wide_path(Path::new(&unavailable_root)).unwrap();
    let resolution_error = Error::from_raw_os_error(ERROR_PATH_NOT_FOUND as i32);
    assert!(
        space_after_exact_root(
            &path,
            SpaceKind::Free,
            &mut root_path,
            Err(resolution_error),
            failing_root_space,
        )
        .is_err()
    );
}

fn failing_root_space(_: &[u16], _: SpaceKind) -> std::io::Result<u64> {
    Err(Error::other("root query failed"))
}

#[test]
fn statistics_preserve_unavailable_volume_errors() {
    let unavailable_root = (b'A'..=b'Z')
        .map(|letter| format!("{}:\\", char::from(letter)))
        .find(|root| !Path::new(root).exists())
        .expect("Windows should expose at least one unavailable drive letter");

    assert!(crate::statvfs(Path::new(&unavailable_root)).is_err());
}

#[test]
fn windows_errors_map_to_documented_hresult_values() {
    assert_eq!(E_NOTIMPL, HRESULT_E_NOTIMPL);
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
    for (win32_error, _) in PATH_ERROR_ENCODINGS {
        let error = std::io::Error::from_raw_os_error(win32_error as i32);
        assert_eq!(exact_root_value(Err(error)).unwrap(), None);
    }
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
        HRESULT_E_FAIL
    }

    unsafe extern "system" fn access_denied_api(
        _root_path: *const u16,
        _info: *mut DISK_SPACE_INFORMATION,
    ) -> windows_sys::core::HRESULT {
        HRESULT_ACCESS_DENIED
    }

    unsafe extern "system" fn missing_path_api(
        _root_path: *const u16,
        _info: *mut DISK_SPACE_INFORMATION,
    ) -> windows_sys::core::HRESULT {
        HRESULT_OBJECT_PATH_NOT_FOUND
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
        Some(HRESULT_E_FAIL)
    );

    let access_denied = modern_statvfs_with(&root_path, Some(access_denied_api)).unwrap_err();
    assert_eq!(access_denied.kind(), ErrorKind::PermissionDenied);
    assert_eq!(
        access_denied.raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );

    let missing_path = modern_statvfs_with(&root_path, Some(missing_path_api)).unwrap_err();
    assert_eq!(missing_path.kind(), ErrorKind::NotFound);
    assert_eq!(
        missing_path.raw_os_error(),
        Some(ERROR_PATH_NOT_FOUND as i32)
    );
}

#[test]
fn statistics_reject_embedded_null_paths() {
    let mut encoded: Vec<_> = std::env::current_dir()
        .unwrap()
        .as_os_str()
        .encode_wide()
        .collect();
    encoded.extend([0, u16::from(b'x')]);
    let path = PathBuf::from(OsString::from_wide(&encoded));

    assert_eq!(
        wide_path(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        crate::statvfs(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        crate::free_space(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        crate::available_space(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        crate::total_space(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        crate::allocation_granularity(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        crate::FsStatsQuery::new(&path).unwrap_err().kind(),
        ErrorKind::InvalidInput
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

#[test]
fn duplicate_preserves_legacy_handle_inheritance() {
    let tempdir = tempdir().unwrap();
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(tempdir.path().join("fs2"))
        .unwrap();
    let duplicate = file.duplicate().unwrap();
    let mut flags = 0;
    let result = unsafe {
        // SAFETY: `duplicate` owns a valid handle and `flags` is writable output storage.
        GetHandleInformation(duplicate.as_raw_handle(), &mut flags)
    };

    assert_ne!(result, 0, "{}", std::io::Error::last_os_error());
    assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
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
