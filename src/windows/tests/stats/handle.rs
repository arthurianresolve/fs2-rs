use super::*;

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
    let os_path = file.as_os_str();
    assert!(matches!(
        handle_space(&path, os_path, SpaceKind::Free),
        DirectSpace::Hit(_)
    ));
    assert!(matches!(
        handle_space(&path, os_path, SpaceKind::Available),
        DirectSpace::Hit(_)
    ));
    assert_eq!(
        handle_space(&path, os_path, SpaceKind::Total),
        DirectSpace::Unavailable
    );
    let tempdir_path = tempdir.path().to_path_buf();
    let tempdir_path_wide = wide_path(&tempdir_path).unwrap();
    assert_eq!(
        handle_space(
            &tempdir_path_wide,
            tempdir_path.as_os_str(),
            SpaceKind::Free
        ),
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
