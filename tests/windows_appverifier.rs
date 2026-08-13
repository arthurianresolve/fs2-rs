#![cfg(windows)]

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

const PROBE_MARKER: &str = "FS2_APPVERIFIER_PROBE_JSON=";

#[test]
fn appverifier_file_fault_is_observed() {
    let mut temporary_directory = None;
    let path = match env::var_os("FS2_APPVERIFIER_PROBE_PATH") {
        Some(path) => PathBuf::from(path),
        None => {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("probe-input");
            fs::write(&path, b"fs2").unwrap();
            temporary_directory = Some(directory);
            path
        }
    };
    let mut wide_path: Vec<u16> = OsStr::new(&path).encode_wide().collect();
    wide_path.push(0);
    let handle = unsafe {
        // SAFETY: `wide_path` is a valid null-terminated path. No data access is
        // requested, sharing is explicit, and the returned handle is closed below.
        CreateFileW(
            wide_path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    let (control_outcome, control_raw_os) = if handle == INVALID_HANDLE_VALUE {
        ("error", std::io::Error::last_os_error().raw_os_error())
    } else {
        let result = unsafe {
            // SAFETY: `handle` was returned by a successful `CreateFileW` call
            // and is closed exactly once here.
            CloseHandle(handle)
        };
        assert_ne!(result, 0, "closing the control handle must succeed");
        ("success", None)
    };

    let (fs2_outcome, fs2_raw_os) = match fs2::free_space(&path) {
        Ok(_) => ("success", None),
        Err(error) => ("error", error.raw_os_error()),
    };
    let fault_expected = env::var_os("FS2_EXPECT_APPVERIFIER_FILE_FAULT").is_some();
    let control_error = control_raw_os.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let fs2_error = fs2_raw_os.map_or_else(|| "null".to_owned(), |value| value.to_string());
    println!(
        "{PROBE_MARKER}{{\"schema_version\":1,\"fault_expected\":{fault_expected},\"control_create_file\":\"{control_outcome}\",\"control_raw_os_error\":{control_error},\"fs2_outcome\":\"{fs2_outcome}\",\"fs2_raw_os_error\":{fs2_error}}}"
    );

    if fault_expected {
        assert_eq!(
            control_outcome, "error",
            "Application Verifier did not inject the configured file-API fault"
        );
        assert!(
            control_raw_os.is_some(),
            "an injected failure must preserve a native error"
        );
        if fs2_outcome == "error" {
            assert!(
                fs2_raw_os.is_some(),
                "fs2 errors under injection must preserve a native error"
            );
        }
    } else {
        assert_eq!(control_outcome, "success");
        assert_eq!(fs2_outcome, "success");
    }

    drop(temporary_directory);
}
