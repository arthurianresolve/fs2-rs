use std::ffi::OsStr;

pub(super) fn report_errors_value(value: Option<&OsStr>) -> bool {
    let value = value.map(|value| value.to_string_lossy().to_ascii_lowercase());
    !matches!(
        value.as_deref(),
        None | Some("") | Some("0") | Some("false") | Some("off") | Some("no")
    )
}

fn escape_label(label: &str) -> String {
    label
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

pub(super) fn failure_record(label: &str, count: usize) -> String {
    format!(
        "[fs2-bench] FS2_BENCH_FAILURE\t{}\t{count}",
        escape_label(label)
    )
}

pub(super) fn prime_record(label: &str, duration_ns: u128) -> String {
    format!(
        "[fs2-bench] FS2_BENCH_PRIME\t{}\t{duration_ns}",
        escape_label(label)
    )
}
