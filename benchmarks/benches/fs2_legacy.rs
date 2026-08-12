use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use fs2::{FileExt, allocation_granularity, available_space, free_space, statvfs, total_space};
use tempfile::tempdir;

fn open_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap()
}

fn bench_file_create(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");

    c.bench_function("file_create", |b| {
        b.iter(|| {
            open_file(&path);
            fs::remove_file(&path).unwrap();
        });
    });
}

fn bench_file_truncate(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");
    let size = 32 * 1024 * 1024;

    c.bench_function("file_truncate", |b| {
        b.iter(|| {
            let file = open_file(&path);
            file.set_len(size).unwrap();
            fs::remove_file(&path).unwrap();
        });
    });
}

fn bench_file_allocate(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");
    let size = 32 * 1024 * 1024;

    c.bench_function("file_allocate", |b| {
        b.iter(|| {
            let file = open_file(&path);
            file.allocate(size).unwrap();
            fs::remove_file(&path).unwrap();
        });
    });
}

fn bench_file_allocate_already_satisfied(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");
    let file = open_file(&path);
    file.allocate(32 * 1024 * 1024).unwrap();

    c.bench_function("file_allocate_already_satisfied", |b| {
        b.iter(|| file.allocate(32 * 1024 * 1024).unwrap());
    });
}

fn bench_allocated_size(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");
    let file = open_file(&path);
    file.allocate(32 * 1024 * 1024).unwrap();

    c.bench_function("allocated_size", |b| {
        b.iter(|| black_box(file.allocated_size().unwrap()));
    });
}

fn bench_duplicate(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");
    let file = open_file(&path);

    c.bench_function("duplicate", |b| {
        b.iter(|| black_box(file.duplicate().unwrap()));
    });
}

fn bench_lock_unlock(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path().join("file");
    let file = open_file(&path);

    c.bench_function("lock_unlock", |b| {
        b.iter(|| {
            file.lock_exclusive().unwrap();
            file.unlock().unwrap();
        });
    });
}

fn bench_free_space(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    c.bench_function("free_space", |b| {
        b.iter(|| black_box(free_space(tempdir.path()).unwrap()));
    });
}

fn bench_available_space(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    c.bench_function("available_space", |b| {
        b.iter(|| black_box(available_space(tempdir.path()).unwrap()));
    });
}

fn bench_total_space(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    c.bench_function("total_space", |b| {
        b.iter(|| black_box(total_space(tempdir.path()).unwrap()));
    });
}

fn bench_stats_snapshot(c: &mut Criterion) {
    let tempdir = tempdir().unwrap();
    let path = tempdir.path();
    let mut group = c.benchmark_group("stats_snapshot");

    group.bench_function("one_snapshot", |b| {
        b.iter(|| {
            let stats = statvfs(path).unwrap();
            black_box((
                stats.free_space(),
                stats.available_space(),
                stats.total_space(),
                stats.allocation_granularity(),
            ))
        });
    });
    group.bench_function("four_convenience_queries", |b| {
        b.iter(|| {
            black_box((
                free_space(path).unwrap(),
                available_space(path).unwrap(),
                total_space(path).unwrap(),
                allocation_granularity(path).unwrap(),
            ))
        });
    });
    group.finish();
}

fn bench_windows_file_space_fallback(c: &mut Criterion) {
    #[cfg(windows)]
    {
        let tempdir = tempdir().unwrap();
        let path = tempdir.path().join("file");
        open_file(&path);

        c.bench_function("free_space_file_fallback", |b| {
            b.iter(|| black_box(free_space(&path).unwrap()));
        });
        c.bench_function("available_space_file_fallback", |b| {
            b.iter(|| black_box(available_space(&path).unwrap()));
        });
    }

    #[cfg(not(windows))]
    let _ = c;
}

fn bench_windows_root_stats(c: &mut Criterion) {
    #[cfg(windows)]
    {
        let current = std::env::current_dir().unwrap();
        let root = current.ancestors().last().unwrap().to_owned();
        let mut group = c.benchmark_group("windows_root_stats");

        group.bench_function("one_top_level_snapshot", |b| {
            b.iter(|| black_box(statvfs(&root).unwrap()));
        });
        group.bench_function("free_space", |b| {
            b.iter(|| black_box(free_space(&root).unwrap()));
        });
        group.bench_function("available_space", |b| {
            b.iter(|| black_box(available_space(&root).unwrap()));
        });
        group.bench_function("total_space", |b| {
            b.iter(|| black_box(total_space(&root).unwrap()));
        });
        group.bench_function("allocation_granularity", |b| {
            b.iter(|| black_box(allocation_granularity(&root).unwrap()));
        });
        group.finish();
    }

    #[cfg(not(windows))]
    let _ = c;
}

criterion_group!(
    benches,
    bench_file_create,
    bench_file_truncate,
    bench_file_allocate,
    bench_file_allocate_already_satisfied,
    bench_allocated_size,
    bench_duplicate,
    bench_lock_unlock,
    bench_free_space,
    bench_available_space,
    bench_total_space,
    bench_stats_snapshot,
    bench_windows_file_space_fallback,
    bench_windows_root_stats,
);
criterion_main!(benches);
