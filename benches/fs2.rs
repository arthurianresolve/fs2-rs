use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use fs2::{FileExt, available_space, free_space, total_space};
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
            file.fs2_lock_exclusive().unwrap();
            file.fs2_unlock().unwrap();
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

criterion_group!(
    benches,
    bench_file_create,
    bench_file_truncate,
    bench_file_allocate,
    bench_allocated_size,
    bench_duplicate,
    bench_lock_unlock,
    bench_free_space,
    bench_available_space,
    bench_total_space,
);
criterion_main!(benches);
