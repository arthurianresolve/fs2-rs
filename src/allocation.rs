use std::fs::File;
use std::io::Result;

pub(crate) fn allocate(
    file: &File,
    len: u64,
    allocated_size: impl Fn(&File) -> Result<u64>,
    allocate_space: impl Fn(&File, u64) -> Result<()>,
) -> Result<()> {
    if allocated_size(file)? < len {
        allocate_space(file, len)?;
    }

    if file.metadata()?.len() < len {
        file.set_len(len)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::OpenOptions;

    use tempfile::tempdir;

    use super::allocate;

    #[test]
    fn reserves_space_before_extending_file() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();
        let reserve_called = Cell::new(false);

        allocate(
            &file,
            8,
            |_| Ok(0),
            |_, len| {
                assert_eq!(len, 8);
                reserve_called.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(reserve_called.get());
        assert_eq!(file.metadata().unwrap().len(), 8);
    }

    #[test]
    fn skips_reservation_when_space_is_already_available() {
        let tempdir = tempdir().unwrap();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(tempdir.path().join("fs2"))
            .unwrap();
        let reserve_called = Cell::new(false);

        allocate(
            &file,
            8,
            |_| Ok(16),
            |_, _| {
                reserve_called.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert!(!reserve_called.get());
        assert_eq!(file.metadata().unwrap().len(), 8);
    }
}
