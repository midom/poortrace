//! ELF reads of requested ranges with bounded caching.
use crate::Result;
use object::read::{ReadCache, ReadRef};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    fs::File,
    ops::Range,
};

pub(crate) const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
const MAX_CACHE_READS: usize = 65536;
const STRING_BLOCK: u64 = 64 * 1024;

#[derive(Debug)]
pub(crate) struct Image {
    cache: ReadCache<File>,
    size: u64,
    reads: RefCell<BTreeSet<(u64, u64)>>,
    bytes: Cell<u64>,
    failure: RefCell<Option<String>>,
    index: Option<std::sync::Arc<crate::binary_index::Index>>,
}

impl Image {
    pub(crate) fn new(file: File) -> Result<Self> {
        let index = crate::binary_index::for_file(&file)?;
        let mut image = Self::without_index(file)?;
        image.index = index;
        Ok(image)
    }

    pub(crate) fn without_index(file: File) -> Result<Self> {
        let size = file.metadata().map_err(|e| e.to_string())?.len();
        if size > MAX_FILE_SIZE {
            return Err("ELF image exceeds 4 GiB".into());
        }
        Ok(Self {
            cache: ReadCache::new(file),
            size,
            reads: RefCell::new(BTreeSet::new()),
            bytes: Cell::new(0),
            failure: RefCell::new(None),
            index: None,
        })
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn index(&self) -> Option<&std::sync::Arc<crate::binary_index::Index>> {
        self.index.as_ref()
    }

    pub(crate) fn parse(&self) -> Result<object::File<'_, &Self>> {
        let parsed = object::File::parse(self).map_err(|e| e.to_string());
        self.check()?;
        parsed
    }

    /// Object iterators can hide read errors; callers must check before using
    /// their results, including an empty symbol or marker list.
    pub(crate) fn check(&self) -> Result<()> {
        match &*self.failure.borrow() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn fail(&self, message: &str) {
        self.failure
            .borrow_mut()
            .get_or_insert_with(|| message.into());
    }

    fn reserve(&self, offset: u64, size: u64) -> std::result::Result<(), ()> {
        if offset.checked_add(size).is_none_or(|end| end > self.size) {
            self.fail("ELF read is outside the file");
            return Err(());
        }
        let mut reads = self.reads.borrow_mut();
        if size == 0 || reads.contains(&(offset, size)) {
            return Ok(());
        }
        let bytes = self.bytes.get().checked_add(size).ok_or(())?;
        if bytes > MAX_CACHE_BYTES || reads.len() >= MAX_CACHE_READS {
            self.fail("ELF read cache exceeds 3 GiB or 65536 ranges");
            return Err(());
        }
        reads.insert((offset, size));
        self.bytes.set(bytes);
        Ok(())
    }
}

impl<'a> ReadRef<'a> for &'a Image {
    fn len(self) -> std::result::Result<u64, ()> {
        Ok(self.size)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> std::result::Result<&'a [u8], ()> {
        self.reserve(offset, size)?;
        let result = (&self.cache).read_bytes_at(offset, size);
        if result.is_err() {
            self.fail("cannot read ELF data; the file may have changed");
        }
        result
    }

    fn read_bytes_at_until(
        self,
        range: Range<u64>,
        delimiter: u8,
    ) -> std::result::Result<&'a [u8], ()> {
        if range.start >= range.end || range.end > self.size {
            self.fail("ELF string read is outside the file");
            return Err(());
        }
        // Share blocks across symbol names so range limits do not impose a
        // symbol-count cap. Names can cross blocks and exceed 4096 bytes.
        let offset = range.start & !(STRING_BLOCK - 1);
        let block = self.read_bytes_at(offset, STRING_BLOCK.min(self.size - offset))?;
        let start = (range.start - offset) as usize;
        let end = block.len().min((range.end - offset) as usize);
        let bytes = &block[start..end];
        if let Some(end) = bytes.iter().position(|&byte| byte == delimiter) {
            return Ok(&bytes[..end]);
        }
        let mut next = offset + block.len() as u64;
        loop {
            if next >= range.end {
                self.fail("cannot read a terminated ELF string");
                return Err(());
            }
            let bytes = self.read_bytes_at(next, STRING_BLOCK.min(self.size - next))?;
            let bytes = &bytes[..bytes.len().min((range.end - next) as usize)];
            if let Some(end) = bytes.iter().position(|&byte| byte == delimiter) {
                // Copy only this string, not another overlapping 64 KiB block.
                return self.read_bytes_at(range.start, next + end as u64 - range.start);
            }
            next += bytes.len() as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom, Write},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn sparse(size: u64) -> File {
        let path = std::env::temp_dir().join(format!(
            "poortrace-elf-reader-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.set_len(size).unwrap();
        file
    }

    #[test]
    fn four_gib_file_reads_high_offsets_without_loading_padding() {
        let mut file = sparse(MAX_FILE_SIZE);
        file.seek(SeekFrom::Start(MAX_FILE_SIZE - 4)).unwrap();
        file.write_all(b"ELF!").unwrap();
        let image = Image::new(file).unwrap();
        assert_eq!(
            (&image).read_bytes_at(MAX_FILE_SIZE - 4, 4).unwrap(),
            b"ELF!"
        );
        assert_eq!(
            (&image).read_bytes_at(MAX_FILE_SIZE - 4, 4).unwrap(),
            b"ELF!"
        );
        assert_eq!(image.bytes.get(), 4);
        assert!(image.check().is_ok());
        assert!(Image::new(sparse(MAX_FILE_SIZE + 1)).is_err());
    }

    #[test]
    fn large_ranges_and_truncated_files_return_errors_before_use() {
        let file = sparse(MAX_FILE_SIZE);
        let writer = file.try_clone().unwrap();
        let image = Image::new(file).unwrap();
        assert!((&image).read_bytes_at(0, MAX_CACHE_BYTES + 1).is_err());
        assert!(image.check().unwrap_err().contains("read cache"));
        let image = Image::new(writer.try_clone().unwrap()).unwrap();
        writer.set_len(0).unwrap();
        assert!((&image).read_bytes_at(MAX_FILE_SIZE - 4, 4).is_err());
        assert!(image.check().is_err());
    }

    #[test]
    fn many_names_share_blocks_and_long_names_cross_boundaries() {
        let mut file = sparse(4 * STRING_BLOCK);
        file.write_all(&b"x\0".repeat(70_000)).unwrap();
        let image = Image::new(file).unwrap();
        for offset in (0..140_000).step_by(2) {
            assert_eq!(
                (&image)
                    .read_bytes_at_until(offset..image.size(), 0)
                    .unwrap(),
                b"x"
            );
        }
        assert!(image.bytes.get() <= 3 * STRING_BLOCK);
        assert!(image.check().is_ok());
        let mut file = sparse(2 * STRING_BLOCK);
        file.seek(SeekFrom::Start(STRING_BLOCK - 2)).unwrap();
        file.write_all(&vec![b'x'; 8192]).unwrap();
        let image = Image::new(file).unwrap();
        let name = (&image)
            .read_bytes_at_until(STRING_BLOCK - 2..image.size(), 0)
            .unwrap();
        assert_eq!(name.len(), 8192);
        assert!(name.iter().all(|&byte| byte == b'x'));
        assert!(image.check().is_ok());
    }
}
