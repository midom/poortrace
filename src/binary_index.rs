//! Versioned flat native symbol indexes. Strings and sorted tables stay on disk;
//! mmap faults in only the pages used by a lookup. Writers publish atomically.
use crate::Result;
use object::{Object, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{File, OpenOptions},
    io::{BufWriter, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

const MAGIC: &[u8; 8] = b"PTRIDX01";
const HEADER: usize = 160;
const RECORD: usize = 56;
const MAX_INDEX: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SYMBOLS: usize = 16_000_000;
const MAX_METADATA: usize = 16 * 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);
static INDEXES: OnceLock<RwLock<Vec<Arc<Index>>>> = OnceLock::new();

fn architecture() -> u64 {
    if cfg!(target_arch = "x86_64") {
        62
    } else {
        183
    }
}

fn stamp(file: &File) -> Result<[u64; 7]> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    Ok([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ])
}

fn file_path(file: &File) -> Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|e| e.to_string())
}

#[derive(Debug)]
struct Mapped {
    pointer: *mut libc::c_void,
    len: usize,
    _file: File,
}
// The mapping is read-only and has no mutable references. Files written by this
// module are never changed in place; replacement preserves existing mappings.
unsafe impl Send for Mapped {}
unsafe impl Sync for Mapped {}
impl Mapped {
    fn new(file: File) -> Result<Self> {
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        if len < HEADER as u64 || len > MAX_INDEX {
            return Err("binary index size is outside 160 bytes..16 GiB".into());
        }
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len as usize,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self {
            pointer,
            len: len as usize,
            _file: file,
        })
    }
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer.cast(), self.len) }
    }
}
impl Drop for Mapped {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer, self.len);
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Metadata {
    path: PathBuf,
    sites: Vec<crate::usdt::Site>,
    site_error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Index {
    data: Mapped,
    stamp: [u64; 7],
    count: usize,
    pool_end: usize,
    records: usize,
    raw_order: usize,
    display_order: usize,
    metadata: Metadata,
}

fn word(bytes: &[u8], at: usize) -> Result<u64> {
    let bytes = bytes
        .get(at..at.checked_add(8).ok_or("binary index offset overflow")?)
        .ok_or("truncated binary index")?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

impl Index {
    fn open(path: &Path) -> Result<Self> {
        let data = Mapped::new(File::open(path).map_err(|e| format!("{}: {e}", path.display()))?)?;
        let bytes = data.bytes();
        if &bytes[..8] != MAGIC || word(bytes, 8)? != 1 || word(bytes, 16)? != architecture() {
            return Err("unsupported binary index version or architecture".into());
        }
        let mut stamp = [0; 7];
        for (i, value) in stamp.iter_mut().enumerate() {
            *value = word(bytes, 24 + 8 * i)?;
        }
        let count = word(bytes, 88)?;
        let pool_end = (HEADER as u64)
            .checked_add(word(bytes, 80)?)
            .ok_or("binary index string size overflow")?;
        let records = word(bytes, 96)?;
        let raw_order = word(bytes, 104)?;
        let display_order = word(bytes, 112)?;
        let metadata_start = word(bytes, 120)?;
        let metadata_len = word(bytes, 128)?;
        // Require one exact, non-overlapping layout before reading table entries.
        if count > MAX_SYMBOLS as u64
            || stamp[2] > crate::elf_image::MAX_FILE_SIZE
            || records != pool_end
            || records.checked_add(count * RECORD as u64) != Some(raw_order)
            || raw_order.checked_add(count * 4) != Some(display_order)
            || display_order.checked_add(count * 4) != Some(metadata_start)
            || metadata_len > MAX_METADATA as u64
            || metadata_start.checked_add(metadata_len) != Some(bytes.len() as u64)
            || word(bytes, 136)? != bytes.len() as u64
            || word(bytes, 144)? != header_hash(&bytes[..144])
        {
            return Err("invalid binary index layout or header".into());
        }
        let metadata: Metadata = serde_json::from_slice(&bytes[metadata_start as usize..])
            .map_err(|e| format!("binary index metadata: {e}"))?;
        for site in &metadata.sites {
            let encoded = format!("__sdt__{}", serde_json::to_string(site).map_err(|e| e.to_string())?);
            crate::usdt::encoded(&encoded)?;
        }
        Ok(Self {
            data,
            stamp,
            count: count as usize,
            pool_end: pool_end as usize,
            records: records as usize,
            raw_order: raw_order as usize,
            display_order: display_order as usize,
            metadata,
        })
    }

    fn record(&self, id: usize) -> Result<[u64; 7]> {
        if id >= self.count {
            return Err("invalid binary index symbol ID".into());
        }
        let mut row = [0; 7];
        for (i, value) in row.iter_mut().enumerate() {
            *value = word(self.data.bytes(), self.records + id * RECORD + i * 8)?;
        }
        Ok(row)
    }

    fn name(&self, row: &[u64; 7], display: bool) -> Result<&str> {
        let i = if display { 5 } else { 3 };
        let (start, size) = (row[i], row[i + 1]);
        let end = start.checked_add(size).ok_or("binary index string overflow")?;
        if start < HEADER as u64 || end > self.pool_end as u64 {
            return Err("binary index name is outside the string pool".into());
        }
        std::str::from_utf8(&self.data.bytes()[start as usize..end as usize])
            .map_err(|e| format!("binary index name: {e}"))
    }

    fn ordered(&self, position: usize, display: bool) -> Result<usize> {
        let start = if display {
            self.display_order
        } else {
            self.raw_order
        };
        let bytes = self.data.bytes()
            .get(start + position * 4..start + position * 4 + 4)
            .ok_or("truncated binary index name table")?;
        let id = u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
        if id >= self.count {
            return Err("invalid binary index name table ID".into());
        }
        Ok(id)
    }

    fn matching_ids(&self, name: &str, exact: bool) -> Result<BTreeSet<usize>> {
        let mut ids = BTreeSet::new();
        for display in [false, true] {
            let (mut low, mut high) = (0, self.count);
            while low < high {
                let middle = low + (high - low) / 2;
                let row = self.record(self.ordered(middle, display)?)?;
                if self.name(&row, display)? < name {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
            while low < self.count {
                let id = self.ordered(low, display)?;
                let candidate = self.name(&self.record(id)?, display)?;
                if (exact && candidate != name) || (!exact && !candidate.starts_with(name)) {
                    break;
                }
                ids.insert(id);
                low += 1;
            }
        }
        Ok(ids)
    }

    pub(crate) fn lookup(&self, name: &str) -> Result<BTreeSet<(u64, u64)>> {
        self.matching_ids(name, true)?
            .into_iter()
            .map(|id| {
                let row = self.record(id)?;
                Ok((row[0], row[1]))
            })
            .collect()
    }

    pub(crate) fn functions(&self, pattern: &str) -> Result<Vec<crate::uprobe::Function>> {
        let exact = !pattern.contains(['*', '?']);
        let prefix_end = pattern.find(['*', '?']).unwrap_or(pattern.len());
        let prefix = &pattern[..prefix_end];
        let ids: Box<dyn Iterator<Item = usize>> = if !prefix.is_empty() || exact {
            Box::new(self.matching_ids(prefix, exact)?.into_iter())
        } else {
            Box::new(0..self.count)
        };
        let mut found = BTreeSet::new();
        for id in ids {
            let row = self.record(id)?;
            let name = self.name(&row, false)?;
            let display = self.name(&row, true)?;
            if exact
                || crate::uprobe::matches(pattern, name)
                || crate::uprobe::matches(pattern, display)
            {
                found.insert(crate::uprobe::Function {
                    offset: row[2],
                    name: name.into(),
                    demangled: display.into(),
                });
            }
        }
        Ok(found.into_iter().collect())
    }

    pub(crate) fn resolve(&self, address: u64) -> Result<Option<(String, u64)>> {
        let (mut low, mut high) = (0, self.count);
        while low < high {
            let middle = low + (high - low) / 2;
            if self.record(middle)?[0] <= address {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let Some(id) = low.checked_sub(1) else {
            return Ok(None);
        };
        let row = self.record(id)?;
        let delta = address - row[0];
        if row[1] != 0 && delta >= row[1] {
            return Ok(None);
        }
        Ok(Some((self.name(&row, true)?.into(), delta)))
    }

    pub(crate) fn sites(&self) -> Result<Vec<crate::usdt::Site>> {
        match &self.metadata.site_error {
            Some(error) => Err(error.clone()),
            None => Ok(self.metadata.sites.clone()),
        }
    }
}

fn header_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |sum, byte| {
        (sum ^ *byte as u64).wrapping_mul(0x100000001b3)
    })
}

/// Register reusable indexes for this tracer process. Invalid files fail explicitly.
pub fn configure(paths: &[PathBuf]) -> Result<()> {
    if paths.len() > 1024 {
        return Err("at most 1024 binary indexes are supported".into());
    }
    let indexes = paths.iter()
        .map(|path| Index::open(path).map(Arc::new))
        .collect::<Result<Vec<_>>>()?;
    *INDEXES.get_or_init(|| RwLock::new(Vec::new()))
        .write().map_err(|e| e.to_string())? = indexes;
    Ok(())
}

pub(crate) fn for_file(file: &File) -> Result<Option<Arc<Index>>> {
    let Some(indexes) = INDEXES.get() else {
        return Ok(None);
    };
    let indexes = indexes.read().map_err(|e| e.to_string())?;
    if indexes.is_empty() {
        return Ok(None);
    }
    let current = stamp(file)?;
    let mut path = None;
    for index in indexes.iter() {
        if current[..2] == index.stamp[..2] {
            if current != index.stamp {
                return Err("stale binary index: binary has changed; rebuild the index".into());
            }
            return Ok(Some(index.clone()));
        }
        if path.is_none() {
            path = Some(file_path(file)?);
        }
        let path = path.as_ref().unwrap();
        if *path == index.metadata.path {
            return Err("stale binary index: binary has been replaced; rebuild the index".into());
        }
    }
    Ok(None)
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build an index without attaching. Absolute binary paths use the PID namespace.
/// Existing output files are replaced atomically; the binary is never overwritten.
pub fn build(tid: i32, binary: &str, output: &Path) -> Result<usize> {
    if tid <= 0 {
        return Err("binary index construction requires a positive PID".into());
    }
    let path = if binary.starts_with('/') {
        format!("/proc/{tid}/root{binary}")
    } else {
        binary.into()
    };
    let file = File::open(&path).map_err(|e| format!("{binary}: {e}"))?;
    let before = stamp(&file)?;
    if before[2] > crate::elf_image::MAX_FILE_SIZE {
        return Err("ELF image exceeds 4 GiB".into());
    }
    if std::fs::metadata(output).is_ok_and(|m| (m.dev(), m.ino()) == (before[0], before[1])) {
        return Err("binary index output must differ from the binary".into());
    }
    let source_path = file_path(&file)?;
    // A build scans symbol names once. Map the source instead of keeping a
    // second heap copy of its string tables beside the output name pool.
    let source = Mapped::new(file.try_clone().map_err(|e| e.to_string())?)?;
    let elf = object::File::parse(source.bytes()).map_err(|e| e.to_string())?;
    let arch = if cfg!(target_arch = "x86_64") {
        object::Architecture::X86_64
    } else {
        object::Architecture::Aarch64
    };
    if !elf.is_64() || elf.architecture() != arch || !elf.is_little_endian() {
        return Err("binary indexes require native 64-bit ELF".into());
    }
    let parent = output.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = Temporary(parent.join(format!(
        ".poortrace-index-{}-{}",
        std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    let out = OpenOptions::new()
        .read(true).write(true).create_new(true).open(&temporary.0)
        .map_err(|e| format!("{}: {e}", temporary.0.display()))?;
    let mut writer = BufWriter::new(out);
    writer.write_all(&[0; HEADER]).map_err(|e| e.to_string())?;
    let mut position = HEADER as u64;
    let mut rows = Vec::<[u64; 7]>::new();
    // Borrow names from the source mapping; retain no second string copy.
    // Regular/dynamic tables and aliases can repeat very large template names.
    let mut names = HashMap::<&str, [u64; 4]>::new();
    for symbol in elf.symbols().chain(elf.dynamic_symbols()) {
        if symbol.kind() != SymbolKind::Text || symbol.is_undefined() {
            continue;
        }
        let offset = elf.segments().find_map(|segment| {
            let (offset, size) = segment.file_range();
            (matches!(segment.flags(), SegmentFlags::Elf {p_flags} if p_flags & 1 != 0)
                && symbol.address() >= segment.address()
                && symbol.address() - segment.address() < size)
                .then(|| offset + symbol.address() - segment.address())
        });
        let (Some(offset), Ok(name)) = (offset, symbol.name()) else {
            continue;
        };
        if rows.len() >= MAX_SYMBOLS {
            return Err("binary index exceeds 16000000 symbols".into());
        }
        let entry = if let Some(entry) = names.get(name) {
            *entry
        } else {
            let display = crate::symbols::demangle(name);
            let raw = position;
            writer.write_all(name.as_bytes()).map_err(|e| e.to_string())?;
            position += name.len() as u64;
            let pretty = if display == name {
                raw
            } else {
                let start = position;
                writer.write_all(display.as_bytes()).map_err(|e| e.to_string())?;
                position += display.len() as u64;
                start
            };
            let entry = [raw, name.len() as u64, pretty, display.len() as u64];
            names.insert(name, entry);
            entry
        };
        if position > MAX_INDEX {
            return Err("binary index exceeds 16 GiB".into());
        }
        rows.push([
            symbol.address(), symbol.size(), offset,
            entry[0], entry[1], entry[2], entry[3],
        ]);
    }
    let (sites, site_error) = match crate::usdt::sites_from_data(source.bytes()) {
        Ok(sites) => (sites, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    drop(names);
    drop(elf);
    drop(source);
    writer.flush().map_err(|e| e.to_string())?;
    let strings = Mapped::new(writer.get_ref().try_clone().map_err(|e| e.to_string())?)?;
    let name = |row: &[u64; 7], display: bool| {
        let i = if display { 5 } else { 3 };
        &strings.bytes()[row[i] as usize..(row[i] + row[i + 1]) as usize]
    };
    rows.sort_unstable_by(|a, b| {
        (a[0], name(a, true), name(a, false), a[1])
            .cmp(&(b[0], name(b, true), name(b, false), b[1]))
    });
    rows.dedup_by(|a, b| a[..3] == b[..3] && name(a, false) == name(b, false));
    let mut raw_order: Vec<u32> = (0..rows.len() as u32).collect();
    raw_order.sort_unstable_by(|&a, &b| {
        name(&rows[a as usize], false).cmp(name(&rows[b as usize], false))
    });
    let mut display_order: Vec<u32> = (0..rows.len() as u32).collect();
    display_order.sort_unstable_by(|&a, &b| {
        name(&rows[a as usize], true).cmp(name(&rows[b as usize], true))
    });
    let records = position;
    for row in &rows {
        for value in row {
            writer.write_all(&value.to_le_bytes()).map_err(|e| e.to_string())?;
        }
    }
    let raw_start = records + rows.len() as u64 * RECORD as u64;
    for id in &raw_order {
        writer.write_all(&id.to_le_bytes()).map_err(|e| e.to_string())?;
    }
    let display_start = raw_start + rows.len() as u64 * 4;
    for id in &display_order {
        writer.write_all(&id.to_le_bytes()).map_err(|e| e.to_string())?;
    }
    let metadata_start = display_start + rows.len() as u64 * 4;
    let metadata = serde_json::to_vec(&Metadata {
        path: source_path, sites, site_error,
    }).map_err(|e| e.to_string())?;
    if metadata.len() > MAX_METADATA {
        return Err("binary index SDT metadata exceeds 16 MiB".into());
    }
    let total = metadata_start + metadata.len() as u64;
    if total > MAX_INDEX {
        return Err("binary index exceeds 16 GiB".into());
    }
    writer.write_all(&metadata).map_err(|e| e.to_string())?;
    let mut header = [0u8; HEADER];
    header[..8].copy_from_slice(MAGIC);
    let values = [
        1, architecture(), before[0], before[1], before[2], before[3], before[4], before[5], before[6],
        records - HEADER as u64, rows.len() as u64, records, raw_start, display_start, metadata_start,
        metadata.len() as u64, total,
    ];
    for (i, value) in values.iter().enumerate() {
        header[8 + i * 8..16 + i * 8].copy_from_slice(&value.to_le_bytes());
    }
    let hash = header_hash(&header[..144]);
    header[144..152].copy_from_slice(&hash.to_le_bytes());
    writer.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    writer.write_all(&header).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    writer.get_ref().sync_all().map_err(|e| e.to_string())?;
    if stamp(&file)? != before || stamp(&File::open(&path).map_err(|e| e.to_string())?)? != before {
        return Err("binary changed while building its index; retry".into());
    }
    std::fs::rename(&temporary.0, output).map_err(|e| e.to_string())?;
    File::open(parent).and_then(|file| file.sync_all()).map_err(|e| e.to_string())?;
    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_names_above_four_gib_and_invalid_record_bounds() {
        let temporary = Temporary(std::env::temp_dir().join(format!(
            "poortrace-index-high-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        )));
        let mut file = OpenOptions::new().read(true).write(true).create_new(true)
            .open(&temporary.0).unwrap();
        let name_start = 4 * 1024 * 1024 * 1024u64;
        let records = name_start + 16;
        let metadata_start = records + RECORD as u64 + 8;
        let metadata = serde_json::to_vec(&Metadata {
            path: PathBuf::from("/fixture"), sites: Vec::new(), site_error: None,
        }).unwrap();
        let total = metadata_start + metadata.len() as u64;
        let mut header = [0u8; HEADER];
        header[..8].copy_from_slice(MAGIC);
        let values = [
            1, architecture(), 0, 0, 1024, 0, 0, 0, 0,
            records - HEADER as u64, 1, records, records + RECORD as u64,
            records + RECORD as u64 + 4, metadata_start, metadata.len() as u64, total,
        ];
        for (i, value) in values.iter().enumerate() {
            header[8 + i * 8..16 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
        let hash = header_hash(&header[..144]);
        header[144..152].copy_from_slice(&hash.to_le_bytes());
        file.write_all(&header).unwrap();
        file.seek(SeekFrom::Start(name_start)).unwrap();
        file.write_all(b"worker").unwrap();
        file.seek(SeekFrom::Start(records)).unwrap();
        let row = [0x400100u64, 16, 0x100, name_start, 6, name_start, 6];
        for value in row { file.write_all(&value.to_le_bytes()).unwrap(); }
        file.write_all(&[0; 8]).unwrap();
        file.write_all(&metadata).unwrap();
        let index = Index::open(&temporary.0).unwrap();
        assert_eq!(index.functions("work*").unwrap()[0].offset, 0x100);
        assert_eq!(index.lookup("worker").unwrap(), BTreeSet::from([(0x400100, 16)]));
        assert_eq!(index.resolve(0x400105).unwrap(), Some(("worker".into(), 5)));
        assert_eq!(index.resolve(0x400110).unwrap(), None);
        drop(index);
        // Reopening a damaged record must return an error, without pointer
        // arithmetic wrapping or reading outside the name pool.
        file.seek(SeekFrom::Start(records + 3 * 8)).unwrap();
        file.write_all(&u64::MAX.to_le_bytes()).unwrap();
        let index = Index::open(&temporary.0).unwrap();
        assert!(index.functions("*").unwrap_err().contains("string overflow"));
        drop(index);
        file.set_len(total - 1).unwrap();
        assert!(Index::open(&temporary.0).unwrap_err().contains("layout"));
    }
}
