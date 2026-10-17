//! Best-effort ELF symbol lookup for sampled user addresses. No target memory is read.
use object::{Object, ObjectSegment, ObjectSymbol, SymbolKind};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Mapping {
    start: u64,
    end: u64,
    offset: u64,
    inode: u64,
    device: u64,
    path: String,
}
impl Mapping {
    fn parse(line: &str) -> Option<Self> {
        let mut rest = line;
        let mut field = || {
            rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let (value, tail) = rest.split_at(end);
            rest = tail;
            value
        };
        let (start, end) = field().split_once('-')?;
        let permissions = field();
        let offset = u64::from_str_radix(field(), 16).ok()?;
        let (major, minor) = field().split_once(':')?;
        let device = libc::makedev(
            u32::from_str_radix(major, 16).ok()?,
            u32::from_str_radix(minor, 16).ok()?,
        );
        let inode = field().parse().ok()?;
        if !permissions.contains('x') {
            return None;
        }
        Some(Self {
            start: u64::from_str_radix(start, 16).ok()?,
            end: u64::from_str_radix(end, 16).ok()?,
            offset,
            inode,
            device,
            path: rest.trim_start().trim_end_matches(" (deleted)").into(),
        })
    }
}

struct Symbol {
    address: u64,
    size: u64,
    name: String,
}
struct Image {
    // ELF load segments: file offset, file size, virtual address.
    segments: Vec<(u64, u64, u64)>,
    symbols: Vec<Symbol>,
}
impl Image {
    fn read(pid: u32, mapping: &Mapping) -> Option<Self> {
        if !mapping.path.starts_with('/') || mapping.inode == 0 {
            return None;
        }
        let root_path = format!("/proc/{pid}/root{}", mapping.path);
        let map_path = format!(
            "/proc/{pid}/map_files/{:x}-{:x}",
            mapping.start, mapping.end
        );
        let file = [root_path, map_path].into_iter().find_map(|path| {
            let file = std::fs::File::open(path).ok()?;
            let meta = file.metadata().ok()?;
            (meta.ino() == mapping.inode
                && meta.dev() == mapping.device
                && meta.len() <= 128 * 1024 * 1024)
                .then_some(file)
        })?;
        let mut bytes = Vec::new();
        file.take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 128 * 1024 * 1024 {
            return None;
        }
        Self::parse(&bytes)
    }
    fn parse(bytes: &[u8]) -> Option<Self> {
        let object = object::File::parse(bytes).ok()?;
        let segments = object
            .segments()
            .map(|segment| {
                let (offset, size) = segment.file_range();
                (offset, size, segment.address())
            })
            .collect();
        let mut symbols: Vec<_> = object
            .symbols()
            .chain(object.dynamic_symbols())
            .filter(|symbol| symbol.kind() == SymbolKind::Text && !symbol.is_undefined())
            .take(250_000)
            .filter_map(|symbol| {
                Some(Symbol {
                    address: symbol.address(),
                    size: symbol.size(),
                    name: demangle(symbol.name().ok()?),
                })
            })
            .collect();
        symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
        Some(Self { segments, symbols })
    }
    fn resolve(&self, file_offset: u64) -> Option<String> {
        let &(offset, _, address) = self
            .segments
            .iter()
            .find(|(offset, size, _)| file_offset >= *offset && file_offset - offset < *size)?;
        let address = address.checked_add(file_offset - offset)?;
        let index = self
            .symbols
            .partition_point(|symbol| symbol.address <= address);
        let symbol = self.symbols.get(index.checked_sub(1)?)?;
        let delta = address - symbol.address;
        if symbol.size != 0 && delta >= symbol.size {
            return None;
        }
        Some(format!("{}+0x{delta:x}", symbol.name))
    }
}

struct Process {
    refreshed: Instant,
    maps: Vec<Mapping>,
}
#[derive(Default)]
pub(crate) struct Symbolizer {
    processes: BTreeMap<u32, Process>,
    images: BTreeMap<(u32, String, u64, u64), Option<Image>>,
}
impl Symbolizer {
    pub(crate) fn stack(&mut self, pid: u32, frames: &[u64]) -> String {
        if frames.is_empty() {
            return "    <no user stack>\n".into();
        }
        let refresh = self
            .processes
            .get(&pid)
            .is_none_or(|process| process.refreshed.elapsed() >= Duration::from_millis(100));
        if refresh {
            if self.processes.len() >= 16 && !self.processes.contains_key(&pid) {
                self.processes.clear();
                self.images.clear();
            }
            if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                self.processes.insert(
                    pid,
                    Process {
                        refreshed: Instant::now(),
                        maps: maps.lines().filter_map(Mapping::parse).collect(),
                    },
                );
            }
        }
        let mut result = String::new();
        for (index, &ip) in frames.iter().take(127).enumerate() {
            // Callers are return addresses; look inside the calling instruction
            // instead of accidentally naming the next function at a boundary.
            let lookup = ip.saturating_sub(u64::from(index != 0));
            let mapping = self.processes.get(&pid).and_then(|process| {
                process
                    .maps
                    .iter()
                    .find(|map| lookup >= map.start && lookup < map.end)
            });
            let frame = if let Some(mapping) = mapping {
                let file_offset = mapping.offset.checked_add(lookup - mapping.start);
                let key = (pid, mapping.path.clone(), mapping.device, mapping.inode);
                if self.images.len() >= 128 && !self.images.contains_key(&key) {
                    self.images.clear();
                }
                let image = self
                    .images
                    .entry(key)
                    .or_insert_with(|| Image::read(pid, mapping));
                let symbol = file_offset.and_then(|offset| image.as_ref()?.resolve(offset));
                match symbol {
                    Some(symbol) => format!("{symbol} ({})", mapping.path),
                    None => format!(
                        "0x{ip:x} ({}+0x{:x})",
                        mapping.path,
                        mapping.offset.saturating_add(ip - mapping.start)
                    ),
                }
            } else {
                format!("0x{ip:x}")
            };
            result.push_str("    ");
            result.push_str(&frame.replace(['\n', '\r'], "?"));
            result.push('\n');
        }
        result
    }
}

fn demangle(name: &str) -> String {
    let name: String = name.chars().take(4096).collect();
    if let Ok(symbol) = rustc_demangle::try_demangle(&name) {
        format!("{symbol:#}")
    } else if let Ok(symbol) = cpp_demangle::Symbol::new(name.as_bytes()) {
        symbol
            .demangle(&cpp_demangle::DemangleOptions::default())
            .unwrap_or(name)
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_mapping_preserves_spaces_and_filters_data() {
        let map = Mapping::parse("1000-2000 r-xp 00004000 08:01 42     /a file (deleted)").unwrap();
        assert_eq!(
            (map.start, map.end, map.offset, map.inode),
            (0x1000, 0x2000, 0x4000, 42)
        );
        assert_eq!(map.path, "/a file");
        assert!(Mapping::parse("1000-2000 rw-p 00004000 08:01 42 /data").is_none());
        assert!(Mapping::parse("invalid").is_none());
    }

    #[inline(never)]
    extern "C" fn symbolizer_fixture() -> u64 {
        std::hint::black_box(42)
    }

    #[test]
    fn resolves_own_pie_and_shared_library_and_falls_back() {
        let mut symbols = Symbolizer::default();
        let text = symbols.stack(
            std::process::id(),
            &[symbolizer_fixture as *const () as u64],
        );
        assert!(text.contains("symbolizer_fixture"), "{text}");
        let text = symbols.stack(std::process::id(), &[libc::getpid as *const () as u64]);
        // GNU libc exports getpid under either name; in a static build it is
        // resolved from the executable's regular symbol table instead.
        assert!(text.contains("getpid"), "{text}");
        assert_eq!(symbols.stack(0, &[0x1234]), "    0x1234\n");
        assert!(symbols.stack(0, &[]).contains("<no user stack>"));
        assert!(Image::parse(b"not an ELF file").is_none());
    }

    #[test]
    fn segment_offsets_handle_non_pie_and_symbol_boundaries() {
        let image = Image {
            segments: vec![(0x1000, 0x1000, 0x401000)],
            symbols: vec![Symbol {
                address: 0x401100,
                size: 16,
                name: "fixture".into(),
            }],
        };
        assert_eq!(image.resolve(0x1103).as_deref(), Some("fixture+0x3"));
        assert!(image.resolve(0x1110).is_none());
        assert!(image.resolve(0).is_none());
        assert_eq!(
            demangle("_ZN4demo6worker17h0123456789abcdefE"),
            "demo::worker"
        );
        assert_eq!(demangle("_Z6workeri"), "worker(int)");
    }
}
