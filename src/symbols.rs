//! Best-effort ELF symbol lookup for sampled user addresses. No target memory is read.
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SymbolKind};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub(crate) struct Mapping {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) offset: u64,
    pub(crate) inode: u64,
    pub(crate) device: u64,
    pub(crate) path: String,
    pub(crate) private: bool,
}
impl Mapping {
    pub(crate) fn parse(line: &str) -> Option<Self> {
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
            private: permissions.as_bytes().get(3) == Some(&b'p'),
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
    lines: Option<addr2line::Loader>,
    sections: framehop::ExplicitModuleSectionInfo<std::sync::Arc<[u8]>>,
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
        let (file, selected_path) = [root_path, map_path].into_iter().find_map(|path| {
            let file = std::fs::File::open(&path).ok()?;
            let meta = file.metadata().ok()?;
            (meta.ino() == mapping.inode
                && meta.dev() == mapping.device
                && meta.len() <= 128 * 1024 * 1024)
                .then_some((file, path))
        })?;
        let mut bytes = Vec::new();
        file.take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 128 * 1024 * 1024 {
            return None;
        }
        let mut image = Self::parse(&bytes)?;
        let object = object::File::parse(bytes.as_slice()).ok()?;
        let mut candidates = Vec::new();
        if let Ok(Some((name, crc))) = object.gnu_debuglink() {
            if let Ok(name) = std::str::from_utf8(name) {
                if !name.contains('/') {
                    let original = std::path::Path::new(&mapping.path);
                    if let Some(parent) = original.parent() {
                        for path in [
                            parent.join(name),
                            parent.join(".debug").join(name),
                            std::path::Path::new("/usr/lib/debug")
                                .join(parent.strip_prefix("/").unwrap_or(parent))
                                .join(name),
                        ] {
                            candidates
                                .push((format!("/proc/{pid}/root{}", path.display()), Some(crc)));
                        }
                    }
                }
            }
        }
        if let Ok(Some(id)) = object.build_id() {
            if id.len() >= 2 {
                let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                candidates.push((
                    format!(
                        "/proc/{pid}/root/usr/lib/debug/.build-id/{}/{}.debug",
                        &hex[..2],
                        &hex[2..]
                    ),
                    None,
                ));
            }
        }
        candidates.push((selected_path, None));
        for (path, crc) in candidates {
            if !std::fs::metadata(&path).is_ok_and(|meta| meta.len() <= 128 * 1024 * 1024) {
                continue;
            }
            if let Some(crc) = crc {
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                let actual = bytes.iter().fold(!0u32, |mut sum, b| {
                    sum ^= *b as u32;
                    for _ in 0..8 {
                        sum = (sum >> 1) ^ if sum & 1 != 0 { 0xedb88320 } else { 0 };
                    }
                    sum
                }) ^ !0;
                if actual != crc {
                    continue;
                }
            }
            if let Ok(loader) = addr2line::Loader::new(&path) {
                image.lines = Some(loader);
                break;
            }
        }
        Some(image)
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
                    // Unwinding loads all module images, but usually resolves
                    // only a handful of names. Keep bounded raw names here.
                    name: symbol.name().ok()?.chars().take(4096).collect(),
                })
            })
            .collect();
        symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        symbols.dedup_by(|a, b| a.address == b.address && a.name == b.name);
        let mut first = 0;
        while first < symbols.len() {
            let address = symbols[first].address;
            let end = first + symbols[first..].partition_point(|symbol| symbol.address == address);
            // Preserve display-name ordering for aliases. Cache each alias's
            // key once; C++ template parsing inside a comparator is expensive.
            if end - first > 1 {
                symbols[first..end].sort_by_cached_key(|symbol| demangle(&symbol.name));
            }
            first = end;
        }
        let section = |name| {
            object
                .section_by_name(name)
                .filter(|section| {
                    section
                        .compressed_data()
                        .is_ok_and(|data| data.uncompressed_size <= 128 * 1024 * 1024)
                })
                .and_then(|section| section.uncompressed_data().ok())
                .map(|bytes| std::sync::Arc::<[u8]>::from(bytes.as_ref()))
        };
        let range = |name| {
            object.section_by_name(name).and_then(|section| {
                Some(section.address()..section.address().checked_add(section.size())?)
            })
        };
        let sections = framehop::ExplicitModuleSectionInfo {
            text_svma: range(".text"),
            text: section(".text"),
            got_svma: range(".got"),
            eh_frame_svma: range(".eh_frame"),
            eh_frame: section(".eh_frame"),
            eh_frame_hdr_svma: range(".eh_frame_hdr"),
            eh_frame_hdr: section(".eh_frame_hdr"),
            debug_frame: section(".debug_frame"),
            ..Default::default()
        };
        Some(Self {
            segments,
            symbols,
            lines: None,
            sections,
        })
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
        let closest = self.symbols.get(index.saturating_sub(1)).filter(|symbol| {
            symbol.address <= address
                && (symbol.size == 0 || address - symbol.address < symbol.size)
        });
        let delta = closest.map(|symbol| address - symbol.address);
        let display_name = closest.map(|symbol| demangle(&symbol.name));
        if let Some(loader) = &self.lines {
            if let Ok(mut frames) = loader.find_frames(address) {
                let mut names = Vec::new();
                while let Ok(Some(frame)) = frames.next() {
                    let name = frame
                        .function
                        .and_then(|name| name.demangle().ok().map(|name| name.into_owned()));
                    let location = frame.location.map(|loc| {
                        format!("{}:{}", loc.file.unwrap_or("?"), loc.line.unwrap_or(0))
                    });
                    if name.is_some() || location.is_some() {
                        let name = name.unwrap_or_else(|| "?".into());
                        let offset = closest
                            .filter(|_| display_name.as_deref() == Some(name.as_str()))
                            .map(|_| format!("+0x{:x}", delta.unwrap()))
                            .unwrap_or_default();
                        names.push(format!(
                            "{name}{offset}{}",
                            location.map(|loc| format!(" at {loc}")).unwrap_or_default()
                        ));
                    }
                }
                if !names.is_empty() {
                    return Some(names.join(" [inlined into] "));
                }
            }
            if let Some(name) = loader.find_symbol(address) {
                return Some(format!(
                    "{}{}",
                    demangle(name),
                    delta
                        .map(|offset| format!("+0x{offset:x}"))
                        .unwrap_or_default()
                ));
            }
        }
        let index = self
            .symbols
            .partition_point(|symbol| symbol.address <= address);
        let symbol = self.symbols.get(index.checked_sub(1)?)?;
        let delta = address - symbol.address;
        if symbol.size != 0 && delta >= symbol.size {
            return None;
        }
        Some(format!("{}+0x{delta:x}", demangle(&symbol.name)))
    }
}

struct Process {
    jit: Vec<(u64, u64, String)>,
    refreshed: Instant,
    maps: Vec<Mapping>,
}

struct UnwindState {
    signature: Vec<(u64, u64, u64, u64, u64)>,
    unwinder: framehop::UnwinderNative<std::sync::Arc<[u8]>, framehop::MayAllocateDuringUnwind>,
    cache: framehop::CacheNative<framehop::MayAllocateDuringUnwind>,
}
#[derive(Default)]
pub(crate) struct Symbolizer {
    processes: BTreeMap<u32, Process>,
    images: BTreeMap<(u32, String, u64, u64), Option<Image>>,
    unwinders: BTreeMap<u32, UnwindState>,
}
impl Symbolizer {
    pub(crate) fn symbol(&mut self, pid: u32, address: u64) -> String {
        self.stack(pid, &[address]).trim().to_string()
    }
    pub(crate) fn unwind(&mut self, sample: &crate::perf::Sample) -> Vec<u64> {
        use framehop::Unwinder;
        if sample.stack.is_empty() {
            return sample.callchain.clone();
        }
        let Some(regs) = sample.regs else {
            return sample.callchain.clone();
        };
        let _ = self.symbol(sample.pid, regs.ip);
        let Some(process) = self.processes.get(&sample.pid) else {
            return vec![regs.ip];
        };
        let signature: Vec<_> = process
            .maps
            .iter()
            .map(|m| (m.start, m.end, m.offset, m.inode, m.device))
            .collect();
        if self
            .unwinders
            .get(&sample.pid)
            .is_none_or(|state| state.signature != signature)
        {
            let mut unwinder = framehop::UnwinderNative::new();
            for map in process.maps.iter().take(128) {
                let key = (sample.pid, map.path.clone(), map.device, map.inode);
                let Some(image) = self
                    .images
                    .entry(key)
                    .or_insert_with(|| Image::read(sample.pid, map))
                    .as_ref()
                else {
                    continue;
                };
                let Some(&(offset, _, svma)) = image.segments.iter().find(|(offset, size, _)| {
                    map.offset >= (*offset & !4095) && map.offset < offset.saturating_add(*size)
                }) else {
                    continue;
                };
                let base = map.start as i128 - (svma as i128 - offset as i128 + map.offset as i128);
                if !(0..=u64::MAX as i128).contains(&base) {
                    continue;
                }
                unwinder.add_module(framehop::Module::new(
                    map.path.clone(),
                    map.start..map.end,
                    base as u64,
                    image.sections.clone(),
                ));
            }
            self.unwinders.insert(
                sample.pid,
                UnwindState {
                    signature,
                    unwinder,
                    cache: framehop::CacheNative::new(),
                },
            );
        }
        let state = self.unwinders.get_mut(&sample.pid).unwrap();
        let mut read = |address: u64| {
            let offset = address.checked_sub(regs.sp).ok_or(())? as usize;
            let bytes = sample
                .stack
                .get(offset..offset.checked_add(8).ok_or(())?)
                .ok_or(())?;
            Ok::<u64, ()>(u64::from_ne_bytes(bytes.try_into().unwrap()))
        };
        #[cfg(target_arch = "x86_64")]
        let unwind_regs = framehop::UnwindRegsNative::new(regs.ip, regs.sp, regs.fp);
        #[cfg(target_arch = "aarch64")]
        let unwind_regs = framehop::UnwindRegsNative::new(regs.lr, regs.sp, regs.fp);
        let mut iter =
            state
                .unwinder
                .iter_frames(regs.ip, unwind_regs, &mut state.cache, &mut read);
        let mut output = Vec::new();
        while output.len() < 127 {
            match iter.next() {
                Ok(Some(frame)) => output.push(frame.address()),
                _ => break,
            }
        }
        if output.is_empty() {
            output.push(regs.ip);
        }
        output
    }

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
                self.unwinders.clear();
            }
            if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
                self.processes.insert(
                    pid,
                    Process {
                        jit: jit_symbols(pid),
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
            let mut frame = if let Some(mapping) = mapping {
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
            if frame.starts_with("0x") {
                if let Some((start, _, name)) = self.processes.get(&pid).and_then(|p| {
                    p.jit
                        .iter()
                        .find(|(start, size, _)| lookup >= *start && lookup - *start < *size)
                }) {
                    frame = format!("{name}+0x{:x} (JIT)", lookup - start);
                }
            }
            result.push_str("    ");
            result.push_str(&frame.replace(['\n', '\r'], "?"));
            result.push('\n');
        }
        result
    }
}

pub(crate) fn demangle(name: &str) -> String {
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

fn jit_symbols(pid: u32) -> Vec<(u64, u64, String)> {
    let inner = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("NSpid:")
                    .and_then(|v| v.split_whitespace().last()?.parse::<u32>().ok())
            })
        })
        .unwrap_or(pid);
    let path = format!("/proc/{pid}/root/tmp/perf-{inner}.map");
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    if file.metadata().is_ok_and(|m| {
        m.len() > 16 * 1024 * 1024
            || std::fs::metadata(format!("/proc/{pid}")).is_ok_and(|p| p.uid() != m.uid())
    }) {
        return Vec::new();
    }
    let mut text = String::new();
    if file
        .take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut text)
        .is_err()
        || text.len() > 16 * 1024 * 1024
    {
        return Vec::new();
    }
    text.lines()
        .take(250_000)
        .filter_map(|line| {
            let mut parts = line.splitn(3, ' ');
            let start = u64::from_str_radix(parts.next()?, 16).ok()?;
            let size = u64::from_str_radix(parts.next()?, 16).ok()?;
            let name = parts.next()?.chars().take(4096).collect();
            Some((start, size, name))
        })
        .collect()
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
            lines: None,
            sections: Default::default(),
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
    #[test]
    fn raw_symbol_names_demangle_when_resolved() {
        let image = Image {
            segments: vec![(0, 0x1000, 0x400000)],
            lines: None,
            sections: Default::default(),
            symbols: vec![
                Symbol {
                    address: 0x400100,
                    size: 16,
                    name: "_ZN4demo6worker17h0123456789abcdefE".into(),
                },
                Symbol {
                    address: 0x400200,
                    size: 16,
                    name: "_Z6workeri".into(),
                },
            ],
        };
        assert_eq!(image.resolve(0x103).as_deref(), Some("demo::worker+0x3"));
        assert_eq!(image.resolve(0x203).as_deref(), Some("worker(int)+0x3"));
    }
    #[test]
    fn target_owned_perf_maps_name_anonymous_jit_code() {
        let pid = std::process::id();
        let path = format!("/tmp/perf-{pid}.map");
        let previous = std::fs::read(&path).ok();
        std::fs::write(&path, b"dead0000 100 jit_fixture_name\n").unwrap();
        let text = Symbolizer::default().stack(pid, &[0xdead0010]);
        if let Some(previous) = previous {
            std::fs::write(&path, previous).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        assert!(text.contains("jit_fixture_name+0x10 (JIT)"), "{text}");
    }
}
