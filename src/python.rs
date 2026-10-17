//! Read-only CPython 3.12 release-build frames. No code is injected into Python.
use crate::{Result, memory};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::{Duration, Instant},
};
#[derive(Default)]
pub struct Reader {
    processes: BTreeMap<u32, Process>,
}
struct Process {
    runtime: u64,
    refreshed: Instant,
    threads: BTreeMap<u32, u64>,
}
fn read(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
    memory::read(pid, address, size, false)
}
fn word(pid: u32, address: u64) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        read(pid, address, 8)?.try_into().unwrap(),
    ))
}
fn unicode(pid: u32, address: u64) -> Result<String> {
    let header = read(pid, address, 40)?;
    let length = i64::from_ne_bytes(header[16..24].try_into().unwrap());
    let state = u32::from_ne_bytes(header[32..36].try_into().unwrap());
    let kind = (state >> 2) & 7;
    let compact = state & (1 << 5) != 0;
    let ascii = state & (1 << 6) != 0;
    if !(0..=4096).contains(&length) || !compact || ![1, 2, 4].contains(&kind) {
        return Err("unsupported Python Unicode object".into());
    }
    let length = (length as usize).min(4096 / kind as usize);
    let start = address
        .checked_add(if ascii { 40 } else { 56 })
        .ok_or("Python string address overflow")?;
    if length == 0 {
        return Ok(String::new());
    }
    let data = read(pid, start, length * kind as usize)?;
    Ok(match kind {
        1 => data.into_iter().map(char::from).collect(),
        2 => String::from_utf16_lossy(
            &data
                .chunks_exact(2)
                .map(|b| u16::from_ne_bytes(b.try_into().unwrap()))
                .collect::<Vec<_>>(),
        ),
        _ => data
            .chunks_exact(4)
            .map(|b| {
                char::from_u32(u32::from_ne_bytes(b.try_into().unwrap()))
                    .unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
    })
}
fn runtime(pid: u32) -> Result<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
    let mut paths = BTreeSet::new();
    for map in text
        .lines()
        .filter_map(crate::symbols::Mapping::parse)
        .take(128)
    {
        if !map.path.starts_with('/') || !paths.insert(map.path.clone()) {
            continue;
        }
        let path = format!("/proc/{pid}/root{}", map.path);
        let Ok(file) = std::fs::File::open(path) else {
            continue;
        };
        if file.metadata().is_ok_and(|m| m.len() > 128 * 1024 * 1024) {
            continue;
        }
        let mut bytes = Vec::new();
        if file
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > 128 * 1024 * 1024
        {
            continue;
        }
        let Ok(elf) = object::File::parse(bytes.as_slice()) else {
            continue;
        };
        #[cfg(target_arch = "aarch64")]
        let native = object::Architecture::Aarch64;
        #[cfg(target_arch = "x86_64")]
        let native = object::Architecture::X86_64;
        if !elf.is_64()
            || elf.architecture() != native
            || elf.is_little_endian() != cfg!(target_endian = "little")
        {
            continue;
        }
        let bias = elf.segments().find_map(|segment| {
            let (offset, size) = segment.file_range();
            (map.offset >= offset && map.offset - offset < size).then(|| {
                map.start
                    .wrapping_sub(segment.address() + map.offset - offset)
            })
        });
        let Some(bias) = bias else {
            continue;
        };
        let mut runtime = None;
        let mut version = None;
        let mut trace_refs = false;
        for symbol in elf
            .symbols()
            .chain(elf.dynamic_symbols())
            .filter(|s| !s.is_undefined())
        {
            match symbol.name().unwrap_or("") {
                "_PyRuntime" => runtime = Some(bias.wrapping_add(symbol.address())),
                "Py_Version" => version = Some(bias.wrapping_add(symbol.address())),
                "Py_GetObjects" | "_Py_GetObjects" | "_Py_Refchain" => trace_refs = true,
                _ => {}
            }
        }
        if let (Some(runtime), Some(version)) = (runtime, version) {
            let version = u32::from_ne_bytes(read(pid, version, 4)?.try_into().unwrap());
            if version >> 16 != 0x030c || trace_refs {
                return Err(format!(
                    "pystack supports CPython 3.12 release layouts; target version=0x{version:x}"
                ));
            }
            return Ok(runtime);
        }
    }
    Err("no CPython runtime symbols found".into())
}
impl Reader {
    pub fn stack(&mut self, pid: u32, tid: u32, depth: usize) -> Result<String> {
        let refresh = self
            .processes
            .get(&pid)
            .is_none_or(|p| p.refreshed.elapsed() > Duration::from_millis(100));
        if refresh {
            let runtime = runtime(pid)?;
            if self.processes.len() >= 16 && !self.processes.contains_key(&pid) {
                self.processes.clear();
            }
            let mut threads = BTreeMap::new();
            let mut interpreter = word(pid, runtime + 40)?;
            let mut seen = BTreeSet::new();
            for _ in 0..32 {
                if interpreter == 0 || !seen.insert(interpreter) {
                    break;
                }
                let mut thread = word(pid, interpreter + 72)?;
                for _ in 0..1024 {
                    if thread == 0 || !seen.insert(thread) {
                        break;
                    }
                    let native = word(pid, thread + 144)?;
                    if let Ok(native) = u32::try_from(native) {
                        threads.insert(native, thread);
                    }
                    thread = word(pid, thread + 8)?;
                }
                interpreter = word(pid, interpreter)?;
            }
            self.processes.insert(
                pid,
                Process {
                    runtime,
                    refreshed: Instant::now(),
                    threads,
                },
            );
        }
        let process = &self.processes[&pid];
        // Verify the cached runtime still belongs to a live initialized interpreter.
        if word(pid, process.runtime + 40)? == 0 {
            return Ok("    <no Python interpreter>\n".into());
        }
        let Some(&thread) = process.threads.get(&tid) else {
            return Ok("    <no Python thread state>\n".into());
        };
        if word(pid, thread + 144)? != tid as u64 {
            self.processes.remove(&pid);
            return Err("Python thread state changed during capture".into());
        }
        let cframe = word(pid, thread + 56)?;
        let mut frame = if cframe == 0 { 0 } else { word(pid, cframe)? };
        let mut seen = BTreeSet::new();
        let mut out = String::new();
        for _ in 0..depth.min(127) {
            if frame == 0 || !seen.insert(frame) {
                break;
            }
            let code = word(pid, frame)?;
            if code != 0 {
                let name = unicode(pid, word(pid, code + 120)?)?;
                let filename = unicode(pid, word(pid, code + 112)?)?;
                let line = u32::from_ne_bytes(read(pid, code + 68, 4)?.try_into().unwrap());
                out.push_str(&format!(
                    "    {} ({}:{line}; function start)\n",
                    name.replace(['\n', '\r'], "?"),
                    filename.replace(['\n', '\r'], "?")
                ));
            }
            frame = word(pid, frame + 8)?;
        }
        if out.is_empty() {
            out.push_str("    <no Python frame>\n");
        }
        Ok(out)
    }
}
