//! Read-only CPython frames. 3.13/3.14 use the runtime debug-offset table.
//! Layout sources: CPython Include/internal/pycore_runtime.h (3.13),
//! pycore_debug_offsets.h (3.14), and Objects/locations.md (line tables).
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
    layout: Layout,
    refreshed: Instant,
    threads: BTreeMap<u32, u64>,
}
#[derive(Clone)]
struct Layout {
    runtime_head: u64,
    interpreter_next: u64,
    interpreter_threads: u64,
    thread_next: u64,
    thread_native: u64,
    thread_frame: u64,
    indirect_frame: bool,
    cframe_current: u64,
    frame_owner: u64,
    frame_previous: u64,
    frame_code: u64,
    frame_instruction: u64,
    code_tag_mask: u64,
    code_filename: u64,
    code_name: u64,
    code_firstline: u64,
    code_linetable: u64,
    code_adaptive: u64,
    bytes_length: u64,
    bytes_data: u64,
    unicode_state: u64,
    unicode_length: u64,
    unicode_ascii_size: u64,
    unicode_compact_extra: u64,
}
impl Layout {
    fn legacy() -> Self {
        Self {
            runtime_head: 40,
            interpreter_next: 0,
            interpreter_threads: 72,
            thread_next: 8,
            thread_native: 144,
            thread_frame: 56,
            indirect_frame: true,
            cframe_current: 0,
            frame_owner: 70,
            frame_previous: 8,
            frame_code: 0,
            frame_instruction: 56,
            code_tag_mask: 0,
            code_filename: 112,
            code_name: 120,
            code_firstline: 68,
            code_linetable: 136,
            code_adaptive: 192,
            bytes_length: 16,
            bytes_data: 32,
            unicode_state: 32,
            unicode_length: 16,
            unicode_ascii_size: 40,
            unicode_compact_extra: 16,
        }
    }
    fn debug(data: &[u8], version: u32) -> Result<Self> {
        if data.get(..8) != Some(b"xdebugpy") {
            return Err("invalid CPython debug cookie".into());
        }
        let get = |index: usize| -> Result<u64> {
            Ok(u64::from_ne_bytes(
                data.get(index * 8..index * 8 + 8)
                    .ok_or("truncated CPython debug offsets")?
                    .try_into()
                    .unwrap(),
            ))
        };
        if get(1)? != version as u64 {
            return Err("CPython debug version mismatch".into());
        }
        if get(2)? > 1 {
            return Err("invalid CPython threading metadata".into());
        }
        // Each table starts with sizeof(struct); remaining words are offsetof fields.
        let (interpreter, thread, frame, code, bytes, unicode) = match version >> 16 {
            0x030d => (6, 19, 28, 34, 64, 67),
            0x030e => (6, 22, 31, 39, 74, 77),
            _ => return Err("unsupported CPython debug-offset version".into()),
        };
        let field = |table: usize, index: usize, width: u64| -> Result<u64> {
            let size = get(table)?;
            let offset = get(table + index)?;
            if size > 64 * 1024 * 1024 || offset.checked_add(width).is_none_or(|end| end > size) {
                return Err("invalid CPython debug field bounds".into());
            }
            Ok(offset)
        };
        let ascii_size = get(unicode + 3)?;
        if !(32..=256).contains(&ascii_size) {
            return Err("invalid CPython Unicode size".into());
        }
        Ok(Self {
            runtime_head: field(3, 2, 8)?,
            interpreter_next: field(interpreter, 2, 8)?,
            interpreter_threads: field(interpreter, 3, 8)?,
            thread_next: field(thread, 2, 8)?,
            thread_native: field(thread, 6, 8)?,
            thread_frame: field(thread, 4, 8)?,
            indirect_frame: false,
            cframe_current: 0,
            frame_owner: field(frame, 5, 1)?,
            frame_previous: field(frame, 1, 8)?,
            frame_code: field(frame, 2, 8)?,
            frame_instruction: field(frame, 3, 8)?,
            code_tag_mask: if version >> 16 == 0x030e { 3 } else { 0 },
            code_filename: field(code, 1, 8)?,
            code_name: field(code, 2, 8)?,
            code_firstline: field(code, 5, 4)?,
            code_linetable: field(code, 4, 8)?,
            code_adaptive: field(code, 9, 1)?,
            bytes_length: field(bytes, 1, 8)?,
            bytes_data: field(bytes, 2, 1)?,
            unicode_state: field(unicode, 1, 4)?,
            unicode_length: field(unicode, 2, 8)?,
            unicode_ascii_size: ascii_size,
            unicode_compact_extra: 16,
        })
    }
}
fn address(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset)
        .ok_or_else(|| "Python address overflow".into())
}
fn field(pid: u32, base: u64, offset: u64) -> Result<u64> {
    word(pid, address(base, offset)?)
}
fn read(pid: u32, address: u64, size: usize) -> Result<Vec<u8>> {
    memory::read(pid, address, size, false)
}
fn word(pid: u32, address: u64) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        read(pid, address, 8)?.try_into().unwrap(),
    ))
}
fn unicode(pid: u32, address: u64, layout: &Layout) -> Result<String> {
    let length = field(pid, address, layout.unicode_length)? as i64;
    let state = u32::from_ne_bytes(
        read(
            pid,
            address
                .checked_add(layout.unicode_state)
                .ok_or("Python Unicode overflow")?,
            4,
        )?
        .try_into()
        .unwrap(),
    );
    let kind = (state >> 2) & 7;
    let compact = state & (1 << 5) != 0;
    let ascii = state & (1 << 6) != 0;
    if !(0..=4096).contains(&length) || !compact || ![1, 2, 4].contains(&kind) {
        return Err("unsupported Python Unicode object".into());
    }
    let length = (length as usize).min(4096 / kind as usize);
    let start = address
        .checked_add(if ascii {
            layout.unicode_ascii_size
        } else {
            layout.unicode_ascii_size + layout.unicode_compact_extra
        })
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
fn runtime(pid: u32) -> Result<(u64, Layout)> {
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
                    .wrapping_sub(segment.address().wrapping_add(map.offset - offset))
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
            if trace_refs {
                return Err("CPython trace-reference builds are unsupported".into());
            }
            let layout = match version >> 16 {
                0x030b => {
                    let mut layout = Layout::legacy();
                    // CPython 3.11 native LP64 release headers (offsetof verified).
                    layout.interpreter_threads = 16;
                    layout.thread_native = 160;
                    layout.cframe_current = 8;
                    layout.frame_previous = 48;
                    layout.frame_code = 32;
                    layout.frame_owner = 69;
                    layout.code_firstline = 72;
                    layout.code_adaptive = 184;
                    layout.unicode_ascii_size = 48;
                    layout.unicode_compact_extra = 24;
                    layout
                }
                0x030c => Layout::legacy(),
                0x030d | 0x030e => Layout::debug(&read(pid, runtime, 656)?, version)?,
                _ => {
                    return Err(format!(
                        "pystack supports CPython 3.11–3.14; target version=0x{version:x}"
                    ));
                }
            };
            // Stack-ref debug builds replace pointers with opaque handles (3.14).
            if version >> 16 == 0x030e
                && elf
                    .symbols()
                    .chain(elf.dynamic_symbols())
                    .any(|s| s.name().ok() == Some("_Py_stackref_get_object") && !s.is_undefined())
            {
                return Err("CPython stack-reference debug builds are unsupported".into());
            }
            return Ok((runtime, layout));
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
            let (runtime, layout) = runtime(pid)?;
            if self.processes.len() >= 16 && !self.processes.contains_key(&pid) {
                self.processes.clear();
            }
            let mut threads = BTreeMap::new();
            let mut interpreter = field(pid, runtime, layout.runtime_head)?;
            let mut seen = BTreeSet::new();
            for _ in 0..32 {
                if interpreter == 0 || !seen.insert(interpreter) {
                    break;
                }
                let mut thread = field(pid, interpreter, layout.interpreter_threads)?;
                for _ in 0..1024 {
                    if thread == 0 || !seen.insert(thread) {
                        break;
                    }
                    let native = field(pid, thread, layout.thread_native)?;
                    if let Ok(native) = u32::try_from(native) {
                        threads.insert(native, thread);
                    }
                    thread = field(pid, thread, layout.thread_next)?;
                }
                interpreter = field(pid, interpreter, layout.interpreter_next)?;
            }
            self.processes.insert(
                pid,
                Process {
                    runtime,
                    layout,
                    refreshed: Instant::now(),
                    threads,
                },
            );
        }
        let process = &self.processes[&pid];
        let layout = &process.layout;
        // Verify the cached runtime still belongs to a live initialized interpreter.
        if field(pid, process.runtime, layout.runtime_head)? == 0 {
            return Ok("    <no Python interpreter>\n".into());
        }
        let Some(&thread) = process.threads.get(&tid) else {
            return Ok("    <no Python thread state>\n".into());
        };
        if field(pid, thread, layout.thread_native)? != tid as u64 {
            self.processes.remove(&pid);
            return Err("Python thread state changed during capture".into());
        }
        let current = field(pid, thread, layout.thread_frame)?;
        let mut frame = if layout.indirect_frame && current != 0 {
            field(pid, current, layout.cframe_current)?
        } else {
            current
        };
        let mut seen = BTreeSet::new();
        let mut out = String::new();
        for _ in 0..depth.min(127) {
            if frame == 0 || !seen.insert(frame) {
                break;
            }
            let code = field(pid, frame, layout.frame_code)? & !layout.code_tag_mask;
            let owner = read(pid, address(frame, layout.frame_owner)?, 1)?[0];
            if code != 0 && owner != 3 {
                let name = unicode(pid, field(pid, code, layout.code_name)?, layout)?;
                let filename = unicode(pid, field(pid, code, layout.code_filename)?, layout)?;
                let first = u32::from_ne_bytes(
                    read(pid, address(code, layout.code_firstline)?, 4)?
                        .try_into()
                        .unwrap(),
                );
                let line = current_line(pid, frame, code, first, layout).ok().flatten();
                let location = line.map_or_else(
                    || format!("{first}; function start"),
                    |line| line.to_string(),
                );
                out.push_str(&format!(
                    "    {} ({}:{location})\n",
                    name.replace(['\n', '\r'], "?"),
                    filename.replace(['\n', '\r'], "?")
                ));
            }
            frame = field(pid, frame, layout.frame_previous)?;
        }
        if out.is_empty() {
            out.push_str("    <no Python frame>\n");
        }
        Ok(out)
    }
}

fn current_line(
    pid: u32,
    frame: u64,
    code: u64,
    first: u32,
    layout: &Layout,
) -> Result<Option<u32>> {
    let instruction = field(pid, frame, layout.frame_instruction)?;
    let offset = instruction
        .checked_sub(address(code, layout.code_adaptive)?)
        .ok_or("Python instruction outside code")?;
    let table = field(pid, code, layout.code_linetable)?;
    let length = field(pid, table, layout.bytes_length)?;
    if length > 4096 {
        return Err("Python line table exceeds capture limit".into());
    }
    if length == 0 {
        return Ok(None);
    }
    line_number(
        &read(pid, address(table, layout.bytes_data)?, length as usize)?,
        offset,
        first,
    )
}
fn line_number(table: &[u8], offset: u64, first: u32) -> Result<Option<u32>> {
    fn varint(table: &[u8], index: &mut usize) -> Result<u32> {
        let mut value = 0u32;
        for shift in (0..30).step_by(6) {
            let byte = *table
                .get(*index)
                .ok_or("truncated Python location varint")?;
            *index += 1;
            if byte & 0x80 != 0 {
                return Err("invalid Python location varint".into());
            }
            value |= (byte as u32 & 63) << shift;
            if byte & 64 == 0 {
                return Ok(value);
            }
        }
        Err("Python location varint overflow".into())
    }
    let mut index = 0;
    let mut end = 0u64;
    let mut line = first as i64;
    while let Some(&header) = table.get(index) {
        index += 1;
        if header & 128 == 0 {
            return Err("invalid Python location header".into());
        }
        let kind = (header >> 3) & 15;
        end += ((header & 7) as u64 + 1) * 2;
        match kind {
            0..=9 => {
                index += 1;
            }
            10..=12 => {
                line += (kind - 10) as i64;
                index += 2;
            }
            13 | 14 => {
                let delta = varint(table, &mut index)?;
                line += if delta & 1 == 0 {
                    (delta >> 1) as i64
                } else {
                    -((delta >> 1) as i64)
                };
                if kind == 14 {
                    for _ in 0..3 {
                        varint(table, &mut index)?;
                    }
                }
            }
            _ => {}
        }
        if index > table.len() {
            return Err("truncated Python location entry".into());
        }
        if offset < end {
            return if kind == 15 {
                Ok(None)
            } else {
                Ok(u32::try_from(line).ok().filter(|n| *n > 0))
            };
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn location_forms_and_malformed_tables() {
        // short entry, one-line +2, no-column -1, long +3, no-location.
        let table = [0x80, 0, 0xe0, 0, 1, 0xe8, 3, 0xf0, 6, 0, 0, 0, 0xf8];
        assert_eq!(line_number(&table, 0, 10).unwrap(), Some(10));
        assert_eq!(line_number(&table, 2, 10).unwrap(), Some(12));
        assert_eq!(line_number(&table, 4, 10).unwrap(), Some(11));
        assert_eq!(line_number(&table, 6, 10).unwrap(), Some(14));
        assert_eq!(line_number(&table, 8, 10).unwrap(), None);
        assert!(line_number(&[0], 0, 1).is_err());
        assert!(line_number(&[0x80], 0, 1).is_err());
        assert!(line_number(&[0xe8, 64, 64, 64, 64, 64], 0, 1).is_err());
    }
    #[test]
    fn debug_metadata_rejects_unknown_versions_and_invalid_offsets() {
        let mut bytes = [0u8; 656];
        bytes[..8].copy_from_slice(b"xdebugpy");
        let version = 0x030d00f0u32;
        bytes[8..16].copy_from_slice(&(version as u64).to_ne_bytes());
        assert!(Layout::debug(&bytes, version).is_err());
        for i in 3..82 {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&64u64.to_ne_bytes());
        }
        // Set structure sizes large enough; all field offsets 64 are in bounds.
        for i in [3, 6, 19, 28, 34, 64, 67] {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&1024u64.to_ne_bytes());
        }
        assert!(Layout::debug(&bytes, version).is_ok());
        bytes[5 * 8..6 * 8].copy_from_slice(&u64::MAX.to_ne_bytes());
        assert!(Layout::debug(&bytes, version).is_err());
        assert!(Layout::debug(&bytes, 0x030f00f0).is_err());
    }
}
