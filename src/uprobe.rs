//! Resolve user function symbols to executable ELF file offsets for the perf uprobe PMU.
use crate::Result;
use object::{Object, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind};
use std::{collections::BTreeSet, ffi::CString, io::Read};

pub struct Resolved {
    pub path: CString,
    pub offset: u64,
    pub kind: u32,
    pub config: u64,
}
pub fn locate(tid: i32, path: &str, function: &str, ret: bool) -> Result<Resolved> {
    let target = if path.starts_with('/') {
        format!("/proc/{tid}/root{path}")
    } else {
        path.to_string()
    };
    let file = std::fs::File::open(&target).map_err(|e| format!("uprobe {path}: {e}"))?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 128 * 1024 * 1024 {
        return Err("uprobe ELF file exceeds 128 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let object =
        object::File::parse(bytes.as_slice()).map_err(|e| format!("uprobe ELF {path}: {e}"))?;
    if !object.is_64() {
        return Err("uprobes require a native 64-bit ELF target".into());
    }
    #[cfg(target_arch = "aarch64")]
    let arch = object::Architecture::Aarch64;
    #[cfg(target_arch = "x86_64")]
    let arch = object::Architecture::X86_64;
    if object.architecture() != arch {
        return Err("uprobe ELF architecture differs from this tracer".into());
    }
    let (name, delta) = function
        .rsplit_once('+')
        .and_then(|(name, offset)| number(offset).map(|offset| (name, offset)))
        .unwrap_or((function, 0));
    if ret && delta != 0 {
        return Err("uretprobe requires a function entry; omit the symbol offset".into());
    }
    let offset = if name.starts_with("0x") {
        number(name)
            .and_then(|value| value.checked_add(delta))
            .ok_or("invalid uprobe file offset")?
    } else {
        let candidates: BTreeSet<_> = object
            .symbols()
            .chain(object.dynamic_symbols())
            .filter(|symbol| symbol.kind() == SymbolKind::Text && !symbol.is_undefined())
            .filter(|symbol| {
                symbol
                    .name()
                    .is_ok_and(|raw| raw == name || crate::symbols::demangle(raw) == name)
            })
            .map(|symbol| (symbol.address(), symbol.size()))
            .collect();
        let addresses: BTreeSet<_> = candidates.iter().map(|(address, _)| *address).collect();
        if addresses.len() != 1 {
            return Err(format!(
                "uprobe symbol '{name}' has {} matches in {path}; use a precise/mangled name or 0xFILE_OFFSET",
                addresses.len()
            ));
        }
        let address = *addresses.first().unwrap();
        if delta != 0
            && candidates
                .iter()
                .all(|(_, size)| *size != 0 && delta >= *size)
        {
            return Err("uprobe offset is outside the symbol".into());
        }
        let address = address
            .checked_add(delta)
            .ok_or("uprobe symbol address overflow")?;
        object
            .segments()
            .find_map(|segment| {
                let (offset, size) = segment.file_range();
                let executable =
                    matches!(segment.flags(),SegmentFlags::Elf {p_flags} if p_flags&1!=0);
                if executable && address >= segment.address() && address - segment.address() < size
                {
                    offset.checked_add(address - segment.address())
                } else {
                    None
                }
            })
            .ok_or("uprobe symbol is outside file-backed executable segments")?
    };
    if !object.segments().any(|segment| {
        let (start, size) = segment.file_range();
        matches!(segment.flags(),SegmentFlags::Elf {p_flags} if p_flags&1!=0)
            && offset >= start
            && offset - start < size
    }) {
        return Err("uprobe file offset is outside executable segments".into());
    }
    #[cfg(target_arch = "aarch64")]
    if offset % 4 != 0 {
        return Err("AArch64 uprobe offsets must be instruction aligned (4 bytes)".into());
    }
    Ok(Resolved {
        path: CString::new(target).map_err(|_| "uprobe path contains NUL")?,
        offset,
        kind: 0,
        config: 0,
    })
}
pub fn resolve(tid: i32, path: &str, function: &str, ret: bool) -> Result<Resolved> {
    let mut resolved = locate(tid, path, function, ret)?;
    let kind = std::fs::read_to_string("/sys/bus/event_source/devices/uprobe/type")
        .map_err(|e| format!("uprobe PMU unavailable: {e}"))?
        .trim()
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    let config = if ret {
        let format =
            std::fs::read_to_string("/sys/bus/event_source/devices/uprobe/format/retprobe")
                .map_err(|e| e.to_string())?;
        let bit = format
            .trim()
            .strip_prefix("config:")
            .and_then(|bit| bit.parse::<u32>().ok())
            .filter(|bit| *bit < 64)
            .ok_or("unsupported uprobe retprobe PMU format")?;
        1u64 << bit
    } else {
        0
    };
    resolved.kind = kind;
    resolved.config = config;
    Ok(resolved)
}
fn number(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}
