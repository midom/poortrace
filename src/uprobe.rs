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
    let sdt = crate::usdt::encoded(function)?;
    let offset_name = sdt.as_ref().map(|s| format!("0x{:x}", s.offset));
    let function = offset_name.as_deref().unwrap_or(function);
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

/// A file-backed native function, suitable for discovery and wildcard expansion.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Function {
    pub offset: u64,
    pub name: String,
    pub demangled: String,
}
/// Match '*' and '?' without recursive backtracking.
pub fn matches(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut i, mut j, mut star, mut retry) = (0, 0, None, 0);
    while j < n.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == n[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            i += 1;
            retry = j;
        } else if let Some(s) = star {
            retry += 1;
            j = retry;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}
pub fn functions(tid: i32, path: &str, pattern: &str) -> Result<Vec<Function>> {
    let target = if path.starts_with('/') {
        format!("/proc/{tid}/root{path}")
    } else {
        path.into()
    };
    let file = std::fs::File::open(&target).map_err(|e| format!("{path}: {e}"))?;
    if file.metadata().map_err(|e| e.to_string())?.len() > 128 * 1024 * 1024 {
        return Err("function ELF exceeds 128 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 128 * 1024 * 1024 {
        return Err("function ELF exceeds 128 MiB".into());
    }
    let object = object::File::parse(bytes.as_slice()).map_err(|e| e.to_string())?;
    let mut found = BTreeSet::new();
    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if symbol.kind() != SymbolKind::Text || symbol.is_undefined() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        let demangled = crate::symbols::demangle(name);
        if !matches(pattern, name) && !matches(pattern, &demangled) {
            continue;
        }
        let offset = object.segments().find_map(|segment| {
            let (offset, size) = segment.file_range();
            (matches!(segment.flags(), SegmentFlags::Elf {p_flags} if p_flags & 1 != 0)
                && symbol.address() >= segment.address()
                && symbol.address() - segment.address() < size)
                .then(|| offset + symbol.address() - segment.address())
        });
        if let Some(offset) = offset {
            found.insert(Function {
                offset,
                name: name.into(),
                demangled,
            });
            if found.len() > 250_000 {
                return Err("function symbol limit exceeded".into());
            }
        }
    }
    Ok(found.into_iter().collect())
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn wildcard_edges() {
        for (p, n, yes) in [
            ("*", "", true),
            ("foo*bar", "fooXXbar", true),
            ("a?c", "abc", true),
            ("*x", "abc", false),
            ("a*b*c", "axbyc", true),
        ] {
            assert_eq!(matches(p, n), yes);
        }
    }
}
