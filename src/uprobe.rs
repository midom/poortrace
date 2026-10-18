//! Resolve user function symbols to executable ELF file offsets for the perf uprobe PMU.
use crate::Result;
use object::{Object, ObjectSegment, ObjectSymbol, SegmentFlags, SymbolKind};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    io::Read,
};

pub struct Resolved {
    pub path: CString,
    pub offset: u64,
    pub kind: u32,
    pub config: u64,
}
pub fn locate(tid: i32, path: &str, function: &str, ret: bool) -> Result<Resolved> {
    locate_many(tid, &[(path, function, ret)])?
        .pop()
        .ok_or_else(|| "missing resolved probe".into())
}

/// Resolve a batch with one ELF read/parse and one symbol index per image.
/// Results retain the input order, including duplicate bindings.
pub fn locate_many(tid: i32, specs: &[(&str, &str, bool)]) -> Result<Vec<Resolved>> {
    let mut images = BTreeMap::<&str, Vec<usize>>::new();
    for (index, (path, _, _)) in specs.iter().enumerate() {
        images.entry(path).or_default().push(index);
    }
    let mut results: Vec<Option<Resolved>> = (0..specs.len()).map(|_| None).collect();
    for (path, indices) in images {
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
        if bytes.len() > 128 * 1024 * 1024 {
            return Err("uprobe ELF file exceeds 128 MiB".into());
        }
        let object =
            object::File::parse(bytes.as_slice()).map_err(|e| format!("uprobe ELF {path}: {e}"))?;
        let mut symbols = BTreeMap::<String, BTreeSet<(u64, u64)>>::new();
        if indices.iter().any(|&index| {
            let function = specs[index].1;
            !function.starts_with("0x") && !function.starts_with("__sdt__")
        }) {
            for symbol in object.symbols().chain(object.dynamic_symbols()) {
                if symbol.kind() != SymbolKind::Text || symbol.is_undefined() {
                    continue;
                }
                if let Ok(name) = symbol.name() {
                    let value = (symbol.address(), symbol.size());
                    symbols.entry(name.into()).or_default().insert(value);
                    let demangled = crate::symbols::demangle(name);
                    if demangled != name {
                        symbols.entry(demangled).or_default().insert(value);
                    }
                }
            }
        }
        for index in indices {
            let (_, function, ret) = specs[index];
            results[index] = Some(locate_object(
                &object, &symbols, &target, path, function, ret,
            )?);
        }
    }
    results
        .into_iter()
        .map(|r| r.ok_or_else(|| "missing resolved probe".into()))
        .collect()
}

fn locate_object(
    object: &object::File<'_>,
    symbols: &BTreeMap<String, BTreeSet<(u64, u64)>>,
    target: &str,
    path: &str,
    function: &str,
    ret: bool,
) -> Result<Resolved> {
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
        let candidates = symbols.get(name).cloned().unwrap_or_default();
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
    resolve_many(tid, &[(path, function, ret)])?
        .pop()
        .ok_or_else(|| "missing resolved probe".into())
}
/// Batch ELF and PMU metadata resolution for perf function probes.
pub fn resolve_many(tid: i32, specs: &[(&str, &str, bool)]) -> Result<Vec<Resolved>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }
    let mut resolved = locate_many(tid, specs)?;
    let kind = std::fs::read_to_string("/sys/bus/event_source/devices/uprobe/type")
        .map_err(|e| format!("uprobe PMU unavailable: {e}"))?
        .trim()
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    let ret_config = if specs.iter().any(|(_, _, ret)| *ret) {
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
    for (probe, (_, _, ret)) in resolved.iter_mut().zip(specs) {
        probe.kind = kind;
        probe.config = if *ret { ret_config } else { 0 };
    }
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
/// Deterministic matching of native raw/demangled names, also usable offline.
pub fn matches_function(pattern: &str, name: &str) -> bool {
    matches(pattern, name) || matches(pattern, &crate::symbols::demangle(name))
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
    functions_from_bytes(&bytes, pattern)
}

pub(crate) fn functions_from_bytes(bytes: &[u8], pattern: &str) -> Result<Vec<Function>> {
    let object = object::File::parse(bytes).map_err(|e| e.to_string())?;
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
