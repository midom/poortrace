//! Read-only discovery of concrete probes in a running process's native ELF images.
use crate::{Result, symbols::Mapping};
use object::Object;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
};

const MAX_IMAGE: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: usize = 512 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 250_000;

pub struct Listing {
    pub probes: Vec<String>,
    /// Inaccessible, replaced, deleted, or unsupported mapped images are explicit.
    pub warnings: Vec<String>,
}

/// Discover one bounded mapping snapshot without perf descriptors or ptrace attachment.
/// Absolute paths are interpreted in the target's filesystem namespace.
pub fn process(pid: i32, pattern: &str) -> Result<Listing> {
    if pid <= 0 {
        return Err("probe discovery requires a positive PID".into());
    }
    let started = crate::managed_bridge::start_ticks(pid as u32)
        .map_err(|e| format!("cannot inspect PID {pid}: {e}"))?;
    let executable = std::fs::metadata(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("cannot inspect executable of PID {pid}: {e}"))?;
    let mut maps = String::new();
    File::open(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("cannot inspect mappings of PID {pid}: {e}"))?
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut maps)
        .map_err(|e| e.to_string())?;
    if maps.len() > 8 * 1024 * 1024 {
        return Err("probe discovery mappings exceed 8 MiB".into());
    }
    let mut images = BTreeMap::new();
    let mut warnings = Vec::new();
    for line in maps.lines() {
        let Some(mapping) = Mapping::parse(line) else {
            continue;
        };
        if mapping.inode == 0 || !mapping.path.starts_with('/') {
            continue;
        }
        // A deleted name must never resolve to a replacement file at that pathname.
        let deleted = line.ends_with(" (deleted)");
        images
            .entry((mapping.device, mapping.inode))
            .or_insert((mapping, deleted));
        if images.len() > 1024 {
            return Err("probe discovery exceeds 1024 mapped images".into());
        }
    }
    let mut images: Vec<_> = images.into_iter().collect();
    images.sort_by_key(|((device, inode), _)| {
        !(*device == executable.dev() && *inode == executable.ino())
    });
    let mut probes = BTreeSet::new();
    let mut total = 0usize;
    let mut functions = 0usize;
    let mut found_executable = false;
    for ((device, inode), (mapping, deleted)) in images {
        let main = device == executable.dev() && inode == executable.ino();
        let path = &mapping.path;
        let loaded = if deleted {
            Err("mapped image has been deleted".into())
        } else {
            read_image(pid, &mapping)
        };
        let bytes = match loaded {
            Ok(bytes) => bytes,
            Err(error) => {
                if main {
                    return Err(format!("cannot list executable {path}: {error}"));
                }
                warnings.push(format!("cannot list mapped image {path}: {error}"));
                continue;
            }
        };
        found_executable |= main;
        total = total
            .checked_add(bytes.len())
            .ok_or("probe discovery byte count overflow")?;
        if total > MAX_TOTAL {
            return Err("probe discovery ELF data exceeds 512 MiB".into());
        }
        let discovered = match crate::uprobe::functions_from_bytes(&bytes, pattern) {
            Ok(found) => found,
            Err(error) if !main => {
                warnings.push(format!("cannot list functions in {path}: {error}"));
                continue;
            }
            Err(error) => return Err(format!("cannot list functions in {path}: {error}")),
        };
        functions += discovered.len();
        if functions > MAX_FUNCTIONS {
            return Err("probe discovery exceeds 250000 functions".into());
        }
        let mut names = BTreeMap::<&str, usize>::new();
        for function in &discovered {
            *names.entry(&function.name).or_default() += 1;
        }
        let path = match component(path, true) {
            Ok(path) => path,
            Err(error) if !main => {
                warnings.push(format!("cannot represent mapped path {path:?}: {error}"));
                continue;
            }
            Err(error) => return Err(error),
        };
        for function in &discovered {
            let symbol = function_selector(function, names[function.name.as_str()] > 1)?;
            for kind in ["uprobe", "uretprobe"] {
                probes.insert(format!("{kind}:{path}:{symbol}"));
            }
        }
        match crate::usdt::sites_from_bytes(&bytes) {
            Ok(sites) => {
                for site in sites {
                    let name = format!("{}:{}", site.provider, site.name);
                    if crate::uprobe::matches(pattern, &name)
                        || crate::uprobe::matches(pattern, &site.name)
                    {
                        // Treat provider:name as one selector when quoting is needed.
                        probes.insert(format!("usdt:{path}:{}", component(&name, false)?));
                    }
                }
            }
            Err(error) => warnings.push(format!(
                "cannot list SDT markers in {}: {error}",
                mapping.path
            )),
        }
        if probes.len() > 2 * MAX_FUNCTIONS + 65536 {
            return Err("probe discovery probe limit exceeded".into());
        }
    }
    if !found_executable {
        return Err(format!(
            "executable of PID {pid} has no readable executable mapping"
        ));
    }
    let current = std::fs::metadata(format!("/proc/{pid}/exe")).map_err(|e| e.to_string())?;
    if crate::managed_bridge::start_ticks(pid as u32)? != started
        || current.dev() != executable.dev()
        || current.ino() != executable.ino()
    {
        return Err("target exited or changed executable during probe discovery; retry".into());
    }
    warnings.sort();
    Ok(Listing {
        probes: probes.into_iter().collect(),
        warnings,
    })
}

fn read_image(pid: i32, mapping: &Mapping) -> Result<Vec<u8>> {
    let file =
        File::open(format!("/proc/{pid}/root{}", mapping.path)).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if metadata.dev() != mapping.device || metadata.ino() != mapping.inode {
        return Err("pathname no longer identifies the mapped image".into());
    }
    if metadata.len() > MAX_IMAGE {
        return Err("ELF image exceeds 128 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_IMAGE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_IMAGE {
        return Err("ELF image exceeds 128 MiB".into());
    }
    let elf = object::File::parse(bytes.as_slice()).map_err(|e| e.to_string())?;
    #[cfg(target_arch = "x86_64")]
    let architecture = object::Architecture::X86_64;
    #[cfg(target_arch = "aarch64")]
    let architecture = object::Architecture::Aarch64;
    if !elf.is_64()
        || elf.architecture() != architecture
        || elf.is_little_endian() != cfg!(target_endian = "little")
    {
        return Err("mapped image is not native 64-bit ELF".into());
    }
    Ok(bytes)
}

fn component(text: &str, path: bool) -> Result<String> {
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("probe name/path contains unrepresentable control characters".into());
    }
    if text.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'_'
            || b == b':' && !path
            || path && matches!(b, b'/' | b'.' | b'-')
    }) {
        Ok(text.into())
    } else {
        serde_json::to_string(text).map_err(|e| e.to_string())
    }
}

// Preserve readable names; only ambiguous or syntactically active names need offsets.
fn function_selector(function: &crate::uprobe::Function, ambiguous: bool) -> Result<String> {
    let name = &function.name;
    if ambiguous
        || name.starts_with("__sdt__")
        || name.starts_with("__usdt__")
        || name.starts_with("0x")
        || name.contains(['*', '?', '+'])
        || name.chars().any(char::is_control)
    {
        Ok(format!("0x{:x}", function.offset))
    } else {
        component(name, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn printed_selectors_roundtrip_without_changing_symbol_names() {
        for name in [
            "plain",
            "work.constprop.0",
            "foo@@VERSION",
            "operator$name",
            "ns::function",
        ] {
            let function = crate::uprobe::Function {
                offset: 64,
                name: name.into(),
                demangled: name.into(),
            };
            let selected = function_selector(&function, false).unwrap();
            let script = format!(
                "uprobe:{}:{selected} {{}}",
                component("/tmp/a path:with-quotes\"", true).unwrap()
            );
            let clauses = crate::language::parse(&script).unwrap();
            let crate::language::Probe::Uprobe { path, function, .. } = &clauses[0].probes[0].1
            else {
                panic!()
            };
            assert_eq!(path, "/tmp/a path:with-quotes\"");
            assert_eq!(function, name);
        }
        for name in [
            "__sdt__encoded",
            "__usdt__encoded",
            "foo*",
            "foo?",
            "foo+1",
            "0x123",
        ] {
            let function = crate::uprobe::Function {
                offset: 64,
                name: name.into(),
                demangled: name.into(),
            };
            assert_eq!(function_selector(&function, false).unwrap(), "0x40");
        }
        let function = crate::uprobe::Function {
            offset: 64,
            name: "local".into(),
            demangled: "local".into(),
        };
        assert_eq!(function_selector(&function, true).unwrap(), "0x40");
    }
}
