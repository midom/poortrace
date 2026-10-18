//! Perf tracepoint formats and dynamic kernel-probe PMU descriptors. No BPF or
//! global tracefs event registration is used. Access is enforced by the host.
use crate::Result;
use std::{collections::BTreeMap, ffi::CString, io::Read};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Value {
    Integer(u64),
    String(String),
}
pub type Fields = BTreeMap<String, Value>;

/// Kernel addresses are resolved only from host-visible kallsyms. Zeroed
/// addresses under kptr_restrict are never treated as usable symbols.
#[derive(Default)]
pub struct Symbols {
    entries: Vec<(u64, String)>,
    loaded: bool,
    restricted: bool,
}
impl Symbols {
    fn load(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let Ok(file) = std::fs::File::open("/proc/kallsyms") else {
            self.restricted = true;
            return;
        };
        let mut text = String::new();
        if file
            .take(32 * 1024 * 1024 + 1)
            .read_to_string(&mut text)
            .is_err()
            || text.len() > 32 * 1024 * 1024
        {
            self.restricted = true;
            return;
        }
        self.entries = Self::parse(&text);
        self.restricted = self.entries.is_empty();
    }
    fn parse(text: &str) -> Vec<(u64, String)> {
        let mut entries = Vec::new();
        for line in text.lines().take(1_000_000) {
            let mut words = line.split_whitespace();
            let Some(address) = words
                .next()
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .filter(|v| *v != 0)
            else {
                continue;
            };
            if !words
                .next()
                .is_some_and(|kind| matches!(kind, "t" | "T" | "w" | "W"))
            {
                continue;
            }
            let Some(name) = words.next() else {
                continue;
            };
            if name.len() > 4096 {
                continue;
            }
            let module = words.next().unwrap_or("");
            entries.push((address, format!("{name}{module}")));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        entries.dedup_by(|a, b| a.0 == b.0);
        entries
    }
    pub fn symbol(&mut self, address: u64) -> String {
        self.load();
        let end = self.entries.partition_point(|entry| entry.0 <= address);
        if end > 0 {
            let (base, name) = &self.entries[end - 1];
            // A distant address is not evidence that it belongs to the last
            // text symbol, particularly across kernel/module address spaces.
            if address - base <= 16 * 1024 * 1024 {
                return format!("{name}+0x{:x}", address - base);
            }
        }
        format!(
            "0x{address:x}{}",
            if self.restricted {
                " <kernel symbols restricted>"
            } else {
                ""
            }
        )
    }
    pub fn stack(&mut self, frames: &[u64]) -> String {
        if frames.is_empty() {
            return "    <no kernel stack>\n".into();
        }
        frames
            .iter()
            .take(127)
            .enumerate()
            .map(|(index, address)| {
                format!(
                    "    {}\n",
                    self.symbol(address.saturating_sub(u64::from(index != 0)))
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod symbol_tests {
    use super::*;
    #[test]
    fn zeroed_kallsyms_and_module_boundaries_are_explicit() {
        let entries = Symbols::parse(
            "0000000000000000 T hidden\nffffffff81000000 T start\nffffffff81000100 t leaf [module]\nffffffff81000200 D data\n",
        );
        let mut symbols = Symbols {
            entries,
            loaded: true,
            restricted: false,
        };
        assert_eq!(symbols.symbol(0xffffffff81000104), "leaf[module]+0x4");
        assert!(symbols.symbol(0xffffffffa0000000).starts_with("0x"));
        let mut symbols = Symbols {
            loaded: true,
            restricted: true,
            ..Default::default()
        };
        assert!(symbols.stack(&[0xffffffff81000104]).contains("restricted"));
        assert!(symbols.stack(&[]).contains("no kernel stack"));
    }
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
enum Kind {
    Integer,
    Text,
    Bytes,
    Dynamic { text: bool, relative: bool },
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Field {
    name: String,
    offset: usize,
    size: usize,
    signed: bool,
    kind: Kind,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Format {
    pub id: u64,
    fields: Vec<Field>,
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}
fn bounded_file(path: &std::path::Path) -> Result<String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("{}: {e}; tracefs access is required", path.display()))?;
    let mut value = String::new();
    file.take(131073)
        .read_to_string(&mut value)
        .map_err(|e| e.to_string())?;
    if value.len() > 131072 {
        return Err("tracepoint format exceeds 128 KiB".into());
    }
    Ok(value)
}
impl Format {
    pub fn load(category: &str, event: &str) -> Result<Self> {
        if !identifier(category) || !identifier(event) {
            return Err("invalid tracepoint category/event".into());
        }
        let root = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
            .into_iter()
            .find(|root| std::path::Path::new(root).join("events").is_dir())
            .ok_or(
                "tracefs event formats are unavailable; mount/access tracefs to use tracepoints",
            )?;
        Self::parse(&bounded_file(
            &std::path::Path::new(root)
                .join("events")
                .join(category)
                .join(event)
                .join("format"),
        )?)
    }
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 131072 {
            return Err("tracepoint format exceeds 128 KiB".into());
        }
        let mut id = None;
        let mut fields = Vec::new();
        for line in text.lines().map(str::trim) {
            if let Some(value) = line.strip_prefix("ID:") {
                id = Some(value.trim().parse::<u64>().map_err(|e| e.to_string())?);
            }
            let Some(line) = line.strip_prefix("field:") else {
                continue;
            };
            let mut parts = line.split(';');
            let declaration = parts
                .next()
                .ok_or("missing tracepoint field declaration")?
                .trim();
            let raw_name = declaration
                .split_whitespace()
                .last()
                .ok_or("missing tracepoint field name")?;
            let name = raw_name.split('[').next().unwrap().trim_start_matches('*');
            if !identifier(name) {
                return Err("invalid tracepoint field name".into());
            }
            let properties: BTreeMap<_, _> =
                parts.filter_map(|p| p.trim().split_once(':')).collect();
            let number = |key| -> Result<usize> {
                properties
                    .get(key)
                    .ok_or_else(|| format!("missing tracepoint field {key}"))?
                    .trim()
                    .parse::<usize>()
                    .map_err(|e| e.to_string())
            };
            let offset = number("offset")?;
            let size = number("size")?;
            if size == 0 || offset.checked_add(size).is_none_or(|end| end > 65536) {
                return Err("tracepoint field outside bounded record".into());
            }
            let text = declaration.contains("char") && declaration.contains('[');
            let kind = if declaration.contains("__data_loc") || declaration.contains("__rel_loc") {
                if size != 4 {
                    return Err("dynamic tracepoint locator must be 4 bytes".into());
                }
                Kind::Dynamic {
                    text,
                    relative: declaration.contains("__rel_loc"),
                }
            } else if text {
                Kind::Text
            } else if declaration.contains('[') || ![1, 2, 4, 8].contains(&size) {
                Kind::Bytes
            } else {
                Kind::Integer
            };
            if fields.iter().any(|f: &Field| f.name == name) {
                return Err("duplicate tracepoint field".into());
            }
            fields.push(Field {
                name: name.into(),
                offset,
                size,
                signed: number("signed")? != 0,
                kind,
            });
            if fields.len() > 256 {
                return Err("tracepoint field limit (256) exceeded".into());
            }
        }
        Ok(Self {
            id: id.ok_or("tracepoint format has no ID")?,
            fields,
        })
    }
    pub fn decode(&self, raw: &[u8]) -> Result<Fields> {
        if self.fields.len() > 256
            || self.fields.iter().any(|field| {
                field.name.is_empty()
                    || field.name.len() > 4096
                    || field.size > 65536
                    || field
                        .offset
                        .checked_add(field.size)
                        .is_none_or(|end| end > 65536)
                    || match field.kind {
                        Kind::Integer => !matches!(field.size, 1 | 2 | 4 | 8),
                        Kind::Dynamic { .. } => field.size != 4,
                        _ => false,
                    }
            })
        {
            return Err("invalid archived tracepoint format bounds".into());
        }
        if raw.len() > 65536 {
            return Err("tracepoint record exceeds 64 KiB".into());
        }
        let mut values = BTreeMap::new();
        for field in &self.fields {
            let bytes = raw
                .get(field.offset..field.offset + field.size)
                .ok_or("truncated tracepoint field")?;
            let value = match field.kind {
                Kind::Integer => {
                    let mut word = [0u8; 8];
                    word[..bytes.len()].copy_from_slice(bytes);
                    let bits = match bytes.len() {
                        1 => bytes[0] as u64,
                        2 => u16::from_ne_bytes(bytes.try_into().unwrap()) as u64,
                        4 => u32::from_ne_bytes(bytes.try_into().unwrap()) as u64,
                        _ => u64::from_ne_bytes(word),
                    };
                    Value::Integer(if field.signed && bytes.len() < 8 {
                        ((bits << (64 - bytes.len() * 8)) as i64 >> (64 - bytes.len() * 8)) as u64
                    } else {
                        bits
                    })
                }
                Kind::Text => Value::String(text(bytes)?),
                Kind::Bytes => Value::String(hex(bytes)?),
                Kind::Dynamic {
                    text: is_text,
                    relative,
                } => {
                    let location = u32::from_ne_bytes(bytes.try_into().unwrap());
                    let offset = (location & 0xffff) as usize;
                    let size = (location >> 16) as usize;
                    let start = offset
                        .checked_add(if relative { field.offset + 4 } else { 0 })
                        .ok_or("tracepoint locator overflow")?;
                    let data = raw
                        .get(
                            start
                                ..start
                                    .checked_add(size)
                                    .ok_or("tracepoint locator overflow")?,
                        )
                        .ok_or("invalid dynamic tracepoint locator")?;
                    Value::String(if is_text { text(data)? } else { hex(data)? })
                }
            };
            values.insert(field.name.clone(), value);
        }
        Ok(values)
    }
}
fn text(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 4096 {
        return Err("tracepoint string exceeds 4096 bytes".into());
    }
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}
fn hex(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 2048 {
        return Err("tracepoint byte array exceeds 2048 bytes".into());
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub struct ProbeConfig {
    pub kind: u32,
    pub config: u64,
    pub function: CString,
}
impl ProbeConfig {
    pub fn load(function: &str, ret: bool) -> Result<Self> {
        if !identifier(function) {
            return Err("invalid kernel function symbol".into());
        }
        let root = std::path::Path::new("/sys/bus/event_source/devices/kprobe");
        let kind = bounded_file(&root.join("type"))?
            .trim()
            .parse::<u32>()
            .map_err(|e| e.to_string())?;
        let config = if ret {
            let format = bounded_file(&root.join("format/retprobe"))?;
            let bit = format
                .trim()
                .strip_prefix("config:")
                .and_then(|b| b.parse::<u32>().ok())
                .filter(|bit| *bit < 64)
                .ok_or("unsupported kretprobe PMU format")?;
            1u64 << bit
        } else {
            0
        };
        Ok(Self {
            kind,
            config,
            function: CString::new(function).map_err(|e| e.to_string())?,
        })
    }
}

/// Online CPU IDs, including sparse cpusets; descriptors use cpu IDs directly.
pub fn online_cpus() -> Result<Vec<i32>> {
    parse_cpu_list(
        &std::fs::read_to_string("/sys/devices/system/cpu/online").map_err(|e| e.to_string())?,
    )
}
pub fn parse_cpu_list(text: &str) -> Result<Vec<i32>> {
    let mut cpus = std::collections::BTreeSet::new();
    for piece in text.trim().split(',') {
        let (first, last) = match piece.split_once('-') {
            Some((a, b)) => (a, b),
            None => (piece, piece),
        };
        let first = first.parse::<i32>().map_err(|e| e.to_string())?;
        let last = last.parse::<i32>().map_err(|e| e.to_string())?;
        if first < 0 || last < first || last > 1048575 || (last - first) > 4095 {
            return Err("invalid or excessive online CPU range".into());
        }
        cpus.extend(first..=last);
        if cpus.len() > 4096 {
            return Err("system-wide CPU limit (4096) exceeded".into());
        }
    }
    if cpus.is_empty() {
        return Err("no online CPUs".into());
    }
    Ok(cpus.into_iter().collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_signed_strings_dynamic_and_truncation() {
        let format=Format::parse("ID: 42\nfield:int pid; offset:0; size:4; signed:1;\nfield:char comm[4]; offset:4; size:4; signed:1;\nfield:__data_loc char[] path; offset:8; size:4; signed:0;").unwrap();
        let mut raw = (-2i32).to_ne_bytes().to_vec();
        raw.extend_from_slice(b"abc\0");
        raw.extend_from_slice(&((3u32 << 16) | 12).to_ne_bytes());
        raw.extend_from_slice(b"xy\0");
        let fields = format.decode(&raw).unwrap();
        assert_eq!(fields["pid"], Value::Integer((-2i64) as u64));
        assert_eq!(fields["comm"], Value::String("abc".into()));
        assert_eq!(fields["path"], Value::String("xy".into()));
        assert!(format.decode(&raw[..11]).is_err());
        raw[8..12].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(format.decode(&raw).is_err());
        assert!(Format::parse("ID:1\nfield:int x; offset:65536; size:4; signed:0;").is_err());
    }
    #[test]
    fn cpu_ranges_are_bounded_and_sparse() {
        assert_eq!(
            parse_cpu_list("0-2,7,9-10\n").unwrap(),
            vec![0, 1, 2, 7, 9, 10]
        );
        for text in ["", "-1", "3-1", "0-99999", "a"] {
            assert!(parse_cpu_list(text).is_err());
        }
    }
}
