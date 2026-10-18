//! Go 1.22–1.25 stripped ELF support. Schemas follow Go's debug/gosym/pclntab.go,
//! internal/abi/type.go, and runtime/traceback.go. Runtime structure offsets are
//! recovered from reflection descriptors, never compiled-in g/m offsets.
use crate::{Result, perf::UserRegs};
use object::{Object, ObjectSection, ObjectSegment};
use std::collections::BTreeMap;

pub(super) struct Image {
    data: Vec<u8>,
    pctab: usize,
    files: usize,
    cutab: usize,
    quantum: u64,
    functions: Vec<Function>,
    pub globals: Vec<(u64, usize)>,
}
struct Function {
    start: u64,
    end: u64,
    name: String,
    pcsp: usize,
    pcfile: usize,
    pcline: usize,
    cu: usize,
    flags: u8,
}
fn bytes(data: &[u8], at: usize, count: usize) -> Result<&[u8]> {
    data.get(at..at.checked_add(count).ok_or("Go metadata overflow")?)
        .ok_or_else(|| "truncated Go metadata".into())
}
fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(data, at, 4)?.try_into().unwrap()))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(data, at, 8)?.try_into().unwrap()))
}
fn varint(data: &[u8], at: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let b = *data.get(*at).ok_or("truncated Go varint")?;
        *at += 1;
        if shift == 63 && b > 1 {
            return Err("Go varint overflow".into());
        }
        value |= ((b & 127) as u64) << shift;
        if b < 128 {
            return Ok(value);
        }
    }
    Err("Go varint overflow".into())
}
fn cstring(data: &[u8], at: usize) -> Result<String> {
    let tail = data.get(at..).ok_or("Go name offset out of bounds")?;
    let end = tail
        .iter()
        .take(4097)
        .position(|b| *b == 0)
        .ok_or("Go name exceeds 4096 bytes")?;
    String::from_utf8(tail[..end].to_vec()).map_err(|e| e.to_string())
}
struct Types<'a> {
    elf: &'a object::File<'a>,
    base: u64,
}
impl Types<'_> {
    fn data(&self, address: u64, size: usize) -> Result<&[u8]> {
        self.elf
            .segments()
            .find_map(|segment| {
                let offset = address.checked_sub(segment.address())?;
                let data = segment.data().ok()?;
                data.get(offset as usize..(offset as usize).checked_add(size)?)
            })
            .ok_or_else(|| "Go reflection address outside ELF".into())
    }
    fn word(&self, address: u64) -> Result<u64> {
        u64_at(self.data(address, 8)?, 0)
    }
    fn name(&self, address: u64) -> Result<String> {
        let mut length = 0u64;
        let mut cursor = address.checked_add(1).ok_or("Go name overflow")?;
        for shift in (0..28).step_by(7) {
            let b = self.data(cursor, 1)?[0];
            cursor += 1;
            length |= ((b & 127) as u64) << shift;
            if b < 128 {
                if length > 4096 {
                    return Err("Go reflected name too long".into());
                }
                return String::from_utf8(self.data(cursor, length as usize)?.to_vec())
                    .map_err(|e| e.to_string());
            }
        }
        Err("Go reflection varint overflow".into())
    }
    fn type_name(&self, address: u64) -> Result<String> {
        let offset = u32_at(self.data(address.wrapping_add(40), 4)?, 0)? as i32;
        if offset < 0 {
            return Err("negative Go type name offset".into());
        }
        self.name(self.base.wrapping_add(offset as u64))
    }
    fn field(&self, mut address: u64, path: &str) -> Result<(u64, usize)> {
        let mut offset = 0u64;
        for name in path.split('.') {
            if self.data(address.wrapping_add(23), 1)?[0] & 31 != 25 {
                return Err("Go reflected field is not a struct".into());
            }
            let data = self.word(address.wrapping_add(56))?;
            let length = self.word(address.wrapping_add(64))?;
            if length > 4096 {
                return Err("too many Go reflected fields".into());
            }
            let mut found = None;
            for index in 0..length {
                let field = data.checked_add(index * 24).ok_or("Go field overflow")?;
                if self.name(self.word(field)?)? == name {
                    found = Some((
                        self.word(field.wrapping_add(8))?,
                        self.word(field.wrapping_add(16))?,
                    ));
                    break;
                }
            }
            let (next, displacement) =
                found.ok_or_else(|| format!("missing Go reflected field {name}"))?;
            offset = offset
                .checked_add(displacement)
                .ok_or("Go field overflow")?;
            address = next;
        }
        let size = self.word(address)?;
        if offset > 1024 * 1024 || ![1, 4, 8].contains(&size) {
            return Err("unsupported Go reflected scalar".into());
        }
        Ok((offset, size as usize))
    }
}
type Fields = BTreeMap<String, (u64, usize)>;
impl Image {
    pub fn parse(elf: &object::File<'_>, bias: u64) -> Result<(Self, Fields)> {
        // Go's internal PIE linker stores preferred virtual-address addends in
        // reflection fields. Interpret them in the ELF, and apply the observed
        // load bias only to live PCs/globals (not to file metadata pointers).
        if !matches!(
            elf.kind(),
            object::ObjectKind::Executable | object::ObjectKind::Dynamic
        ) {
            return Err("stripped Go requires an executable ELF".into());
        }
        let build = elf
            .section_by_name(".go.buildinfo")
            .ok_or("Go build info unavailable")?
            .data()
            .map_err(|e| e.to_string())?;
        if bytes(build, 0, 14)? != b"\xff Go buildinf:"
            || *build.get(14).ok_or("Go build info truncated")? != 8
            || *build.get(15).ok_or("Go build info truncated")? & 3 != 2
        {
            return Err("unsupported Go build info schema".into());
        }
        let mut at = 32;
        let len = varint(build, &mut at)? as usize;
        let version = std::str::from_utf8(bytes(build, at, len)?).map_err(|e| e.to_string())?;
        if !["go1.22", "go1.23", "go1.24", "go1.25"]
            .iter()
            .any(|prefix| version == *prefix || version.starts_with(&format!("{prefix}.")))
        {
            return Err(format!(
                "stripped Go metadata schema unavailable for {version}"
            ));
        }
        let pie = elf.section_by_name(".data.rel.ro.typelink").is_some();
        let ro = elf
            .section_by_name(if pie { ".data.rel.ro" } else { ".rodata" })
            .ok_or("Go reflection types unavailable")?;
        let types = Types {
            elf,
            base: ro.address(),
        };
        let links = elf
            .section_by_name(if pie {
                ".data.rel.ro.typelink"
            } else {
                ".typelink"
            })
            .ok_or("Go typelinks unavailable")?
            .data()
            .map_err(|e| e.to_string())?;
        if links.len() > 4 * 1024 * 1024 || links.len() % 4 != 0 {
            return Err("invalid Go typelink table".into());
        }
        let mut roots = BTreeMap::new();
        for item in links.chunks_exact(4) {
            let offset = i32::from_le_bytes(item.try_into().unwrap());
            if offset < 0 {
                continue;
            }
            let address = types.base.wrapping_add(offset as u64);
            if types.data(address.wrapping_add(23), 1)?[0] & 31 != 22 {
                continue;
            }
            let name = types.type_name(address)?;
            if name == "*runtime.g" || name == "*runtime.m" {
                let element = types.word(address.wrapping_add(48))?;
                if types.type_name(element)? != name {
                    return Err("inconsistent Go pointer element type".into());
                }
                roots.insert(name, element);
            }
        }
        let mut fields = BTreeMap::new();
        for (kind, path) in [
            ("g", "goid"),
            ("g", "m"),
            ("g", "atomicstatus.value"),
            ("g", "stack.lo"),
            ("g", "stack.hi"),
            ("g", "sched.sp"),
            ("g", "sched.pc"),
            ("g", "sched.bp"),
            ("g", "sched.lr"),
            ("m", "procid"),
            ("m", "curg"),
        ] {
            let root = roots
                .get(&format!("*runtime.{kind}"))
                .ok_or("Go g/m reflection metadata unavailable")?;
            fields.insert(format!("{kind}.{path}"), types.field(*root, path)?);
        }
        let section = elf
            .section_by_name(if pie {
                ".data.rel.ro.gopclntab"
            } else {
                ".gopclntab"
            })
            .ok_or("Go pclntab unavailable")?;
        let data = section.data().map_err(|e| e.to_string())?.to_vec();
        if data.len() > 64 * 1024 * 1024
            || u32_at(&data, 0)? != 0xfffffff1
            || bytes(&data, 4, 2)? != [0, 0]
            || ![1, 2, 4].contains(&data[6])
            || data[7] != 8
        {
            return Err("unsupported Go pclntab schema".into());
        }
        let count = u64_at(&data, 8)? as usize;
        if count == 0 || count > 1_000_000 {
            return Err("Go function table exceeds bounds".into());
        }
        let text = u64_at(&data, 24)?
            .checked_add(bias)
            .ok_or("Go text bias overflow")?;
        let names = u64_at(&data, 32)? as usize;
        let cutab = u64_at(&data, 40)? as usize;
        let files = u64_at(&data, 48)? as usize;
        let pctab = u64_at(&data, 56)? as usize;
        let functions_at = u64_at(&data, 64)? as usize;
        for offset in [names, cutab, files, pctab, functions_at] {
            bytes(&data, offset, 0)?;
        }
        bytes(
            &data,
            functions_at,
            count
                .checked_mul(8)
                .and_then(|n| n.checked_add(4))
                .ok_or("Go function table overflow")?,
        )?;
        let mut functions = Vec::with_capacity(count);
        for index in 0..count {
            let row = functions_at + index * 8;
            let start = text
                .checked_add(u32_at(&data, row)? as u64)
                .ok_or("Go text address overflow")?;
            let end = text
                .checked_add(u32_at(&data, row + 8)? as u64)
                .ok_or("Go text address overflow")?;
            let f = functions_at
                .checked_add(u32_at(&data, row + 4)? as usize)
                .ok_or("Go function offset overflow")?;
            bytes(&data, f, 44)?;
            if start >= end
                || (index > 0 && functions.last().is_some_and(|f: &Function| f.end > start))
            {
                return Err("unsorted Go functions".into());
            }
            functions.push(Function {
                start,
                end,
                name: cstring(&data, names + u32_at(&data, f + 4)? as usize)?,
                pcsp: u32_at(&data, f + 16)? as usize,
                pcfile: u32_at(&data, f + 20)? as usize,
                pcline: u32_at(&data, f + 24)? as usize,
                cu: u32_at(&data, f + 32)? as usize,
                flags: data[f + 41],
            });
        }
        let mut globals = Vec::new();
        let mut size = 0usize;
        for name in [".data", ".bss"] {
            let section = elf.section_by_name(name).ok_or("Go globals unavailable")?;
            let length = usize::try_from(section.size()).map_err(|_| "Go globals too large")?;
            size = size.checked_add(length).ok_or("Go globals overflow")?;
            if size > 8 * 1024 * 1024 {
                return Err("Go globals exceed 8 MiB".into());
            }
            globals.push((
                section
                    .address()
                    .checked_add(bias)
                    .ok_or("Go globals bias overflow")?,
                length,
            ));
        }
        Ok((
            Self {
                quantum: data[6] as u64,
                data,
                pctab,
                cutab,
                files,
                functions,
                globals,
            },
            fields,
        ))
    }
    fn function(&self, pc: u64) -> Option<&Function> {
        let n = self.functions.partition_point(|f| f.start <= pc);
        n.checked_sub(1)
            .map(|n| &self.functions[n])
            .filter(|f| pc < f.end)
    }
    fn value(&self, function: &Function, table: usize, pc: u64) -> Result<i64> {
        if table == 0 {
            return Err("Go PC table unavailable".into());
        }
        let mut cursor = self
            .pctab
            .checked_add(table)
            .ok_or("Go PC table overflow")?;
        let mut value = -1i64;
        let mut start = function.start;
        for iteration in 0..1_000_000 {
            let delta = varint(&self.data, &mut cursor)?;
            if delta == 0 && iteration > 0 {
                break;
            }
            let delta = ((delta >> 1) as i64) ^ -((delta & 1) as i64);
            value = value.checked_add(delta).ok_or("Go PC value overflow")?;
            let step = varint(&self.data, &mut cursor)?
                .checked_mul(self.quantum)
                .ok_or("Go PC step overflow")?;
            start = start.checked_add(step).ok_or("Go PC overflow")?;
            if pc < start {
                return Ok(value);
            }
        }
        Err("Go PC table does not cover frame".into())
    }
    pub fn unwind(&self, regs: UserRegs, stack: &[u8], depth: usize) -> Vec<u64> {
        let mut frames = Vec::new();
        let (mut pc, mut sp) = (regs.ip, regs.sp);
        for index in 0..depth.min(127) {
            let lookup = if index == 0 { pc } else { pc.saturating_sub(1) };
            let Some(function) = self.function(lookup) else {
                break;
            };
            frames.push(lookup);
            if function.flags & 3 != 0
                || [
                    "runtime.sigpanic",
                    "runtime.asyncPreempt",
                    "runtime.debugCallV2",
                    "runtime.systemstack",
                    "runtime.mcall",
                ]
                .contains(&function.name.as_str())
            {
                break;
            }
            let Ok(delta) = self.value(function, function.pcsp, lookup) else {
                break;
            };
            if !(0..=1024 * 1024 * 1024).contains(&delta) {
                break;
            }
            let Some(next_sp) = sp.checked_add(delta as u64) else {
                break;
            };
            #[cfg(target_arch = "x86_64")]
            let Some(next_sp) = next_sp.checked_add(8) else {
                break;
            };
            #[cfg(target_arch = "aarch64")]
            let slot = sp;
            #[cfg(target_arch = "x86_64")]
            let slot = next_sp - 8;
            #[cfg(target_arch = "aarch64")]
            let return_pc = if index == 0 && delta == 0 {
                Some(regs.lr)
            } else {
                slot.checked_sub(regs.sp)
                    .and_then(|n| stack.get(n as usize..n as usize + 8))
                    .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
            };
            #[cfg(target_arch = "x86_64")]
            let return_pc = slot
                .checked_sub(regs.sp)
                .and_then(|n| stack.get(n as usize..n as usize + 8))
                .map(|b| u64::from_ne_bytes(b.try_into().unwrap()));
            let Some(next_pc) = return_pc else { break };
            if next_pc == 0 || next_sp < sp || (next_sp == sp && next_pc == pc) {
                break;
            }
            sp = next_sp;
            pc = next_pc;
        }
        frames
    }
    pub fn stack(&self, frames: &[u64]) -> String {
        let mut out = String::new();
        for pc in frames {
            let Some(f) = self.function(*pc) else {
                continue;
            };
            let location = (|| -> Result<String> {
                let line = self.value(f, f.pcline, *pc)?;
                let file = self.value(f, f.pcfile, *pc)?;
                if line < 0 || file < 0 || f.cu == u32::MAX as usize {
                    return Err("Go source unavailable".into());
                }
                let offset = self
                    .cutab
                    .checked_add(
                        (f.cu + file as usize)
                            .checked_mul(4)
                            .ok_or("Go source overflow")?,
                    )
                    .ok_or("Go source overflow")?;
                let name = u32_at(&self.data, offset)?;
                Ok(format!(
                    " ({}:{line})",
                    cstring(&self.data, self.files + name as usize)?
                ))
            })()
            .unwrap_or_default();
            out.push_str(&format!("    {}+0x{:x}{location}\n", f.name, pc - f.start));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires Go 1.22 compiler"]
    fn real_stripped_go_reflection_and_pc_tables() {
        let directory =
            std::env::temp_dir().join(format!("poortrace-go-pcln-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let binary = directory.join("stripped");
        let build = std::process::Command::new("go")
            .args(["build", "-ldflags", "-s -w", "-o"])
            .arg(&binary)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/go_stacks.go"
            ))
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let bytes = std::fs::read(&binary).unwrap();
        let elf = object::File::parse(bytes.as_slice()).unwrap();
        let (image, fields) = Image::parse(&elf, 0).unwrap();
        assert_eq!(fields["g.goid"], (152, 8));
        assert!(image.functions.iter().any(|f| f.name == "main.leaf"));
        let leaf = image
            .functions
            .iter()
            .find(|f| f.name == "main.leaf")
            .unwrap();
        assert!(image.value(leaf, leaf.pcsp, leaf.start).is_ok());
        assert!(image.stack(&[leaf.start]).contains("go_stacks.go:"));
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn malformed_tables_and_varints_are_rejected() {
        assert!(u64_at(&[], 0).is_err());
        assert!(cstring(b"unterminated", 0).is_err());
        assert!(varint(&[255; 10], &mut 0).is_err());
        assert!(bytes(&[], usize::MAX, 1).is_err());
    }
}
