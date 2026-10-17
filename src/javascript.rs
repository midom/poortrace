//! Read-only V8 frame decoding using the target's exported postmortem metadata.
//! Object layouts: Node deps/v8/tools/gen-postmortem-metadata.py; ScopeInfo's
//! optional fields are version-gated to V8 12.4's objects/scope-info.tq.
use crate::{Result, memory, perf::UserRegs};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

#[derive(Default)]
pub struct Reader {
    processes: BTreeMap<u32, (String, Result<Layout>)>,
}
struct Layout {
    values: BTreeMap<String, i32>,
    version: (i32, i32),
}
fn word(pid: u32, address: u64) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        memory::read(pid, address, 8, false)?.try_into().unwrap(),
    ))
}
fn add(address: u64, offset: i32) -> Result<u64> {
    address
        .checked_add_signed(offset as i64)
        .ok_or_else(|| "V8 address overflow".into())
}
impl Layout {
    fn get(&self, name: &str) -> Result<i32> {
        self.values
            .get(name)
            .copied()
            .ok_or_else(|| format!("missing V8 metadata {name}"))
    }
    fn field(&self, pid: u32, object: u64, name: &str) -> Result<u64> {
        word(pid, add(self.object(object)?, self.get(name)?)?)
    }
    fn object(&self, value: u64) -> Result<u64> {
        let tag = self.get("HeapObjectTag")? as u64;
        if value & self.get("HeapObjectTagMask")? as u64 != tag {
            return Err("not a V8 heap object".into());
        }
        value
            .checked_sub(tag)
            .ok_or_else(|| "invalid V8 object".into())
    }
    fn kind(&self, pid: u32, value: u64) -> Result<i32> {
        let map = self.field(pid, value, "class_HeapObject__map__Map")?;
        let data = memory::read(
            pid,
            add(
                self.object(map)?,
                self.get("class_Map__instance_type__uint16_t")?,
            )?,
            2,
            false,
        )?;
        Ok(u16::from_ne_bytes(data.try_into().unwrap()) as i32)
    }
    fn smi(&self, value: u64) -> Result<i64> {
        if value & self.get("SmiTagMask")? as u64 != self.get("SmiTag")? as u64 {
            return Err("invalid V8 small integer".into());
        }
        let shift = self
            .get("SmiShiftSize")?
            .checked_add(self.get("SmiValueShift")?)
            .ok_or("invalid V8 Smi shift")?;
        if !(1..64).contains(&shift) {
            return Err("unsupported V8 Smi layout".into());
        }
        Ok((value as i64) >> shift)
    }
    fn string(&self, pid: u32, value: u64, budget: &mut usize) -> Result<String> {
        if *budget == 0 {
            return Err("V8 string recursion limit".into());
        }
        *budget -= 1;
        let kind = self.kind(pid, value)?;
        if kind >= self.get("FirstNonstringType")? {
            return Err("not a V8 string".into());
        }
        let base = self.object(value)?;
        let length = i32::from_ne_bytes(
            memory::read(
                pid,
                add(base, self.get("class_String__length__int32_t")?)?,
                4,
                false,
            )?
            .try_into()
            .unwrap(),
        );
        if !(0..=4096).contains(&length) {
            return Err("V8 string exceeds 4096 code units".into());
        }
        if length == 0 {
            return Ok(String::new());
        }
        let representation = kind & self.get("StringRepresentationMask")?;
        if representation == self.get("SeqStringTag")? {
            let one = kind & self.get("StringEncodingMask")? == self.get("OneByteStringTag")?;
            let offset = self.get(if one {
                "class_SeqOneByteString__chars__char"
            } else {
                "class_SeqTwoByteString__chars__char"
            })?;
            let count = length as usize * if one { 1 } else { 2 };
            if count > 4096 {
                return Err("V8 string exceeds 4096 bytes".into());
            }
            let bytes = memory::read(pid, add(base, offset)?, count, false)?;
            return Ok(if one {
                bytes.into_iter().map(char::from).collect()
            } else {
                String::from_utf16_lossy(
                    &bytes
                        .chunks_exact(2)
                        .map(|b| u16::from_ne_bytes(b.try_into().unwrap()))
                        .collect::<Vec<_>>(),
                )
            });
        }
        if representation == self.get("ConsStringTag")? {
            let first = self.field(pid, value, "class_ConsString__first__String")?;
            let second = self.field(pid, value, "class_ConsString__second__String")?;
            let mut text = self.string(pid, first, budget)?;
            text.push_str(&self.string(pid, second, budget)?);
            if text.len() > 16384 {
                return Err("V8 string exceeds output limit".into());
            }
            return Ok(text);
        }
        if representation == self.get("ThinStringTag")? {
            return self.string(
                pid,
                self.field(pid, value, "class_ThinString__actual__String")?,
                budget,
            );
        }
        Err("unsupported V8 string representation".into())
    }
    fn name(&self, pid: u32, shared: u64) -> Result<String> {
        let value = self.field(
            pid,
            shared,
            "class_SharedFunctionInfo__name_or_scope_info__Tagged_Object_",
        )?;
        if self.kind(pid, value)? < self.get("FirstNonstringType")? {
            return self.string(pid, value, &mut 32);
        }
        if self.kind(pid, value)? != self.get("type_ScopeInfo__SCOPE_INFO_TYPE")?
            || self.version != (12, 4)
        {
            return Err("unsupported V8 ScopeInfo layout (currently V8 12.4)".into());
        }
        let base = self.object(value)?;
        let flags = self.smi(word(pid, add(base, 8)?)?)? as u64;
        let locals = self.smi(word(pid, add(base, 24)?)?)?;
        // V8 12.4 inlines small local-name tables.
        // Reject large scopes rather than guessing an unexported threshold.
        if !(0..=32).contains(&locals) {
            return Err("V8 scope has too many context locals".into());
        }
        let mut offset = 32 + locals as i32 * 16;
        if flags & 15 == 3 {
            offset += 8;
        } // module_variable_count
        if flags & (1 << 10) != 0 {
            offset += 8;
        } // saved class variable
        if flags & (3 << 12) != 0 {
            let name = word(pid, add(base, offset)?)?;
            if let Ok(text) = self.string(pid, name, &mut 32) {
                if !text.is_empty() {
                    return Ok(text);
                }
            }
            offset += 16;
        }
        if flags & (1 << 14) != 0 {
            return self.string(pid, word(pid, add(base, offset)?)?, &mut 32);
        }
        Ok(String::new())
    }
    fn frame(&self, pid: u32, function: u64) -> Result<String> {
        let kind = self.kind(pid, function)?;
        if kind < self.get("FirstJSFunctionType")? || kind > self.get("LastJSFunctionType")? {
            return Err("not a JavaScript function".into());
        }
        let shared = self.field(
            pid,
            function,
            "class_JSFunction__shared__SharedFunctionInfo",
        )?;
        let name = self.name(pid, shared)?;
        let script = self
            .field(
                pid,
                shared,
                "class_SharedFunctionInfo__script__Tagged_HeapObject_",
            )
            .or_else(|_| {
                self.field(
                    pid,
                    shared,
                    "class_SharedFunctionInfo__raw_script__Tagged_Object_",
                )
            })?;
        let file = self
            .field(pid, script, "class_Script__name__Object")
            .and_then(|name| self.string(pid, name, &mut 32))
            .unwrap_or_else(|_| "<unknown script>".into());
        let name = if name.is_empty() {
            "<anonymous>".into()
        } else {
            name
        };
        Ok(format!(
            "    {} ({})\n",
            name.replace(['\n', '\r', '\0'], "?"),
            file.replace(['\n', '\r', '\0'], "?")
        ))
    }
}
fn discover(pid: u32, maps: &str) -> Result<Layout> {
    let mut paths = BTreeSet::new();
    for map in maps
        .lines()
        .filter_map(crate::symbols::Mapping::parse)
        .take(128)
    {
        if !map.path.starts_with('/') || !paths.insert(map.path.clone()) {
            continue;
        }
        let Ok(file) = std::fs::File::open(format!("/proc/{pid}/root{}", map.path)) else {
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
        let Some(bias) = elf.segments().find_map(|segment| {
            let (offset, size) = segment.file_range();
            (map.offset >= offset && map.offset - offset < size).then(|| {
                map.start
                    .wrapping_sub(segment.address() + map.offset - offset)
            })
        }) else {
            continue;
        };
        let mut values = BTreeMap::new();
        let mut version = (0, 0);
        for symbol in elf
            .symbols()
            .chain(elf.dynamic_symbols())
            .filter(|s| !s.is_undefined())
        {
            let name = symbol.name().unwrap_or("");
            if let Some(name) = name.strip_prefix("v8dbg_") {
                if values.len() >= 4096 {
                    return Err("too many V8 metadata symbols".into());
                }
                let value = i32::from_ne_bytes(
                    memory::read(pid, bias.wrapping_add(symbol.address()), 4, false)?
                        .try_into()
                        .unwrap(),
                );
                values.insert(name.into(), value);
            } else if name == "_ZN2v88internal7Version6major_E"
                || name == "_ZN2v88internal7Version6minor_E"
            {
                let value = i32::from_ne_bytes(
                    memory::read(pid, bias.wrapping_add(symbol.address()), 4, false)?
                        .try_into()
                        .unwrap(),
                );
                if name.contains("major") {
                    version.0 = value;
                } else {
                    version.1 = value;
                }
            }
        }
        if values.contains_key("HeapObjectTag") {
            let layout = Layout { values, version };
            if layout.get("TaggedSize")? != 8 || layout.get("SystemPointerSize")? != 8 {
                return Err("V8 pointer-compressed builds are unsupported".into());
            }
            return Ok(layout);
        }
    }
    Err("no exported V8 postmortem metadata found".into())
}
impl Reader {
    pub fn stack(
        &mut self,
        pid: u32,
        tid: u32,
        depth: usize,
        snapshot: Option<&(UserRegs, Vec<u8>)>,
    ) -> Result<String> {
        let maps =
            std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
        let identity = format!(
            "{}:{:?}",
            maps.lines().next().unwrap_or(""),
            std::fs::read_link(format!("/proc/{pid}/exe"))
        );
        if self
            .processes
            .get(&pid)
            .is_none_or(|(key, _)| *key != identity)
        {
            let layout = discover(pid, &maps);
            if self.processes.len() >= 16 {
                self.processes.clear();
            }
            self.processes.insert(pid, (identity, layout));
        }
        let layout = self.processes[&pid].1.as_ref().map_err(Clone::clone)?;
        let regs = match snapshot {
            Some((regs, _)) => *regs,
            None => crate::functions::user_registers(tid as i32)?,
        };
        let stack_word = |address: u64| -> Result<u64> {
            if let Some((regs, bytes)) = snapshot {
                let offset = address
                    .checked_sub(regs.sp)
                    .ok_or("frame outside captured stack")? as usize;
                let data = bytes
                    .get(offset..offset.saturating_add(8))
                    .ok_or("frame outside captured stack; increase --stack-bytes")?;
                return Ok(u64::from_ne_bytes(data.try_into().unwrap()));
            }
            word(tid, address)
        };
        let mut fp = regs.fp;
        let mut output = String::new();
        for _ in 0..512 {
            if fp == 0 || fp & 7 != 0 {
                break;
            }
            let function = stack_word(add(fp, layout.get("off_fp_function")?)?);
            if let Ok(function) = function {
                if let Ok(frame) = layout.frame(pid, function) {
                    output.push_str(&frame);
                    if output.lines().count() >= depth.min(127) {
                        break;
                    }
                }
            }
            let next = match stack_word(fp) {
                Ok(next) => next,
                Err(error) if output.is_empty() => return Err(error),
                Err(_) => break,
            };
            if next <= fp || next - fp > 16 * 1024 * 1024 {
                break;
            }
            fp = next;
        }
        if output.is_empty() {
            return Err(
                "no readable JavaScript frames (native code, GC, or unsupported layout)".into(),
            );
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C)]
    struct Text {
        map: u64,
        length: u64,
        bytes: [u8; 16],
    }
    fn layout() -> Layout {
        Layout {
            version: (12, 4),
            values: [
                ("HeapObjectTag", 1),
                ("HeapObjectTagMask", 3),
                ("class_HeapObject__map__Map", 0),
                ("class_Map__instance_type__uint16_t", 8),
                ("FirstNonstringType", 128),
                ("class_String__length__int32_t", 8),
                ("StringRepresentationMask", 7),
                ("StringEncodingMask", 8),
                ("OneByteStringTag", 8),
                ("SeqStringTag", 0),
                ("ConsStringTag", 1),
                ("ThinStringTag", 5),
                ("class_SeqOneByteString__chars__char", 16),
                ("class_SeqTwoByteString__chars__char", 16),
                ("class_ConsString__first__String", 16),
                ("class_ConsString__second__String", 24),
                ("SmiTag", 0),
                ("SmiTagMask", 1),
                ("SmiShiftSize", 31),
                ("SmiValueShift", 1),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
        }
    }
    #[test]
    fn strings_smis_and_malformed_objects_are_bounded() {
        let pid = std::process::id();
        let mut layout = layout();
        let one_map = [0u64, 8];
        let two_map = [0u64, 0];
        let cons_map = [0u64, 1];
        let mut text = Text {
            map: one_map.as_ptr() as u64 + 1,
            length: 3,
            bytes: [0; 16],
        };
        text.bytes[..3].copy_from_slice(b"abc");
        let tagged = std::hint::black_box(&text) as *const _ as u64 + 1;
        assert_eq!(layout.string(pid, tagged, &mut 32).unwrap(), "abc");
        text.map = two_map.as_ptr() as u64 + 1;
        text.length = 2;
        text.bytes[..4].copy_from_slice(&[0x41u16.to_ne_bytes(), 0x3bbu16.to_ne_bytes()].concat());
        std::hint::black_box(&text);
        assert_eq!(layout.string(pid, tagged, &mut 32).unwrap(), "Aλ");
        text.length = 4097;
        std::hint::black_box(&text);
        assert!(layout.string(pid, tagged, &mut 32).is_err());
        assert!(layout.string(pid, 0, &mut 32).is_err());
        let mut cycle = [cons_map.as_ptr() as u64 + 1, 1u64, 0, 0];
        let tagged = cycle.as_ptr() as u64 + 1;
        cycle[2] = tagged;
        cycle[3] = tagged;
        std::hint::black_box(&cycle);
        let mut budget = 8;
        assert!(layout.string(pid, tagged, &mut budget).is_err());
        assert_eq!(budget, 0);
        assert_eq!(layout.smi((-123i64 << 32) as u64).unwrap(), -123);
        layout.values.insert("SmiShiftSize".into(), i32::MAX);
        assert!(layout.smi(0).is_err());
        assert!(add(0, -1).is_err());
    }
}
