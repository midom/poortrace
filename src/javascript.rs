//! Read-only V8 frame decoding using the target's exported postmortem metadata.
//! Object layouts: Node deps/v8/tools/gen-postmortem-metadata.py; ScopeInfo's
//! optional fields are gated to verified Node 20/22/24 scope-info.tq layouts.
use crate::{Result, memory, perf::UserRegs};
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{
    collections::{BTreeMap, BTreeSet},
};

#[derive(Default)]
pub struct Reader {
    processes: BTreeMap<u32, (String, Result<Layout>)>,
}
struct Layout {
    values: BTreeMap<String, i32>,
    version: (i32, i32),
    interpreter_ranges: Vec<(u64, u64)>,
    code_cache: std::sync::Mutex<Vec<(u64, u64, u64)>>,
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
            .or_else(|| {
                // Torque's type spelling changes across V8 versions; the
                // exported class and member still identify the same offset.
                if name.starts_with("class_") {
                    let (prefix, _) = name.rsplit_once("__")?;
                    let prefix = format!("{prefix}__");
                    self.values
                        .iter()
                        .find(|(key, _)| key.starts_with(&prefix))
                        .map(|(_, value)| *value)
                } else if matches!(name, "FirstJSFunctionType" | "LastJSFunctionType") {
                    self.values
                        .get("type_JSFunction__JS_FUNCTION_TYPE")
                        .copied()
                } else {
                    None
                }
            })
            .ok_or_else(|| format!("missing V8 metadata {name}"))
    }
    fn field(&self, pid: u32, object: u64, name: &str) -> Result<u64> {
        self.tagged(pid, add(self.object(object)?, self.get(name)?)?, object)
    }
    fn tagged(&self, pid: u32, address: u64, owner: u64) -> Result<u64> {
        if self.get("TaggedSize")? == 4 {
            let value =
                u32::from_ne_bytes(memory::read(pid, address, 4, false)?.try_into().unwrap());
            // V8 heap compression uses an aligned 4-GiB cage; stack pointers
            // retain the full address, and all ordinary heap fields share its cage.
            Ok(
                if value & self.get("HeapObjectTagMask")? as u32
                    == self.get("HeapObjectTag")? as u32
                {
                    (owner & !0xffff_ffff) | value as u64
                } else {
                    value as i32 as i64 as u64
                },
            )
        } else {
            word(pid, address)
        }
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
        let value = if self.get("TaggedSize")? == 4 {
            value as i32 as i64
        } else {
            value as i64
        };
        Ok(value >> shift)
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
        if representation == self.get("SlicedStringTag")? {
            let parent = self.field(pid, value, "class_SlicedString__parent__String")?;
            let offset = self.smi(self.field(pid, value, "class_SlicedString__offset__SMI")?)?;
            if !(0..=4096).contains(&offset) {
                return Err("invalid V8 string slice offset".into());
            }
            let parent = self.string(pid, parent, budget)?;
            // SlicedString offsets count UTF-16 code units, including surrogate pairs.
            let units: Vec<_> = parent.encode_utf16().collect();
            let units = units
                .get(offset as usize..offset as usize + length as usize)
                .ok_or("V8 string slice exceeds parent")?;
            return Ok(String::from_utf16_lossy(units));
        }
        Err("unsupported V8 string representation".into())
    }
    fn name(&self, pid: u32, shared: u64) -> Result<(String, Option<i64>)> {
        let value = self.field(
            pid,
            shared,
            "class_SharedFunctionInfo__name_or_scope_info__Tagged_Object_",
        )?;
        if self.kind(pid, value)? < self.get("FirstNonstringType")? {
            return Ok((self.string(pid, value, &mut 32)?, None));
        }
        if self.kind(pid, value)? != self.get("type_ScopeInfo__SCOPE_INFO_TYPE")?
            || !matches!(self.version, (11, 3) | (12, 4) | (13, 6))
        {
            return Err("unsupported V8 ScopeInfo layout (verified V8 11.3, 12.4, 13.6)".into());
        }
        let base = self.object(value)?;
        let size = self.get("TaggedSize")?;
        let flags = if self.version == (13, 6) {
            u32::from_ne_bytes(
                memory::read(pid, add(base, size)?, 4, false)?
                    .try_into()
                    .unwrap(),
            ) as u64
        } else {
            self.smi(self.tagged(pid, add(base, size)?, value)?)? as u64
        };
        let locals = self.smi(self.tagged(pid, add(base, size * 3)?, value)?)?;
        // globals.h fixes the inline-name threshold at 75 in all verified
        // versions. Larger scopes reserve one hash-table slot, then local info.
        if !(0..=8192).contains(&locals) {
            return Err("V8 scope has too many context locals".into());
        }
        let slots = if locals < 75 { locals * 2 } else { locals + 1 };
        let mut offset = size * (4 + slots as i32);
        if self.version == (13, 6) {
            offset += size * 2;
        } // position_info moved before locals
        let module_scope = if self.version == (13, 6) { 5 } else { 3 };
        if self.version != (11, 3) && flags & 15 == module_scope {
            offset += size;
        }
        if flags & (1 << 10) != 0 {
            offset += size;
        } // saved class variable
        let mut name = String::new();
        if flags & (3 << 12) != 0 {
            if let Ok(text) =
                self.string(pid, self.tagged(pid, add(base, offset)?, value)?, &mut 32)
            {
                name = text;
            }
            offset += size * 2;
        }
        if flags & (1 << 14) != 0 {
            if name.is_empty() {
                name = self.string(pid, self.tagged(pid, add(base, offset)?, value)?, &mut 32)?;
            }
            offset += size;
        }
        // ScopeInfo PositionInfo contains source UTF-16 offsets, not PCs.
        // Restrict old schemas to function scopes, where its presence is guaranteed.
        let position = if self.version == (13, 6) {
            self.smi(self.tagged(pid, add(base, size * 4)?, value)?)
                .ok()
        } else if flags & 15 == 2 {
            self.smi(self.tagged(pid, add(base, offset)?, value)?).ok()
        } else {
            None
        };
        Ok((name, position.filter(|p| *p >= 0)))
    }
    fn source_line(&self, pid: u32, script: u64, position: i64) -> Result<i64> {
        let size = self.get("TaggedSize")?;
        // script.tq places line_offset directly after the exported name field.
        let line_offset = self.smi(
            self.tagged(
                pid,
                add(
                    self.object(script)?,
                    self.get("class_Script__name__Object")?
                        .checked_add(size)
                        .ok_or("V8 script offset overflow")?,
                )?,
                script,
            )?,
        )?;
        if line_offset < 0 {
            return Err("invalid V8 script line offset".into());
        }
        let line_ends = self.field(pid, script, "class_Script__line_ends__Object")?;
        if self.kind(pid, line_ends).is_ok_and(|kind| {
            self.get("type_FixedArray__FIXED_ARRAY_TYPE")
                .is_ok_and(|expected| kind == expected)
        }) {
            let count =
                self.smi(self.field(pid, line_ends, "class_FixedArrayBase__length__SMI")?)?;
            if !(0..=1_000_000).contains(&count) {
                return Err("invalid V8 line-end table length".into());
            }
            let data = add(
                self.object(line_ends)?,
                self.get("class_FixedArray__data__uintptr_t")?,
            )?;
            let (mut low, mut high) = (0, count);
            while low < high {
                let mid = low + (high - low) / 2;
                let end = self.smi(
                    self.tagged(
                        pid,
                        data.checked_add(mid as u64 * size as u64)
                            .ok_or("V8 line table overflow")?,
                        line_ends,
                    )?,
                )?;
                if end < position {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            }
            return Ok(line_offset + low + 1);
        }
        // Line-end arrays are initialized lazily. Read only the source prefix
        // needed for this location, in bounded chunks, without invoking V8.
        if position > 65536 {
            return Err("V8 source position exceeds prefix capture limit".into());
        }
        let source = self.field(pid, script, "class_Script__source__Object")?;
        let kind = self.kind(pid, source)?;
        if kind >= self.get("FirstNonstringType")?
            || kind & self.get("StringRepresentationMask")? != self.get("SeqStringTag")?
        {
            return Err("V8 source is not a sequential string".into());
        }
        let base = self.object(source)?;
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
        if length < 0 || position > length as i64 {
            return Err("V8 source position exceeds string".into());
        }
        let one = kind & self.get("StringEncodingMask")? == self.get("OneByteStringTag")?;
        let offset = self.get(if one {
            "class_SeqOneByteString__chars__char"
        } else {
            "class_SeqTwoByteString__chars__char"
        })?;
        let bytes = position as usize * if one { 1 } else { 2 };
        let start = add(base, offset)?;
        let mut units = Vec::new();
        for offset in (0..bytes).step_by(4096) {
            let data = memory::read(
                pid,
                start
                    .checked_add(offset as u64)
                    .ok_or("V8 source overflow")?,
                (bytes - offset).min(4096),
                false,
            )?;
            if one {
                units.extend(data.into_iter().map(u16::from));
            } else {
                units.extend(
                    data.chunks_exact(2)
                        .map(|b| u16::from_ne_bytes(b.try_into().unwrap())),
                );
            }
        }
        let mut line = line_offset + 1;
        let mut previous = 0;
        for unit in units {
            if unit == 13 || unit == 0x2028 || unit == 0x2029 || unit == 10 && previous != 13 {
                line += 1;
            }
            previous = unit;
        }
        Ok(line)
    }
    fn current_position(
        &self,
        pid: u32,
        fp: u64,
        pc: u64,
        stack_word: &impl Fn(u64) -> Result<u64>,
    ) -> Result<i64> {
        // Trusted byte-array layouts below are verified for noncompressed V8
        // 12.4. Require a known interpreter PC so optimized stack slots cannot
        // accidentally be interpreted as bytecode state.
        if !matches!(self.version, (11, 3) | (12, 4) | (13, 6))
            || self.get("TaggedSize")? != 8
            || !self
                .interpreter_ranges
                .iter()
                .any(|(start, end)| *start <= pc && pc < *end)
        {
            return Err("current position requires a verified V8 interpreted frame".into());
        }
        let bytecode = stack_word(add(fp, self.get("off_fp_bytecode_array")?)?)?;
        if self.kind(pid, bytecode)? != self.get("type_BytecodeArray__BYTECODE_ARRAY_TYPE")? {
            return Err("invalid V8 interpreted bytecode array".into());
        }
        let raw_offset = self.smi(stack_word(add(fp, self.get("off_fp_bytecode_offset")?)?)?)?;
        let offset = raw_offset - self.get("class_BytecodeArray__data__uintptr_t")? as i64
            + self.get("HeapObjectTag")? as i64;
        let length = self.smi(if self.version == (11, 3) {
            word(pid, add(self.object(bytecode)?, 8)?)?
        } else {
            self.field(pid, bytecode, "class_BytecodeArray__length__SMI")?
        })?;
        if offset < 0 || offset >= length {
            return Err("invalid V8 bytecode position".into());
        }
        let table_offset = if self.version == (11, 3) {
            32
        } else {
            self.get("class_BytecodeArray__wrapper__Tagged_BytecodeWrapper_")?
                .checked_add(8)
                .ok_or("V8 bytecode offset overflow")?
        };
        let table = word(pid, add(self.object(bytecode)?, table_offset)?)?;
        let kind = if self.version == (11, 3) {
            "type_ByteArray__BYTE_ARRAY_TYPE"
        } else {
            "type_TrustedByteArray__TRUSTED_BYTE_ARRAY_TYPE"
        };
        source_position(&self.byte_array(pid, table, kind)?, offset)
    }
    fn byte_array(&self, pid: u32, value: u64, kind: &str) -> Result<Vec<u8>> {
        if self.kind(pid, value)? != self.get(kind)? {
            return Err("invalid V8 byte array".into());
        }
        let base = self.object(value)?;
        let length = self.smi(word(pid, add(base, 8)?)?)?;
        if !(1..=65536).contains(&length) {
            return Err("V8 byte array exceeds capture limit".into());
        }
        let mut data = Vec::new();
        for offset in (0..length as usize).step_by(4096) {
            data.extend(memory::read(
                pid,
                add(base, 16 + offset as i32)?,
                (length as usize - offset).min(4096),
                false,
            )?);
        }
        Ok(data)
    }
    fn fixed_element(&self, pid: u32, array: u64, index: i32, kind: &str) -> Result<u64> {
        if self.kind(pid, array)? != self.get(kind)? {
            return Err("invalid V8 fixed array".into());
        }
        let base = self.object(array)?;
        let length = self.smi(word(pid, add(base, 8)?)?)?;
        if index < 0 || index as i64 >= length || length > 65536 {
            return Err("V8 fixed array index exceeds capture limit".into());
        }
        word(pid, add(base, 16 + index * 8)?)
    }
    fn code_bounds(&self, pid: u32, code: u64) -> Result<(u64, u64)> {
        if self.kind(pid, code)? != self.get("type_Code__CODE_TYPE")? {
            return Err("not V8 Code".into());
        }
        let base = self.object(code)?;
        let (start, offset) = if self.version == (11, 3) {
            // V8 11.3 CODE_DATA_FIELDS: position, stream, entrypoint,
            // flags(4), builtinID(2), specificFlags(2), instruction_size.
            let position = self.get("class_Code__source_position_table__ByteArray")?;
            (
                word(
                    pid,
                    add(
                        base,
                        position.checked_add(16).ok_or("V8 code offset overflow")?,
                    )?,
                )?,
                position.checked_add(32).ok_or("V8 code offset overflow")?,
            )
        } else {
            let entry = self.get("class_Code__instruction_start__Address")?;
            let extra = if self.version == (13, 6) { 12 } else { 8 };
            if self.get("class_Code__flags__uint32_t")?
                != entry.checked_add(extra).ok_or("V8 code offset overflow")?
            {
                return Err("unsupported sandboxed Code entrypoint".into());
            }
            (
                word(pid, add(base, entry)?)?,
                self.get("class_Code__instruction_size__int")?,
            )
        };
        let size = u32::from_ne_bytes(
            memory::read(pid, add(base, offset)?, 4, false)?
                .try_into()
                .unwrap(),
        ) as u64;
        if size == 0 || size > 64 * 1024 * 1024 {
            return Err("invalid V8 code size".into());
        }
        Ok((
            start,
            start.checked_add(size).ok_or("V8 code range overflow")?,
        ))
    }
    fn code_for_pc(&self, pid: u32, pc: u64) -> Result<u64> {
        if let Ok(cache) = self.code_cache.lock() {
            for &(start, end, code) in cache.iter() {
                if start <= pc && pc < end && self.code_bounds(pid, code).ok() == Some((start, end))
                {
                    return Ok(code);
                }
            }
        }
        // Leaptiering removes JSFunction.code in V8 13.6. Read bounded code
        // pages backward for an InstructionStream header, and require both
        // its Code back-pointer and Code's reverse pointer/range to agree.
        let stream_kind = self.get("type_InstructionStream__INSTRUCTION_STREAM_TYPE")?;
        let lower = pc.saturating_sub(65536) & !4095;
        let mut page = pc & !4095;
        loop {
            if let Ok(bytes) = memory::read(pid, page, 4096, true) {
                for offset in (0..bytes.len().saturating_sub(7)).step_by(8).rev() {
                    let address = page + offset as u64;
                    if address > pc {
                        continue;
                    }
                    let map = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
                    if map < 65536 || map >> 56 != 0 || map & 7 != 1 {
                        continue;
                    }
                    let candidate = address + 1;
                    if self.kind(pid, candidate).ok() != Some(stream_kind) {
                        continue;
                    }
                    let Ok(code) = word(pid, address + 8) else {
                        continue;
                    };
                    let Ok((start, end)) = self.code_bounds(pid, code) else {
                        continue;
                    };
                    if !(start <= pc && pc < end)
                        || self
                            .field(
                                pid,
                                code,
                                "class_Code__instruction_stream__Tagged_InstructionStream_",
                            )
                            .ok()
                            != Some(candidate)
                    {
                        continue;
                    }
                    if let Ok(mut cache) = self.code_cache.lock() {
                        if cache.len() >= 256 {
                            cache.clear();
                        }
                        cache.push((start, end, code));
                    }
                    return Ok(code);
                }
            }
            if page <= lower {
                break;
            }
            page = page.saturating_sub(4096);
        }
        Err("V8 instruction header unavailable within64KiB of sampled PC".into())
    }
    fn optimized_frames(
        &self,
        pid: u32,
        function: u64,
        pc: u64,
        is_return: bool,
    ) -> Result<String> {
        if !matches!(self.version, (11, 3) | (12, 4) | (13, 6)) || self.get("TaggedSize")? != 8 {
            return Err("unsupported optimized V8 layout".into());
        }
        let function_kind = self.kind(pid, function)?;
        if function_kind < self.get("FirstJSFunctionType")?
            || function_kind > self.get("LastJSFunctionType")?
        {
            return Err("not a JavaScript function".into());
        }
        let code = match self.version {
            (11, 3) => self.tagged(
                pid,
                add(
                    self.object(function)?,
                    self.get("class_JSFunction__shared__SharedFunctionInfo")?
                        .checked_add(24)
                        .ok_or("V8 function offset overflow")?,
                )?,
                function,
            )?,
            (13, 6) => self.code_for_pc(pid, pc)?,
            _ => self.field(pid, function, "class_JSFunction__code__Tagged_Code_")?,
        };
        let (start, end) = self.code_bounds(pid, code)?;
        if pc < start || pc >= end {
            return Err("PC is outside current V8 function code".into());
        }
        let offset = (pc - start).saturating_sub(u64::from(is_return));
        let (table, deopt) = if self.version == (11, 3) {
            (
                self.field(pid, code, "class_Code__source_position_table__ByteArray")?,
                self.field(pid, code, "class_Code__deoptimization_data__FixedArray")?,
            )
        } else {
            let wrapper = self.get("class_Code__wrapper__Tagged_CodeWrapper_")?;
            if !(16..=65536).contains(&wrapper) {
                return Err("invalid V8 code wrapper offset".into());
            }
            (
                word(pid, add(self.object(code)?, wrapper - 8)?)?,
                word(pid, add(self.object(code)?, wrapper - 16)?)?,
            )
        };
        let byte_kind = if self.version == (11, 3) {
            "type_ByteArray__BYTE_ARRAY_TYPE"
        } else {
            "type_TrustedByteArray__TRUSTED_BYTE_ARRAY_TYPE"
        };
        let deopt_kind = match self.version {
            (11, 3) => "type_FixedArray__FIXED_ARRAY_TYPE",
            (13, 6) => "type_ProtectedFixedArray__PROTECTED_FIXED_ARRAY_TYPE",
            _ => "type_TrustedFixedArray__TRUSTED_FIXED_ARRAY_TYPE",
        };
        let inline_kind = if self.version == (13, 6) {
            "type_TrustedByteArray__TRUSTED_BYTE_ARRAY_TYPE"
        } else {
            "type_ByteArray__BYTE_ARRAY_TYPE"
        };
        let literal_kind = if self.version == (13, 6) {
            "type_TrustedWeakFixedArray__TRUSTED_WEAK_FIXED_ARRAY_TYPE"
        } else {
            "type_WeakFixedArray__WEAK_FIXED_ARRAY_TYPE"
        };
        let raw = source_position_raw(&self.byte_array(pid, table, byte_kind)?, offset as i64)?;
        let mut raw = raw;
        let shared = self.field(
            pid,
            function,
            "class_JSFunction__shared__SharedFunctionInfo",
        )?;
        let mut output = String::new();
        let mut seen = BTreeSet::new();
        for _ in 0..64 {
            if raw < 0 || raw & 1 != 0 {
                return Err("V8 position is external or invalid".into());
            }
            let source = ((raw >> 1) & 0x3fff_ffff) - 1;
            if source < 0 {
                return Err("unknown V8 script position".into());
            }
            let inline = ((raw >> 31) & 0xffff) - 1;
            if inline < 0 {
                output.push_str(&self.shared_frame(pid, shared, Some(source), "current")?);
                return Ok(output);
            }
            if !seen.insert(inline) {
                return Err("cyclic V8 inline position".into());
            }
            let positions = self.fixed_element(
                pid,
                deopt,
                self.get("DeoptimizationDataInliningPositionsIndex")?,
                deopt_kind,
            )?;
            let data = self.byte_array(pid, positions, inline_kind)?;
            let slot = (inline as usize)
                .checked_mul(16)
                .ok_or("V8 inline position overflow")?;
            let entry = data
                .get(slot..slot + 16)
                .ok_or("V8 inline position exceeds table")?;
            let parent = i64::from_ne_bytes(entry[..8].try_into().unwrap());
            let literal = i32::from_ne_bytes(entry[8..12].try_into().unwrap());
            let literals = self.fixed_element(
                pid,
                deopt,
                self.get("DeoptimizationDataLiteralArrayIndex")?,
                deopt_kind,
            )?;
            // DeoptimizationLiteralArray stores weak references to SFIs.
            let inner = self.fixed_element(pid, literals, literal, literal_kind)? & !2;
            output.push_str(&self.shared_frame(pid, inner, Some(source), "current; inlined")?);
            raw = parent;
        }
        Err("V8 inline depth exceeds64".into())
    }
    fn frame(&self, pid: u32, function: u64, current: Option<i64>) -> Result<String> {
        let kind = self.kind(pid, function)?;
        if kind < self.get("FirstJSFunctionType")? || kind > self.get("LastJSFunctionType")? {
            return Err("not a JavaScript function".into());
        }
        let shared = self.field(
            pid,
            function,
            "class_JSFunction__shared__SharedFunctionInfo",
        )?;
        self.shared_frame(pid, shared, current, "current")
    }
    fn shared_frame(
        &self,
        pid: u32,
        shared: u64,
        current: Option<i64>,
        label: &str,
    ) -> Result<String> {
        if self.kind(pid, shared)?
            != self.get("type_SharedFunctionInfo__SHARED_FUNCTION_INFO_TYPE")?
        {
            return Err("not a V8 shared function".into());
        }
        let (name, position) = self.name(pid, shared)?;
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
            })
            .or_else(|_| {
                self.field(
                    pid,
                    shared,
                    "class_SharedFunctionInfo__script_or_debug_info__HeapObject",
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
        let location = current
            .or(position)
            .and_then(|position| self.source_line(pid, script, position).ok())
            .map(|line| {
                if current.is_some() {
                    format!(" [line {line}; {label}]")
                } else {
                    format!(" [line {line}; function start]")
                }
            })
            .unwrap_or_default();
        Ok(format!(
            "    {} ({}){location}\n",
            name.replace(['\n', '\r', '\0'], "?"),
            file.replace(['\n', '\r', '\0'], "?")
        ))
    }
}
fn source_position(bytes: &[u8], target: i64) -> Result<i64> {
    let raw = source_position_raw(bytes, target)?;
    if raw & 1 != 0 || raw >> 31 != 0 {
        return Err("V8 bytecode position is external or inlined".into());
    }
    let source = ((raw >> 1) & 0x3fff_ffff) - 1;
    if source < 0 {
        return Err("unknown V8 script position".into());
    }
    Ok(source)
}
fn source_position_raw(bytes: &[u8], target: i64) -> Result<i64> {
    fn decode(bytes: &[u8], index: &mut usize) -> Result<i64> {
        let mut value = 0u64;
        for shift in (0..63).step_by(7) {
            let byte = *bytes.get(*index).ok_or("truncated V8 source position")?;
            *index += 1;
            value |= (byte as u64 & 127) << shift;
            if byte & 128 == 0 {
                return Ok(((value >> 1) as i64) ^ -((value & 1) as i64));
            }
        }
        Err("V8 source-position varint overflow".into())
    }
    let (mut index, mut offset, mut position) = (0, 0i64, 0i64);
    let mut found = None;
    while index < bytes.len() {
        let code = decode(bytes, &mut index)?;
        let delta = if code < 0 { -(code + 1) } else { code };
        offset = offset
            .checked_add(delta)
            .ok_or("V8 bytecode offset overflow")?;
        position = position
            .checked_add(decode(bytes, &mut index)?)
            .ok_or("V8 source offset overflow")?;
        if offset > target {
            break;
        }
        if position < 0 {
            return Err("negative V8 source position".into());
        }
        found = Some(position);
    }
    found.ok_or_else(|| "no current JavaScript source position".into())
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
        let Ok(image) = crate::elf_image::Image::new(file) else {
            continue;
        };
        let Ok(elf) = image.parse() else {
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
                    .wrapping_sub(segment.address().wrapping_add(map.offset - offset))
            })
        }) else {
            continue;
        };
        let mut values = BTreeMap::new();
        let mut version = (0, 0);
        let mut interpreter_ranges = Vec::new();
        for symbol in elf
            .symbols()
            .chain(elf.dynamic_symbols())
            .filter(|s| !s.is_undefined())
        {
            let name = symbol.name().unwrap_or("");
            if matches!(
                name,
                "Builtins_InterpreterEntryTrampoline"
                    | "Builtins_InterpreterEntryTrampolineForProfiling"
                    | "Builtins_InterpreterEnterAtBytecode"
                    | "Builtins_InterpreterEnterAtNextBytecode"
            ) && symbol.size() > 0
            {
                let start = bias.wrapping_add(symbol.address());
                if let Some(end) = start.checked_add(symbol.size()) {
                    interpreter_ranges.push((start, end));
                }
            }
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
        image.check()?;
        if values.contains_key("HeapObjectTag") {
            let layout = Layout {
                values,
                version,
                interpreter_ranges,
                code_cache: Default::default(),
            };
            if ![4, 8].contains(&layout.get("TaggedSize")?) || layout.get("SystemPointerSize")? != 8
            {
                return Err("unsupported V8 pointer size".into());
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
        let mut pc = regs.ip;
        let mut is_return = false;
        let mut output = String::new();
        for _ in 0..512 {
            if fp == 0 || fp & 7 != 0 {
                break;
            }
            let function = stack_word(add(fp, layout.get("off_fp_function")?)?);
            if let Ok(function) = function {
                let frame = layout
                    .optimized_frames(pid, function, pc, is_return)
                    .or_else(|_| {
                        let current = layout.current_position(pid, fp, pc, &stack_word).ok();
                        layout.frame(pid, function, current)
                    });
                if let Ok(frame) = frame {
                    let remaining = depth.min(127).saturating_sub(output.lines().count());
                    for line in frame.lines().take(remaining) {
                        output.push_str(line);
                        output.push('\n');
                    }
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
            pc = stack_word(add(fp, 8)?).unwrap_or(0);
            fp = next;
            is_return = true;
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
            interpreter_ranges: Vec::new(),
            code_cache: Default::default(),
            values: [
                ("TaggedSize", 8),
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
                ("SlicedStringTag", 3),
                ("class_SlicedString__parent__String", 16),
                ("class_SlicedString__offset__SMI", 24),
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
    fn bytecode_source_positions_validate_varints_and_deltas() {
        let bytes = [0, 24, 4, 20, 5, 11];
        assert_eq!(source_position(&bytes, 0).unwrap(), 5);
        assert_eq!(source_position(&bytes, 1).unwrap(), 5);
        assert_eq!(source_position(&bytes, 2).unwrap(), 10);
        assert_eq!(source_position(&bytes, 4).unwrap(), 7);
        assert!(source_position(&[0], 0).is_err());
        assert!(source_position(&[255; 16], 0).is_err());
        assert!(source_position(&[], 0).is_err());
    }
    #[test]
    fn compressed_heap_fields_and_signed_smis() {
        let pid = std::process::id();
        let mut layout = layout();
        layout.values.insert("TaggedSize".into(), 4);
        layout.values.insert("SmiShiftSize".into(), 0);
        layout
            .values
            .insert("class_Map__instance_type__uint16_t".into(), 4);
        layout
            .values
            .insert("class_String__length__int32_t".into(), 8);
        // Keep map and object in one allocation, so they share their compression cage.
        let mut storage = [0u64; 16];
        let map = storage.as_ptr() as u64;
        let object = map + 32;
        storage[0] = 8u64 << 32;
        storage[4] = (map as u32 + 1) as u64;
        storage[5] = 3;
        storage[6] = u64::from_ne_bytes(*b"abc\0\0\0\0\0");
        std::hint::black_box(&storage);
        assert_eq!(layout.string(pid, object + 1, &mut 32).unwrap(), "abc");
        assert_eq!(layout.smi((-123i32 << 1) as u32 as u64).unwrap(), -123);
    }
    #[test]
    fn sliced_strings_use_utf16_offsets() {
        let pid = std::process::id();
        let layout = layout();
        let map = [0u64, 0];
        let sliced_map = [0u64, 3];
        let mut parent = Text {
            map: map.as_ptr() as u64 + 1,
            length: 4,
            bytes: [0; 16],
        };
        for (i, unit) in "A😀B".encode_utf16().enumerate() {
            parent.bytes[i * 2..i * 2 + 2].copy_from_slice(&unit.to_ne_bytes());
        }
        let slice = [
            sliced_map.as_ptr() as u64 + 1,
            2,
            &parent as *const _ as u64 + 1,
            1u64 << 32,
        ];
        std::hint::black_box((&parent, &slice));
        assert_eq!(
            layout
                .string(pid, slice.as_ptr() as u64 + 1, &mut 32)
                .unwrap(),
            "😀"
        );
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
