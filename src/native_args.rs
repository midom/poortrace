//! Argument locations described by DWARF, without guessing a managed-language ABI.
use crate::{
    Result,
    types::{self, R},
};
use addr2line::gimli::{self, AttributeValue, Reader as _, UnwindSection};
use object::{Object, ObjectSection, ObjectSegment};
use std::{io::Read, os::unix::fs::MetadataExt};
#[derive(Default)]
pub struct Reader {
    image: Option<(String, Image)>,
}
struct Image {
    sections: gimli::DwarfSections<Vec<u8>>,
    endian: gimli::RunTimeEndian,
    segments: Vec<(u64, u64, u64)>,
    eh_frame: Vec<u8>,
    bases: gimli::BaseAddresses,
}
impl Reader {
    pub fn format(&mut self, pid: u32, tid: u32, path: &str, function: &str) -> Result<String> {
        let target = if path.starts_with('/') {
            format!("/proc/{pid}/root{path}")
        } else if path.is_empty() {
            format!("/proc/{pid}/exe")
        } else {
            path.to_owned()
        };
        let meta = std::fs::metadata(&target).map_err(|e| e.to_string())?;
        let identity = format!(
            "{pid}:{target}:{}:{}:{}:{}",
            meta.dev(),
            meta.ino(),
            meta.mtime(),
            meta.mtime_nsec()
        );
        if self.image.as_ref().is_none_or(|(key, _)| *key != identity) {
            self.image = Some((identity, Image::load(&target)?));
        }
        let image = &self.image.as_ref().unwrap().1;
        let regs = crate::functions::user_registers(tid as i32)?;
        let mappings =
            std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
        let mapping = mappings
            .lines()
            .filter_map(crate::symbols::Mapping::parse)
            .find(|map| {
                map.start <= regs.ip
                    && regs.ip < map.end
                    && map.inode == meta.ino()
                    && map.device == meta.dev()
            })
            .ok_or("stopped PC is outside the selected DWARF image")?;
        let (offset, _, address) = image
            .segments
            .iter()
            .find(|(offset, size, _)| {
                mapping.offset >= (*offset & !4095) && mapping.offset < offset.saturating_add(*size)
            })
            .ok_or("PC mapping has no matching ELF segment")?;
        let linked = (regs.ip - mapping.start) as i128 + mapping.offset as i128 - *offset as i128
            + *address as i128;
        let pc = u64::try_from(linked).map_err(|_| "DWARF linked PC overflow")?;
        let bias = regs.ip as i128 - pc as i128;
        let dwarf = image
            .sections
            .borrow(|section| gimli::EndianSlice::new(section, image.endian));
        let function = function
            .rsplit_once('+')
            .filter(|(_, offset)| {
                offset.starts_with("0x") || offset.bytes().all(|c| c.is_ascii_digit())
            })
            .map_or(function, |(name, _)| name);
        let mut units = dwarf.units();
        let mut visited = 0;
        while let Some(header) = units.next().map_err(|e| e.to_string())? {
            let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().map_err(|e| e.to_string())? {
                visited += 1;
                if visited > 1_000_000 {
                    return Err("DWARF entry limit exceeded".into());
                }
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let mut matches = false;
                for name in [gimli::DW_AT_linkage_name, gimli::DW_AT_name] {
                    if let Some(value) = attribute(&unit, entry.offset(), name, 0)? {
                        matches |= dwarf
                            .attr_string(&unit, value)
                            .map_err(|e| e.to_string())?
                            .to_string_lossy()
                            .as_ref()
                            == function;
                    }
                }
                if !matches {
                    continue;
                }
                let mut ranges = dwarf.die_ranges(&unit, entry).map_err(|e| e.to_string())?;
                let mut begin = u64::MAX;
                let mut contains = false;
                while let Some(range) = ranges.next().map_err(|e| e.to_string())? {
                    begin = begin.min(range.begin);
                    contains |= range.begin <= pc && pc < range.end;
                }
                if !contains {
                    continue;
                }
                let at_entry = pc == begin;
                let cfa = image.cfa(tid, pc).or_else(|| {
                    at_entry
                        .then(|| {
                            regs.sp
                                .checked_add(if cfg!(target_arch = "x86_64") { 8 } else { 0 })
                        })
                        .flatten()
                });
                let frame = attribute(&unit, entry.offset(), gimli::DW_AT_frame_base, 0)?
                    .and_then(|value| expression(&dwarf, &unit, value, pc).ok().flatten())
                    .and_then(|expression| {
                        evaluate(expression, unit.encoding(), tid, None, cfa, bias).ok()
                    })
                    .and_then(|pieces| single_address(&pieces, tid).ok());
                let mut tree = unit
                    .entries_tree(Some(entry.offset()))
                    .map_err(|e| e.to_string())?;
                let root = tree.root().map_err(|e| e.to_string())?;
                let mut children = root.children();
                let mut output = String::new();
                let mut count = 0;
                while let Some(node) = children.next().map_err(|e| e.to_string())? {
                    let parameter = node.entry();
                    if parameter.tag() != gimli::DW_TAG_formal_parameter {
                        continue;
                    }
                    count += 1;
                    if count > 32 {
                        return Err("native DWARF arguments exceed32parameters".into());
                    }
                    let name = attribute(&unit, parameter.offset(), gimli::DW_AT_name, 0)?
                        .map(|value| {
                            dwarf
                                .attr_string(&unit, value)
                                .map(|name| name.to_string_lossy().into_owned())
                                .map_err(|e| e.to_string())
                        })
                        .transpose()?
                        .unwrap_or_else(|| format!("arg{}", count - 1));
                    if name.len() > 256 {
                        return Err("DWARF parameter name exceeds256bytes".into());
                    }
                    let result = (|| -> Result<String> {
                        let reference = attribute(&unit, parameter.offset(), gimli::DW_AT_type, 0)?
                            .ok_or("missing parameter type")?;
                        let layout = types::resolve_reference(&dwarf, &unit, reference, "", 0)?;
                        if layout.size == 0 || layout.size > 4096 {
                            return Err("unsupported argument object size".into());
                        }
                        let location =
                            attribute(&unit, parameter.offset(), gimli::DW_AT_location, 0)?
                                .ok_or("optimized-away or missing location")?;
                        let location = expression(&dwarf, &unit, location, pc)?
                            .ok_or("no location at this PC")?;
                        let pieces = evaluate(location, unit.encoding(), tid, frame, cfa, bias)?;
                        let bytes = read_pieces(&pieces, layout.size as usize, tid, at_entry, cfa)?;
                        if layout.scalar {
                            return crate::arguments::field_text(&bytes, &layout);
                        }
                        let mut fields = Vec::new();
                        types::flatten(&dwarf, &unit, reference, "", 0, &mut fields)?;
                        let mut text = String::from("{");
                        for (n, (name, layout)) in fields.iter().enumerate() {
                            if n > 0 {
                                text.push_str(", ");
                            }
                            text.push_str(name);
                            text.push_str(": ");
                            text.push_str(&crate::arguments::field_text(&bytes, layout)?);
                            if text.len() > 4096 {
                                return Err("formatted argument exceeds4096bytes".into());
                            }
                        }
                        text.push('}');
                        Ok(text)
                    })();
                    if !output.is_empty() {
                        output.push_str(", ");
                    }
                    output.push_str(&name);
                    output.push('=');
                    match result {
                        Ok(text) => output.push_str(&text),
                        Err(error) => {
                            output.push_str("<unavailable: ");
                            output.extend(error.chars().take(256));
                            output.push('>');
                        }
                    }
                    if output.len() > 4096 {
                        return Err("formatted native arguments exceed4096bytes".into());
                    }
                }
                return Ok(output);
            }
        }
        Err("DWARF function/location unavailable at the stopped PC".into())
    }
}
impl Image {
    fn load(path: &str) -> Result<Self> {
        let mut data = Vec::new();
        std::fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > 128 * 1024 * 1024 {
            return Err("DWARF image exceeds128MiB".into());
        }
        let object = object::File::parse(data.as_slice()).map_err(|e| e.to_string())?;
        let segments=object.segments().filter(|segment|matches!(segment.flags(),object::SegmentFlags::Elf{p_flags} if p_flags & object::elf::PF_X!=0)).take(129).map(|segment|{let(offset,size)=segment.file_range();(offset,size,segment.address())}).collect::<Vec<_>>();
        if segments.len() > 128 {
            return Err("ELF segment limit exceeded".into());
        }
        let mut bases = gimli::BaseAddresses::default();
        if let Some(section) = object.section_by_name(".text") {
            bases = bases.set_text(section.address());
        }
        if let Some(section) = object.section_by_name(".got") {
            bases = bases.set_got(section.address());
        }
        let eh_frame = if let Some(section) = object.section_by_name(".eh_frame") {
            if section.size() > 16 * 1024 * 1024 {
                return Err("CFI section exceeds16MiB".into());
            }
            bases = bases.set_eh_frame(section.address());
            section.data().map_err(|e| e.to_string())?.to_vec()
        } else {
            Vec::new()
        };
        let (sections, endian) =
            types::load_dwarf(std::fs::File::open(path).map_err(|e| e.to_string())?)?;
        Ok(Self {
            sections,
            endian,
            segments,
            eh_frame,
            bases,
        })
    }
    fn cfa(&self, tid: u32, pc: u64) -> Option<u64> {
        let eh = gimli::EhFrame::new(&self.eh_frame, self.endian);
        let mut context = gimli::UnwindContext::new();
        let row = eh
            .unwind_info_for_address(
                &self.bases,
                &mut context,
                pc,
                gimli::EhFrame::cie_from_offset,
            )
            .ok()?;
        if let gimli::CfaRule::RegisterAndOffset { register, offset } = row.cfa() {
            crate::functions::dwarf_register(tid as i32, register.0)
                .ok()?
                .checked_add_signed(*offset)
        } else {
            None
        }
    }
}
fn attribute<'a>(
    unit: &gimli::Unit<R<'a>>,
    offset: gimli::UnitOffset,
    name: gimli::DwAt,
    depth: u32,
) -> Result<Option<AttributeValue<R<'a>>>> {
    if depth >= 8 {
        return Err("DWARF abstract origin limit exceeded".into());
    }
    let entry = unit.entry(offset).map_err(|e| e.to_string())?;
    if let Some(value) = entry.attr_value(name).map_err(|e| e.to_string())? {
        return Ok(Some(value));
    }
    for origin in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
        if let Some(AttributeValue::UnitRef(offset)) =
            entry.attr_value(origin).map_err(|e| e.to_string())?
        {
            if let Some(value) = attribute(unit, offset, name, depth + 1)? {
                return Ok(Some(value));
            }
        }
    }
    Ok(None)
}
fn expression<'a>(
    dwarf: &gimli::Dwarf<R<'a>>,
    unit: &gimli::Unit<R<'a>>,
    value: AttributeValue<R<'a>>,
    pc: u64,
) -> Result<Option<gimli::Expression<R<'a>>>> {
    if let AttributeValue::Exprloc(expression) = value {
        return Ok(Some(expression));
    }
    if let Some(mut locations) = dwarf
        .attr_locations(unit, value)
        .map_err(|e| e.to_string())?
    {
        let mut count = 0;
        while let Some(location) = locations.next().map_err(|e| e.to_string())? {
            count += 1;
            if count > 65536 {
                return Err("DWARF location-list limit exceeded".into());
            }
            if location.range.begin <= pc && pc < location.range.end {
                return Ok(Some(location.data));
            }
        }
    }
    Ok(None)
}
fn evaluate<'a>(
    expression: gimli::Expression<R<'a>>,
    encoding: gimli::Encoding,
    tid: u32,
    frame: Option<u64>,
    cfa: Option<u64>,
    bias: i128,
) -> Result<Vec<gimli::Piece<R<'a>>>> {
    if expression.0.len() > 4096 {
        return Err("DWARF expression exceeds4096bytes".into());
    }
    let mut evaluation = expression.evaluation(encoding);
    evaluation.set_max_iterations(256);
    let mut state = evaluation.evaluate().map_err(|e| e.to_string())?;
    for _ in 0..256 {
        state = match state {
            gimli::EvaluationResult::Complete => {
                let pieces = evaluation.result();
                if pieces.len() > 128 {
                    return Err("DWARF piece limit exceeded".into());
                }
                return Ok(pieces);
            }
            gimli::EvaluationResult::RequiresRegister {
                register,
                base_type,
            } if base_type.0 == 0 => evaluation.resume_with_register(gimli::Value::Generic(
                crate::functions::dwarf_register(tid as i32, register.0)?,
            )),
            gimli::EvaluationResult::RequiresMemory {
                address,
                size,
                space,
                base_type,
            } if space.is_none() && base_type.0 == 0 && (1..=8).contains(&size) => {
                let bytes = crate::memory::read(tid, address, size as usize, false)?;
                let mut raw = [0; 8];
                raw[..bytes.len()].copy_from_slice(&bytes);
                evaluation.resume_with_memory(gimli::Value::Generic(u64::from_ne_bytes(raw)))
            }
            gimli::EvaluationResult::RequiresFrameBase => {
                evaluation.resume_with_frame_base(frame.ok_or("frame base unavailable")?)
            }
            gimli::EvaluationResult::RequiresCallFrameCfa => {
                evaluation.resume_with_call_frame_cfa(cfa.ok_or("CFA unavailable")?)
            }
            gimli::EvaluationResult::RequiresRelocatedAddress(address) => evaluation
                .resume_with_relocated_address(
                    u64::try_from(address as i128 + bias)
                        .map_err(|_| "relocated address overflow")?,
                ),
            _ => return Err("unsupported DWARF location operation or entry value".into()),
        }
        .map_err(|e| e.to_string())?;
    }
    Err("DWARF location evaluation budget exceeded".into())
}
fn value_bits(value: gimli::Value) -> Result<u64> {
    match value {
        gimli::Value::F32(value) => Ok(value.to_bits() as u64),
        gimli::Value::F64(value) => Ok(value.to_bits()),
        _ => value.to_u64(u64::MAX).map_err(|e| e.to_string()),
    }
}
fn single_address(pieces: &[gimli::Piece<R<'_>>], tid: u32) -> Result<u64> {
    if pieces.len() != 1 {
        return Err("frame base requires one location".into());
    }
    match pieces[0].location {
        gimli::Location::Address { address } => Ok(address),
        gimli::Location::Value { value } => value_bits(value),
        gimli::Location::Register { register } => {
            crate::functions::dwarf_register(tid as i32, register.0)
        }
        _ => Err("unsupported frame base location".into()),
    }
}
fn read_pieces(
    pieces: &[gimli::Piece<R<'_>>],
    size: usize,
    tid: u32,
    at_entry: bool,
    cfa: Option<u64>,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for piece in pieces {
        let bits = piece.size_in_bits.unwrap_or((size * 8) as u64);
        let offset = piece.bit_offset.unwrap_or(0);
        if bits % 8 != 0
            || offset % 8 != 0
            || bits > 32768
            || output.len().saturating_add(bits as usize / 8) > size
        {
            return Err("unsupported or oversized DWARF bit piece".into());
        }
        let count = bits as usize / 8;
        let skip = offset as usize / 8;
        let bytes = match piece.location {
            gimli::Location::Register { register } => {
                if skip + count > 8 {
                    return Err("DWARF register piece exceeds64bits".into());
                }
                crate::functions::dwarf_register(tid as i32, register.0)?.to_ne_bytes()
                    [skip..skip + count]
                    .to_vec()
            }
            gimli::Location::Address { address } => {
                if at_entry && cfa.is_some_and(|cfa| address < cfa) {
                    return Err(
                        "prologue spill unavailable at function entry; attach after the prologue"
                            .into(),
                    );
                }
                crate::memory::read(
                    tid,
                    address
                        .checked_add(skip as u64)
                        .ok_or("piece address overflow")?,
                    count,
                    false,
                )?
            }
            gimli::Location::Value { value } => {
                if skip + count > 8 {
                    return Err("DWARF immediate piece exceeds64bits".into());
                }
                value_bits(value)?.to_ne_bytes()[skip..skip + count].to_vec()
            }
            gimli::Location::Bytes { value } => value
                .to_slice()
                .map_err(|e| e.to_string())?
                .get(skip..skip + count)
                .ok_or("DWARF bytes piece truncated")?
                .to_vec(),
            _ => return Err("optimized-away or implicit argument location".into()),
        };
        output.extend(bytes);
    }
    if output.len() != size {
        return Err("DWARF argument pieces are incomplete".into());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expression(bytes: &[u8]) -> gimli::Expression<R<'_>> {
        gimli::Expression(gimli::EndianSlice::new(bytes, gimli::RunTimeEndian::Little))
    }
    fn encoding() -> gimli::Encoding {
        gimli::Encoding {
            address_size: 8,
            format: gimli::Format::Dwarf32,
            version: 5,
        }
    }
    #[test]
    fn native_location_values_pieces_memory_and_budgets_are_bounded() {
        let bytes = [
            gimli::DW_OP_constu.0,
            17,
            gimli::DW_OP_stack_value.0,
            gimli::DW_OP_piece.0,
            1,
            gimli::DW_OP_constu.0,
            34,
            gimli::DW_OP_stack_value.0,
            gimli::DW_OP_piece.0,
            1,
        ];
        let pieces = evaluate(
            expression(&bytes),
            encoding(),
            std::process::id(),
            None,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            read_pieces(&pieces, 2, std::process::id(), false, None).unwrap(),
            vec![17, 34]
        );
        assert!(read_pieces(&pieces, 1, std::process::id(), false, None).is_err());
        let value = 42u64;
        let mut bytes = vec![gimli::DW_OP_addr.0];
        bytes.extend_from_slice(&(&value as *const u64 as u64).to_le_bytes());
        let pieces = evaluate(
            expression(&bytes),
            encoding(),
            std::process::id(),
            None,
            None,
            0,
        )
        .unwrap();
        assert_eq!(
            read_pieces(&pieces, 8, std::process::id(), false, None).unwrap(),
            42u64.to_ne_bytes()
        );
        let loop_expression = [gimli::DW_OP_skip.0, 0xfd, 0xff];
        assert!(evaluate(expression(&loop_expression), encoding(), 0, None, None, 0).is_err());
        let frame = [gimli::DW_OP_fbreg.0, 0];
        assert!(evaluate(expression(&frame), encoding(), 0, None, None, 0).is_err());
        for size in [0, 9, 16, 255] {
            let mut oversized = vec![gimli::DW_OP_addr.0];
            oversized.extend_from_slice(&(&value as *const u64 as u64).to_le_bytes());
            oversized.extend([gimli::DW_OP_deref_size.0, size]);
            assert!(
                evaluate(
                    expression(&oversized),
                    encoding(),
                    std::process::id(),
                    None,
                    None,
                    0
                )
                .is_err()
            );
        }
    }
}
