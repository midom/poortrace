//! Bounded DWARF scalar/structure layout reads; unsupported location expressions fail explicitly.
use crate::Result;
use addr2line::gimli::{self, AttributeValue, EndianSlice, RunTimeEndian, UnitOffset};
use object::{Object, ObjectSection};
use std::{collections::BTreeMap, io::Read, os::unix::fs::MetadataExt};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub offset: u64,
    pub size: u64,
    pub signed: bool,
    pub float: bool,
    pub scalar: bool,
    pub pointer: bool,
    pub vector: bool,
    pub vector_size: u64,
    pub vector_offset: u64,
    pub by_reference: bool,
    pub alignment: u64,
    pub members: Vec<String>,
    pub dereferences: Vec<u64>,
    pub bits: Option<(u32, u32)>,
}
#[derive(Default)]
pub struct Reader {
    signatures: BTreeMap<(u32, String, String), Vec<Parameter>>,
    cache: BTreeMap<(u32, String, String, String), Layout>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub hidden: bool,
    pub name: String,
    pub layout: Layout,
    pub fields: Vec<(String, Layout)>,
}
impl Reader {
    pub fn signature(&mut self, pid: u32, path: &str, function: &str) -> Result<Vec<Parameter>> {
        let path = if path.is_empty() {
            format!("/proc/{pid}/exe")
        } else if path.starts_with('/') {
            format!("/proc/{pid}/root{path}")
        } else {
            path.into()
        };
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        let key = (
            pid,
            format!(
                "{path}@{}:{}:{}:{}",
                meta.dev(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec()
            ),
            function.to_owned(),
        );
        if let Some(parameters) = self.signatures.get(&key) {
            return Ok(parameters.clone());
        }
        let (sections, endian) = load_dwarf(file)?;
        let dwarf = sections.borrow(|bytes| EndianSlice::new(bytes, endian));
        let mut headers = dwarf.units();
        let mut visited = 0;
        let mut result = None;
        while let Some(header) = headers.next().map_err(|e| e.to_string())? {
            let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
            let mut roots = unit.entries();
            let language = match roots.next_dfs().map_err(|e| e.to_string())? {
                Some((_, root)) => root
                    .attr_value(gimli::DW_AT_language)
                    .map_err(|e| e.to_string())?,
                None => None,
            };
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
                for attribute in [gimli::DW_AT_linkage_name, gimli::DW_AT_name] {
                    if let Some(value) = entry.attr_value(attribute).map_err(|e| e.to_string())? {
                        matches |= dwarf
                            .attr_string(&unit, value)
                            .map_err(|e| e.to_string())?
                            .to_string_lossy()
                            .as_ref()
                            == function;
                    }
                }
                if !matches
                    || entry
                        .attr_value(gimli::DW_AT_declaration)
                        .map_err(|e| e.to_string())?
                        == Some(AttributeValue::Flag(true))
                {
                    continue;
                }
                validate_c_language(language)?;
                validate_calling_convention(
                    entry
                        .attr_value(gimli::DW_AT_calling_convention)
                        .map_err(|e| e.to_string())?,
                )?;
                let mut tree = unit
                    .entries_tree(Some(entry.offset()))
                    .map_err(|e| e.to_string())?;
                let root = tree.root().map_err(|e| e.to_string())?;
                let mut children = root.children();
                let mut parameters = Vec::new();
                while let Some(node) = children.next().map_err(|e| e.to_string())? {
                    let child = node.entry();
                    if child.tag() == gimli::DW_TAG_unspecified_parameters {
                        return Err("automatic arguments require a nonvariadic function".into());
                    }
                    if child.tag() != gimli::DW_TAG_formal_parameter {
                        continue;
                    }
                    if parameters.len() >= 32 {
                        return Err("function argument limit (32) exceeded".into());
                    }
                    let name = if let Some(value) = child
                        .attr_value(gimli::DW_AT_name)
                        .map_err(|e| e.to_string())?
                    {
                        dwarf
                            .attr_string(&unit, value)
                            .map_err(|e| e.to_string())?
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        format!("arg{}", parameters.len())
                    };
                    if name.len() > 256 {
                        return Err("DWARF parameter name exceeds 256 bytes".into());
                    }
                    let reference = child
                        .attr_value(gimli::DW_AT_type)
                        .map_err(|e| e.to_string())?
                        .ok_or("missing DWARF parameter type")?;
                    let layout = resolve_reference(&dwarf, &unit, reference, "", 0)?;
                    let mut fields = Vec::new();
                    flatten(&dwarf, &unit, reference, "", 0, &mut fields)?;
                    parameters.push(Parameter {
                        hidden: false,
                        name,
                        layout,
                        fields,
                    });
                }
                if cfg!(target_arch = "x86_64") {
                    if let Some(reference) = entry
                        .attr_value(gimli::DW_AT_type)
                        .map_err(|e| e.to_string())?
                    {
                        let layout = resolve_reference(&dwarf, &unit, reference, "", 0)?;
                        let mut fields = Vec::new();
                        if !layout.scalar {
                            flatten(&dwarf, &unit, reference, "", 0, &mut fields)?;
                        }
                        let memory = layout.by_reference
                            || !layout.scalar
                                && !layout.vector
                                && (layout.size > 16
                                    || fields.iter().any(|(_, field)| {
                                        field.bits.is_none()
                                            && field.offset % field.alignment.max(1) != 0
                                    }));
                        if memory {
                            let pointer = Layout {
                                offset: 0,
                                size: 8,
                                signed: false,
                                float: false,
                                scalar: true,
                                pointer: true,
                                vector: false,
                                vector_size: 0,
                                vector_offset: 0,
                                by_reference: false,
                                alignment: 8,
                                members: Vec::new(),
                                dereferences: Vec::new(),
                                bits: None,
                            };
                            parameters.insert(
                                0,
                                Parameter {
                                    hidden: true,
                                    name: "$return".into(),
                                    layout: pointer.clone(),
                                    fields: vec![(String::new(), pointer)],
                                },
                            );
                        }
                    }
                }
                if result.as_ref().is_some_and(|old| old != &parameters) {
                    return Err("ambiguous DWARF function signature".into());
                }
                result = Some(parameters);
            }
        }
        let parameters =
            result.ok_or("DWARF function signature unavailable; provide an unstripped image")?;
        if self.signatures.len() >= 256 {
            self.signatures.clear();
        }
        self.signatures.insert(key, parameters.clone());
        Ok(parameters)
    }
    pub fn layout(&mut self, pid: u32, path: &str, name: &str, field: &str) -> Result<Layout> {
        let path = if path.is_empty() {
            format!("/proc/{pid}/exe")
        } else if path.starts_with('/') {
            format!("/proc/{pid}/root{path}")
        } else {
            path.into()
        };
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        let key = (
            pid,
            format!(
                "{path}@{}:{}:{}:{}",
                meta.dev(),
                meta.ino(),
                meta.mtime(),
                meta.mtime_nsec()
            ),
            name.into(),
            field.into(),
        );
        if let Some(layout) = self.cache.get(&key) {
            return Ok(layout.clone());
        }
        let (sections, endian) = load_dwarf(file)?;
        let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
        let mut headers = dwarf.units();
        let mut result = None;
        let mut visited = 0;
        while let Some(header) = headers.next().map_err(|e| e.to_string())? {
            let unit = dwarf.unit(header).map_err(|e| e.to_string())?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs().map_err(|e| e.to_string())? {
                visited += 1;
                if visited > 1_000_000 {
                    return Err("DWARF entry limit exceeded".into());
                }
                if !matches!(
                    entry.tag(),
                    gimli::DW_TAG_structure_type
                        | gimli::DW_TAG_union_type
                        | gimli::DW_TAG_class_type
                        | gimli::DW_TAG_typedef
                        | gimli::DW_TAG_base_type
                        | gimli::DW_TAG_enumeration_type
                ) {
                    continue;
                }
                let Some(value) = entry
                    .attr_value(gimli::DW_AT_name)
                    .map_err(|e| e.to_string())?
                else {
                    continue;
                };
                let text = dwarf.attr_string(&unit, value).map_err(|e| e.to_string())?;
                if text.to_string_lossy().as_ref() != name {
                    continue;
                }
                let offset = entry.offset();
                let candidate = resolve(&dwarf, &unit, offset, field, 0);
                if let Ok(layout) = candidate {
                    if result.as_ref().is_some_and(|old: &Layout| old != &layout) {
                        return Err("ambiguous DWARF type layout".into());
                    }
                    result = Some(layout);
                }
            }
        }
        let layout=result.ok_or_else(||format!("DWARF layout {name}.{field} unavailable; provide an unstripped image and a supported scalar field"))?;
        if self.cache.len() >= 1024 {
            self.cache.clear();
        }
        self.cache.insert(key, layout.clone());
        Ok(layout)
    }
}
impl Reader {
    /// Render a bounded structure value without following pointer members implicitly.
    pub fn describe(&mut self, pid: u32, path: &str, name: &str, address: u64) -> Result<String> {
        let mut budget = 128;
        self.describe_field(pid, path, name, "", address, 0, &mut budget)
    }
    #[allow(clippy::too_many_arguments)]
    fn describe_field(
        &mut self,
        pid: u32,
        path: &str,
        name: &str,
        field: &str,
        address: u64,
        depth: u32,
        budget: &mut usize,
    ) -> Result<String> {
        if depth >= 8 || *budget == 0 {
            return Err("structured value nesting/member limit exceeded".into());
        }
        *budget -= 1;
        let layout = self.layout(pid, path, name, field)?;
        if layout.scalar {
            let raw = self.scalar(pid, address, &layout)?;
            return Ok(if layout.pointer {
                format!("0x{raw:x}")
            } else if layout.float && layout.size == 4 {
                f32::from_bits(raw as u32).to_string()
            } else if layout.float && layout.size == 8 {
                f64::from_bits(raw).to_string()
            } else if layout.signed {
                (raw as i64).to_string()
            } else {
                raw.to_string()
            });
        }
        if layout.members.is_empty() {
            return Err("structured value requires a structure with named DWARF members".into());
        }
        let mut output = String::from("{");
        for member in layout.members {
            let key = if field.is_empty() {
                member.clone()
            } else {
                format!("{field}.{member}")
            };
            let value = self.describe_field(pid, path, name, &key, address, depth + 1, budget)?;
            if output.len() > 1 {
                output.push_str(", ");
            }
            output.push_str(&member);
            output.push_str(": ");
            output.push_str(&value);
            if output.len() > 4095 {
                return Err("structured value exceeds 4096 bytes".into());
            }
        }
        output.push('}');
        Ok(output)
    }
    pub fn scalar(&self, pid: u32, mut address: u64, layout: &Layout) -> Result<u64> {
        if !layout.scalar || !(1..=8).contains(&layout.size) {
            return Err("value requires a scalar of at most 8 bytes".into());
        }
        for offset in &layout.dereferences {
            let bytes = crate::memory::read(
                pid,
                address
                    .checked_add(*offset)
                    .ok_or("pointer member address overflow")?,
                8,
                false,
            )?;
            address = u64::from_ne_bytes(bytes.try_into().unwrap());
            if address == 0 {
                return Err("null pointer in DWARF field traversal".into());
            }
        }
        let bytes = crate::memory::read(
            pid,
            address
                .checked_add(layout.offset)
                .ok_or("field address overflow")?,
            layout.size as usize,
            false,
        )?;
        let mut raw = [0; 8];
        raw[..bytes.len()].copy_from_slice(&bytes);
        let mut raw = u64::from_ne_bytes(raw);
        let width = if let Some((shift, bits)) = layout.bits {
            raw >>= shift;
            if bits < 64 {
                raw &= (1u64 << bits) - 1;
            }
            bits as u64
        } else {
            layout.size * 8
        };
        if layout.signed && width < 64 {
            raw = ((raw << (64 - width)) as i64 >> (64 - width)) as u64;
        }
        Ok(raw)
    }
}
pub(crate) type R<'a> = EndianSlice<'a, RunTimeEndian>;
fn validate_c_language(language: Option<AttributeValue<R<'_>>>) -> Result<()> {
    match language {
        Some(AttributeValue::Language(gimli::DW_LANG_C89|gimli::DW_LANG_C|gimli::DW_LANG_C99|gimli::DW_LANG_C11|gimli::DW_LANG_C17|gimli::DW_LANG_C_plus_plus|gimli::DW_LANG_C_plus_plus_03|gimli::DW_LANG_C_plus_plus_11|gimli::DW_LANG_C_plus_plus_14|gimli::DW_LANG_C_plus_plus_17|gimli::DW_LANG_C_plus_plus_20)) => Ok(()),
        _=>Err("automatic arguments require a C/C++ DWARF compilation unit; other language ABIs are unsupported".into()),
    }
}
fn validate_calling_convention(convention: Option<AttributeValue<R<'_>>>) -> Result<()> {
    match convention {
        None | Some(AttributeValue::CallingConvention(gimli::DW_CC_normal)) => Ok(()),
        _ => Err("unsupported DWARF function calling convention; automatic arguments require the native C ABI".into()),
    }
}
pub(crate) fn load_dwarf(
    file: std::fs::File,
) -> Result<(gimli::DwarfSections<Vec<u8>>, RunTimeEndian)> {
    let mut data = Vec::new();
    file.take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() > 128 * 1024 * 1024 {
        return Err("DWARF image exceeds 128 MiB".into());
    }
    let object = object::File::parse(data.as_slice()).map_err(|e| e.to_string())?;
    #[cfg(target_arch = "aarch64")]
    let architecture = object::Architecture::Aarch64;
    #[cfg(target_arch = "x86_64")]
    let architecture = object::Architecture::X86_64;
    if !object.is_64()
        || object.architecture() != architecture
        || object.is_little_endian() != cfg!(target_endian = "little")
    {
        return Err("DWARF image does not match the native target architecture".into());
    }
    let endian = if object.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mut section_bytes = 0u64;
    let dwarf = gimli::DwarfSections::load(|section| -> Result<Vec<u8>> {
        match object.section_by_name(section.name()) {
            Some(section) => {
                let size = section
                    .compressed_data()
                    .map_err(|e| e.to_string())?
                    .uncompressed_size;
                section_bytes = section_bytes
                    .checked_add(size)
                    .ok_or("DWARF section size overflow")?;
                if section_bytes > 256 * 1024 * 1024 {
                    return Err("DWARF sections exceed 256 MiB".into());
                }
                section
                    .uncompressed_data()
                    .map(|data| data.into_owned())
                    .map_err(|e| e.to_string())
            }
            None => Ok(Vec::new()),
        }
    })?;
    Ok((dwarf, endian))
}
fn resolve(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    offset: UnitOffset,
    field: &str,
    depth: u32,
) -> Result<Layout> {
    if depth >= 32 {
        return Err("DWARF type nesting limit exceeded".into());
    }
    let field = field.strip_prefix("->").unwrap_or(field);
    let entry = unit.entry(offset).map_err(|e| e.to_string())?;
    if matches!(
        entry.tag(),
        gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type
    ) {
        let reference = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(|e| e.to_string())?
            .ok_or("missing DWARF type reference")?;
        return resolve_reference(dwarf, unit, reference, field, depth + 1);
    }
    if matches!(
        entry.tag(),
        gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
    ) && !field.is_empty()
    {
        let reference = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(|e| e.to_string())?
            .ok_or("missing DWARF pointer type")?;
        let mut layout = resolve_reference(dwarf, unit, reference, field, depth + 1)?;
        layout.dereferences.insert(0, 0);
        return Ok(layout);
    }
    if entry.tag() == gimli::DW_TAG_array_type {
        let reference = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(|e| e.to_string())?
            .ok_or("missing array element type")?;
        let element = resolve_reference(dwarf, unit, reference, "", depth + 1)?;
        let mut count = 1u64;
        let mut dimensions = Vec::new();
        let mut tree = unit.entries_tree(Some(offset)).map_err(|e| e.to_string())?;
        let root = tree.root().map_err(|e| e.to_string())?;
        let mut children = root.children();
        while let Some(node) = children.next().map_err(|e| e.to_string())? {
            if node.entry().tag() != gimli::DW_TAG_subrange_type {
                continue;
            }
            let child = node.entry();
            let lower = child
                .attr_value(gimli::DW_AT_lower_bound)
                .map_err(|e| e.to_string())?
                .and_then(|v| v.udata_value())
                .unwrap_or(0);
            let size = if let Some(value) = child
                .attr_value(gimli::DW_AT_count)
                .map_err(|e| e.to_string())?
                .and_then(|v| v.udata_value())
            {
                value
            } else {
                child
                    .attr_value(gimli::DW_AT_upper_bound)
                    .map_err(|e| e.to_string())?
                    .and_then(|v| v.udata_value())
                    .and_then(|n| n.checked_sub(lower))
                    .and_then(|n| n.checked_add(1))
                    .ok_or("array requires a constant bound")?
            };
            count = count.checked_mul(size).ok_or("array size overflow")?;
            dimensions.push(size);
            if dimensions.len() > 8 || size > 128 || count > 4096 {
                return Err("typed arrays support at most8dimensions,128elements per dimension,and4096elements total".into());
            }
        }
        if dimensions.is_empty() {
            return Err("typed array requires constant dimensions".into());
        }
        let vector = entry
            .attr_value(gimli::DW_AT_GNU_vector)
            .map_err(|e| e.to_string())?
            == Some(AttributeValue::Flag(true));
        let alignment = entry
            .attr_value(gimli::DW_AT_alignment)
            .map_err(|e| e.to_string())?
            .and_then(|v| v.udata_value())
            .unwrap_or(element.alignment);
        return resolve_dimensions(
            dwarf,
            unit,
            reference,
            &dimensions,
            field,
            depth + 1,
            vector,
            alignment,
        );
    }
    if !field.is_empty() {
        let split = field
            .find('.')
            .map(|i| (i, 1))
            .into_iter()
            .chain(field.find("->").map(|i| (i, 2)))
            .chain(field.find('[').filter(|i| *i > 0).map(|i| (i, 0)))
            .min_by_key(|(i, _)| *i);
        let (head, tail) = split.map_or((field, ""), |(i, n)| (&field[..i], &field[i + n..]));
        let mut tree = unit.entries_tree(Some(offset)).map_err(|e| e.to_string())?;
        let root = tree.root().map_err(|e| e.to_string())?;
        let mut children = root.children();
        while let Some(node) = children.next().map_err(|e| e.to_string())? {
            let child = node.entry();
            if child.tag() != gimli::DW_TAG_member {
                continue;
            }
            let Some(name) = child
                .attr_value(gimli::DW_AT_name)
                .map_err(|e| e.to_string())?
            else {
                continue;
            };
            if dwarf
                .attr_string(unit, name)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .as_ref()
                != head
            {
                continue;
            }
            let bits = child
                .attr_value(gimli::DW_AT_bit_size)
                .map_err(|e| e.to_string())?
                .and_then(|v| v.udata_value());
            let data_bit_offset = child
                .attr_value(gimli::DW_AT_data_bit_offset)
                .map_err(|e| e.to_string())?
                .and_then(|v| v.udata_value());
            let member = match child
                .attr_value(gimli::DW_AT_data_member_location)
                .map_err(|e| e.to_string())?
            {
                Some(value) => value
                    .udata_value()
                    .ok_or("nonconstant DWARF member offset")?,
                None if entry.tag() == gimli::DW_TAG_union_type || data_bit_offset.is_some() => 0,
                _ => return Err("missing DWARF member offset".into()),
            };
            let reference = child
                .attr_value(gimli::DW_AT_type)
                .map_err(|e| e.to_string())?
                .ok_or("missing DWARF member type")?;
            let mut result = resolve_reference(dwarf, unit, reference, tail, depth + 1)?;
            if let Some(bits) = bits {
                if !tail.is_empty()
                    || !result.dereferences.is_empty()
                    || !(1..=64).contains(&bits)
                    || result.float
                {
                    return Err("unsupported DWARF bitfield type".into());
                }
                let (byte_offset, shift) = if let Some(bit_offset) = data_bit_offset {
                    (bit_offset / 8, bit_offset % 8)
                } else {
                    let old = child
                        .attr_value(gimli::DW_AT_bit_offset)
                        .map_err(|e| e.to_string())?
                        .and_then(|v| v.udata_value())
                        .ok_or("missing DWARF bitfield offset")?;
                    let shift = result
                        .size
                        .checked_mul(8)
                        .and_then(|n| n.checked_sub(old))
                        .and_then(|n| n.checked_sub(bits))
                        .ok_or("invalid DWARF bitfield offset")?;
                    (member, shift)
                };
                if shift + bits > 64 {
                    return Err("DWARF bitfield exceeds 64-bit storage".into());
                }
                result.offset = byte_offset;
                result.size = (shift + bits).div_ceil(8);
                result.bits = Some((shift as u32, bits as u32));
            } else if let Some(first) = result.dereferences.first_mut() {
                *first = first
                    .checked_add(member)
                    .ok_or("DWARF member offset overflow")?;
            } else {
                result.offset = result
                    .offset
                    .checked_add(member)
                    .ok_or("DWARF member offset overflow")?;
            }
            if result.vector_size > 0 {
                result.vector_offset = result
                    .vector_offset
                    .checked_add(member)
                    .ok_or("vector member offset overflow")?;
            }
            return Ok(result);
        }
        return Err("DWARF member not found".into());
    }
    let size = entry
        .attr_value(gimli::DW_AT_byte_size)
        .map_err(|e| e.to_string())?
        .and_then(|v| v.udata_value())
        .or_else(|| {
            (matches!(
                entry.tag(),
                gimli::DW_TAG_pointer_type
                    | gimli::DW_TAG_reference_type
                    | gimli::DW_TAG_rvalue_reference_type
            ))
            .then_some(unit.encoding().address_size as u64)
        })
        .ok_or("missing DWARF type size")?;
    if entry.tag() == gimli::DW_TAG_enumeration_type {
        if let Some(reference) = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(|e| e.to_string())?
        {
            let mut layout = resolve_reference(dwarf, unit, reference, "", depth + 1)?;
            layout.size = size;
            return Ok(layout);
        }
    }
    let encoding = entry
        .attr_value(gimli::DW_AT_encoding)
        .map_err(|e| e.to_string())?;
    if entry.tag() == gimli::DW_TAG_base_type
        && !matches!(
            encoding,
            Some(AttributeValue::Encoding(
                gimli::DW_ATE_address
                    | gimli::DW_ATE_boolean
                    | gimli::DW_ATE_float
                    | gimli::DW_ATE_signed
                    | gimli::DW_ATE_signed_char
                    | gimli::DW_ATE_unsigned
                    | gimli::DW_ATE_unsigned_char
                    | gimli::DW_ATE_UTF
            ))
        )
    {
        return Err("unsupported DWARF base type encoding".into());
    }
    let mut members = Vec::new();
    if matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type | gimli::DW_TAG_class_type
    ) {
        let mut tree = unit.entries_tree(Some(offset)).map_err(|e| e.to_string())?;
        let root = tree.root().map_err(|e| e.to_string())?;
        let mut children = root.children();
        while let Some(node) = children.next().map_err(|e| e.to_string())? {
            if node.entry().tag() != gimli::DW_TAG_member {
                continue;
            }
            if let Some(value) = node
                .entry()
                .attr_value(gimli::DW_AT_name)
                .map_err(|e| e.to_string())?
            {
                let bytes = dwarf.attr_string(unit, value).map_err(|e| e.to_string())?;
                let name = bytes.to_string_lossy();
                if name.len() > 256 {
                    return Err("DWARF member name exceeds 256 bytes".into());
                }
                members.push(name.into_owned());
                if members.len() > 128 {
                    return Err("DWARF structure exceeds 128 named members".into());
                }
            }
        }
    }
    Ok(Layout {
        offset: 0,
        pointer: matches!(
            entry.tag(),
            gimli::DW_TAG_pointer_type
                | gimli::DW_TAG_reference_type
                | gimli::DW_TAG_rvalue_reference_type
        ),
        vector: false,
        vector_size: 0,
        vector_offset: 0,
        by_reference: entry
            .attr_value(gimli::DW_AT_calling_convention)
            .map_err(|e| e.to_string())?
            == Some(AttributeValue::CallingConvention(
                gimli::DW_CC_pass_by_reference,
            )),
        alignment: entry
            .attr_value(gimli::DW_AT_alignment)
            .map_err(|e| e.to_string())?
            .and_then(|v| v.udata_value())
            .unwrap_or(
                if matches!(
                    entry.tag(),
                    gimli::DW_TAG_base_type
                        | gimli::DW_TAG_pointer_type
                        | gimli::DW_TAG_enumeration_type
                ) {
                    size.min(8)
                } else {
                    0
                },
            ),
        members,
        dereferences: Vec::new(),
        bits: None,
        size,
        scalar: matches!(
            entry.tag(),
            gimli::DW_TAG_base_type
                | gimli::DW_TAG_pointer_type
                | gimli::DW_TAG_reference_type
                | gimli::DW_TAG_rvalue_reference_type
                | gimli::DW_TAG_enumeration_type
        ),
        signed: matches!(
            encoding,
            Some(AttributeValue::Encoding(
                gimli::DW_ATE_signed | gimli::DW_ATE_signed_char
            ))
        ),
        float: matches!(
            encoding,
            Some(AttributeValue::Encoding(gimli::DW_ATE_float))
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_dimensions(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    reference: AttributeValue<R<'_>>,
    dimensions: &[u64],
    field: &str,
    depth: u32,
    vector: bool,
    alignment: u64,
) -> Result<Layout> {
    if depth >= 32 {
        return Err("DWARF type nesting limit exceeded".into());
    }
    let element = resolve_reference(dwarf, unit, reference, "", depth + 1)?;
    let count = dimensions.iter().try_fold(1u64, |count, n| {
        count.checked_mul(*n).ok_or("array size overflow")
    })?;
    let size = element
        .size
        .checked_mul(count)
        .ok_or("array size overflow")?;
    if !field.is_empty() {
        let end = field.find(']').ok_or("array member requires [index]")?;
        let index = field
            .strip_prefix('[')
            .ok_or("array member requires [index]")?[..end - 1]
            .parse::<u64>()
            .map_err(|_| "invalid typed array index")?;
        if index >= dimensions[0] {
            return Err("typed array index out of bounds".into());
        }
        let tail = field[end + 1..]
            .strip_prefix('.')
            .unwrap_or(&field[end + 1..]);
        let stride = size
            .checked_div(dimensions[0])
            .ok_or("invalid zero-sized array dimension")?;
        let offset = index.checked_mul(stride).ok_or("array offset overflow")?;
        let mut layout = if dimensions.len() > 1 {
            resolve_dimensions(
                dwarf,
                unit,
                reference,
                &dimensions[1..],
                tail,
                depth + 1,
                false,
                alignment,
            )?
        } else {
            resolve_reference(dwarf, unit, reference, tail, depth + 1)?
        };
        if let Some(first) = layout.dereferences.first_mut() {
            *first = first.checked_add(offset).ok_or("array offset overflow")?;
        } else {
            layout.offset = layout
                .offset
                .checked_add(offset)
                .ok_or("array offset overflow")?;
        }
        if vector {
            layout.vector_size = size;
            layout.vector_offset = 0;
        } else if layout.vector_size > 0 {
            layout.vector_offset = layout
                .vector_offset
                .checked_add(offset)
                .ok_or("vector offset overflow")?;
        }
        return Ok(layout);
    }
    Ok(Layout {
        offset: 0,
        size,
        signed: false,
        float: false,
        scalar: false,
        pointer: false,
        vector,
        vector_size: if vector { size } else { 0 },
        vector_offset: 0,
        by_reference: false,
        alignment,
        members: (0..dimensions[0]).map(|i| format!("[{i}]")).collect(),
        dereferences: Vec::new(),
        bits: None,
    })
}
pub(crate) fn flatten(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    reference: AttributeValue<R<'_>>,
    field: &str,
    depth: u32,
    out: &mut Vec<(String, Layout)>,
) -> Result<()> {
    if depth >= 8 || out.len() >= 128 {
        return Err("DWARF argument member/nesting limit exceeded".into());
    }
    let layout = resolve_reference(dwarf, unit, reference, field, 0)?;
    if layout.scalar {
        out.push((field.to_owned(), layout));
        return Ok(());
    }
    if layout.members.is_empty() {
        return Err("unsupported aggregate argument layout".into());
    }
    for member in layout.members {
        let path = if field.is_empty() {
            member
        } else {
            format!("{field}.{member}")
        };
        flatten(dwarf, unit, reference, &path, depth + 1, out)?;
    }
    Ok(())
}
pub(crate) fn resolve_reference(
    dwarf: &gimli::Dwarf<R<'_>>,
    unit: &gimli::Unit<R<'_>>,
    reference: AttributeValue<R<'_>>,
    field: &str,
    depth: u32,
) -> Result<Layout> {
    match reference {
        AttributeValue::UnitRef(offset) => resolve(dwarf, unit, offset, field, depth),
        AttributeValue::DebugInfoRef(offset) => {
            let mut headers = dwarf.units();
            while let Some(header) = headers.next().map_err(|e| e.to_string())? {
                if let Some(offset) = offset.to_unit_offset(&header) {
                    let target = dwarf.unit(header).map_err(|e| e.to_string())?;
                    return resolve(dwarf, &target, offset, field, depth);
                }
            }
            Err("DWARF cross-unit reference outside debug_info".into())
        }
        _ => Err("unsupported DWARF type reference".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automatic_arguments_reject_explicit_non_native_calling_conventions() {
        assert!(validate_c_language(Some(AttributeValue::Language(gimli::DW_LANG_C11))).is_ok());
        assert!(
            validate_c_language(Some(AttributeValue::Language(
                gimli::DW_LANG_C_plus_plus_17
            )))
            .is_ok()
        );
        assert!(validate_c_language(Some(AttributeValue::Language(gimli::DW_LANG_Go))).is_err());
        assert!(validate_c_language(Some(AttributeValue::Language(gimli::DW_LANG_Rust))).is_err());
        assert!(validate_c_language(None).is_err());
        assert!(validate_calling_convention(None).is_ok());
        assert!(
            validate_calling_convention(Some(AttributeValue::CallingConvention(
                gimli::DW_CC_normal
            )))
            .is_ok()
        );
        // LLVM emits a vendor calling convention for x86 ms_abi functions.
        assert!(
            validate_calling_convention(Some(AttributeValue::CallingConvention(gimli::DwCc(0xc1))))
                .is_err()
        );
        assert!(
            validate_calling_convention(Some(AttributeValue::CallingConvention(
                gimli::DW_CC_nocall
            )))
            .is_err()
        );
        assert!(validate_calling_convention(Some(AttributeValue::Udata(1))).is_err());
    }
    #[test]
    fn dwarf_bitfields_and_pointer_members() {
        let directory =
            std::env::temp_dir().join(format!("poortrace-types-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("types.c");
        let image = directory.join("types");
        std::fs::write(
            &source,
            r#"
struct Child { long value; };
struct Payload { struct Child *child; unsigned first:3; signed negative:5; unsigned rest:13; };
struct Payload payload;
typedef long Matrix[2][3]; Matrix matrix;
void complex_arg(float _Complex argument) { (void)argument; }
int main(void) { return payload.first; }
"#,
        )
        .unwrap();
        for version in ["-gdwarf-4", "-gdwarf-5"] {
            let status = std::process::Command::new("cc")
                .args(["-O0", version])
                .arg(&source)
                .arg("-o")
                .arg(&image)
                .status()
                .unwrap();
            assert!(status.success());
            let mut reader = Reader::default();
            let pid = std::process::id();
            let path = image.to_str().unwrap();
            assert!(reader.signature(pid, path, "complex_arg").is_err());
            let matrix_layout = reader.layout(pid, path, "Matrix", "[1][2]").unwrap();
            assert_eq!(matrix_layout.offset, 40);
            assert_eq!(matrix_layout.size, 8);
            let values = [[1i64, 2, 3], [4, 5, 6]];
            assert_eq!(
                reader
                    .scalar(pid, values.as_ptr() as u64, &matrix_layout)
                    .unwrap(),
                6
            );
            let matrix = reader
                .describe(pid, path, "Matrix", values.as_ptr() as u64)
                .unwrap();
            assert!(matrix.contains("[1]: {[0]: 4, [1]: 5, [2]: 6}"), "{matrix}");
            assert!(reader.layout(pid, path, "Matrix", "[2][0]").is_err());
            let child = reader.layout(pid, path, "Payload", "child->value").unwrap();
            assert_eq!(child.dereferences, vec![0]);
            assert_eq!(child.offset, 0);
            assert_eq!(child.size, 8);
            let first = reader.layout(pid, path, "Payload", "first").unwrap();
            let negative = reader.layout(pid, path, "Payload", "negative").unwrap();
            let rest = reader.layout(pid, path, "Payload", "rest").unwrap();
            assert_eq!(first.bits.unwrap().1, 3);
            assert_eq!(negative.bits.unwrap().1, 5);
            assert!(negative.signed);
            assert_eq!(rest.bits.unwrap().1, 13);
            let value = 42i64;
            let mut payload = [0u8; 16];
            payload[..8].copy_from_slice(&(&value as *const i64 as u64).to_ne_bytes());
            let packed = (5u32) | (29u32 << 3) | (1234u32 << 8);
            payload[8..12].copy_from_slice(&packed.to_ne_bytes());
            let description = reader
                .describe(pid, path, "Payload", payload.as_ptr() as u64)
                .unwrap();
            assert!(
                description.contains("first: 5, negative: -3, rest: 1234"),
                "{description}"
            );
            let script = format!(
                r#"BEGIN {{ printf("%d %d %d %d\n",field(arg0,{path:?},"Payload","first"),field(arg0,{path:?},"Payload","negative"),field(arg0,{path:?},"Payload","rest"),field(arg0,{path:?},"Payload","child->value")); printf("%.2f\n",fieldf(arg0,{path:?},"Payload","negative")+0.5); }}"#
            );
            let program = crate::codegen::Program::compile(&script).unwrap();
            let mut output = Vec::new();
            {
                let mut state = program.state(&mut output);
                let mut event = crate::runtime::Event::new(c"x", c"x");
                event.pid = pid as u64;
                event.args[0] = payload.as_ptr() as u64;
                program.invoke(0, &mut state, &event);
                state.flush().unwrap();
            }
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "5 -3 1234 42\n-2.50\n",
                "{version}"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
