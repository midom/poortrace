//! Bounded DWARF scalar/structure layout reads; unsupported location expressions fail explicitly.
use crate::Result;
use addr2line::gimli::{self, AttributeValue, EndianSlice, RunTimeEndian, UnitOffset};
use object::{Object, ObjectSection};
use std::{borrow::Cow, collections::BTreeMap, io::Read, os::unix::fs::MetadataExt};
#[derive(Clone, Debug)]
pub struct Layout {
    pub offset: u64,
    pub size: u64,
    pub signed: bool,
    pub float: bool,
    pub scalar: bool,
}
#[derive(Default)]
pub struct Reader {
    cache: BTreeMap<(u32, String, String, String), Layout>,
}
impl Reader {
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
        let mut data = Vec::new();
        file.take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > 128 * 1024 * 1024 {
            return Err("DWARF image exceeds 128 MiB".into());
        }
        let object = object::File::parse(data.as_slice()).map_err(|e| e.to_string())?;
        let endian = if object.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let mut section_bytes = 0u64;
        let dwarf = gimli::DwarfSections::load(|section| -> Result<Cow<'_, [u8]>> {
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
                    section.uncompressed_data().map_err(|e| e.to_string())
                }
                None => Ok(Cow::Borrowed(&[])),
            }
        })?;
        let dwarf = dwarf.borrow(|section| EndianSlice::new(section, endian));
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
                    if result.as_ref().is_some_and(|old: &Layout| {
                        (old.offset, old.size, old.signed, old.float, old.scalar)
                            != (
                                layout.offset,
                                layout.size,
                                layout.signed,
                                layout.float,
                                layout.scalar,
                            )
                    }) {
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
type R<'a> = EndianSlice<'a, RunTimeEndian>;
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
    let entry = unit.entry(offset).map_err(|e| e.to_string())?;
    if matches!(
        entry.tag(),
        gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type
            | gimli::DW_TAG_atomic_type
    ) {
        let Some(AttributeValue::UnitRef(next)) = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(|e| e.to_string())?
        else {
            return Err("unsupported DWARF type reference".into());
        };
        return resolve(dwarf, unit, next, field, depth + 1);
    }
    if !field.is_empty() {
        let (head, tail) = field.split_once('.').unwrap_or((field, ""));
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
            if child
                .attr_value(gimli::DW_AT_bit_size)
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err("DWARF bitfields are unsupported".into());
            }
            let member = match child
                .attr_value(gimli::DW_AT_data_member_location)
                .map_err(|e| e.to_string())?
            {
                Some(value) => value
                    .udata_value()
                    .ok_or("nonconstant DWARF member offset")?,
                None if entry.tag() == gimli::DW_TAG_union_type => 0,
                _ => return Err("missing DWARF member offset".into()),
            };
            let Some(AttributeValue::UnitRef(next)) = child
                .attr_value(gimli::DW_AT_type)
                .map_err(|e| e.to_string())?
            else {
                return Err("unsupported DWARF member type".into());
            };
            let mut result = resolve(dwarf, unit, next, tail, depth + 1)?;
            result.offset = result
                .offset
                .checked_add(member)
                .ok_or("DWARF member offset overflow")?;
            return Ok(result);
        }
        return Err("DWARF member not found".into());
    }
    let size = entry
        .attr_value(gimli::DW_AT_byte_size)
        .map_err(|e| e.to_string())?
        .and_then(|v| v.udata_value())
        .or_else(|| {
            (entry.tag() == gimli::DW_TAG_pointer_type)
                .then_some(unit.encoding().address_size as u64)
        })
        .ok_or("missing DWARF type size")?;
    if entry.tag() == gimli::DW_TAG_enumeration_type {
        if let Some(AttributeValue::UnitRef(base)) = entry
            .attr_value(gimli::DW_AT_type)
            .map_err(|e| e.to_string())?
        {
            let mut layout = resolve(dwarf, unit, base, "", depth + 1)?;
            layout.size = size;
            return Ok(layout);
        }
    }
    let encoding = entry
        .attr_value(gimli::DW_AT_encoding)
        .map_err(|e| e.to_string())?;
    Ok(Layout {
        offset: 0,
        size,
        scalar: matches!(
            entry.tag(),
            gimli::DW_TAG_base_type | gimli::DW_TAG_pointer_type | gimli::DW_TAG_enumeration_type
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
