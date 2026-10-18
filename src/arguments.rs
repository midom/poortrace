//! Bounded native C ABI argument reconstruction from stopped registers and DWARF.
//! Rules follow the System V AMD64 psABI and Arm AAPCS64 parameter-passing rules.
//! https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex
//! https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
use crate::{
    Result,
    types::{Parameter, Reader},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bank {
    Integer,
    Float,
    Upper,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Piece {
    offset: usize,
    size: usize,
    index: usize,
    bank: Bank,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Location {
    Registers(Vec<Piece>),
    Stack(usize),
    Indirect(Box<Location>),
}
fn aligned(value: usize, alignment: usize) -> Result<usize> {
    if !alignment.is_power_of_two() || alignment > 16 {
        return Err("unsupported native argument alignment".into());
    }
    value
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or("argument stack offset overflow".into())
}
fn alignment(parameter: &Parameter) -> usize {
    parameter
        .layout
        .alignment
        .max(if parameter.layout.vector {
            parameter.layout.size
        } else {
            1
        })
        .max(
            parameter
                .fields
                .iter()
                .map(|(_, l)| l.alignment.max(l.vector_size))
                .max()
                .unwrap_or(1),
        )
        .max(1) as usize
}
fn plan(parameters: &[Parameter], architecture: Architecture) -> Result<Vec<Location>> {
    let mut integer = 0usize;
    let mut float = 0usize;
    let mut stack = 0usize;
    let mut result = Vec::new();
    for parameter in parameters {
        let size = usize::try_from(parameter.layout.size).map_err(|_| "argument size overflow")?;
        if size == 0
            || size > 4096
            || parameter.fields.iter().any(|(_, l)| {
                !l.dereferences.is_empty()
                    || !l.scalar
                    || !(1..=8).contains(&l.size)
                    || l.float && !matches!(l.size, 4 | 8)
                    || l.offset
                        .checked_add(l.size)
                        .is_none_or(|end| end > size as u64)
            })
        {
            return Err("unsupported DWARF argument size or layout".into());
        }
        let alignment = alignment(parameter);
        if parameter.layout.by_reference {
            let limit = if architecture == Architecture::Aarch64 {
                8
            } else {
                6
            };
            let pointer = if integer < limit {
                let index = integer;
                integer += 1;
                Location::Registers(vec![Piece {
                    offset: 0,
                    size: 8,
                    index,
                    bank: Bank::Integer,
                }])
            } else {
                stack = aligned(stack, 8)?;
                let at = stack;
                stack += 8;
                Location::Stack(at)
            };
            result.push(Location::Indirect(Box::new(pointer)));
            continue;
        }
        if architecture == Architecture::Aarch64 {
            let mut homogeneous = std::collections::BTreeMap::new();
            let all_float = parameter.fields.iter().all(|(_, field)| {
                field.float && matches!(field.size, 4 | 8) && field.vector_size == 0
            });
            let all_vector = parameter
                .fields
                .iter()
                .all(|(_, field)| matches!(field.vector_size, 8 | 16));
            if all_float {
                for (_, field) in &parameter.fields {
                    homogeneous.insert(field.offset, field.size);
                }
            } else if all_vector {
                for (_, field) in &parameter.fields {
                    homogeneous.insert(field.vector_offset, field.vector_size);
                }
            }
            let same_float_type = all_float
                && parameter
                    .fields
                    .iter()
                    .all(|(_, field)| field.size == parameter.fields[0].1.size);
            let homogeneous = (!parameter.layout.scalar
                && !parameter.layout.vector
                && (same_float_type || all_vector)
                && (1..=4).contains(&homogeneous.len())
                && homogeneous.iter().enumerate().all(|(i, (offset, size))| {
                    *size == *homogeneous.values().next().unwrap() && *offset == i as u64 * *size
                })
                && parameter.layout.size
                    == homogeneous.len() as u64 * *homogeneous.values().next().unwrap_or(&0))
            .then_some(homogeneous);
            let floating =
                parameter.layout.float || parameter.layout.vector || homogeneous.is_some();
            if floating {
                if parameter.layout.vector && !matches!(size, 8 | 16)
                    || parameter.layout.float && !matches!(size, 4 | 8)
                {
                    return Err("unsupported native floating/vector type".into());
                }
                let groups = homogeneous
                    .map(|groups| groups.into_iter().collect::<Vec<_>>())
                    .unwrap_or_else(|| vec![(0, size as u64)]);
                if float + groups.len() <= 8 {
                    let pieces = groups
                        .iter()
                        .enumerate()
                        .map(|(n, (offset, size))| Piece {
                            offset: *offset as usize,
                            size: *size as usize,
                            index: float + n,
                            bank: Bank::Float,
                        })
                        .collect();
                    float += groups.len();
                    result.push(Location::Registers(pieces));
                    continue;
                }
                float = 8;
                stack = aligned(stack, alignment.max(8))?;
                result.push(Location::Stack(stack));
                stack += aligned(size, 8)?;
                continue;
            }
            if size > 16 {
                let location = if integer < 8 {
                    let index = integer;
                    integer += 1;
                    Location::Registers(vec![Piece {
                        offset: 0,
                        size: 8,
                        index,
                        bank: Bank::Integer,
                    }])
                } else {
                    stack = aligned(stack, 8)?;
                    let at = stack;
                    stack += 8;
                    Location::Stack(at)
                };
                result.push(Location::Indirect(Box::new(location)));
                continue;
            }
            if alignment >= 16 {
                integer = aligned(integer, 2)?;
            }
            let count = size.div_ceil(8);
            if integer + count <= 8 {
                result.push(Location::Registers(
                    (0..count)
                        .map(|n| Piece {
                            offset: n * 8,
                            size: (size - n * 8).min(8),
                            index: integer + n,
                            bank: Bank::Integer,
                        })
                        .collect(),
                ));
                integer += count;
                continue;
            }
            integer = 8;
            stack = aligned(stack, alignment.max(8))?;
            result.push(Location::Stack(stack));
            stack += aligned(size, 8)?;
        } else {
            let mut classes = vec![None; size.div_ceil(8)];
            let mut memory = size > 16;
            if parameter.layout.vector {
                if !matches!(size, 8 | 16) {
                    return Err("only 64/128-bit vector arguments are supported".into());
                }
                if float < 8 {
                    result.push(Location::Registers(vec![Piece {
                        offset: 0,
                        size,
                        index: float,
                        bank: Bank::Float,
                    }]));
                    float += 1;
                    continue;
                }
                memory = true;
            } else {
                for (_, field) in &parameter.fields {
                    if field.vector_size > 0 {
                        continue;
                    }
                    if field.offset.saturating_add(field.size) > size as u64 {
                        return Err("DWARF argument member lies outside its object".into());
                    }
                    if field.float && !matches!(field.size, 4 | 8) {
                        return Err("unsupported native floating-point type".into());
                    }
                    if field.bits.is_none() && field.offset % field.alignment.max(1) != 0 {
                        memory = true;
                    }
                    let bank = if field.float {
                        Bank::Float
                    } else {
                        Bank::Integer
                    };
                    for class in &mut classes[field.offset as usize / 8
                        ..(field.offset as usize + field.size as usize).div_ceil(8)]
                    {
                        if *class != Some(Bank::Integer) {
                            *class = Some(bank);
                        }
                    }
                }
            }
            let mut groups = std::collections::BTreeMap::new();
            for (_, field) in &parameter.fields {
                if field.vector_size > 0 {
                    groups.insert(field.vector_offset, field.vector_size);
                }
            }
            for (offset, vector_size) in groups {
                if !matches!(vector_size, 8 | 16)
                    || offset
                        .checked_add(vector_size)
                        .is_none_or(|end| end > size as u64)
                {
                    return Err("unsupported vector argument member layout".into());
                }
                if offset % vector_size != 0 {
                    memory = true;
                }
                let start = offset as usize / 8;
                if classes[start] != Some(Bank::Integer) {
                    classes[start] = Some(Bank::Float);
                }
                if vector_size == 16 && classes[start + 1].is_none() {
                    classes[start + 1] = Some(Bank::Upper);
                }
            }
            for index in 0..classes.len() {
                if classes[index] == Some(Bank::Upper)
                    && (index == 0
                        || !matches!(classes[index - 1], Some(Bank::Float | Bank::Upper)))
                {
                    classes[index] = Some(Bank::Float);
                }
            }
            let integers = classes
                .iter()
                .filter(|c| **c == Some(Bank::Integer))
                .count();
            let floats = classes.iter().filter(|c| **c == Some(Bank::Float)).count();
            if !memory && integer + integers <= 6 && float + floats <= 8 {
                let mut pieces = Vec::new();
                let mut n = 0;
                while n < classes.len() {
                    if let Some(bank) = classes[n] {
                        if bank == Bank::Upper {
                            n += 1;
                            continue;
                        }
                        let index = if bank == Bank::Integer {
                            let index = integer;
                            integer += 1;
                            index
                        } else {
                            let index = float;
                            float += 1;
                            index
                        };
                        let wide =
                            bank == Bank::Float && classes.get(n + 1) == Some(&Some(Bank::Upper));
                        pieces.push(Piece {
                            offset: n * 8,
                            size: (size - n * 8).min(if wide { 16 } else { 8 }),
                            index,
                            bank,
                        });
                        n += if wide { 2 } else { 1 };
                    } else {
                        n += 1;
                    }
                }
                result.push(Location::Registers(pieces));
                continue;
            }
            stack = aligned(stack, alignment.max(8))?;
            result.push(Location::Stack(stack));
            stack += aligned(size, 8)?;
        }
        if stack > 16384 {
            return Err("native argument stack limit exceeded".into());
        }
    }
    if stack > 16384 {
        return Err("native argument stack limit exceeded".into());
    }
    Ok(result)
}
fn read_location(tid: u32, sp: u64, location: &Location, size: usize) -> Result<Vec<u8>> {
    match location {
        Location::Registers(pieces) => {
            let mut bytes = vec![0; size];
            for piece in pieces {
                let data = match piece.bank {
                    Bank::Integer => {
                        let mut raw = [0; 16];
                        raw[..8].copy_from_slice(
                            &crate::functions::integer_argument(tid as i32, piece.index)?
                                .to_ne_bytes(),
                        );
                        raw
                    }
                    Bank::Float => {
                        crate::functions::floating_argument_bits(tid as i32, piece.index)?
                    }
                    Bank::Upper => return Err("invalid SIMD continuation piece".into()),
                };
                bytes[piece.offset..piece.offset + piece.size].copy_from_slice(&data[..piece.size]);
            }
            Ok(bytes)
        }
        Location::Stack(offset) => crate::memory::read(
            tid,
            sp.checked_add(*offset as u64)
                .ok_or("native argument address overflow")?,
            size,
            false,
        ),
        Location::Indirect(pointer) => {
            let bytes = read_location(tid, sp, pointer, 8)?;
            let address = u64::from_ne_bytes(bytes.try_into().unwrap());
            crate::memory::read(tid, address, size, false)
        }
    }
}
pub(crate) fn field_text(bytes: &[u8], layout: &crate::types::Layout) -> Result<String> {
    if !(1..=8).contains(&layout.size)
        || layout.float && !matches!(layout.size, 4 | 8)
        || layout.bits.is_some_and(|(shift, bits)| {
            bits == 0
                || bits > 64
                || shift >= 64
                || u64::from(shift) + u64::from(bits) > layout.size * 8
        })
    {
        return Err("unsupported native scalar argument layout".into());
    }
    let start = usize::try_from(layout.offset).map_err(|_| "argument field offset overflow")?;
    let end = start
        .checked_add(layout.size as usize)
        .ok_or("argument field range overflow")?;
    let bytes = bytes
        .get(start..end)
        .ok_or("argument field outside object")?;
    let mut raw = [0; 8];
    raw[..bytes.len()].copy_from_slice(bytes);
    let mut raw = u64::from_ne_bytes(raw);
    let bits = if let Some((shift, bits)) = layout.bits {
        raw >>= shift;
        if bits < 64 {
            raw &= (1u64 << bits) - 1;
        }
        bits as u64
    } else {
        layout.size * 8
    };
    Ok(if layout.pointer {
        format!("0x{raw:x}")
    } else if layout.float && layout.size == 4 {
        f32::from_bits(raw as u32).to_string()
    } else if layout.float && layout.size == 8 {
        f64::from_bits(raw).to_string()
    } else if layout.signed {
        ((raw << (64 - bits)) as i64 >> (64 - bits)).to_string()
    } else {
        raw.to_string()
    })
}
pub fn format(
    reader: &mut Reader,
    pid: u32,
    tid: u32,
    path: &str,
    function: &str,
) -> Result<String> {
    let parameters = reader.signature(pid, path, function)?;
    #[cfg(target_arch = "aarch64")]
    let architecture = Architecture::Aarch64;
    #[cfg(target_arch = "x86_64")]
    let architecture = Architecture::X86_64;
    format_parameters(&parameters, tid, architecture)
}
fn format_parameters(
    parameters: &[Parameter],
    tid: u32,
    architecture: Architecture,
) -> Result<String> {
    let locations = plan(parameters, architecture)?;
    let regs = crate::functions::user_registers(tid as i32)?;
    let sp = regs
        .sp
        .checked_add(if architecture == Architecture::X86_64 {
            8
        } else {
            0
        })
        .ok_or("native argument stack address overflow")?;
    let mut output = String::new();
    for (parameter, location) in parameters.iter().zip(&locations) {
        if parameter.hidden {
            continue;
        }
        let bytes = read_location(tid, sp, location, parameter.layout.size as usize)?;
        if !output.is_empty() {
            output.push_str(", ");
        }
        output.push_str(&parameter.name);
        output.push('=');
        if parameter.layout.scalar {
            output.push_str(&field_text(&bytes, &parameter.layout)?);
        } else {
            output.push('{');
            for (n, (name, layout)) in parameter.fields.iter().enumerate() {
                if n != 0 {
                    output.push_str(", ");
                }
                output.push_str(name);
                output.push_str(": ");
                output.push_str(&field_text(&bytes, layout)?);
            }
            output.push('}');
        }
        if output.len() > 4096 {
            return Err("formatted arguments exceed 4096 bytes".into());
        }
    }
    Ok(output)
}

pub fn format_explicit(
    reader: &mut Reader,
    pid: u32,
    tid: u32,
    path: &str,
    signature: &str,
) -> Result<String> {
    if signature.len() > 4096 {
        return Err("explicit argument signature exceeds4096bytes".into());
    }
    let (arguments, result) = signature
        .split_once("->")
        .map_or((signature, None), |(args, result)| {
            (args, Some(result.trim()))
        });
    let mut parameters = Vec::new();
    let mut variadic = false;
    for value in arguments
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if value == "..." {
            if variadic {
                return Err("duplicate variadic marker".into());
            }
            variadic = true;
            continue;
        }
        if parameters.len() >= 32 {
            return Err("explicit arguments exceed32parameters".into());
        }
        let (name, ty) = value
            .split_once('=')
            .map_or((format!("arg{}", parameters.len()), value), |(name, ty)| {
                (name.trim().to_owned(), ty.trim())
            });
        if name.is_empty()
            || name.len() > 256
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err("invalid explicit argument name".into());
        }
        let parameter = explicit_parameter(reader, pid, path, &name, ty)?;
        if variadic
            && parameter.layout.scalar
            && (parameter.layout.float && parameter.layout.size < 8
                || !parameter.layout.float
                    && !parameter.layout.pointer
                    && parameter.layout.size < 4)
        {
            return Err("variadic arguments require promoted i32/u32 or f64 scalar types".into());
        }
        parameters.push(parameter);
    }
    #[cfg(target_arch = "aarch64")]
    let architecture = Architecture::Aarch64;
    #[cfg(target_arch = "x86_64")]
    let architecture = Architecture::X86_64;
    if let Some(result) = result.filter(|result| *result != "void") {
        let result = explicit_parameter(reader, pid, path, "$result", result)?;
        if architecture == Architecture::X86_64
            && (result.layout.by_reference
                || matches!(
                    plan(std::slice::from_ref(&result), architecture)?.first(),
                    Some(Location::Stack(_) | Location::Indirect(_))
                ))
        {
            let mut hidden = explicit_parameter(reader, pid, path, "$return", "ptr")?;
            hidden.hidden = true;
            parameters.insert(0, hidden);
        }
    }
    format_parameters(&parameters, tid, architecture)
}
fn primitive(ty: &str) -> Option<crate::types::Layout> {
    let (size, signed, float, pointer) = match ty {
        "i8" => (1, true, false, false),
        "u8" | "bool" => (1, false, false, false),
        "i16" => (2, true, false, false),
        "u16" => (2, false, false, false),
        "i32" => (4, true, false, false),
        "u32" => (4, false, false, false),
        "i64" | "isize" => (8, true, false, false),
        "u64" | "usize" => (8, false, false, false),
        "ptr" => (8, false, false, true),
        "f32" => (4, false, true, false),
        "f64" => (8, false, true, false),
        _ => return None,
    };
    Some(crate::types::Layout {
        offset: 0,
        size,
        signed,
        float,
        scalar: true,
        pointer,
        vector: false,
        vector_size: 0,
        vector_offset: 0,
        by_reference: false,
        alignment: size,
        members: Vec::new(),
        dereferences: Vec::new(),
        bits: None,
    })
}
fn explicit_parameter(
    reader: &mut Reader,
    pid: u32,
    path: &str,
    name: &str,
    ty: &str,
) -> Result<Parameter> {
    if let Some(layout) = primitive(ty) {
        return Ok(Parameter {
            hidden: false,
            name: name.into(),
            fields: vec![(String::new(), layout.clone())],
            layout,
        });
    }
    if let Some(vector) = ty.strip_prefix('v') {
        let digits = vector.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            let count = vector[..digits]
                .parse::<u64>()
                .map_err(|_| "invalid vector count")?;
            let base = primitive(&vector[digits..]).ok_or("invalid vector element type")?;
            let size = base.size.checked_mul(count).ok_or("vector size overflow")?;
            if !matches!(size, 8 | 16) {
                return Err("explicit vectors must be64or128bits".into());
            }
            let fields = (0..count)
                .map(|index| {
                    let mut layout = base.clone();
                    layout.offset = index * base.size;
                    layout.vector_size = size;
                    (format!("[{index}]"), layout)
                })
                .collect();
            let mut layout = base;
            layout.size = size;
            layout.scalar = false;
            layout.vector = true;
            layout.vector_size = size;
            layout.alignment = size;
            return Ok(Parameter {
                hidden: false,
                name: name.into(),
                layout,
                fields,
            });
        }
    }
    let layout = reader.layout(pid, path, ty, "")?;
    let mut fields = Vec::new();
    fn fields_for(
        reader: &mut Reader,
        pid: u32,
        path: &str,
        ty: &str,
        field: &str,
        depth: u32,
        out: &mut Vec<(String, crate::types::Layout)>,
    ) -> Result<()> {
        if depth >= 8 || out.len() >= 128 {
            return Err("explicit argument member limit exceeded".into());
        }
        let layout = reader.layout(pid, path, ty, field)?;
        if layout.scalar {
            out.push((field.into(), layout));
            return Ok(());
        }
        if layout.members.is_empty() {
            return Err("explicit aggregate needs named DWARF members".into());
        }
        for member in layout.members {
            let field = if field.is_empty() {
                member
            } else {
                format!("{field}.{member}")
            };
            fields_for(reader, pid, path, ty, &field, depth + 1, out)?;
        }
        Ok(())
    }
    fields_for(reader, pid, path, ty, "", 0, &mut fields)?;
    Ok(Parameter {
        hidden: false,
        name: name.into(),
        layout,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn layout(size: u64, float: bool, offset: u64) -> crate::types::Layout {
        crate::types::Layout {
            offset,
            size,
            signed: !float,
            float,
            scalar: true,
            pointer: false,
            vector: false,
            vector_size: 0,
            vector_offset: 0,
            by_reference: false,
            alignment: size.min(8),
            members: Vec::new(),
            dereferences: Vec::new(),
            bits: None,
        }
    }
    fn parameter(name: &str, fields: Vec<(String, crate::types::Layout)>, size: u64) -> Parameter {
        let mut root = layout(size, false, 0);
        root.scalar = false;
        root.alignment = 0;
        Parameter {
            hidden: false,
            name: name.into(),
            layout: root,
            fields,
        }
    }
    #[test]
    fn malformed_zero_width_and_unsupported_float_members_fail_before_register_reads() {
        for member in [layout(0, false, 0), layout(2, true, 0)] {
            let parameter = parameter("bad", vec![("member".into(), member.clone())], 8);
            for architecture in [Architecture::X86_64, Architecture::Aarch64] {
                assert!(plan(std::slice::from_ref(&parameter), architecture).is_err());
            }
            assert!(field_text(&[0; 8], &member).is_err());
        }
        for bits in [(0, 0), (64, 1), (0, 65)] {
            let mut member = layout(8, false, 0);
            member.bits = Some(bits);
            assert!(field_text(&[0; 8], &member).is_err());
        }
    }
    #[test]
    fn sysv_and_aapcs_aggregate_and_float_classification() {
        let pair = parameter(
            "pair",
            vec![
                ("integer".into(), layout(8, false, 0)),
                ("float".into(), layout(8, true, 8)),
            ],
            16,
        );
        let x86 = plan(std::slice::from_ref(&pair), Architecture::X86_64).unwrap();
        assert_eq!(
            x86,
            vec![Location::Registers(vec![
                Piece {
                    offset: 0,
                    size: 8,
                    index: 0,
                    bank: Bank::Integer
                },
                Piece {
                    offset: 8,
                    size: 8,
                    index: 0,
                    bank: Bank::Float
                }
            ])]
        );
        let arm = plan(&[pair], Architecture::Aarch64).unwrap();
        assert_eq!(
            arm,
            vec![Location::Registers(vec![
                Piece {
                    offset: 0,
                    size: 8,
                    index: 0,
                    bank: Bank::Integer
                },
                Piece {
                    offset: 8,
                    size: 8,
                    index: 1,
                    bank: Bank::Integer
                }
            ])]
        );
        let hfa = parameter(
            "hfa",
            (0..3)
                .map(|i| (format!("f{i}"), layout(4, true, i * 4)))
                .collect(),
            12,
        );
        let arm = plan(&[hfa], Architecture::Aarch64).unwrap();
        assert_eq!(
            arm,
            vec![Location::Registers(
                (0..3)
                    .map(|i| Piece {
                        offset: i * 4,
                        size: 4,
                        index: i,
                        bank: Bank::Float
                    })
                    .collect()
            )]
        );
    }
    #[test]
    fn union_hfa_and_nested_vectors_preserve_native_register_groups() {
        let union = parameter(
            "union",
            vec![
                ("first".into(), layout(4, true, 0)),
                ("second".into(), layout(4, true, 0)),
            ],
            4,
        );
        assert_eq!(
            plan(&[union], Architecture::Aarch64).unwrap(),
            vec![Location::Registers(vec![Piece {
                offset: 0,
                size: 4,
                index: 0,
                bank: Bank::Float
            }])]
        );
        let fields = (0..4)
            .map(|i| {
                let mut field = layout(4, true, i * 4);
                field.vector_size = 16;
                (format!("first.{i}"), field)
            })
            .collect();
        let nested = parameter("nested", fields, 16);
        let expected = vec![Location::Registers(vec![Piece {
            offset: 0,
            size: 16,
            index: 0,
            bank: Bank::Float,
        }])];
        assert_eq!(
            plan(std::slice::from_ref(&nested), Architecture::Aarch64).unwrap(),
            expected
        );
        assert_eq!(plan(&[nested], Architecture::X86_64).unwrap(), expected);
    }
    #[test]
    fn spilled_vector_uses_sixteen_byte_alignment_on_both_abis() {
        let integer = Parameter {
            hidden: false,
            name: "i".into(),
            layout: layout(8, false, 0),
            fields: vec![(String::new(), layout(8, false, 0))],
        };
        let floating = Parameter {
            hidden: false,
            name: "f".into(),
            layout: layout(8, true, 0),
            fields: vec![(String::new(), layout(8, true, 0))],
        };
        let fields = (0..4)
            .map(|i| {
                let mut field = layout(4, true, i * 4);
                field.vector_size = 16;
                (format!("v{i}"), field)
            })
            .collect();
        let mut vector = parameter("vector", fields, 16);
        vector.layout.vector = true;
        let mut parameters = vec![integer; 9];
        parameters.extend(vec![floating; 8]);
        parameters.push(vector);
        assert_eq!(
            plan(&parameters, Architecture::Aarch64).unwrap().last(),
            Some(&Location::Stack(16))
        );
        assert_eq!(
            plan(&parameters, Architecture::X86_64).unwrap().last(),
            Some(&Location::Stack(32))
        );
    }
    #[test]
    fn large_arguments_are_indirect_on_arm_and_on_stack_on_x86() {
        let big = parameter(
            "big",
            (0..3)
                .map(|i| (format!("f{i}"), layout(8, false, i * 8)))
                .collect(),
            24,
        );
        assert!(matches!(
            &plan(std::slice::from_ref(&big), Architecture::Aarch64).unwrap()[0],
            Location::Indirect(_)
        ));
        assert_eq!(
            plan(&[big], Architecture::X86_64).unwrap(),
            vec![Location::Stack(0)]
        );
    }
    #[test]
    fn register_exhaustion_preserves_other_register_bank_and_aligns_stack() {
        let integer = Parameter {
            hidden: false,
            name: "x".into(),
            layout: layout(8, false, 0),
            fields: vec![(String::new(), layout(8, false, 0))],
        };
        let floating = Parameter {
            hidden: false,
            name: "f".into(),
            layout: layout(8, true, 0),
            fields: vec![(String::new(), layout(8, true, 0))],
        };
        let pair = parameter(
            "pair",
            vec![
                ("a".into(), layout(8, false, 0)),
                ("b".into(), layout(8, true, 8)),
            ],
            16,
        );
        let mut parameters = vec![integer; 6];
        parameters.push(pair);
        parameters.push(floating);
        let locations = plan(&parameters, Architecture::X86_64).unwrap();
        assert_eq!(locations[6], Location::Stack(0));
        assert_eq!(
            locations[7],
            Location::Registers(vec![Piece {
                offset: 0,
                size: 8,
                index: 0,
                bank: Bank::Float
            }])
        );
    }
}
