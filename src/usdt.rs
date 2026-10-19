//! SystemTap SDT ELF notes and bounded native argument descriptions.
use crate::Result;
use object::{Object, ObjectSection, ObjectSegment, SegmentFlags};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Site {
    pub provider: String,
    pub name: String,
    pub offset: u64,
    pub semaphore_delta: Option<i64>,
    pub arguments: Vec<Argument>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Argument {
    pub size: i8,
    pub expression: String,
}
pub fn sites(tid: i32, path: &str) -> Result<Vec<Site>> {
    let path = if path.starts_with('/') {
        format!("/proc/{tid}/root{path}")
    } else {
        path.into()
    };
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let image = crate::elf_image::Image::new(file)?;
    if let Some(index) = image.index() {
        return index.sites();
    }
    let sites = sites_from_data(&image);
    image.check()?;
    sites
}

pub(crate) fn sites_from_data<'a, R: object::read::ReadRef<'a>>(data: R) -> Result<Vec<Site>> {
    let elf = object::File::parse(data).map_err(|e| e.to_string())?;
    if !elf.is_64() || elf.is_little_endian() != cfg!(target_endian = "little") {
        return Err("native 64-bit SDT notes required".into());
    }
    let Some(section) = elf.section_by_name(".note.stapsdt") else {
        return Ok(Vec::new());
    };
    let bytes = section.data().map_err(|e| e.to_string())?;
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < bytes.len() {
        let header = bytes.get(at..at + 12).ok_or("truncated SDT note header")?;
        let size = |i| u32::from_ne_bytes(header[i..i + 4].try_into().unwrap()) as usize;
        let (namesz, descsz, kind) = (size(0), size(4), size(8));
        at += 12;
        let name = bytes
            .get(at..at.checked_add(namesz).ok_or("SDT note overflow")?)
            .ok_or("truncated SDT name")?;
        at = at
            .checked_add(namesz.checked_add(3).ok_or("SDT note overflow")? & !3)
            .ok_or("SDT note overflow")?;
        let desc = bytes
            .get(at..at.checked_add(descsz).ok_or("SDT note overflow")?)
            .ok_or("truncated SDT descriptor")?;
        at = at
            .checked_add(descsz.checked_add(3).ok_or("SDT note overflow")? & !3)
            .ok_or("SDT note overflow")?;
        if name != b"stapsdt\0" || kind != 3 {
            continue;
        }
        if desc.len() < 24 {
            return Err("truncated 64-bit SDT descriptor".into());
        }
        let address = u64::from_ne_bytes(desc[..8].try_into().unwrap());
        let semaphore = u64::from_ne_bytes(desc[16..24].try_into().unwrap());
        let mut strings = desc[24..].split(|b| *b == 0);
        let mut string = || -> Result<String> {
            String::from_utf8(strings.next().ok_or("missing SDT string")?.to_vec())
                .map_err(|e| e.to_string())
        };
        let provider = string()?;
        let name = string()?;
        let args = string()?;
        let offset = elf
            .segments()
            .find_map(|segment| {
                let (offset, size) = segment.file_range();
                (matches!(segment.flags(),SegmentFlags::Elf{p_flags} if p_flags&1!=0)
                    && address >= segment.address()
                    && address - segment.address() < size)
                    .then(|| offset + address - segment.address())
            })
            .ok_or("SDT site is outside executable segments")?;
        let mut arguments = Vec::new();
        let mut depth = 0i32;
        let mut start = 0;
        for (i, c) in args
            .char_indices()
            .chain(std::iter::once((args.len(), ' ')))
        {
            if c == '(' || c == '[' {
                depth += 1;
            }
            if c == ')' || c == ']' {
                depth -= 1;
            }
            if c.is_whitespace() && depth == 0 {
                if start < i {
                    let arg = &args[start..i];
                    let (size, expression) = arg.split_once('@').ok_or("invalid SDT argument")?;
                    let size = size.parse::<i8>().map_err(|e| e.to_string())?;
                    if ![1, 2, 4, 8].contains(&size.unsigned_abs()) {
                        return Err("SDT argument sizes must be 1/2/4/8 bytes".into());
                    }
                    arguments.push(Argument {
                        size,
                        expression: expression.into(),
                    });
                }
                start = i + c.len_utf8();
            }
        }
        if depth != 0 || arguments.len() > 6 {
            return Err("SDT supports at most six scalar arguments with balanced operands".into());
        }
        out.push(Site {
            provider,
            name,
            offset,
            semaphore_delta: if semaphore == 0 {
                None
            } else {
                Some(semaphore.wrapping_sub(address) as i64)
            },
            arguments,
        });
    }
    Ok(out)
}
pub fn encoded(function: &str) -> Result<Option<Site>> {
    let Some(json) = function.strip_prefix("__sdt__") else {
        return Ok(None);
    };
    let site: Site = serde_json::from_str(json).map_err(|e| format!("invalid SDT binding: {e}"))?;
    if site.arguments.len() > 6
        || site.arguments.iter().any(|arg| {
            ![1, 2, 4, 8].contains(&arg.size.unsigned_abs()) || arg.expression.len() > 4096
        })
    {
        return Err("invalid SDT argument count, size, or expression".into());
    }
    Ok(Some(site))
}
