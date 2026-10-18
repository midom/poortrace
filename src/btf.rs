//! Bounded, read-only BTF type lookup and optional /proc/kcore field reads.
use crate::Result;
use std::{collections::BTreeMap, fs::File, io::Read, os::unix::fs::FileExt};

#[derive(Clone)]
struct Type {
    kind: u32,
    size_type: u32,
    flag: bool,
    data: Vec<u32>,
}
pub struct Database {
    types: Vec<Type>,
    names: BTreeMap<String, Vec<usize>>,
    little: bool,
    strings: Vec<u8>,
}
#[derive(Clone, Debug)]
struct Layout {
    id: usize,
    offset: u64,
    shift: u32,
    width: Option<u32>,
}
fn word(bytes: &[u8], offset: usize, little: bool) -> Result<u32> {
    let data: [u8; 4] = bytes
        .get(offset..offset.checked_add(4).ok_or("BTF offset overflow")?)
        .ok_or("truncated BTF word")?
        .try_into()
        .unwrap();
    Ok(if little {
        u32::from_le_bytes(data)
    } else {
        u32::from_be_bytes(data)
    })
}
impl Database {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_with_name_budget(bytes, 64 * 1024 * 1024)
    }
    fn parse_with_name_budget(bytes: &[u8], mut name_budget: usize) -> Result<Self> {
        if bytes.len() > 64 * 1024 * 1024 || bytes.len() < 24 {
            return Err("BTF input must contain a header and fit 64 MiB".into());
        }
        let little = match &bytes[..2] {
            [0x9f, 0xeb] => true,
            [0xeb, 0x9f] => false,
            _ => return Err("invalid BTF magic".into()),
        };
        if bytes[2] != 1 || bytes[3] != 0 {
            return Err("unsupported BTF version/flags".into());
        }
        let header = word(bytes, 4, little)? as usize;
        if header < 24 || header > bytes.len() {
            return Err("invalid BTF header length".into());
        }
        let section = |offset: usize, length: usize| -> Result<&[u8]> {
            let start = header.checked_add(offset).ok_or("BTF section overflow")?;
            bytes
                .get(start..start.checked_add(length).ok_or("BTF section overflow")?)
                .ok_or_else(|| "truncated BTF section".into())
        };
        let data = section(
            word(bytes, 8, little)? as usize,
            word(bytes, 12, little)? as usize,
        )?;
        let strings = section(
            word(bytes, 16, little)? as usize,
            word(bytes, 20, little)? as usize,
        )?;
        if strings.first() != Some(&0) {
            return Err("BTF string table must begin with NUL".into());
        }
        let name = |offset: u32| -> Result<&str> {
            let rest = strings
                .get(offset as usize..)
                .ok_or("invalid BTF name offset")?;
            let end = rest
                .iter()
                .take(4097)
                .position(|b| *b == 0)
                .ok_or("unterminated/oversized BTF name")?;
            std::str::from_utf8(&rest[..end]).map_err(|e| e.to_string())
        };
        let mut result = Self {
            types: vec![Type {
                kind: 0,
                size_type: 0,
                flag: false,
                data: Vec::new(),
            }],
            names: BTreeMap::new(),
            little,
            strings: strings.to_vec(),
        };
        let mut at = 0usize;
        while at < data.len() {
            if result.types.len() > 262144 {
                return Err("BTF type limit (262144) exceeded".into());
            }
            let info = word(data, at + 4, little)?;
            let kind = info >> 24 & 31;
            let count = (info & 0xffff) as usize;
            if info & 0x60ff0000 != 0 || kind == 0 || kind > 19 {
                return Err("unsupported BTF kind/info".into());
            }
            let extra = match kind {
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => count.checked_mul(12).ok_or("BTF member overflow")?,
                6 | 13 => count.checked_mul(8).ok_or("BTF member overflow")?,
                _ => 0,
            };
            let end = at
                .checked_add(12)
                .and_then(|n| n.checked_add(extra))
                .ok_or("BTF type overflow")?;
            if end > data.len() {
                return Err("truncated BTF type".into());
            }
            let item_name = name(word(data, at, little)?)?;
            let item = Type {
                kind,
                size_type: word(data, at + 8, little)?,
                flag: info >> 31 != 0,
                data: (at + 12..end)
                    .step_by(4)
                    .map(|p| word(data, p, little))
                    .collect::<Result<_>>()?,
            };
            // Member names are string offsets, not type IDs. Resolve them only when needed.
            if !item_name.is_empty() {
                if let Some(ids) = result.names.get_mut(item_name) {
                    ids.push(result.types.len());
                } else {
                    name_budget = name_budget
                        .checked_sub(item_name.len())
                        .ok_or("BTF decoded name budget (64 MiB) exceeded")?;
                    result
                        .names
                        .insert(item_name.to_owned(), vec![result.types.len()]);
                }
            }
            result.types.push(item);
            at = end;
        }
        // Retain member names without keeping a second copy of the complete string table.
        for item in &result.types {
            if matches!(item.kind, 4 | 5) {
                for member in item.data.chunks_exact(3) {
                    name(member[0])?;
                }
            }
        }
        Ok(result)
    }
    fn member_name(&self, offset: u32) -> Result<&str> {
        let tail = self
            .strings
            .get(offset as usize..)
            .ok_or("invalid BTF member name offset")?;
        let end = tail
            .iter()
            .take(4097)
            .position(|b| *b == 0)
            .ok_or("unterminated BTF member name")?;
        std::str::from_utf8(&tail[..end]).map_err(|e| e.to_string())
    }
    fn canonical(&self, mut id: usize) -> Result<usize> {
        for _ in 0..32 {
            let item = self.types.get(id).ok_or("invalid BTF type reference")?;
            if matches!(item.kind, 8..=11 | 17 | 18) {
                id = item.size_type as usize;
            } else if item.kind == 0 {
                return Err("void/invalid BTF type".into());
            } else {
                return Ok(id);
            }
        }
        Err("BTF type nesting limit exceeded".into())
    }
    fn named(&self, name: &str) -> Result<usize> {
        let (kind, name) = if let Some(n) = name.strip_prefix("struct ") {
            (Some(4), n)
        } else if let Some(n) = name.strip_prefix("union ") {
            (Some(5), n)
        } else if let Some(n) = name.strip_prefix("enum ") {
            (Some(6), n)
        } else {
            (None, name)
        };
        let ids = self
            .names
            .get(name)
            .ok_or_else(|| format!("BTF type '{name}' not found"))?;
        let mut found = None;
        for &id in ids {
            if kind.is_some_and(|kind| self.types[id].kind != kind) {
                continue;
            }
            if !matches!(self.types[id].kind, 1..=11 | 16 | 19) {
                continue;
            }
            let id = self.canonical(id)?;
            if found.is_some_and(|old| old != id) {
                return Err(format!("ambiguous BTF type '{name}'"));
            }
            found = Some(id);
        }
        found.ok_or_else(|| format!("BTF type '{name}' not found"))
    }
    fn size(&self, id: usize, depth: usize) -> Result<u64> {
        if depth >= 32 {
            return Err("BTF size nesting limit exceeded".into());
        }
        let item = &self.types[self.canonical(id)?];
        match item.kind {
            1 | 4 | 5 | 6 | 16 | 19 => Ok(item.size_type as u64),
            2 => Ok(8),
            3 => self
                .size(item.data[0] as usize, depth + 1)?
                .checked_mul(item.data[2] as u64)
                .ok_or_else(|| "BTF array size overflow".into()),
            _ => Err("BTF type has no data size".into()),
        }
    }
    pub fn size_of(&self, name: &str) -> Result<u64> {
        self.size(self.named(name)?, 0)
    }
    fn layout(&self, name: &str, path: &str) -> Result<Layout> {
        if path.len() > 4096 {
            return Err("BTF field path too long".into());
        }
        let mut layout = Layout {
            id: self.named(name)?,
            offset: 0,
            shift: 0,
            width: None,
        };
        let mut rest = path;
        let mut steps = 0;
        while !rest.is_empty() {
            steps += 1;
            if steps > 32 {
                return Err("BTF field path nesting limit exceeded".into());
            }
            let id = self.canonical(layout.id)?;
            let item = &self.types[id];
            if rest.starts_with("->") {
                return Err("BTF pointer traversal requires an explicit pointer field read".into());
            }
            rest = rest.strip_prefix('.').unwrap_or(rest);
            if let Some(array) = rest.strip_prefix('[') {
                if item.kind != 3 {
                    return Err("BTF index requires an array".into());
                }
                let (index, tail) = array
                    .split_once(']')
                    .ok_or("unterminated BTF array index")?;
                let index = index.parse::<u64>().map_err(|e| e.to_string())?;
                if index >= item.data[2] as u64 {
                    return Err("BTF array index outside bounds".into());
                }
                layout.offset = layout
                    .offset
                    .checked_add(
                        self.size(item.data[0] as usize, 0)?
                            .checked_mul(index)
                            .ok_or("BTF array offset overflow")?,
                    )
                    .ok_or("BTF offset overflow")?;
                layout.id = item.data[0] as usize;
                rest = tail;
                continue;
            }
            if !matches!(item.kind, 4 | 5) {
                return Err("BTF member selection requires a struct/union".into());
            }
            if layout.width.is_some() {
                return Err("cannot select a member of a bitfield".into());
            }
            let end = rest.find(['.', '[', '-']).unwrap_or(rest.len());
            let field = &rest[..end];
            if field.is_empty() {
                return Err("empty BTF field component".into());
            }
            let mut found = None;
            for member in item.data.chunks_exact(3) {
                if self.member_name(member[0])? == field {
                    if found.is_some() {
                        return Err("ambiguous BTF member".into());
                    }
                    found = Some(member);
                }
            }
            let member = found.ok_or_else(|| format!("BTF field '{field}' not found"))?;
            let bits = if item.flag {
                member[2] & 0xffffff
            } else {
                member[2]
            };
            let width = if item.flag { member[2] >> 24 } else { 0 };
            let extent = if width == 0 {
                self.size(member[1] as usize, 0)?
                    .checked_mul(8)
                    .ok_or("BTF member overflow")?
            } else {
                width as u64
            };
            if (bits as u64)
                .checked_add(extent)
                .is_none_or(|end| end > item.size_type as u64 * 8)
            {
                return Err("BTF member exceeds its object".into());
            }
            layout.offset = layout
                .offset
                .checked_add((bits / 8) as u64)
                .ok_or("BTF field offset overflow")?;
            layout.shift = bits % 8;
            layout.width = (width != 0).then_some(width);
            layout.id = member[1] as usize;
            rest = &rest[end..];
        }
        layout.id = self.canonical(layout.id)?;
        Ok(layout)
    }
    pub fn offset_of(&self, name: &str, path: &str) -> Result<u64> {
        let l = self.layout(name, path)?;
        if l.width.is_some() || l.shift != 0 {
            return Err("offsetof is undefined for bitfields".into());
        }
        Ok(l.offset)
    }
    fn scalar(&self, l: &Layout, bytes: &[u8]) -> Result<u64> {
        let item = &self.types[l.id];
        if !matches!(item.kind, 1 | 2 | 6 | 16 | 19) || bytes.is_empty() || bytes.len() > 8 {
            return Err("BTF field must be a scalar up to 8 bytes".into());
        }
        let mut raw = [0; 8];
        if self.little {
            raw[..bytes.len()].copy_from_slice(bytes);
        } else {
            raw[8 - bytes.len()..].copy_from_slice(bytes);
        }
        let mut value = if self.little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        };
        let (extra, width) = if item.kind == 1 {
            (item.data[0] >> 16 & 255, item.data[0] & 255)
        } else {
            (0, bytes.len() as u32 * 8)
        };
        let width = l.width.unwrap_or(width);
        let shift = l.shift.checked_add(extra).ok_or("BTF bitfield overflow")?;
        if width == 0 || width > 64 || shift + width > bytes.len() as u32 * 8 {
            return Err("invalid BTF bitfield width".into());
        }
        let shift = if self.little {
            shift
        } else {
            bytes.len() as u32 * 8 - shift - width
        };
        value >>= shift;
        if width < 64 {
            value &= (1u64 << width) - 1;
        }
        let signed = if item.kind == 1 {
            item.data[0] >> 24 & 1 != 0
        } else {
            item.flag
        };
        if signed && width < 64 {
            value = ((value << (64 - width)) as i64 >> (64 - width)) as u64;
        }
        Ok(value)
    }
}

#[derive(Default)]
pub struct Reader {
    database: Option<Database>,
    path: Option<std::path::PathBuf>,
    memory: Option<KernelMemory>,
}
impl Reader {
    pub fn configure(&mut self, path: impl Into<std::path::PathBuf>) {
        self.path = Some(path.into());
        self.database = None;
    }
    fn database(&mut self) -> Result<&Database> {
        if self.database.is_none() {
            let path = self
                .path
                .clone()
                .unwrap_or_else(|| "/sys/kernel/btf/vmlinux".into());
            let mut bytes = Vec::new();
            File::open(&path)
                .map_err(|e| format!("BTF {}: {e}", path.display()))?
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            self.database = Some(Database::parse(&bytes)?);
        }
        Ok(self.database.as_ref().unwrap())
    }
    pub fn function_exists(&mut self, name: &str) -> Result<bool> {
        let db = self.database()?;
        Ok(db
            .names
            .get(name)
            .is_some_and(|ids| ids.iter().any(|id| db.types[*id].kind == 12)))
    }
    pub fn size_of(&mut self, name: &str) -> Result<u64> {
        self.database()?.size_of(name)
    }
    pub fn offset_of(&mut self, name: &str, path: &str) -> Result<u64> {
        self.database()?.offset_of(name, path)
    }
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>> {
        if self.memory.is_none() {
            self.memory = Some(KernelMemory::open()?);
        }
        self.memory.as_ref().unwrap().read(address, length)
    }
    pub fn field(&mut self, address: u64, name: &str, path: &str) -> Result<u64> {
        let layout = self.database()?.layout(name, path)?;
        let size = self.database()?.size(layout.id, 0)?;
        let size = if let Some(bits) = layout.width {
            ((layout.shift + bits) as u64).div_ceil(8)
        } else {
            size
        };
        if !(1..=8).contains(&size) {
            return Err("numeric kernel field must fit 1..8 bytes".into());
        }
        let bytes = self.read(
            address
                .checked_add(layout.offset)
                .ok_or("kernel address overflow")?,
            size as usize,
        )?;
        self.database()?.scalar(&layout, &bytes)
    }
    pub fn field_string(&mut self, address: u64, name: &str, path: &str) -> Result<String> {
        let l = self.database()?.layout(name, path)?;
        let kind = self.database()?.types[l.id].kind;
        let size = self.database()?.size(l.id, 0)?;
        if kind == 3 && size <= 4096 {
            let element = self.database()?.types[l.id].data[0] as usize;
            if self.database()?.size(element, 0)? != 1 {
                return Err("kernel string field must be a byte array".into());
            }
            let bytes = self.read(
                address
                    .checked_add(l.offset)
                    .ok_or("kernel address overflow")?,
                size as usize,
            )?;
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            return Ok(String::from_utf8_lossy(&bytes[..end]).into_owned());
        }
        let value = self.field(address, name, path)?;
        let item = &self.database()?.types[l.id];
        Ok(if item.kind == 16 && size == 4 {
            (f32::from_bits(value as u32)).to_string()
        } else if item.kind == 16 && size == 8 {
            f64::from_bits(value).to_string()
        } else if (item.kind == 1 && item.data[0] >> 24 & 1 != 0) || item.flag {
            (value as i64).to_string()
        } else {
            value.to_string()
        })
    }
}
struct KernelMemory {
    file: File,
    segments: Vec<(u64, u64, u64)>,
}
impl KernelMemory {
    fn open() -> Result<Self> {
        let file = File::open("/proc/kcore")
            .map_err(|e| format!("kernel field reads require permitted /proc/kcore access: {e}"))?;
        let mut h = [0u8; 64];
        file.read_exact_at(&mut h, 0).map_err(|e| e.to_string())?;
        if &h[..4] != b"\x7fELF"
            || h[4] != 2
            || h[5] != if cfg!(target_endian = "little") { 1 } else { 2 }
        {
            return Err("kcore must be native-endian ELF64".into());
        }
        let offset = u64::from_ne_bytes(h[32..40].try_into().unwrap());
        let width = u16::from_ne_bytes(h[54..56].try_into().unwrap()) as usize;
        let count = u16::from_ne_bytes(h[56..58].try_into().unwrap()) as usize;
        if !(56..=256).contains(&width) || count > 4096 {
            return Err("invalid kcore program header bounds".into());
        }
        let mut segments = Vec::new();
        for i in 0..count {
            let mut p = vec![0; width];
            let at = offset
                .checked_add((i * width) as u64)
                .ok_or("kcore header overflow")?;
            file.read_exact_at(&mut p, at).map_err(|e| e.to_string())?;
            if u32::from_ne_bytes(p[..4].try_into().unwrap()) == 1 {
                let off = u64::from_ne_bytes(p[8..16].try_into().unwrap());
                let addr = u64::from_ne_bytes(p[16..24].try_into().unwrap());
                let size = u64::from_ne_bytes(p[32..40].try_into().unwrap());
                addr.checked_add(size).ok_or("kcore address overflow")?;
                off.checked_add(size).ok_or("kcore file offset overflow")?;
                segments.push((addr, size, off));
            }
        }
        Ok(Self { file, segments })
    }
    fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 || length > 4096 {
            return Err("kernel memory read must contain 1..4096 bytes".into());
        }
        let end = address
            .checked_add(length as u64)
            .ok_or("kernel memory address overflow")?;
        let &(start, _, offset) = self
            .segments
            .iter()
            .find(|(start, size, _)| address >= *start && end <= start + size)
            .ok_or("kernel address is outside readable kcore segments")?;
        let mut bytes = vec![0; length];
        self.file
            .read_exact_at(&mut bytes, offset + (address - start))
            .map_err(|e| format!("kernel memory read: {e}"))?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let strings = b"\0int\0Pair\0a\0b\0Bits\0flag\0";
        let words = [
            1,
            1 << 24,
            4,
            (1 << 24) | 32,
            5,
            (4 << 24) | 2,
            8,
            10,
            1,
            0,
            12,
            1,
            32,
            14,
            (1 << 31) | (4 << 24) | 1,
            4,
            19,
            1,
            (3 << 24) | 1,
        ];
        let types: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for n in [
            24,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            bytes.extend(n.to_le_bytes());
        }
        bytes.extend(types);
        bytes.extend(strings);
        bytes
    }
    #[test]
    fn bounded_types_offsets_signed_bitfields_and_corruption() {
        let bytes = fixture();
        let db = Database::parse(&bytes).unwrap();
        assert!(Database::parse_with_name_budget(&bytes, 0).is_err());
        assert!(Database::parse_with_name_budget(&bytes, 11).is_ok());
        assert_eq!(db.size_of("struct Pair").unwrap(), 8);
        assert_eq!(db.offset_of("Pair", "b").unwrap(), 4);
        let layout = db.layout("Bits", "flag").unwrap();
        assert_eq!(db.scalar(&layout, &[0b1110]).unwrap(), (-1i64) as u64);
        assert!(db.offset_of("Bits", "flag").is_err());
        assert!(db.offset_of("Pair", "absent").is_err());
        for length in 0..24 {
            assert!(Database::parse(&bytes[..length]).is_err());
        }
        let mut corrupt = bytes.clone();
        corrupt[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Database::parse(&corrupt).is_err());
        let mut cycle = fixture();
        cycle[28..32].copy_from_slice(&(8u32 << 24).to_le_bytes());
        cycle[32..36].copy_from_slice(&1u32.to_le_bytes());
        assert!(Database::parse(&cycle).is_err());
    }
}
