//! Read-only Go goroutine identification from target DWARF, never fixed offsets.
//! Runtime states follow Go runtime/runtime2.go; all memory reads are bounded.
use crate::{
    Result, memory,
    perf::{Sample, UserRegs},
    symbols::Symbolizer,
    types,
};
#[path = "golang_pcln.rs"]
mod pcln;
use object::{Object, ObjectSegment, ObjectSymbol};
use std::{collections::BTreeMap, io::Read, os::unix::fs::MetadataExt};

#[derive(Default)]
pub struct Reader {
    types: types::Reader,
    processes: BTreeMap<u32, Layout>,
    symbols: Symbolizer,
}
struct Layout {
    identity: String,
    allgs: u64,
    fields: BTreeMap<String, (u64, usize)>,
    pcln: Option<pcln::Image>,
}
fn word(pid: u32, address: u64) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        memory::read(pid, address, 8, false)?.try_into().unwrap(),
    ))
}
fn add(address: u64, offset: u64) -> Result<u64> {
    address
        .checked_add(offset)
        .ok_or_else(|| "Go address overflow".into())
}
impl Layout {
    fn field(&self, pid: u32, base: u64, name: &str) -> Result<u64> {
        let &(offset, size) = self
            .fields
            .get(name)
            .ok_or_else(|| format!("missing Go field {name}"))?;
        let bytes = memory::read(pid, add(base, offset)?, size, false)?;
        Ok(match size {
            1 => bytes[0] as u64,
            4 => u32::from_ne_bytes(bytes.try_into().unwrap()) as u64,
            8 => u64::from_ne_bytes(bytes.try_into().unwrap()),
            _ => return Err("unsupported Go field width".into()),
        })
    }
    // A stripped Go ELF keeps reflection types but drops the allgs symbol.
    // Find a unique live slice whose elements validate as goroutines. This is
    // bounded observation, not an assumed linker-specific global offset.
    fn find_allgs(&self, pid: u32) -> Result<u64> {
        let image = self.pcln.as_ref().ok_or("Go allgs metadata unavailable")?;
        let mut found = None;
        let mut candidates = 0;
        for &(data_address, data_size) in &image.globals {
            for start in (0..data_size).step_by(4080) {
                let bytes = memory::read(
                    pid,
                    add(data_address, start as u64)?,
                    (data_size - start).min(4096),
                    false,
                )?;
                for index in (0..bytes.len().saturating_sub(23)).step_by(8) {
                    let read =
                        |n| u64::from_ne_bytes(bytes[index + n..index + n + 8].try_into().unwrap());
                    let (data, len, cap) = (read(0), read(8), read(16));
                    if data == 0
                        || data & 7 != 0
                        || !(2..=65536).contains(&len)
                        || len > cap
                        || cap > 1048576
                    {
                        continue;
                    }
                    candidates += 1;
                    if candidates > 512 {
                        return Err("stripped Go slice discovery exceeded candidate budget".into());
                    }
                    let Ok(gs) = memory::read(pid, data, (len.min(32) * 8) as usize, false) else {
                        continue;
                    };
                    let mut ids = std::collections::BTreeSet::new();
                    let valid = gs.chunks_exact(8).all(|b| {
                        let g = u64::from_ne_bytes(b.try_into().unwrap());
                        if g < 4096 || g & 7 != 0 {
                            return false;
                        }
                        let check = (|| -> Result<bool> {
                            let id = self.field(pid, g, "g.goid")?;
                            let status = self.field(pid, g, "g.atomicstatus.value")?;
                            let lo = self.field(pid, g, "g.stack.lo")?;
                            let hi = self.field(pid, g, "g.stack.hi")?;
                            if status & !0x1000 == 6 && lo == 0 && hi == 0 {
                                return Ok(true);
                            }
                            Ok(id > 0
                                && id < 1u64 << 48
                                && status & !0x1000 <= 9
                                && lo > 0
                                && hi > lo
                                && hi - lo <= 1024 * 1024 * 1024
                                && ids.insert(id))
                        })();
                        check.unwrap_or(false)
                    });
                    if !valid || !ids.contains(&1) {
                        continue;
                    }
                    let address = data_address + start as u64 + index as u64;
                    if found.replace(address).is_some() {
                        return Err("ambiguous stripped Go goroutine slice".into());
                    }
                }
            }
        }
        found.ok_or_else(|| "stripped Go goroutine slice unavailable or raced".into())
    }
    fn state(&self, pid: u32, g: u64) -> Result<(u64, u64, u64, u64)> {
        let id = self.field(pid, g, "g.goid")?;
        let status = self.field(pid, g, "g.atomicstatus.value")?;
        let lo = self.field(pid, g, "g.stack.lo")?;
        let hi = self.field(pid, g, "g.stack.hi")?;
        if id == 0 || lo == 0 || hi <= lo || hi - lo > 1024 * 1024 * 1024 {
            return Err("invalid Go goroutine identity/stack".into());
        }
        Ok((id, status, lo, hi))
    }
}
impl Reader {
    fn layout(&mut self, pid: u32) -> Result<&Layout> {
        let path = format!("/proc/{pid}/exe");
        let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
        let maps =
            std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
        let identity = format!(
            "{}:{}:{}:{}:{}",
            meta.dev(),
            meta.ino(),
            meta.mtime(),
            meta.mtime_nsec(),
            maps.lines().next().unwrap_or("")
        );
        if self
            .processes
            .get(&pid)
            .is_none_or(|layout| layout.identity != identity)
        {
            let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
            if meta.len() > 128 * 1024 * 1024 {
                return Err("Go image exceeds128MiB".into());
            }
            let mut bytes = Vec::new();
            file.take(128 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 128 * 1024 * 1024 {
                return Err("Go image exceeds 128 MiB".into());
            }
            let elf = object::File::parse(bytes.as_slice()).map_err(|e| e.to_string())?;
            #[cfg(target_arch = "aarch64")]
            let native = object::Architecture::Aarch64;
            #[cfg(target_arch = "x86_64")]
            let native = object::Architecture::X86_64;
            if !elf.is_64()
                || elf.architecture() != native
                || elf.is_little_endian() != cfg!(target_endian = "little")
            {
                return Err("Go image architecture mismatch".into());
            }
            let exe = std::fs::read_link(&path)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_owned();
            let bias = maps
                .lines()
                .filter_map(crate::symbols::Mapping::parse)
                .filter(|map| map.path == exe)
                .find_map(|map| {
                    elf.segments().find_map(|segment| {
                        let (offset, size) = segment.file_range();
                        (map.offset >= offset && map.offset - offset < size).then(|| {
                            map.start
                                .wrapping_sub(segment.address().wrapping_add(map.offset - offset))
                        })
                    })
                })
                .ok_or("Go image load bias unavailable")?;
            let allgs = elf
                .symbols()
                .chain(elf.dynamic_symbols())
                .find(|symbol| {
                    !symbol.is_undefined() && symbol.name().ok() == Some("runtime.allgs")
                })
                .map(|symbol| bias.wrapping_add(symbol.address()))
                .unwrap_or(0);
            let mut fields = BTreeMap::new();
            let dwarf = (|| -> Result<()> {
                for (name, field) in [
                    ("runtime.g", "goid"),
                    ("runtime.g", "m"),
                    ("runtime.g", "atomicstatus.value"),
                    ("runtime.g", "stack.lo"),
                    ("runtime.g", "stack.hi"),
                    ("runtime.g", "sched.sp"),
                    ("runtime.g", "sched.pc"),
                    ("runtime.g", "sched.bp"),
                    ("runtime.g", "sched.lr"),
                    ("runtime.m", "procid"),
                    ("runtime.m", "curg"),
                ] {
                    let layout = self.types.layout(pid, "", name, field)?;
                    if !layout.scalar
                        || layout.float
                        || layout.vector
                        || layout.bits.is_some()
                        || !layout.dereferences.is_empty()
                        || layout.size != if field == "atomicstatus.value" { 4 } else { 8 }
                        || layout.offset > 1024 * 1024
                    {
                        return Err(format!("unsupported Go DWARF layout {name}.{field}"));
                    }
                    fields.insert(
                        format!("{}.{}", name.strip_prefix("runtime.").unwrap(), field),
                        (layout.offset, layout.size as usize),
                    );
                }
                Ok(())
            })();
            let pcln = if dwarf.is_err() || allgs == 0 {
                let (image, recovered) = pcln::Image::parse(&elf, bias)?;
                fields = recovered;
                Some(image)
            } else {
                None
            };
            if self.processes.len() >= 16 {
                self.processes.clear();
            }
            self.processes.insert(
                pid,
                Layout {
                    identity,
                    allgs,
                    fields,
                    pcln,
                },
            );
        }
        Ok(&self.processes[&pid])
    }
    /// Identify the goroutine carried in the captured Go register. Heap metadata
    /// is live and checked before and after unwind; migration/reuse is observable.
    pub fn stack(
        &mut self,
        pid: u32,
        tid: u32,
        depth: usize,
        snapshot: Option<&(UserRegs, Vec<u8>)>,
    ) -> Result<String> {
        let regs = match snapshot {
            Some((regs, _)) => *regs,
            None => crate::functions::user_registers(tid as i32)?,
        };
        let g = regs.runtime_g;
        if g == 0 || g & 7 != 0 {
            return Err("captured Go goroutine register is unavailable".into());
        }
        let layout = self.layout(pid)?;
        let before = layout.state(pid, g)?;
        if ![2, 3].contains(&before.1) {
            return Err(
                "Go goroutine is migrating, scanning, or no longer running on the sampled thread"
                    .into(),
            );
        }
        let m = layout.field(pid, g, "g.m")?;
        if m == 0
            || layout.field(pid, m, "m.procid")? != tid as u64
            || layout.field(pid, m, "m.curg")? != g
        {
            return Err(
                "Go goroutine register is a system goroutine or no longer belongs to this thread"
                    .into(),
            );
        }
        if regs.sp < before.2 || regs.sp >= before.3 {
            return Err(
                "sampled stack is outside the Go goroutine stack (cgo/system stack)".into(),
            );
        }
        let stack = match snapshot {
            Some((_, bytes)) => bytes.clone(),
            None => memory::read_stack(pid, regs.sp, (before.3 - regs.sp).min(32768) as usize)?,
        };
        let sample = Sample {
            pid,
            tid,
            ip: regs.ip,
            regs: Some(regs),
            stack,
            ..Sample::default()
        };
        let mut frames = match &self.processes[&pid].pcln {
            Some(image) => image.unwind(regs, &sample.stack, depth),
            None => self.symbols.unwind(&sample),
        };
        frames.truncate(depth.min(127));
        let layout = &self.processes[&pid];
        if layout.state(pid, g)? != before
            || layout.field(pid, g, "g.m")? != m
            || layout.field(pid, m, "m.curg")? != g
            || layout.field(pid, m, "m.procid")? != tid as u64
        {
            return Err("Go goroutine moved during capture".into());
        }
        Ok(format!(
            "    goroutine {}\n{}",
            before.0,
            match &layout.pcln {
                Some(image) => image.stack(&frames),
                None => self.symbols.stack(pid, &frames),
            }
        ))
    }
    /// Best-effort parked snapshots. A waiting goroutine's stack can move while
    /// another thread runs; every saved context and status is rechecked afterward.
    pub fn parked(&mut self, pid: u32, depth: usize, limit: usize) -> Result<String> {
        let layout = self.layout(pid)?;
        let allgs = if layout.allgs != 0 {
            layout.allgs
        } else {
            layout.find_allgs(pid)?
        };
        let data = word(pid, allgs)?;
        let length = word(pid, add(allgs, 8)?)?;
        let capacity = word(pid, add(allgs, 16)?)?;
        if length > 65536 || length > capacity || data == 0 {
            return Err("Go allgs slice exceeds65536goroutines or is inconsistent".into());
        }
        let mut gs = Vec::new();
        for start in (0..length as usize).step_by(512) {
            let bytes = memory::read(
                pid,
                add(data, start as u64 * 8)?,
                (length as usize - start).min(512) * 8,
                false,
            )?;
            gs.extend(
                bytes
                    .chunks_exact(8)
                    .map(|b| u64::from_ne_bytes(b.try_into().unwrap())),
            );
        }
        let mut output = String::new();
        let mut emitted = 0;
        for g in gs {
            if g == 0 || emitted >= limit.min(1024) {
                continue;
            }
            let layout = &self.processes[&pid];
            let Ok(before) = layout.state(pid, g) else {
                continue;
            };
            if before.1 != 4 {
                continue;
            }
            let regs = UserRegs {
                ip: layout.field(pid, g, "g.sched.pc")?,
                sp: layout.field(pid, g, "g.sched.sp")?,
                fp: layout.field(pid, g, "g.sched.bp")?,
                lr: layout.field(pid, g, "g.sched.lr")?,
                runtime_g: g,
            };
            if regs.sp < before.2 || regs.sp >= before.3 {
                continue;
            }
            emitted += 1;
            let stack = memory::read_stack(pid, regs.sp, (before.3 - regs.sp).min(32768) as usize)?;
            let sample = Sample {
                pid,
                ip: regs.ip,
                regs: Some(regs),
                stack,
                ..Sample::default()
            };
            let mut frames = match &self.processes[&pid].pcln {
                Some(image) => image.unwind(regs, &sample.stack, depth),
                None => self.symbols.unwind(&sample),
            };
            frames.truncate(depth.min(127));
            let layout = &self.processes[&pid];
            if layout.state(pid, g)? != before
                || layout.field(pid, g, "g.sched.sp")? != regs.sp
                || layout.field(pid, g, "g.sched.pc")? != regs.ip
                || layout.field(pid, g, "g.sched.bp")? != regs.fp
                || layout.field(pid, g, "g.sched.lr")? != regs.lr
            {
                output.push_str("    <parked Go goroutine changed during capture>\n");
                continue;
            }
            let rendered = format!(
                "    goroutine {} [parked; observed]\n{}",
                before.0,
                match &layout.pcln {
                    Some(image) => image.stack(&frames),
                    None => self.symbols.stack(pid, &frames),
                }
            );
            if output.len() + rendered.len() > 512 * 1024 {
                output.push_str("    <Go goroutine output truncated at 512 KiB>\n");
                break;
            }
            output.push_str(&rendered);
        }
        if output.is_empty() {
            output.push_str("    <no stable parked Go goroutine>\n");
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_fields_and_goroutine_bounds_are_validated() {
        let layout = Layout {
            identity: String::new(),
            pcln: None,
            allgs: 0,
            fields: [
                ("g.goid".into(), (0, 8)),
                ("g.atomicstatus.value".into(), (8, 4)),
                ("g.stack.lo".into(), (16, 8)),
                ("g.stack.hi".into(), (24, 8)),
            ]
            .into_iter()
            .collect(),
        };
        let pid = std::process::id();
        let mut data = [7u64, 2, 100, 200];
        let address = data.as_ptr() as u64;
        std::hint::black_box(&data);
        assert_eq!(layout.state(pid, address).unwrap(), (7, 2, 100, 200));
        data[3] = 99;
        std::hint::black_box(&data);
        assert!(layout.state(pid, address).is_err());
        data[3] = 200;
        data[0] = 0;
        std::hint::black_box(&data);
        assert!(layout.state(pid, address).is_err());
        assert!(layout.field(pid, address, "g.missing").is_err());
        assert!(add(u64::MAX, 1).is_err());
    }
}
