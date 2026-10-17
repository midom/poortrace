//! Grouped per-thread counter reads, with explicit enabled/running times.
use crate::{Result, language::Probe};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[repr(C)]
#[derive(Default)]
struct Attr {
    kind: u32,
    size: u32,
    config: u64,
    period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup: u32,
    bp_type: u32,
    config1: u64,
}
#[derive(Clone, Debug, serde::Serialize)]
pub struct Reading {
    pub event: String,
    pub raw: u64,
    pub enabled_ns: u64,
    pub running_ns: u64,
    pub scaled: Option<f64>,
}
pub struct Group {
    pub tid: i32,
    files: Vec<OwnedFd>,
    names: Vec<String>,
}
impl Group {
    pub fn open(tid: i32, events: &[String], on_exec: bool) -> Result<Self> {
        if events.is_empty() || events.len() > 16 {
            return Err("counter groups need 1..16 events".into());
        }
        let mut files: Vec<OwnedFd> = Vec::new();
        for name in events {
            let Probe::Perf { kind, config, .. } = Probe::parse(name)? else {
                return Err(
                    "counter events must be hardware, software, raw, cache, or pmu events".into(),
                );
            };
            let attr = Attr {
                kind,
                size: size_of::<Attr>() as u32,
                config,
                read_format: 11,
                flags: 1 | 1 << 5 | 1 << 6 | if on_exec { 1 << 12 } else { 0 },
                ..Attr::default()
            };
            let leader = files.first().map(AsRawFd::as_raw_fd).unwrap_or(-1);
            let fd = unsafe {
                libc::syscall(libc::SYS_perf_event_open, &attr, tid, -1i32, leader, 8u64)
            };
            if fd < 0 {
                return Err(format!(
                    "counter {name} TID {tid}: {} (host perf policy/PMU constraints apply)",
                    std::io::Error::last_os_error()
                ));
            }
            files.push(unsafe { OwnedFd::from_raw_fd(fd as i32) });
        }
        Ok(Self {
            tid,
            files,
            names: events.to_vec(),
        })
    }
    pub fn enable(&self) -> Result<()> {
        self.control(0x2400)
    }
    pub fn disable(&self) -> Result<()> {
        self.control(0x2401)
    }
    fn control(&self, op: libc::c_ulong) -> Result<()> {
        if unsafe { libc::ioctl(self.files[0].as_raw_fd(), op, 1) } < 0 {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }
    pub fn read(&self) -> Result<Vec<Reading>> {
        let mut bytes = vec![0u8; (3 + self.names.len()) * 8];
        let n = unsafe {
            libc::read(
                self.files[0].as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if n < 0 {
            return Err(format!("counter read: {}", std::io::Error::last_os_error()));
        }
        decode(&bytes[..n as usize], &self.names)
    }
}
fn decode(bytes: &[u8], names: &[String]) -> Result<Vec<Reading>> {
    if bytes.len() != (3 + names.len()) * 8 {
        return Err("short or unscheduled perf counter group read".into());
    }
    let values: Vec<u64> = bytes
        .chunks_exact(8)
        .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
        .collect();
    if values[0] as usize != names.len() {
        return Err("perf counter group size mismatch".into());
    }
    let enabled = values[1];
    let running = values[2];
    if running > enabled {
        return Err("invalid perf counter scheduling times".into());
    }
    Ok(names
        .iter()
        .zip(&values[3..])
        .map(|(name, &raw)| Reading {
            event: name.clone(),
            raw,
            enabled_ns: enabled,
            running_ns: running,
            scaled: if running == 0 {
                None
            } else {
                Some(raw as f64 * enabled as f64 / running as f64)
            },
        })
        .collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scaling_is_explicit_and_unscheduled_is_not_zero() {
        let bytes: Vec<u8> = [1u64, 100, 50, 30]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect();
        let result = decode(&bytes, &["cycles".into()]).unwrap();
        assert_eq!(result[0].scaled, Some(60.0));
        assert!(decode(&bytes[..8], &["cycles".into()]).is_err());
        let bytes: Vec<u8> = [1u64, 100, 0, 0]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect();
        assert_eq!(decode(&bytes, &["cycles".into()]).unwrap()[0].scaled, None);
    }
}
