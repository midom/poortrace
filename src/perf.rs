//! Linux perf_event_open and the forward mmap ring protocol, with no BPF attachment.
use crate::{Result, language::Probe};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering, fence},
};

const SAMPLE_TYPE: u64 = 1 | 2 | 4 | 128 | 256; // IP, TID, TIME, CPU, PERIOD
#[repr(C)]
#[derive(Default)]
struct Attr {
    kind: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub time: u64,
    pub ip: u64,
    pub period: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Sample(Sample),
    Comm { pid: u32, tid: u32, name: String },
    Lost(u64),
    Other,
}

pub struct PerfEvent {
    fd: OwnedFd,
    mapping: NonNull<c_void>,
    mapping_len: usize,
    offset: usize,
    size: usize,
    tail: u64,
}
impl PerfEvent {
    pub fn open(tid: i32, probe: &Probe, pages: usize) -> Result<Self> {
        Self::open_inner(tid, probe, pages, false)
    }
    /// Leave the event disabled until the target calls exec, excluding the
    /// launcher's setup work between fork and exec from command measurements.
    pub fn open_on_exec(tid: i32, probe: &Probe, pages: usize) -> Result<Self> {
        Self::open_inner(tid, probe, pages, true)
    }
    fn open_inner(tid: i32, probe: &Probe, pages: usize, on_exec: bool) -> Result<Self> {
        if tid <= 0 {
            return Err("perf target TID must be positive".into());
        }
        if !pages.is_power_of_two() || pages > 1024 {
            return Err("mmap pages must be a power of two from 1 to 1024".into());
        }
        let Probe::Perf {
            kind,
            config,
            period,
            frequency,
        } = probe
        else {
            return Err("not a perf probe".into());
        };
        let attr = Attr {
            kind: *kind,
            size: size_of::<Attr>() as u32,
            config: *config,
            sample_period: *period,
            sample_type: SAMPLE_TYPE,
            // Per-thread, user-mode only, initially disabled. Inherit is deliberately
            // off: inherited events with cpu=-1 cannot use an mmap sample buffer.
            flags: 1
                | (1 << 5)
                | (1 << 6)
                | (1 << 9)
                | if *frequency { 1 << 10 } else { 0 }
                | if on_exec { 1 << 12 } else { 0 },
            wakeup_events: 1,
            ..Attr::default()
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &attr as *const Attr,
                tid,
                -1i32,
                -1i32,
                8u64,
            )
        };
        if fd < 0 {
            return Err(open_error(tid, io::Error::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = (pages + 1) * page_size;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(format!(
                "perf mmap: {} (check perf_event_mlock_kb and --mmap-pages)",
                io::Error::last_os_error()
            ));
        }
        let mut event = Self {
            fd,
            mapping: NonNull::new(mapping).unwrap(),
            mapping_len: len,
            offset: page_size,
            size: pages * page_size,
            tail: 0,
        };
        // UAPI offsets in perf_event_mmap_page are architecture independent.
        let offset = unsafe { event.base().add(1040).cast::<u64>().read_volatile() } as usize;
        let size = unsafe { event.base().add(1048).cast::<u64>().read_volatile() } as usize;
        if offset != 0 {
            event.offset = offset;
        }
        if size != 0 {
            event.size = size;
        }
        if !event.size.is_power_of_two()
            || event.offset < page_size
            || event.offset.checked_add(event.size).is_none_or(|n| n > len)
        {
            return Err("invalid perf ring metadata".into());
        }
        Ok(event)
    }
    fn base(&self) -> *mut u8 {
        self.mapping.as_ptr().cast()
    }
    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub fn enable(&self) -> Result<()> {
        self.control(0x2400)
    }
    pub fn disable(&self) -> Result<()> {
        self.control(0x2401)
    }
    fn control(&self, request: libc::c_ulong) -> Result<()> {
        if unsafe { libc::ioctl(self.fd(), request, 0) } < 0 {
            Err(format!("perf ioctl: {}", io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
    pub fn drain(&mut self) -> Result<Vec<Record>> {
        let head = unsafe { &*self.base().add(1024).cast::<AtomicU64>() }.load(Ordering::Acquire);
        let available = head.wrapping_sub(self.tail);
        if available > self.size as u64 {
            return Err("perf ring overrun/corrupt head".into());
        }
        let mut records = Vec::new();
        while self.tail != head {
            if head.wrapping_sub(self.tail) < 8 {
                return Err("truncated perf record header".into());
            }
            let mut header = [0u8; 8];
            self.copy(self.tail, &mut header);
            let size = u16::from_ne_bytes(header[6..8].try_into().unwrap()) as usize;
            if size < 8 || size as u64 > head.wrapping_sub(self.tail) || size > self.size {
                return Err("invalid perf record size".into());
            }
            let mut bytes = vec![0; size];
            self.copy(self.tail, &mut bytes);
            records.push(decode(&bytes)?);
            self.tail = self.tail.wrapping_add(size as u64);
        }
        // The kernel must not reuse these bytes until all our reads complete.
        // A full fence implements the perf UAPI's smp_mb before publishing tail.
        fence(Ordering::SeqCst);
        unsafe { &*self.base().add(1032).cast::<AtomicU64>() }.store(self.tail, Ordering::Release);
        Ok(records)
    }
    fn copy(&self, tail: u64, dst: &mut [u8]) {
        let start = tail as usize & (self.size - 1);
        let first = dst.len().min(self.size - start);
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.base().add(self.offset + start),
                dst.as_mut_ptr(),
                first,
            );
            std::ptr::copy_nonoverlapping(
                self.base().add(self.offset),
                dst.as_mut_ptr().add(first),
                dst.len() - first,
            );
        }
    }
}
impl Drop for PerfEvent {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping.as_ptr(), self.mapping_len);
        }
    }
}

fn open_error(tid: i32, error: io::Error) -> String {
    let policy = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .unwrap_or_else(|_| "unknown".into());
    let hint = match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => {
            "access denied by host perf policy, credentials, or sandbox; user-only per-task events generally require perf_event_paranoid <= 2 (some distributions block all unprivileged perf at higher values)"
        }
        Some(libc::ENOENT | libc::EOPNOTSUPP | libc::ENODEV) => {
            "event/PMU not available on this host; try software:cpu-clock or profile:hz:99"
        }
        Some(libc::EINVAL) => "event or requested sampling mode is unsupported by this kernel/PMU",
        _ => "check the target TID, event availability, and file descriptor limits",
    };
    format!(
        "perf_event_open(tid={tid}): {error}; {hint}; perf_event_paranoid={}",
        policy.trim()
    )
}

fn decode(bytes: &[u8]) -> Result<Record> {
    if bytes.len() < 8 {
        return Err("short perf header".into());
    }
    let declared = u16::from_ne_bytes(bytes[6..8].try_into().unwrap()) as usize;
    if declared != bytes.len() {
        return Err("perf record size mismatch".into());
    }
    let kind = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let u64_at = |i| u64::from_ne_bytes(bytes[i..i + 8].try_into().unwrap());
    let u32_at = |i| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
    match kind {
        9 if bytes.len() >= 48 => Ok(Record::Sample(Sample {
            ip: u64_at(8),
            pid: u32_at(16),
            tid: u32_at(20),
            time: u64_at(24),
            cpu: u32_at(32),
            period: u64_at(40),
        })),
        2 if bytes.len() >= 24 => Ok(Record::Lost(u64_at(16))),
        13 if bytes.len() >= 16 => Ok(Record::Lost(u64_at(8))),
        3 if bytes.len() >= 17 => {
            let end = bytes[16..]
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated perf comm record")?;
            Ok(Record::Comm {
                pid: u32_at(8),
                tid: u32_at(12),
                name: String::from_utf8_lossy(&bytes[16..16 + end]).into_owned(),
            })
        }
        9 | 2 | 13 | 3 => Err("truncated perf sample/lost/comm record".into()),
        _ => Ok(Record::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(kind: u32, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(kind.to_ne_bytes());
        b.extend(0u16.to_ne_bytes());
        b.extend(((data.len() + 8) as u16).to_ne_bytes());
        b.extend(data);
        b
    }
    #[test]
    fn decode_sample_and_loss() {
        let mut p = Vec::new();
        p.extend(0x1234u64.to_ne_bytes());
        p.extend(10u32.to_ne_bytes());
        p.extend(11u32.to_ne_bytes());
        p.extend(55u64.to_ne_bytes());
        p.extend(3u32.to_ne_bytes());
        p.extend(0u32.to_ne_bytes());
        p.extend(100u64.to_ne_bytes());
        assert_eq!(
            decode(&record(9, &p)).unwrap(),
            Record::Sample(Sample {
                ip: 0x1234,
                pid: 10,
                tid: 11,
                time: 55,
                cpu: 3,
                period: 100
            })
        );
        assert_eq!(
            decode(&record(
                2,
                &[0u64.to_ne_bytes(), 7u64.to_ne_bytes()].concat()
            ))
            .unwrap(),
            Record::Lost(7)
        );
        assert!(decode(&record(9, &[])).is_err());
    }
    #[test]
    fn command_names_and_malformed_records() {
        let mut payload = Vec::new();
        payload.extend(10u32.to_ne_bytes());
        payload.extend(11u32.to_ne_bytes());
        payload.extend(b"worker\0\0");
        assert_eq!(
            decode(&record(3, &payload)).unwrap(),
            Record::Comm {
                pid: 10,
                tid: 11,
                name: "worker".into()
            }
        );
        payload.truncate(14); // no terminator
        assert!(decode(&record(3, &payload)).is_err());
        assert!(decode(&[0; 4]).is_err());
        let mut bad_size = record(13, &42u64.to_ne_bytes());
        bad_size[6] = 0;
        assert!(decode(&bad_size).is_err());
    }
    #[test]
    fn wrapped_ring_and_tail_publication() {
        let len = 8192;
        let memory = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(memory, libc::MAP_FAILED);
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        let mut ring = PerfEvent {
            fd,
            mapping: NonNull::new(memory).unwrap(),
            mapping_len: len,
            offset: 4096,
            size: 4096,
            tail: 4092,
        };
        let bytes = record(13, &42u64.to_ne_bytes());
        for (i, b) in bytes.iter().enumerate() {
            unsafe {
                ring.base().add(4096 + ((4092 + i) & 4095)).write(*b);
            }
        }
        unsafe { &*ring.base().add(1024).cast::<AtomicU64>() }.store(4108, Ordering::Release);
        assert_eq!(ring.drain().unwrap(), vec![Record::Lost(42)]);
        assert_eq!(
            unsafe { &*ring.base().add(1032).cast::<AtomicU64>() }.load(Ordering::Acquire),
            4108
        );
    }
    #[test]
    fn attr_matches_version_zero_abi() {
        assert_eq!(size_of::<Attr>(), 64);
        assert_eq!(std::mem::offset_of!(Attr, flags), 40);
    }
}
