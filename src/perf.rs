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
    config2: u64,
    branch_type: u64,
    regs_user: u64,
    stack_user: u32,
    clockid: i32,
}
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Branch {
    pub from: u64,
    pub to: u64,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserRegs {
    pub ip: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct Capture {
    pub ptrace_functions: bool,
    pub callchain: bool,
    pub dwarf_stack: u32,
    pub branches: bool,
    pub addr: bool,
    pub offcpu: bool,
    pub uprobe: bool,
    pub retprobe: bool,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sample {
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub time: u64,
    pub ip: u64,
    pub period: u64,
    pub callchain: Vec<u64>,
    pub addr: u64,
    pub regs: Option<UserRegs>,
    pub stack: Vec<u8>,
    pub branches: Vec<Branch>,
    pub offcpu_ns: u64,
    pub preempt: bool,
    pub args: [u64; 6],
    pub retval: i64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Sample(Sample),
    Comm {
        pid: u32,
        tid: u32,
        name: String,
    },
    Lost(u64),
    Switch {
        out: bool,
        preempt: bool,
        pid: u32,
        tid: u32,
        cpu: u32,
        time: u64,
    },
    Other,
}

pub struct PerfEvent {
    fd: OwnedFd,
    mapping: NonNull<c_void>,
    mapping_len: usize,
    offset: usize,
    size: usize,
    tail: u64,
    capture: Capture,
}
impl PerfEvent {
    pub fn open(tid: i32, probe: &Probe, pages: usize) -> Result<Self> {
        Self::open_config(tid, probe, pages, false, Capture::default())
    }
    /// Leave the event disabled until the target calls exec, excluding the
    /// launcher's setup work between fork and exec from command measurements.
    pub fn open_on_exec(tid: i32, probe: &Probe, pages: usize) -> Result<Self> {
        Self::open_config(tid, probe, pages, true, Capture::default())
    }
    pub fn open_with_ustack(tid: i32, probe: &Probe, pages: usize, on_exec: bool) -> Result<Self> {
        Self::open_config(
            tid,
            probe,
            pages,
            on_exec,
            Capture {
                callchain: true,
                ..Capture::default()
            },
        )
    }
    pub fn open_config(
        tid: i32,
        probe: &Probe,
        pages: usize,
        on_exec: bool,
        capture: Capture,
    ) -> Result<Self> {
        Self::try_open_config(tid, probe, pages, on_exec, capture)?
            .ok_or_else(|| format!("perf target TID {tid} exited during attachment"))
    }
    /// None means the task exited during the perf syscall, including the window
    /// where /proc still exposes a dying task but perf rejects it with ESRCH.
    pub fn try_open_config(
        tid: i32,
        probe: &Probe,
        pages: usize,
        on_exec: bool,
        mut capture: Capture,
    ) -> Result<Option<Self>> {
        if tid <= 0 {
            return Err("perf target TID must be positive".into());
        }
        if !pages.is_power_of_two() || pages > 1024 {
            return Err("mmap pages must be a power of two from 1 to 1024".into());
        }
        let uprobe = if let Probe::Uprobe {
            path,
            function,
            ret,
        } = probe
        {
            Some(crate::uprobe::resolve(tid, path, function, *ret)?)
        } else {
            None
        };
        let (kind, config, period, frequency, bp_type, config1, config2) = match probe {
            Probe::Uprobe { ret, .. } => {
                capture.uprobe = true;
                capture.retprobe = *ret;
                let resolved = uprobe.as_ref().unwrap();
                (
                    resolved.kind,
                    resolved.config,
                    1,
                    false,
                    0,
                    resolved.path.as_ptr() as u64,
                    resolved.offset,
                )
            }
            Probe::Perf {
                kind,
                config,
                period,
                frequency,
            } => (*kind, *config, *period, *frequency, 0, 0, 0),
            Probe::Watchpoint {
                address,
                length,
                access,
            } => {
                capture.addr = true;
                (5, 0, 1, false, *access, *address, *length)
            }
            Probe::OffCpu => {
                capture.offcpu = true;
                (1, 9, 0, false, 0, 0, 0)
            }
            _ => return Err("not a perf probe".into()),
        };
        if capture.dwarf_stack > 32768 || capture.dwarf_stack % 8 != 0 {
            return Err("DWARF stack size must be a multiple of 8 up to 32768".into());
        }
        if capture.offcpu {
            capture.callchain = false;
            capture.dwarf_stack = 0;
            capture.branches = false;
            capture.addr = false;
            capture.uprobe = false;
            capture.retprobe = false;
        }
        if capture.dwarf_stack != 0 {
            capture.callchain = false;
        }
        let sample_type = if capture.offcpu {
            2 | 4 | 128
        } else {
            SAMPLE_TYPE
                | if capture.callchain { 1 << 5 } else { 0 }
                | if capture.addr { 1 << 3 } else { 0 }
                | if capture.branches { 1 << 11 } else { 0 }
                | if capture.dwarf_stack != 0 || capture.uprobe {
                    1 << 12
                } else {
                    0
                }
                | if capture.dwarf_stack != 0 { 1 << 13 } else { 0 }
        };
        let attr = Attr {
            kind,
            size: if capture.dwarf_stack != 0 || capture.uprobe {
                96
            } else if capture.branches {
                80
            } else if bp_type != 0 {
                72
            } else {
                64
            },
            config,
            sample_period: period,
            sample_type,
            flags: 1
                | 1 << 5
                | 1 << 6
                | 1 << 9
                | if frequency { 1 << 10 } else { 0 }
                | if capture.callchain { 1 << 21 } else { 0 }
                | if on_exec { 1 << 12 } else { 0 }
                | if capture.offcpu {
                    (1 << 18) | (1 << 26)
                } else {
                    0
                },
            wakeup_events: 1,
            bp_type,
            config1,
            config2,
            branch_type: if capture.branches { 1 | 8 } else { 0 },
            regs_user: if capture.dwarf_stack != 0 || capture.uprobe {
                register_mask(capture.uprobe)
            } else {
                0
            },
            stack_user: capture.dwarf_stack,
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
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            if capture.uprobe && matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
                return Err(format!(
                    "dynamic perf uprobes require privileged kernel access (commonly CAP_SYS_ADMIN); use --uprobe-backend ptrace for unprivileged function probes: {}",
                    open_error(tid, error)
                ));
            }
            return Err(open_error(tid, error));
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
            capture,
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
        Ok(Some(event))
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
            records.push(decode_capture(&bytes, self.capture)?);
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

#[cfg(target_arch = "x86_64")]
fn register_mask(arguments: bool) -> u64 {
    (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | if arguments {
            (1 << 0) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 11) | (1 << 12)
        } else {
            0
        }
}
#[cfg(target_arch = "aarch64")]
fn register_mask(arguments: bool) -> u64 {
    (1 << 29) | (1 << 30) | (1 << 31) | (1 << 32) | if arguments { 63 } else { 0 }
}
#[cfg(test)]
fn decode(bytes: &[u8], callchain: bool) -> Result<Record> {
    decode_capture(
        bytes,
        Capture {
            callchain,
            ..Capture::default()
        },
    )
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(size)
            .ok_or("perf record length overflow")?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or("truncated perf record")?;
        self.at = end;
        Ok(value)
    }
    fn word(&mut self) -> Result<u64> {
        Ok(u64::from_ne_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn pair(&mut self) -> Result<(u32, u32)> {
        let b = self.take(8)?;
        Ok((
            u32::from_ne_bytes(b[..4].try_into().unwrap()),
            u32::from_ne_bytes(b[4..].try_into().unwrap()),
        ))
    }
}
fn decode_capture(bytes: &[u8], capture: Capture) -> Result<Record> {
    if bytes.len() < 8 {
        return Err("short perf header".into());
    }
    let size = u16::from_ne_bytes(bytes[6..8].try_into().unwrap()) as usize;
    if size != bytes.len() {
        return Err("perf record size mismatch".into());
    }
    let kind = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let misc = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
    let mut c = Cursor { bytes, at: 8 };
    let record = match kind {
        9 => {
            let ip = c.word()?;
            let (pid, tid) = c.pair()?;
            let time = c.word()?;
            let addr = if capture.addr { c.word()? } else { 0 };
            let (cpu, _) = c.pair()?;
            let period = c.word()?;
            let mut sample = Sample {
                pid,
                tid,
                time,
                ip,
                cpu,
                period,
                addr,
                ..Sample::default()
            };
            if capture.callchain {
                let count = c.word()?;
                if count > (bytes.len().saturating_sub(c.at) / 8) as u64 {
                    return Err("invalid perf callchain length".into());
                }
                let mut user = true;
                for _ in 0..count {
                    let ip = c.word()?;
                    if ip >= (-4095i64) as u64 {
                        user = ip == (-512i64) as u64;
                    } else if user && ip != 0 && sample.callchain.len() < 127 {
                        sample.callchain.push(ip);
                    }
                }
                if sample.callchain.is_empty() && ip != 0 {
                    sample.callchain.push(ip);
                }
            }
            if capture.branches {
                let count = c.word()?;
                if count > (bytes.len().saturating_sub(c.at) / 24) as u64 {
                    return Err("invalid branch stack length".into());
                }
                for index in 0..count {
                    let from = c.word()?;
                    let to = c.word()?;
                    let _flags = c.word()?;
                    if index < 128 {
                        sample.branches.push(Branch { from, to });
                    }
                }
            }
            if capture.dwarf_stack != 0 || capture.uprobe {
                let abi = c.word()?;
                if abi != 0 {
                    if abi != 2 {
                        return Err("only 64-bit sampled user registers are supported".into());
                    }
                    let mut values = [0u64; 33];
                    for (index, value) in values.iter_mut().enumerate() {
                        if register_mask(capture.uprobe) & (1u64 << index) != 0 {
                            *value = c.word()?;
                        }
                    }
                    #[cfg(target_arch = "x86_64")]
                    let (regs, args, retval) = (
                        UserRegs {
                            fp: values[6],
                            sp: values[7],
                            ip: values[8],
                            lr: 0,
                        },
                        [
                            values[5], values[4], values[3], values[2], values[11], values[12],
                        ],
                        values[0] as i64,
                    );
                    #[cfg(target_arch = "aarch64")]
                    let (regs, args, retval) = (
                        UserRegs {
                            fp: values[29],
                            lr: values[30],
                            sp: values[31],
                            ip: values[32],
                        },
                        values[..6].try_into().unwrap(),
                        values[0] as i64,
                    );
                    sample.regs = Some(regs);
                    if capture.uprobe && !capture.retprobe {
                        sample.args = args;
                    }
                    if capture.retprobe {
                        sample.retval = retval;
                    }
                }
            }
            if capture.dwarf_stack != 0 {
                let size = c.word()?;
                if size > capture.dwarf_stack as u64 || size > 32768 {
                    return Err("invalid sampled user stack size".into());
                }
                if size != 0 {
                    let stack = c.take(size as usize)?;
                    let dynamic = c.word()?;
                    if dynamic > size {
                        return Err("invalid dynamic user stack size".into());
                    }
                    sample.stack = stack[..dynamic as usize].to_vec();
                }
            }
            Record::Sample(sample)
        }
        2 => {
            let _id = c.word()?;
            Record::Lost(c.word()?)
        }
        13 => Record::Lost(c.word()?),
        3 => {
            let (pid, tid) = c.pair()?;
            let end = bytes
                .len()
                .checked_sub(if capture.offcpu { 24 } else { 0 })
                .filter(|end| *end >= c.at)
                .ok_or("truncated perf comm sample ID")?;
            let rest = &bytes[c.at..end];
            let end = rest
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated perf comm record")?;
            return Ok(Record::Comm {
                pid,
                tid,
                name: String::from_utf8_lossy(&rest[..end]).into_owned(),
            });
        }
        14 if capture.offcpu => {
            let (pid, tid) = c.pair()?;
            let time = c.word()?;
            let (cpu, _) = c.pair()?;
            Record::Switch {
                out: misc & (1 << 13) != 0,
                preempt: misc & (1 << 14) != 0,
                pid,
                tid,
                cpu,
                time,
            }
        }
        _ => return Ok(Record::Other),
    };
    if capture.offcpu && matches!(kind, 2 | 13) {
        c.take(24)?;
    }
    if c.at != bytes.len() {
        return Err("unexpected trailing perf record data".into());
    }
    Ok(record)
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
            decode(&record(9, &p), false).unwrap(),
            Record::Sample(Sample {
                ip: 0x1234,
                pid: 10,
                tid: 11,
                time: 55,
                cpu: 3,
                period: 100,
                callchain: vec![],
                ..Sample::default()
            })
        );
        assert_eq!(
            decode(
                &record(2, &[0u64.to_ne_bytes(), 7u64.to_ne_bytes()].concat()),
                false
            )
            .unwrap(),
            Record::Lost(7)
        );
        assert!(decode(&record(9, &[]), false).is_err());
    }
    #[test]
    fn command_names_and_malformed_records() {
        let mut payload = Vec::new();
        payload.extend(10u32.to_ne_bytes());
        payload.extend(11u32.to_ne_bytes());
        payload.extend(b"worker\0\0");
        assert_eq!(
            decode(&record(3, &payload), false).unwrap(),
            Record::Comm {
                pid: 10,
                tid: 11,
                name: "worker".into()
            }
        );
        payload.truncate(14); // no terminator
        assert!(decode(&record(3, &payload), false).is_err());
        assert!(decode(&[0; 4], false).is_err());
        let mut bad_size = record(13, &42u64.to_ne_bytes());
        bad_size[6] = 0;
        assert!(decode(&bad_size, false).is_err());
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
            capture: Capture::default(),
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
        assert_eq!(size_of::<Attr>(), 96);
        assert_eq!(std::mem::offset_of!(Attr, regs_user), 80);
        assert_eq!(std::mem::offset_of!(Attr, flags), 40);
    }

    #[test]
    fn user_callchains_are_bounded_and_context_markers_are_not_frames() {
        let mut payload = vec![0; 40];
        payload[..8].copy_from_slice(&0x1234u64.to_ne_bytes());
        let ips = [
            (-128i64) as u64,
            0xffff_0000_0000_1234,
            (-512i64) as u64,
            0x1234,
            0x2345,
            0,
        ];
        payload.extend((ips.len() as u64).to_ne_bytes());
        for ip in ips {
            payload.extend(ip.to_ne_bytes());
        }
        let Record::Sample(sample) = decode(&record(9, &payload), true).unwrap() else {
            panic!()
        };
        assert_eq!(sample.callchain, [0x1234, 0x2345]);
        assert!(decode(&record(9, &payload), false).is_err());
        payload[40..48].copy_from_slice(&u64::MAX.to_ne_bytes());
        assert!(decode(&record(9, &payload), true).is_err());
        payload.truncate(40);
        assert!(decode(&record(9, &payload), true).is_err());
        payload.extend(0u64.to_ne_bytes());
        let Record::Sample(sample) = decode(&record(9, &payload), true).unwrap() else {
            panic!()
        };
        assert_eq!(sample.callchain, [0x1234]);
        payload.truncate(40);
        payload.extend(200u64.to_ne_bytes());
        for _ in 0..200 {
            payload.extend(0x1234u64.to_ne_bytes());
        }
        let Record::Sample(sample) = decode(&record(9, &payload), true).unwrap() else {
            panic!()
        };
        assert_eq!(sample.callchain.len(), 127);
        payload.pop();
        assert!(decode(&record(9, &payload), true).is_err());
    }
}

#[cfg(test)]
mod extended_tests {
    use super::*;
    fn record(kind: u32, payload: &[u8], misc: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(misc.to_ne_bytes());
        bytes.extend(((payload.len() + 8) as u16).to_ne_bytes());
        bytes.extend(payload);
        bytes
    }
    #[test]
    fn branches_registers_stack_and_truncation_are_validated() {
        let capture = Capture {
            addr: true,
            branches: true,
            dwarf_stack: 16,
            uprobe: true,
            ..Default::default()
        };
        let mut bytes = Vec::new();
        for word in [
            0x1234u64,
            (43u64 << 32) | 42,
            100,
            0xabcd,
            3,
            99,
            1,
            0x1111,
            0x2222,
            0,
            2,
        ] {
            bytes.extend(word.to_ne_bytes());
        }
        for index in 0..33 {
            if register_mask(true) & (1 << index) != 0 {
                bytes.extend((index as u64 + 1000).to_ne_bytes());
            }
        }
        bytes.extend(16u64.to_ne_bytes());
        bytes.extend([7u8; 16]);
        bytes.extend(8u64.to_ne_bytes());
        let Record::Sample(sample) = decode_capture(&record(9, &bytes, 0), capture).unwrap() else {
            panic!()
        };
        assert_eq!(sample.addr, 0xabcd);
        assert_eq!(
            sample.branches,
            [Branch {
                from: 0x1111,
                to: 0x2222
            }]
        );
        assert_eq!(sample.stack, [7u8; 8]);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(sample.args, [1000, 1001, 1002, 1003, 1004, 1005]);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(sample.args, [1005, 1004, 1003, 1002, 1011, 1012]);
        for length in 0..bytes.len() {
            assert!(
                decode_capture(&record(9, &bytes[..length], 0), capture).is_err(),
                "length {length}"
            );
        }
        let last = bytes.len() - 8;
        bytes[last..].copy_from_slice(&17u64.to_ne_bytes());
        assert!(decode_capture(&record(9, &bytes, 0), capture).is_err());
    }
    #[test]
    fn switch_sideband_and_loss_trailers() {
        let capture = Capture {
            offcpu: true,
            ..Default::default()
        };
        let mut bytes = Vec::new();
        for word in [(43u64 << 32) | 42, 12345, 3] {
            bytes.extend(word.to_ne_bytes());
        }
        assert_eq!(
            decode_capture(&record(14, &bytes, (1 << 13) | (1 << 14)), capture).unwrap(),
            Record::Switch {
                out: true,
                preempt: true,
                pid: 42,
                tid: 43,
                cpu: 3,
                time: 12345
            }
        );
        let mut lost = vec![];
        lost.extend(0u64.to_ne_bytes());
        lost.extend(7u64.to_ne_bytes());
        lost.extend(&bytes);
        assert_eq!(
            decode_capture(&record(2, &lost, 0), capture).unwrap(),
            Record::Lost(7)
        );
        assert!(decode_capture(&record(14, &bytes[..16], 0), capture).is_err());
    }
}
