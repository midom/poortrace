//! Userspace compatibility helpers and pointer-independent replay descriptors.
use crate::{
    Result,
    recording::Helper,
    runtime::{Event, State, Type},
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    io::Read,
    os::unix::fs::MetadataExt,
};

pub(crate) struct DeferredSignal {
    fd: std::os::fd::OwnedFd,
    signal: i32,
    flags: u32,
}
impl DeferredSignal {
    pub(crate) fn deliver(self) -> Result<()> {
        use std::os::fd::AsRawFd;
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                self.signal,
                std::ptr::null::<libc::siginfo_t>(),
                self.flags,
            )
        };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("signal delivery: {error}"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub(crate) enum Arg {
    Number(u64),
    Text(String),
    Float(u64),
}
impl Arg {
    fn number(&self) -> Result<u64> {
        match self {
            Self::Number(n) => Ok(*n),
            _ => Err("expected an integer".into()),
        }
    }
    fn text(&self) -> Result<&str> {
        match self {
            Self::Text(s) => Ok(s),
            _ => Err("expected a string".into()),
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Call {
    name: String,
    args: Vec<Arg>,
}

pub(crate) fn signature(name: &str) -> Option<(Type, usize, usize)> {
    use Type::{Number as N, String as S};
    Some(match name {
        "__stack_format" => (Type::Stack, 3, 3),
        "func" | "probetype" | "pcomm" | "leader_comm" => (S, 0, 0),
        "comm" => (S, 0, 1),
        "default_str_length" => (N, 0, 0),
        "kfunc_exist" | "kfunc_allowed" => (N, 1, 1),
        "uid" | "gid" | "ppid" | "leader_tid" | "cpid" | "has_cpid" | "elapsed" | "ncpus"
        | "numaid" | "rand" => (N, 0, 0),
        "cgroup" => (N, 0, 0),
        "username" => (S, 0, 1),
        "cgroupid" | "strcap" | "len" | "uptr" | "signal" | "signal_thread" | "unwatch" => {
            (N, 1, 1)
        }
        "uaddr" | "kaddr" => (N, 1, 1),
        "bswap" => (N, 1, 2),
        "percpu_kaddr" => (N, 1, 2),
        "strerror" | "syscall_name" | "signal_name" | "pton" | "macaddr" => (S, 1, 1),
        "cgroup_path" => (S, 1, 2),
        "ntop" => (S, 1, 2),
        "strstr" => (N, 2, 2),
        "strncmp" | "memcmp" | "write_user" => (N, 3, 3),
        "strftime" => (S, 2, 2),
        "reg" => (N, 1, 1),
        "nsecs" => (N, 0, 1),
        "getopt" => (N, 1, 3),
        "assert" => (N, 1, 2),
        "cat" | "system" | "join" | "errorf" | "warnf" => (S, 1, 16),
        "override" | "skboutput" | "socket_cookie" | "path" | "curtask" | "jiffies"
        | "usermode" | "kptr" => (N, 0, 16),
        _ => return None,
    })
}
pub(crate) fn unavailable(name: &str) -> Option<&'static str> {
    Some(match name {
        "override" => "requires kernel-side error injection; poortrace does not load BPF programs",
        "skboutput" => {
            "requires an event-time kernel packet buffer; poortrace has no BPF packet backend"
        }
        "socket_cookie" => "requires a kernel socket context unavailable in perf/ptrace handlers",
        "path" => "requires a live kernel struct path context unavailable to userspace handlers",
        "curtask" => "kernel task pointers are not exposed by the perf/ptrace event ABI",
        "jiffies" => "exact kernel jiffies are unavailable; use nsecs for event timestamps",
        "usermode" => "event-time processor privilege state is not captured by this backend",
        "kptr" => {
            "kernel address-space pointer types are unavailable; use explicit BTF field helpers"
        }
        "kfunc_allowed" => "BPF kfunc attachment policy is inapplicable to the no-BPF backend",
        "percpu_kaddr" => {
            "per-CPU kernel symbol relocation is unavailable without a kernel context"
        }
        _ => return None,
    })
}
fn pure(name: &str, args: &[Arg]) -> bool {
    matches!(
        name,
        "bswap"
            | "strcap"
            | "strstr"
            | "ntop"
            | "pton"
            | "uptr"
            | "signal_name"
            | "len"
            | "unwatch"
    ) || matches!(name, "strncmp" | "memcmp")
        && (args.iter().take(2).all(|arg| matches!(arg, Arg::Text(_)))
            || args.get(2).is_some_and(|arg| arg.number() == Ok(0)))
        || name == "macaddr" && matches!(args.first(), Some(Arg::Text(_)))
        || name == "__stack_format" && args.get(1).is_some_and(|arg| arg.text() == Ok("raw"))
}
fn bounded(path: &str, max: usize) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("{path}: {e}"))?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err(format!("{path}: input exceeds {max} bytes"));
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
fn status(pid: u64, key: &str) -> Result<u64> {
    let text = bounded(&format!("/proc/{pid}/status"), 65536)?;
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("{key} unavailable for PID {pid}"))
}
fn parent_thread(pid: u64) -> Result<u64> {
    let parent = status(pid, "PPid:")?;
    if parent == 0 {
        return Ok(0);
    }
    let mut tasks = 0usize;
    for task in std::fs::read_dir(format!("/proc/{parent}/task")).map_err(|e| e.to_string())? {
        tasks += 1;
        if tasks > 4096 {
            return Err("parent task lookup exceeds 4096 threads".into());
        }
        let task = task.map_err(|e| e.to_string())?;
        let tid = task
            .file_name()
            .to_string_lossy()
            .parse::<u64>()
            .map_err(|_| "invalid parent task id")?;
        let children = bounded(&format!("/proc/{parent}/task/{tid}/children"), 65536)?;
        if children
            .split_whitespace()
            .any(|child| child.parse::<u64>() == Ok(pid))
        {
            if status(pid, "PPid:")? != parent {
                return Err("parent changed during metadata lookup".into());
            }
            return Ok(tid);
        }
    }
    Err("parent task identity is unavailable".into())
}
fn comm(pid: u64) -> Result<String> {
    Ok(bounded(&format!("/proc/{pid}/comm"), 4096)?
        .trim_end_matches('\n')
        .into())
}
fn bytes(arg: &Arg) -> Result<Vec<u8>> {
    let text = arg.text()?;
    // buf()/pton() provide a space-separated byte representation.
    if text
        .split_whitespace()
        .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
        && text.contains(' ')
    {
        text.split_whitespace()
            .map(|p| u8::from_str_radix(p, 16).map_err(|e| e.to_string()))
            .collect()
    } else {
        Ok(text.as_bytes().to_vec())
    }
}
fn clock(id: libc::clockid_t) -> Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok((ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64))
}
fn format_time(format: &str, ns: u64) -> Result<String> {
    if format.len() > 1024 || format.contains('\0') {
        return Err("strftime format must be at most 1024 bytes without NUL".into());
    }
    let secs = (ns / 1_000_000_000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return Err("strftime timestamp is outside the calendar range".into());
    }
    let mut expanded = String::from(" ");
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('f') => expanded.push_str(&format!("{:06}", (ns % 1_000_000_000) / 1000)),
                Some(next) => {
                    expanded.push('%');
                    expanded.push(next);
                }
                None => return Err("incomplete strftime conversion".into()),
            }
        } else {
            expanded.push(c);
        }
    }
    let format = CString::new(expanded).map_err(|e| e.to_string())?;
    let mut out = [0u8; 4097];
    let len = unsafe { libc::strftime(out.as_mut_ptr().cast(), out.len(), format.as_ptr(), &tm) };
    if len == 0 {
        return Err("strftime output exceeds 4095 bytes".into());
    }
    Ok(String::from_utf8_lossy(&out[1..len]).into_owned())
}
fn formatted(args: &[Arg]) -> Result<String> {
    let format = crate::runtime::Format::parse(args[0].text()?)?;
    if format.types.len() != args.len() - 1 {
        return Err("format argument count does not match".into());
    }
    let mut strings = Vec::new();
    let mut values = Vec::new();
    for (arg, ty) in args[1..].iter().zip(&format.types) {
        values.push(match (arg, ty) {
            (Arg::Number(n), Type::Number) | (Arg::Float(n), Type::Float) => *n,
            (Arg::Text(s), Type::String) => {
                let s = CString::new(s.replace('\0', "\\0")).map_err(|e| e.to_string())?;
                let p = s.as_ptr() as u64;
                strings.push(s);
                p
            }
            _ => return Err("formatted helper argument has the wrong type".into()),
        });
    }
    Ok(format.render(&values))
}
fn checked_signal(arg: &Arg) -> Result<i32> {
    let signal = match arg {
        Arg::Number(n) => i32::try_from(*n).map_err(|_| "invalid signal")?,
        Arg::Float(_) => return Err("signal requires an integer or name".into()),
        Arg::Text(s) => {
            let s = s.strip_prefix("SIG").unwrap_or(s);
            signal_table()
                .iter()
                .find(|(_, name)| *name == s)
                .map(|(n, _)| *n)
                .ok_or("unknown signal name")?
        }
    };
    if !(1..=64).contains(&signal) {
        return Err("signal must be 1..64".into());
    }
    Ok(signal)
}
fn signal_table() -> &'static [(i32, &'static str)] {
    &[
        (libc::SIGHUP, "HUP"),
        (libc::SIGINT, "INT"),
        (libc::SIGQUIT, "QUIT"),
        (libc::SIGILL, "ILL"),
        (libc::SIGTRAP, "TRAP"),
        (libc::SIGABRT, "ABRT"),
        (libc::SIGBUS, "BUS"),
        (libc::SIGFPE, "FPE"),
        (libc::SIGKILL, "KILL"),
        (libc::SIGUSR1, "USR1"),
        (libc::SIGSEGV, "SEGV"),
        (libc::SIGUSR2, "USR2"),
        (libc::SIGPIPE, "PIPE"),
        (libc::SIGALRM, "ALRM"),
        (libc::SIGTERM, "TERM"),
        (libc::SIGCHLD, "CHLD"),
        (libc::SIGCONT, "CONT"),
        (libc::SIGSTOP, "STOP"),
        (libc::SIGTSTP, "TSTP"),
        (libc::SIGTTIN, "TTIN"),
        (libc::SIGTTOU, "TTOU"),
        (libc::SIGURG, "URG"),
        (libc::SIGXCPU, "XCPU"),
        (libc::SIGXFSZ, "XFSZ"),
        (libc::SIGVTALRM, "VTALRM"),
        (libc::SIGPROF, "PROF"),
        (libc::SIGWINCH, "WINCH"),
        (libc::SIGIO, "IO"),
        (libc::SIGPWR, "PWR"),
        (libc::SIGSYS, "SYS"),
    ]
}
fn target_observation(
    s: &mut State<'_>,
    e: &Event<'_>,
    name: &str,
    args: &[Arg],
) -> Result<Option<(u32, u64)>> {
    let target = if name == "comm" && !args.is_empty() {
        Some((args[0].number()?, true))
    } else if matches!(
        name,
        "uid" | "gid" | "ppid" | "pcomm" | "leader_comm" | "cgroup" | "uaddr" | "join"
    ) || name == "username" && args.is_empty()
        || name == "macaddr" && matches!(args.first(), Some(Arg::Number(_)))
        || matches!(name, "strncmp" | "memcmp")
            && !args.get(2).is_some_and(|arg| arg.number() == Ok(0))
            && args.iter().take(2).any(|arg| matches!(arg, Arg::Number(_)))
    {
        Some((e.pid, false))
    } else {
        None
    };
    let Some((pid, explicit)) = target else {
        return Ok(None);
    };
    let pid = u32::try_from(pid).map_err(|_| "target PID out of range")?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("target PID out of range".into());
    }
    if !s.has_target_identity(pid) {
        if explicit || pid == std::process::id() {
            s.register_target_identity(pid)?;
        } else {
            return Err(format!(
                "{name} requires a known target identity; attach with -p or launch a command"
            ));
        }
    }
    let started = crate::managed_bridge::start_ticks(pid)?;
    if s.target_starts.get(&pid) != Some(&started) {
        return Err(format!("PID {pid} changed identity before {name}"));
    }
    if matches!(name, "uid" | "gid") && status(e.tid, "Tgid:")? != e.pid {
        return Err("event thread no longer belongs to its target process".into());
    }
    Ok(Some((pid, started)))
}
fn evaluate(s: &mut State<'_>, e: &Event<'_>, name: &str, args: &[Arg]) -> Result<Arg> {
    use Arg::{Number as N, Text as T};
    let n = |i: usize| args.get(i).ok_or("missing argument")?.number();
    let t = |i: usize| args.get(i).ok_or("missing argument")?.text();
    Ok(match name {
        "__stack_format" => {
            let source = t(0)?;
            let mode = t(1)?;
            let depth = n(2)?;
            if depth == 0 || depth > 127 {
                return Err("stack depth must be 1..127".into());
            }
            let frames = match source {
                "user" => e.stack_frames().to_vec(),
                "kernel" => s.kernel_frames.clone(),
                _ => return Err("invalid stack source".into()),
            };
            if frames.is_empty() {
                return Ok(T(format!("    <no {source} stack>\n")));
            }
            let mut output = String::new();
            for ip in frames.into_iter().take(depth as usize) {
                match mode {
                    "raw" => output.push_str(&format!("    0x{ip:x}\n")),
                    "perf" => {
                        let symbol = if source == "user" {
                            s.symbols.symbol(e.pid as u32, ip)
                        } else {
                            s.kernel_symbols.symbol(ip)
                        };
                        output.push_str(&format!("    {ip:016x} {symbol}\n"));
                    }
                    _ => return Err("invalid stack format".into()),
                }
            }
            T(output)
        }
        "func" => {
            let probe = unsafe { CStr::from_ptr(e.probe) }.to_string_lossy();
            let parsed = crate::language::Probe::parse(&probe)?;
            T(match parsed {
                crate::language::Probe::Uprobe { function, .. }
                | crate::language::Probe::KernelProbe { function, .. } => function,
                _ => return Err("func requires a function probe".into()),
            })
        }
        "probetype" => T(unsafe { CStr::from_ptr(e.probe) }
            .to_string_lossy()
            .split(':')
            .next()
            .unwrap_or("")
            .into()),
        "uid" => N(status(e.tid, "Uid:")?),
        "gid" => N(status(e.tid, "Gid:")?),
        "ppid" => N(parent_thread(e.pid)?),
        "leader_tid" => N(e.pid),
        "leader_comm" => T(comm(e.pid)?),
        "comm" => T(if args.is_empty() {
            unsafe { CStr::from_ptr(e.comm) }
                .to_string_lossy()
                .into_owned()
        } else {
            comm(n(0)?)?
        }),
        "default_str_length" => N(256),
        "kfunc_exist" => N(s.btf.function_exists(t(0)?)? as u64),
        "pcomm" => T(comm(parent_thread(e.pid)?)?),
        "cpid" => N(s
            .child_pid
            .ok_or("cpid is unavailable without a launched command")?),
        "has_cpid" => N(s.child_pid.is_some() as u64),
        "username" => {
            let uid = if args.is_empty() {
                status(e.tid, "Uid:")?
            } else {
                n(0)?
            };
            let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found = std::ptr::null_mut();
            let mut buffer = vec![0u8; 65536];
            let error = unsafe {
                libc::getpwuid_r(
                    uid.try_into().map_err(|_| "UID out of range")?,
                    &mut pwd,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut found,
                )
            };
            if error != 0 || found.is_null() {
                return Err(format!("username unavailable for UID {uid}"));
            }
            T(unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned())
        }
        "ncpus" => N(crate::kernel::online_cpus()?.len() as u64),
        "numaid" => {
            let cpu = if s.report.provenance.as_ref().is_some_and(|p| {
                matches!(p.backend.as_str(), "functions" | "syscalls" | "reliable")
            }) {
                let stat = bounded(&format!("/proc/{}/stat", e.tid), 65536)?;
                stat.rsplit_once(')')
                    .and_then(|(_, tail)| tail.split_whitespace().nth(36))
                    .and_then(|cpu| cpu.parse::<u64>().ok())
                    .ok_or("stopped-thread CPU is unavailable")?
            } else {
                e.cpu
            };
            let path = format!("/sys/devices/system/cpu/cpu{cpu}");
            let mut nodes = std::fs::read_dir(path)
                .map_err(|e| e.to_string())?
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| {
                    entry
                        .file_name()
                        .to_str()?
                        .strip_prefix("node")?
                        .parse::<u64>()
                        .ok()
                });
            N(nodes.next().ok_or("NUMA node unavailable for event CPU")?)
        }
        "elapsed" => N(e
            .nsecs
            .saturating_sub(*s.first_event_ns.get_or_insert(e.nsecs))),
        "nsecs" => {
            let mode = if args.is_empty() { "monotonic" } else { t(0)? };
            N(match mode {
                "monotonic" => e.nsecs,
                "boot" => e.nsecs.saturating_add(
                    clock(libc::CLOCK_BOOTTIME)?.saturating_sub(clock(libc::CLOCK_MONOTONIC)?),
                ),
                "tai" | "sw_tai" => e.nsecs.saturating_add(
                    clock(libc::CLOCK_TAI)?.saturating_sub(clock(libc::CLOCK_MONOTONIC)?),
                ),
                _ => return Err("nsecs mode must be monotonic, boot, tai or sw_tai".into()),
            })
        }
        "rand" => {
            let mut value = 0u32;
            let got = unsafe { libc::getrandom((&mut value as *mut u32).cast(), 4, 0) };
            if got != 4 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            N(value as u64)
        }
        "bswap" => N(match if args.len() > 1 { n(1)? } else { 64 } {
            8 => n(0)? & 255,
            16 => (n(0)? as u16).swap_bytes() as u64,
            32 => (n(0)? as u32).swap_bytes() as u64,
            64 => n(0)?.swap_bytes(),
            _ => return Err("bswap width must be 8, 16, 32 or 64".into()),
        }),
        "uptr" => N(n(0)?),
        "unwatch" => {
            let address = n(0)?;
            if !s.unwatched.contains(&address) && s.unwatched.len() >= s.max_entries {
                return Err("unwatch address limit exceeded (--max-map-entries)".into());
            }
            s.unwatched.insert(address);
            N(0)
        }
        "strcap" => N(t(0)?.len() as u64),
        "len" => N(t(0)?
            .lines()
            .filter(|line| !line.contains("<no ") && !line.trim().is_empty())
            .count() as u64),
        "strstr" => N(t(0)?.find(t(1)?).map_or(u64::MAX, |n| n as u64)),
        "strncmp" | "memcmp" => {
            let max = usize::try_from(n(2)?).map_err(|_| "invalid byte count")?;
            if max > 4096 {
                return Err("comparison limit is 4096 bytes".into());
            }
            if max == 0 {
                return Ok(N(0));
            }
            let read = |arg: &Arg| -> Result<Vec<u8>> {
                match arg {
                    Arg::Number(address) => {
                        let mut bytes =
                            crate::memory::read(e.pid as u32, *address, max, name == "strncmp")?;
                        if name == "strncmp" {
                            if let Some(end) = bytes.iter().position(|b| *b == 0) {
                                bytes.truncate(end);
                            } else if bytes.len() < max {
                                return Err("strncmp input is not fully accessible".into());
                            }
                        }
                        Ok(bytes)
                    }
                    Arg::Text(text) if name == "strncmp" => Ok(text.as_bytes().to_vec()),
                    _ => bytes(arg),
                }
            };
            let a = read(&args[0])?;
            let b = read(&args[1])?;
            if name == "memcmp" && (a.len() < max || b.len() < max) {
                return Err("memcmp input is shorter than count".into());
            }
            N(match a.iter().take(max).cmp(b.iter().take(max)) {
                std::cmp::Ordering::Less => u64::MAX,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            })
        }
        "strerror" => {
            let mut output = [0 as libc::c_char; 1024];
            let code = n(0)? as i32;
            let result = unsafe { libc::strerror_r(code, output.as_mut_ptr(), output.len()) };
            T(if result == 0 {
                unsafe { CStr::from_ptr(output.as_ptr()) }
                    .to_string_lossy()
                    .into_owned()
            } else {
                format!("Unknown error {code}")
            })
        }
        "syscall_name" => T(crate::syscall::name(n(0)? as i64)),
        "signal_name" => {
            let number = n(0)? as i32;
            T(signal_table()
                .iter()
                .find(|(n, _)| *n == number)
                .map(|(_, s)| format!("SIG{s}"))
                .unwrap_or_else(|| format!("SIG{number}")))
        }
        "pton" => {
            let ip: std::net::IpAddr = t(0)?.parse().map_err(|_| "invalid IP address")?;
            let data = match ip {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            };
            T(data
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "))
        }
        "ntop" => {
            let (family, arg) = if args.len() == 2 {
                (Some(n(0)?), &args[1])
            } else {
                (None, &args[0])
            };
            let data = match arg {
                N(n) => (*n as u32).to_ne_bytes().to_vec(),
                Arg::Float(_) => return Err("ntop does not accept floats".into()),
                T(_) => bytes(arg)?,
            };
            T(match data.len() {
                4 if family.is_none() || family == Some(libc::AF_INET as u64) => {
                    std::net::Ipv4Addr::from(
                        <[u8; 4]>::try_from(data).map_err(|_| "IPv4 needs 4 bytes")?,
                    )
                    .to_string()
                }
                16 if family.is_none() || family == Some(libc::AF_INET6 as u64) => {
                    std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(data).map_err(|_| "IPv6 needs 16 bytes")?,
                    )
                    .to_string()
                }
                _ => return Err("ntop family/address size mismatch".into()),
            })
        }
        "macaddr" => {
            let data = match &args[0] {
                T(_) => bytes(&args[0])?,
                N(address) => crate::memory::read(e.pid as u32, *address, 6, false)?,
                Arg::Float(_) => return Err("macaddr does not accept floats".into()),
            };
            if data.len() != 6 {
                return Err("macaddr requires six bytes".into());
            }
            T(data
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"))
        }
        "strftime" => {
            let realtime = clock(libc::CLOCK_REALTIME)?;
            let monotonic = clock(libc::CLOCK_MONOTONIC)?;
            let epoch = (n(1)? as i128) + (realtime as i128) - (monotonic as i128);
            T(format_time(
                t(0)?,
                u64::try_from(epoch).map_err(|_| "strftime timestamp out of range")?,
            )?)
        }
        "reg" => {
            let regs = s
                .register_snapshot
                .as_ref()
                .or_else(|| s.js_snapshot.as_ref().map(|(regs, _)| regs))
                .ok_or("reg requires captured event registers")?;
            let name = t(0)?;
            let special = match name {
                "ip" | "pc" | "rip" => Some(regs.ip),
                "sp" | "rsp" => Some(regs.sp),
                "bp" | "fp" | "rbp" => Some(regs.fp),
                "lr" | "x30" if cfg!(target_arch = "aarch64") => Some(regs.lr),
                "x29" if cfg!(target_arch = "aarch64") => Some(regs.fp),
                _ => None,
            };
            if let Some(value) = special {
                N(value)
            } else {
                #[cfg(target_arch = "x86_64")]
                let index = match name.trim_start_matches('r') {
                    "ax" => Some(0),
                    "bx" => Some(1),
                    "cx" => Some(2),
                    "dx" => Some(3),
                    "si" => Some(4),
                    "di" => Some(5),
                    "flags" => Some(9),
                    "cs" => Some(10),
                    "ss" => Some(11),
                    n => n
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (8..=15).contains(n))
                        .map(|n| n + 8),
                };
                #[cfg(target_arch = "aarch64")]
                let index = name
                    .strip_prefix('x')
                    .and_then(|n| n.parse::<usize>().ok())
                    .filter(|n| *n <= 30);
                let index = index.ok_or("unknown register for this architecture")?;
                if regs.valid & (1u64 << index) == 0 {
                    return Err(format!("register {name} was not captured"));
                }
                N(regs.extra[index])
            }
        }
        "uaddr" => {
            let selector = t(0)?;
            let paths = crate::discovery::process_functions(e.pid as i32, selector)?;
            let matches: Vec<_> = paths
                .functions
                .iter()
                .filter(|f| f.name == selector || crate::symbols::demangle(&f.name) == selector)
                .collect();
            let maps = bounded(&format!("/proc/{}/maps", e.pid), 8 * 1024 * 1024)?;
            let mut addresses = std::collections::BTreeSet::new();
            for found in matches {
                for line in maps.lines() {
                    if let Some(map) = crate::symbols::Mapping::parse(line) {
                        if map.path == found.path
                            && map.device == found.device
                            && map.inode == found.inode
                            && found.offset >= map.offset
                            && found.offset - map.offset < map.end - map.start
                        {
                            addresses.insert(map.start + found.offset - map.offset);
                        }
                    }
                }
            }
            if addresses.len() != 1 {
                return Err(format!(
                    "uaddr symbol {selector:?} has {} loaded addresses",
                    addresses.len()
                ));
            }
            N(*addresses.first().unwrap())
        }
        "kaddr" => {
            let name = t(0)?;
            let text = bounded("/proc/kallsyms", 64 * 1024 * 1024)?;
            let found: Vec<_> = text
                .lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    let address = u64::from_str_radix(fields.next()?, 16).ok()?;
                    fields.next()?;
                    (fields.next()? == name).then_some(address)
                })
                .collect();
            if found.len() != 1 || found[0] == 0 {
                return Err(
                    "kernel symbol is unavailable, ambiguous or restricted by host policy".into(),
                );
            }
            N(found[0])
        }
        "cgroup" | "cgroup_path" | "cgroupid" => {
            if name == "cgroup_path" {
                if args.len() > 1 && !crate::uprobe::matches(t(1)?, "unified") {
                    return Ok(T(String::new()));
                }
                let target = n(0)?;
                let root = std::path::PathBuf::from("/sys/fs/cgroup");
                let mut pending = std::collections::VecDeque::from([(root.clone(), 0usize)]);
                let mut visited = 0usize;
                while let Some((path, depth)) = pending.pop_front() {
                    visited += 1;
                    if visited > 4096 {
                        return Err("cgroup_path exceeds 4096 directories".into());
                    }
                    let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                    if !meta.is_dir() {
                        continue;
                    }
                    if meta.ino() == target {
                        return Ok(T(format!(
                            "/{}",
                            path.strip_prefix(&root)
                                .map_err(|e| e.to_string())?
                                .to_string_lossy()
                        )));
                    }
                    if depth < 64 {
                        for entry in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
                            let entry = entry.map_err(|e| e.to_string())?;
                            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                                if pending.len() >= 4096 {
                                    return Err("cgroup_path directory queue limit exceeded".into());
                                }
                                pending.push_back((entry.path(), depth + 1));
                            }
                        }
                    }
                }
                return Err("cgroup id is not visible in the current cgroup mount".into());
            }
            let path = if name == "cgroupid" {
                t(0)?.to_string()
            } else {
                let text = bounded(&format!("/proc/{}/cgroup", e.pid), 65536)?;
                let path = text
                    .lines()
                    .find_map(|line| line.strip_prefix("0::"))
                    .ok_or("cgroup requires cgroup v2")?;
                format!("/sys/fs/cgroup{path}")
            };
            let encoded = CString::new(path.as_str()).map_err(|e| e.to_string())?;
            let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
            if unsafe { libc::statfs(encoded.as_ptr(), &mut fs) } != 0
                || fs.f_type as u64 != 0x63677270
            {
                return Err("cgroupid requires a visible cgroup v2 filesystem".into());
            }
            let magic = std::fs::metadata(&path).map_err(|e| format!("cgroup {path}: {e}"))?;
            N(magic.ino())
        }
        "getopt" => {
            let key = t(0)?;
            let supplied = s.script_args.get(key);
            match args.get(1) {
                Some(T(default)) => T(supplied.cloned().unwrap_or_else(|| default.clone())),
                Some(N(default)) => N(if let Some(v) = supplied {
                    match v.as_str() {
                        "true" => 1,
                        "false" => 0,
                        _ => v
                            .parse::<i64>()
                            .map_err(|_| "getopt value is not an integer")?
                            as u64,
                    }
                } else {
                    *default
                }),
                Some(Arg::Float(_)) => {
                    return Err("getopt defaults must be integer or string".into());
                }
                None => N(supplied.is_some_and(|v| !matches!(v.as_str(), "false" | "0")) as u64),
            }
        }
        "assert" => {
            if n(0)? == 0 {
                return Err(if args.len() > 1 {
                    t(1)?.to_string()
                } else {
                    "assertion failed".into()
                });
            }
            N(1)
        }
        "errorf" | "warnf" => {
            let message = formatted(args)?;
            T(format!(
                "{}: {}{}",
                if name == "errorf" { "ERROR" } else { "WARNING" },
                message,
                if message.ends_with('\n') { "" } else { "\n" }
            ))
        }
        "join" => {
            let mut output = String::new();
            let separator = if args.len() > 1 { t(1)? } else { " " };
            let address = n(0)?;
            for index in 0..256u64 {
                let ptr = crate::memory::read(
                    e.pid as u32,
                    address
                        .checked_add(index * 8)
                        .ok_or("join address overflow")?,
                    8,
                    false,
                )?;
                let ptr =
                    u64::from_ne_bytes(ptr.try_into().map_err(|_| "join pointer read truncated")?);
                if ptr == 0 {
                    return Ok(T(output));
                }
                let text = crate::memory::read(e.pid as u32, ptr, 4096, true)?;
                let end = text.iter().position(|b| *b == 0).unwrap_or(text.len());
                if index > 0 {
                    output.push_str(separator);
                }
                output.push_str(&String::from_utf8_lossy(&text[..end]));
                if output.len() > 65536 {
                    return Err("join output exceeds 64 KiB".into());
                }
            }
            return Err("join exceeds 256 pointers".into());
        }
        "cat" => T(bounded(&formatted(args)?, 65536)?),
        "system" => {
            if !s.allow_unsafe {
                return Err("system requires --unsafe".into());
            }
            T(command_output(&formatted(args)?)?)
        }
        "signal" | "signal_thread" => {
            if !s.allow_unsafe {
                return Err(format!("{name} requires --unsafe"));
            }
            if !s.target_paused {
                return Err(format!(
                    "{name} requires a verified --reliable stopped-target handler"
                ));
            }
            if e.pid == 0
                || e.pid > i32::MAX as u64
                || e.tid == 0
                || e.tid > i32::MAX as u64
                || e.pid == std::process::id() as u64
            {
                return Err("signal requires an external target event".into());
            }
            if s.register_snapshot.is_none() {
                return Err("signals require a stopped-register event, not BEGIN/END".into());
            }
            if s.pending_signals.len() >= 4096 {
                return Err("pending signal limit (4096) exceeded".into());
            }
            let signal = checked_signal(&args[0])?;
            use std::os::fd::FromRawFd;
            // PIDFD_THREAD is O_EXCL; PIDFD_SIGNAL_THREAD is bit 0 in Linux's
            // pidfd UAPI. Thread pidfds prevent TID reuse after detachment.
            let thread = name == "signal_thread";
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_open,
                    if thread { e.tid } else { e.pid } as i32,
                    if thread { libc::O_EXCL } else { 0 },
                )
            };
            if raw < 0 {
                return Err(format!(
                    "{name} requires supported pidfds: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
            s.pending_signals.push(DeferredSignal {
                fd,
                signal,
                flags: if thread { 1 } else { 0 },
            });
            N(0)
        }
        "write_user" => {
            if !s.allow_unsafe {
                return Err("write_user requires --unsafe".into());
            }
            if !s.target_paused || s.register_snapshot.is_none() {
                return Err(
                    "write_user requires a verified --reliable stopped-register handler".into(),
                );
            }
            if e.pid == 0 || e.pid > i32::MAX as u64 || e.pid == std::process::id() as u64 {
                return Err("write_user requires an external target event".into());
            }
            let count = usize::try_from(n(2)?).map_err(|_| "invalid write length")?;
            if count > 4096 {
                return Err("write_user limit is 4096 bytes".into());
            }
            if n(0)?.checked_add(count as u64).is_none() {
                return Err("write_user address overflow".into());
            }
            if count == 0 {
                return Ok(N(1));
            }
            let mut data = bytes(&args[1])?;
            data.push(0);
            if data.len() < count {
                return Err("write_user source is shorter than length".into());
            }
            let local = libc::iovec {
                iov_base: data.as_ptr() as *mut _,
                iov_len: count,
            };
            let remote = libc::iovec {
                iov_base: n(0)? as *mut _,
                iov_len: count,
            };
            let written =
                unsafe { libc::process_vm_writev(e.pid as i32, &local, 1, &remote, 1, 0) };
            N((written == count as isize) as u64)
        }
        _ => {
            return Err(format!(
                "{name} unavailable: {}",
                unavailable(name).unwrap_or("unsupported helper")
            ));
        }
    })
}

pub(crate) unsafe fn invoke(
    state: *mut State<'_>,
    event: *const Event<'_>,
    op: u64,
    values: u64,
    descriptor: u64,
) -> u64 {
    let s = unsafe { &mut *state };
    let e = unsafe { &*event };
    let empty = if op == 200 { c"".as_ptr() as u64 } else { 0 };
    if s.stopped || s.error.is_some() {
        return empty;
    }
    let result = (|| -> Result<Arg> {
        let metadata = unsafe { CStr::from_ptr(descriptor as *const libc::c_char) }
            .to_str()
            .map_err(|e| e.to_string())?;
        let (name, types): (String, Vec<u64>) =
            serde_json::from_str(metadata).map_err(|e| e.to_string())?;
        if types.len() > 16 {
            return Err("helper argument limit exceeded".into());
        }
        let raw = unsafe { std::slice::from_raw_parts(values as *const u64, types.len()) };
        let mut args = Vec::new();
        for (value, ty) in raw.iter().zip(types) {
            args.push(if ty == Type::String as u64 || ty == Type::Stack as u64 {
                Arg::Text(
                    unsafe { CStr::from_ptr(*value as *const libc::c_char) }
                        .to_string_lossy()
                        .into_owned(),
                )
            } else if ty == Type::Float as u64 {
                Arg::Float(*value)
            } else {
                Arg::Number(*value)
            });
        }
        if args
            .iter()
            .any(|arg| matches!(arg,Arg::Text(text) if text.len()>65536))
        {
            return Err("helper string argument exceeds 64 KiB".into());
        }
        let call = Call { name, args };
        let descriptor = serde_json::to_string(&call).map_err(|e| e.to_string())?;
        if let Some(queue) = s.replay.as_mut().filter(|_| !pure(&call.name, &call.args)) {
            let item = if s.replay_lookup {
                let candidates: Vec<_> = queue
                    .iter()
                    .filter(|h| h.op == op && h.descriptor.as_ref() == Some(&descriptor))
                    .cloned()
                    .collect();
                if candidates.windows(2).any(|pair| {
                    pair[0].text != pair[1].text
                        || pair[0].number != pair[1].number
                        || pair[0].error != pair[1].error
                }) {
                    return Err("conflicting captured helper results".into());
                }
                candidates.into_iter().next()
            } else {
                queue.pop_front()
            };
            let item = item.ok_or("replay requires a captured result for this helper")?;
            if item.op != op
                || item.descriptor.as_ref() != Some(&descriptor)
                || item.text.is_some() != (op == 200)
            {
                return Err("captured helper descriptor or result type does not match".into());
            }
            if let Some(error) = item.error {
                return Err(error);
            }
            return Ok(if let Some(text) = item.text {
                Arg::Text(text)
            } else {
                Arg::Number(item.number)
            });
        }
        // Pure helpers can be recomputed in alternate replay, but normal replay
        // must consume and validate the original journal entry.
        let value = (|| -> Result<Arg> {
            let identity = target_observation(s, e, &call.name, &call.args)?;
            let value = evaluate(s, e, &call.name, &call.args)?;
            if let Some((pid, started)) = identity {
                if crate::managed_bridge::start_ticks(pid)? != started {
                    return Err(format!("PID {pid} changed identity during {}", call.name));
                }
            }
            Ok(value)
        })();

        if let Some(queue) = s.replay.as_mut().filter(|_| !s.replay_lookup) {
            let item = queue
                .pop_front()
                .ok_or("recording helper stream exhausted")?;
            if item.op != op
                || item.descriptor.as_ref() != Some(&descriptor)
                || item.text.is_some() != (op == 200)
            {
                return Err("recording helper does not match script".into());
            }
            if let Some(error) = item.error {
                return Err(error);
            }
            let recorded = if let Some(text) = item.text {
                Arg::Text(text)
            } else {
                Arg::Number(item.number)
            };
            if value.as_ref().ok() != Some(&recorded) {
                return Err("deterministic helper result mismatch".into());
            }
        }
        if s.recorder.is_some() {
            s.journal.push(Helper {
                op,
                value: 0,
                length: 0,
                number: match &value {
                    Ok(Arg::Number(n)) => *n,
                    _ => 0,
                },
                text: if op == 200 {
                    Some(match &value {
                        Ok(Arg::Text(t)) => t.clone(),
                        _ => String::new(),
                    })
                } else {
                    None
                },
                descriptor: Some(descriptor),
                error: value.as_ref().err().cloned(),
            });
        }
        value
    })();
    match result {
        Ok(Arg::Number(n)) if op == 201 => n,
        Ok(Arg::Text(t)) if op == 200 => {
            let text = CString::new(t.replace('\0', "\\0")).unwrap();
            let ptr = text.as_ptr() as u64;
            s.stack_strings.push(text);
            ptr
        }
        Ok(_) => {
            s.fail("helper result type mismatch".into());
            empty
        }
        Err(error) => {
            s.fail(error);
            empty
        }
    }
}

fn command_output(command: &str) -> Result<String> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err("system requires default, waitable SIGCHLD handling".into());
    }
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new("/bin/sh")
        .args(["-c", command])
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let group = child.id() as i32;
    let result = (|| -> Result<String> {
        let mut pipe = child.stdout.take().ok_or("system stdout is unavailable")?;
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut output = Vec::new();
        let mut eof = false;
        loop {
            let mut buffer = [0u8; 4096];
            match pipe.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(n) => {
                    output.extend_from_slice(&buffer[..n]);
                    if output.len() > 65536 {
                        return Err("system output exceeds 64 KiB".into());
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.to_string()),
            }
            let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    group as u32,
                    &mut status,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if unsafe { status.si_pid() } != 0 && eof {
                if status.si_code != libc::CLD_EXITED || unsafe { status.si_status() } != 0 {
                    return Err(format!("system command exited with status {}", unsafe {
                        status.si_status()
                    }));
                }
                return Ok(String::from_utf8_lossy(&output).into_owned());
            }
            if Instant::now() >= deadline {
                return Err("system command exceeded 5 seconds".into());
            }
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe {
                libc::poll(&mut poll, 1, 1);
            }
        }
    })();
    // This group contains only the explicitly launched helper command, never
    // traced/attached tasks. Close inherited stdout writers and reap on errors.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    result
}

pub(crate) fn constant(name: &str) -> Option<u64> {
    Some(match name {
        "AF_INET" => libc::AF_INET as u64,
        "AF_INET6" => libc::AF_INET6 as u64,
        "SIGRTMIN" => libc::SIGRTMIN() as u64,
        "SIGRTMAX" => libc::SIGRTMAX() as u64,
        _ => {
            let name = name.strip_prefix("SIG")?;
            signal_table().iter().find(|(_, signal)| *signal == name)?.0 as u64
        }
    })
}
