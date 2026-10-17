//! Explicit ptrace syscall backend. Seized targets are detached, never killed here.
use crate::Result;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

#[cfg(target_arch = "x86_64")]
const TABLE: &str = include_str!("syscalls/x86_64.txt");
#[cfg(target_arch = "aarch64")]
const TABLE: &str = include_str!("syscalls/aarch64.txt");
fn names() -> &'static BTreeMap<i64, &'static str> {
    static NAMES: std::sync::OnceLock<BTreeMap<i64, &'static str>> = std::sync::OnceLock::new();
    NAMES.get_or_init(|| {
        TABLE
            .lines()
            .filter_map(|line| {
                let (number, name) = line.split_once(' ')?;
                Some((number.parse().ok()?, name))
            })
            .collect()
    })
}
pub fn number(name: &str) -> Option<i64> {
    names()
        .iter()
        .find(|(_, value)| **value == name)
        .map(|(number, _)| *number)
        .or_else(|| name.parse::<i64>().ok().filter(|n| *n >= 0))
}
pub fn name(number: i64) -> String {
    names()
        .get(&number)
        .map(|name| (*name).into())
        .unwrap_or_else(|| format!("sys_{number}"))
}
#[derive(Clone, Debug)]
pub struct Event {
    pub tid: i32,
    pub enter: bool,
    pub number: i64,
    pub args: [u64; 6],
    pub retval: i64,
    pub latency: u64,
    pub ip: u64,
}
struct Entry {
    number: i64,
    args: [u64; 6],
    start: Instant,
}
pub struct Tracer {
    pid: i32,
    tids: BTreeSet<i32>,
    initial: BTreeSet<i32>,
    entries: BTreeMap<i32, Entry>,
    pub exits: BTreeMap<i32, i32>,
    active: bool,
    held: BTreeSet<i32>,
}
fn ptrace(request: libc::c_uint, tid: i32, address: usize, data: usize) -> Result<libc::c_long> {
    let value = unsafe {
        libc::ptrace(
            request,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if value < 0 {
        Err(format!(
            "ptrace TID {tid}: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(value)
    }
}
impl Tracer {
    pub fn seize(pid: i32, tids: impl IntoIterator<Item = i32>, launched: bool) -> Result<Self> {
        let mut tracer = Self {
            pid,
            tids: BTreeSet::new(),
            initial: BTreeSet::new(),
            entries: BTreeMap::new(),
            exits: BTreeMap::new(),
            active: !launched,
            held: BTreeSet::new(),
        };
        let flags =
            libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC;
        for tid in tids {
            ptrace(libc::PTRACE_SEIZE, tid, 0, flags as usize)?;
            tracer.tids.insert(tid);
            tracer.initial.insert(tid);
            ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0)?;
        }
        Ok(tracer)
    }
    pub fn is_empty(&self) -> bool {
        self.tids.is_empty()
    }
    pub fn poll(&mut self) -> Result<Vec<Event>> {
        let mut output = Vec::new();
        // Bound each pass so timers, duration limits and interrupts remain responsive.
        for _ in 0..1024 {
            let mut status = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if tid == 0 {
                break;
            }
            if tid < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(error.raw_os_error(), Some(libc::ECHILD | libc::EINTR)) {
                    break;
                }
                return Err(error.to_string());
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.tids.remove(&tid);
                self.initial.remove(&tid);
                self.entries.remove(&tid);
                self.exits.insert(
                    tid,
                    if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        128 + libc::WTERMSIG(status)
                    },
                );
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            if self.initial.contains(&tid) || !self.tids.contains(&tid) {
                let tgid = std::fs::read_to_string(format!("/proc/{tid}/status"))
                    .ok()
                    .and_then(|status| {
                        status.lines().find_map(|line| {
                            line.strip_prefix("Tgid:")
                                .and_then(|value| value.trim().parse::<i32>().ok())
                        })
                    });
                if tgid.is_some_and(|tgid| tgid != self.pid) {
                    let _ = ptrace(libc::PTRACE_DETACH, tid, 0, 0);
                    self.tids.remove(&tid);
                    self.initial.remove(&tid);
                    continue;
                }
            }
            self.tids.insert(tid);
            let signal = libc::WSTOPSIG(status);
            let event = status >> 16;
            self.initial.remove(&tid);
            let mut deliver = 0;
            if event == libc::PTRACE_EVENT_CLONE {
                let mut child = 0usize;
                ptrace(
                    libc::PTRACE_GETEVENTMSG,
                    tid,
                    0,
                    (&mut child as *mut usize) as usize,
                )?;
                self.tids.insert(child as i32);
                self.initial.insert(child as i32);
            } else if event == libc::PTRACE_EVENT_EXEC {
                self.active = true;
                self.entries.remove(&tid);
            } else if signal == (libc::SIGTRAP | 0x80) {
                let mut info = [0u8; 88];
                let n = ptrace(0x420e, tid, info.len(), info.as_mut_ptr() as usize)? as usize;
                if n < 24 {
                    return Err("PTRACE_GET_SYSCALL_INFO requires Linux 5.3 or newer".into());
                }
                #[cfg(target_arch = "x86_64")]
                let native_arch = 0xc000003eu32;
                #[cfg(target_arch = "aarch64")]
                let native_arch = 0xc00000b7u32;
                if u32::from_ne_bytes(info[4..8].try_into().unwrap()) != native_arch {
                    return Err("syscall tracing supports native 64-bit targets only".into());
                }
                let word = |at| u64::from_ne_bytes(info[at..at + 8].try_into().unwrap());
                if self.active {
                    if info[0] == 1 && n >= 80 {
                        let number = word(24) as i64;
                        let args = std::array::from_fn(|i| word(32 + i * 8));
                        self.entries.insert(
                            tid,
                            Entry {
                                number,
                                args,
                                start: Instant::now(),
                            },
                        );
                        output.push(Event {
                            tid,
                            enter: true,
                            number,
                            args,
                            retval: 0,
                            latency: 0,
                            ip: word(8),
                        });
                    } else if info[0] == 2 && n >= 33 {
                        if let Some(entry) = self.entries.remove(&tid) {
                            output.push(Event {
                                tid,
                                enter: false,
                                number: entry.number,
                                args: entry.args,
                                retval: word(24) as i64,
                                latency: entry.start.elapsed().as_nanos().min(u64::MAX as u128)
                                    as u64,
                                ip: word(8),
                            });
                        }
                    }
                }
            } else if event == libc::PTRACE_EVENT_STOP {
                if signal != libc::SIGTRAP {
                    ptrace(libc::PTRACE_LISTEN, tid, 0, 0)?;
                    continue;
                }
            } else {
                deliver = signal;
            }
            // Dispatch each stop before resuming so memory helpers observe the stopped task.
            if !output.is_empty() {
                self.held.insert(tid);
                return Ok(output);
            }
            ptrace(libc::PTRACE_SYSCALL, tid, 0, deliver as usize)?;
        }
        Ok(output)
    }
    pub fn resume(&mut self, tid: i32) -> Result<()> {
        self.held.remove(&tid);
        ptrace(libc::PTRACE_SYSCALL, tid, 0, 0).map(|_| ())
    }
}
impl Tracer {
    pub fn detach(&mut self) {
        // A pending syscall event may already be stopped; detach it directly.
        let mut pending = BTreeSet::new();
        for &tid in &self.tids {
            if self.held.contains(&tid) && ptrace(libc::PTRACE_DETACH, tid, 0, 0).is_ok() {
                continue;
            }
            let _ = ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0);
            pending.insert(tid);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while !pending.is_empty() && Instant::now() < deadline {
            let mut progressed = false;
            for tid in pending.clone() {
                let mut status = 0;
                let result =
                    unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
                if result == tid {
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        self.exits.insert(
                            tid,
                            if libc::WIFEXITED(status) {
                                libc::WEXITSTATUS(status)
                            } else {
                                128 + libc::WTERMSIG(status)
                            },
                        );
                    }
                    let signal = if libc::WIFSTOPPED(status)
                        && status >> 16 == 0
                        && libc::WSTOPSIG(status) != (libc::SIGTRAP | 0x80)
                    {
                        libc::WSTOPSIG(status)
                    } else {
                        0
                    };
                    let _ = ptrace(libc::PTRACE_DETACH, tid, 0, signal as usize);
                    pending.remove(&tid);
                    progressed = true;
                } else if result < 0 {
                    pending.remove(&tid);
                }
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.tids.clear();
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if !self.tids.is_empty() {
            self.detach();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_names_and_numeric_fallback() {
        assert_eq!(number("write"), Some(libc::SYS_write));
        assert_eq!(name(libc::SYS_getpid), "getpid");
        assert_eq!(name(99999), "sys_99999");
        assert_eq!(number("99999"), Some(99999));
        assert_eq!(number("-1"), None);
        for (&number, &name) in names() {
            assert_eq!(super::number(name), Some(number));
        }
    }
}
