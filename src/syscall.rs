//! Explicit ptrace syscall backend. Seized targets are detached, never killed here.
use crate::Result;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    follow: bool,
    observe_syscalls: bool,
    discovered: Vec<i32>,
    pending: VecDeque<(i32, i32)>,
    wait_cursor: i32,
}
fn ptrace_io(
    request: libc::c_uint,
    tid: i32,
    address: usize,
    data: usize,
) -> std::io::Result<libc::c_long> {
    let value = unsafe {
        libc::ptrace(
            request,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if value < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
fn ptrace(request: libc::c_uint, tid: i32, address: usize, data: usize) -> Result<libc::c_long> {
    ptrace_io(request, tid, address, data)
        .map_err(|error| format!("ptrace TID {tid} request {request}: {error}"))
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
            follow: false,
            observe_syscalls: true,
            discovered: Vec::new(),
            pending: VecDeque::new(),
            wait_cursor: 0,
        };
        let flags = libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK;
        for tid in tids {
            ptrace(libc::PTRACE_SEIZE, tid, 0, flags as usize)?;
            tracer.tids.insert(tid);
            tracer.initial.insert(tid);
            ptrace(libc::PTRACE_INTERRUPT, tid, 0, 0)?;
        }
        Ok(tracer)
    }
    /// Attach a bounded snapshot of already-existing descendants as well as the root.
    pub fn seize_tree(
        pid: i32,
        tids: impl IntoIterator<Item = i32>,
        launched: bool,
        include_descendants: bool,
    ) -> Result<Self> {
        let mut tasks: BTreeSet<i32> = tids.into_iter().collect();
        if include_descendants {
            tasks.extend(descendant_tasks(pid)?);
        }
        let mut tracer = Self::seize(pid, tasks, launched)?;
        tracer.follow = include_descendants;
        Ok(tracer)
    }
    pub fn trace_syscalls(&mut self, enabled: bool) {
        self.observe_syscalls = enabled;
    }
    pub fn take_discovered(&mut self) -> Vec<i32> {
        std::mem::take(&mut self.discovered)
    }
    pub fn follow_forks(&mut self, follow: bool) {
        self.follow = follow;
    }
    pub fn targets(&self) -> BTreeSet<i32> {
        self.tids.iter().filter_map(|tid| tgid(*tid)).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.tids.is_empty()
    }
    fn record_exit(&mut self, tid: i32, status: i32) {
        self.tids.remove(&tid);
        self.initial.remove(&tid);
        self.held.remove(&tid);
        self.entries.remove(&tid);
        self.exits.insert(
            tid,
            if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            },
        );
    }
    // A sibling may execute exit_group, or exec may replace the leader, even
    // while this TID has an observed syscall stop. Accept ESRCH only after a
    // newer wait status or explicit evidence that the old task has died.
    fn request(
        &mut self,
        request: libc::c_uint,
        tid: i32,
        address: usize,
        data: usize,
    ) -> Result<Option<libc::c_long>> {
        match ptrace_io(request, tid, address, data) {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                if error.raw_os_error() == Some(libc::ESRCH) {
                    let deadline = Instant::now() + Duration::from_millis(20);
                    loop {
                        let mut status = 0;
                        let waited = unsafe {
                            libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG)
                        };
                        if waited == tid {
                            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                                self.record_exit(tid, status);
                                return Ok(None);
                            }
                            if libc::WIFSTOPPED(status) {
                                self.held.insert(tid);
                                self.pending.push_back((tid, status));
                                return Ok(None);
                            }
                        }
                        let wait_error = std::io::Error::last_os_error().raw_os_error();
                        match std::fs::read_to_string(format!("/proc/{tid}/stat")) {
                            Ok(stat)
                                if stat.rsplit_once(')').is_some_and(|(_, tail)| {
                                    matches!(tail.split_whitespace().next(), Some("Z" | "X" | "x"))
                                }) =>
                            {
                                return Ok(None);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                if waited < 0 && wait_error == Some(libc::ECHILD) {
                                    self.tids.remove(&tid);
                                    self.initial.remove(&tid);
                                    self.held.remove(&tid);
                                    self.entries.remove(&tid);
                                }
                                return Ok(None);
                            }
                            _ => {}
                        }
                        if Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_micros(50));
                    }
                }
                Err(format!("ptrace TID {tid} request {request}: {error}"))
            }
        }
    }
    fn wait_next(&mut self, status: &mut i32) -> i32 {
        use std::ops::Bound::{Excluded, Unbounded};
        // waitpid(-1) can repeatedly choose the lowest busy TID. Check one
        // rotating tracked task first, then accept any other ready/new child.
        // This costs at most two waits per event, independent of thread count.
        let candidate = self
            .tids
            .range((Excluded(self.wait_cursor), Unbounded))
            .next()
            .or_else(|| self.tids.first())
            .copied();
        if let Some(tid) = candidate {
            self.wait_cursor = tid;
            let result = unsafe { libc::waitpid(tid, status, libc::__WALL | libc::WNOHANG) };
            if result > 0
                || result < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
            {
                return result;
            }
        }
        unsafe { libc::waitpid(-1, status, libc::__WALL | libc::WNOHANG) }
    }
    pub fn poll(&mut self) -> Result<Vec<Event>> {
        let mut output = Vec::new();
        // Bound each pass so timers, duration limits and interrupts remain responsive.
        for _ in 0..1024 {
            let mut status = 0;
            let tid = if let Some((tid, saved)) = self.pending.pop_front() {
                status = saved;
                tid
            } else {
                self.wait_next(&mut status)
            };
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
                self.record_exit(tid, status);
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }
            self.held.remove(&tid);
            if self.initial.contains(&tid) || !self.tids.contains(&tid) {
                let tgid = std::fs::read_to_string(format!("/proc/{tid}/status"))
                    .ok()
                    .and_then(|status| {
                        status.lines().find_map(|line| {
                            line.strip_prefix("Tgid:")
                                .and_then(|value| value.trim().parse::<i32>().ok())
                        })
                    });
                if !self.follow && tgid.is_some_and(|tgid| tgid != self.pid) {
                    let _ = ptrace(libc::PTRACE_DETACH, tid, 0, 0);
                    self.tids.remove(&tid);
                    self.initial.remove(&tid);
                    continue;
                }
            }
            self.tids.insert(tid);
            let signal = libc::WSTOPSIG(status);
            let event = status >> 16;
            let initial = self.initial.remove(&tid);
            let mut deliver = 0;
            if matches!(
                event,
                libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK
            ) {
                let mut child = 0usize;
                if self
                    .request(
                        libc::PTRACE_GETEVENTMSG,
                        tid,
                        0,
                        (&mut child as *mut usize) as usize,
                    )?
                    .is_none()
                {
                    continue;
                }
                self.tids.insert(child as i32);
                self.initial.insert(child as i32);
            } else if event == libc::PTRACE_EVENT_EXEC {
                let mut old = 0usize;
                if self
                    .request(
                        libc::PTRACE_GETEVENTMSG,
                        tid,
                        0,
                        (&mut old as *mut usize) as usize,
                    )?
                    .is_none()
                {
                    continue;
                }
                if old as i32 != tid {
                    self.tids.remove(&(old as i32));
                    self.initial.remove(&(old as i32));
                    self.entries.remove(&(old as i32));
                }
                self.active = true;
                self.entries.remove(&tid);
            } else if signal == (libc::SIGTRAP | 0x80) {
                let mut info = [0u8; 88];
                let Some(n) = self.request(0x420e, tid, info.len(), info.as_mut_ptr() as usize)?
                else {
                    continue;
                };
                let n = n as usize;
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
                    self.request(libc::PTRACE_LISTEN, tid, 0, 0)?;
                    continue;
                }
            } else {
                deliver = signal;
            }
            if initial && event == libc::PTRACE_EVENT_STOP && signal == libc::SIGTRAP {
                self.discovered.push(tid);
                self.held.insert(tid);
                return Ok(output);
            }
            // Dispatch each stop before resuming so memory helpers observe the stopped task.
            if !output.is_empty() {
                self.held.insert(tid);
                return Ok(output);
            }
            self.request(
                if self.observe_syscalls {
                    libc::PTRACE_SYSCALL
                } else {
                    libc::PTRACE_CONT
                },
                tid,
                0,
                deliver as usize,
            )?;
        }
        Ok(output)
    }
    pub fn resume(&mut self, tid: i32) -> Result<()> {
        self.held.remove(&tid);
        self.request(
            if self.observe_syscalls {
                libc::PTRACE_SYSCALL
            } else {
                libc::PTRACE_CONT
            },
            tid,
            0,
            0,
        )
        .map(|_| ())
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
    fn live_untraced_task_is_not_mistaken_for_an_exited_target() {
        let pid = std::process::id() as i32;
        let mut tracer = Tracer {
            pid,
            tids: BTreeSet::from([pid]),
            initial: BTreeSet::new(),
            entries: BTreeMap::new(),
            exits: BTreeMap::new(),
            active: true,
            held: BTreeSet::new(),
            follow: false,
            observe_syscalls: true,
            discovered: Vec::new(),
            pending: VecDeque::new(),
            wait_cursor: 0,
        };
        assert!(tracer.resume(pid).is_err());
        assert!(tracer.tids.contains(&pid));
        assert!(tracer.exits.is_empty());
        // This fixture owns no ptrace attachment to detach.
        tracer.tids.clear();
    }
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

pub fn tgid(tid: i32) -> Option<i32> {
    std::fs::read_to_string(format!("/proc/{tid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:")?.trim().parse().ok())
}

/// Decode native syscall stops for the shared function/syscall dispatcher.
#[derive(Default)]
pub struct Decoder {
    entries: BTreeMap<i32, Entry>,
}
impl Decoder {
    pub fn clear(&mut self, tid: i32) {
        self.entries.remove(&tid);
    }
    pub fn stop(&mut self, tid: i32) -> Result<Option<Event>> {
        let mut info = [0u8; 88];
        let n = ptrace(0x420e, tid, info.len(), info.as_mut_ptr() as usize)? as usize;
        if n < 24 {
            return Err("PTRACE_GET_SYSCALL_INFO requires Linux 5.3+".into());
        }
        #[cfg(target_arch = "x86_64")]
        let arch = 0xc000003eu32;
        #[cfg(target_arch = "aarch64")]
        let arch = 0xc00000b7u32;
        if u32::from_ne_bytes(info[4..8].try_into().unwrap()) != arch {
            return Err("native 64-bit syscall ABI required".into());
        }
        let word = |at| u64::from_ne_bytes(info[at..at + 8].try_into().unwrap());
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
            Ok(Some(Event {
                tid,
                enter: true,
                number,
                args,
                retval: 0,
                latency: 0,
                ip: word(8),
            }))
        } else if info[0] == 2 && n >= 33 {
            Ok(self.entries.remove(&tid).map(|e| Event {
                tid,
                enter: false,
                number: e.number,
                args: e.args,
                retval: word(24) as i64,
                latency: e.start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                ip: word(8),
            }))
        } else {
            Ok(None)
        }
    }
}

/// Snapshot descendants through every thread's children list, with explicit bounds.
/// Tasks can still exit or reparent while this snapshot is collected.
pub fn descendants(pid: i32) -> Result<Vec<i32>> {
    let mut seen = BTreeSet::from([pid]);
    let mut queue = std::collections::VecDeque::from([pid]);
    let mut output = Vec::new();
    while let Some(parent) = queue.pop_front() {
        let tasks = match std::fs::read_dir(format!("/proc/{parent}/task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("discover descendants of {parent}: {error}")),
        };
        for task in tasks {
            let task = task.map_err(|e| e.to_string())?;
            let children = match std::fs::read_to_string(task.path().join("children")) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("read descendant list: {error}")),
            };
            for child in children
                .split_whitespace()
                .filter_map(|s| s.parse::<i32>().ok())
            {
                if seen.insert(child) {
                    if seen.len() > 1024 {
                        return Err("existing descendant limit (1024) exceeded".into());
                    }
                    output.push(child);
                    queue.push_back(child);
                }
            }
        }
    }
    Ok(output)
}
pub(crate) fn descendant_tasks(pid: i32) -> Result<Vec<i32>> {
    let mut output = Vec::new();
    for child in descendants(pid)? {
        let tasks = match std::fs::read_dir(format!("/proc/{child}/task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        for task in tasks {
            if let Ok(tid) = task
                .map_err(|e| e.to_string())?
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
            {
                output.push(tid);
            }
            if output.len() > 4096 {
                return Err("existing descendant thread limit (4096) exceeded".into());
            }
        }
    }
    Ok(output)
}
