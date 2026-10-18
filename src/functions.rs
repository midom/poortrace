//! All-stop ptrace function breakpoints. Text words are restored before detach.
use crate::{Result, perf::UserRegs, symbols::Mapping};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Spec {
    pub path: String,
    pub function: String,
    pub ret: bool,
}
struct Binding {
    usdt: Option<crate::usdt::Site>,
    offset: u64,
    inode: u64,
    device: u64,
    ret: bool,
}
#[derive(Clone)]
struct Breakpoint {
    entries: Vec<usize>,
    returns: usize,
    enabled: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    inode: u64,
    device: u64,
    offset: u64,
}
#[derive(Clone)]
struct Word {
    original: u64,
    identity: Identity,
}
#[derive(Clone)]
struct Call {
    binding: usize,
    address: u64,
    image: Identity,
    sp: u64,
    args: [u64; 6],
    start: Instant,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub binding: usize,
    pub syscall: Option<crate::syscall::Event>,
    pub tid: i32,
    pub args: [u64; 6],
    pub retval: i64,
    pub latency: u64,
    pub regs: UserRegs,
}
#[derive(Clone)]
struct Registers {
    data: [u64; 34],
    length: usize,
}
impl Registers {
    fn read(tid: i32) -> Result<Self> {
        let mut regs = Self {
            data: [0; 34],
            length: 34 * 8,
        };
        let mut iov = libc::iovec {
            iov_base: regs.data.as_mut_ptr().cast(),
            iov_len: regs.length,
        };
        control(
            libc::PTRACE_GETREGSET,
            tid,
            1,
            (&mut iov as *mut libc::iovec) as usize,
        )?;
        regs.length = iov.iov_len;
        #[cfg(target_arch = "x86_64")]
        let expected = 216;
        #[cfg(target_arch = "aarch64")]
        let expected = 272;
        if regs.length != expected {
            return Err("function probes require native 64-bit register sets".into());
        }
        Ok(regs)
    }
    fn write(&self, tid: i32) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: self.data.as_ptr() as *mut libc::c_void,
            iov_len: self.length,
        };
        control(
            libc::PTRACE_SETREGSET,
            tid,
            1,
            (&mut iov as *mut libc::iovec) as usize,
        )
        .map(|_| ())
    }
    #[cfg(target_arch = "x86_64")]
    fn user(&self) -> UserRegs {
        UserRegs {
            ip: self.data[16],
            sp: self.data[19],
            fp: self.data[4],
            lr: 0,
            runtime_g: self.data[1],
        }
    }
    #[cfg(target_arch = "aarch64")]
    fn user(&self) -> UserRegs {
        UserRegs {
            ip: self.data[32],
            sp: self.data[31],
            fp: self.data[29],
            lr: self.data[30],
            runtime_g: self.data[28],
        }
    }
    #[cfg(target_arch = "x86_64")]
    fn set_ip(&mut self, ip: u64) {
        self.data[16] = ip;
    }
    #[cfg(target_arch = "aarch64")]
    fn set_ip(&mut self, ip: u64) {
        self.data[32] = ip;
    }
    #[cfg(target_arch = "x86_64")]
    fn args(&self) -> [u64; 6] {
        [
            self.data[14],
            self.data[13],
            self.data[12],
            self.data[11],
            self.data[9],
            self.data[8],
        ]
    }
    #[cfg(target_arch = "aarch64")]
    fn args(&self) -> [u64; 6] {
        self.data[..6].try_into().unwrap()
    }
    #[cfg(target_arch = "x86_64")]
    fn syscall_number(&self) -> i64 {
        self.data[15] as i64
    }
    #[cfg(target_arch = "aarch64")]
    fn syscall_number(&self) -> i64 {
        self.data[8] as i64
    }
    #[cfg(target_arch = "x86_64")]
    fn retval(&self) -> i64 {
        self.data[10] as i64
    }
    #[cfg(target_arch = "aarch64")]
    fn retval(&self) -> i64 {
        self.data[0] as i64
    }
}
fn control_io(
    request: libc::c_uint,
    tid: i32,
    address: usize,
    data: usize,
) -> std::io::Result<libc::c_long> {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let value = unsafe {
        libc::ptrace(
            request,
            tid,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if value == -1 && std::io::Error::last_os_error().raw_os_error() != Some(0) {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(value)
    }
}
fn control(request: libc::c_uint, tid: i32, address: usize, data: usize) -> Result<libc::c_long> {
    control_io(request, tid, address, data)
        .map_err(|error| format!("function ptrace request {request} TID {tid}: {error}"))
}
fn maps(pid: i32) -> Result<Vec<Mapping>> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|text| text.lines().filter_map(Mapping::parse).collect())
        .map_err(|e| e.to_string())
}
// Include non-executable mappings when deciding whether our saved original
// bytes still belong to a live image after mprotect removes execute permission.
fn memory_maps(pid: i32) -> Result<Vec<Mapping>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|e| e.to_string())?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut rest = line;
            let mut field = || {
                rest = rest.trim_start();
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                let (value, tail) = rest.split_at(end);
                rest = tail;
                value
            };
            let (start, end) = field().split_once('-')?;
            let permissions = field();
            let offset = u64::from_str_radix(field(), 16).ok()?;
            let (major, minor) = field().split_once(':')?;
            let inode = field().parse().ok()?;
            Some(Mapping {
                start: u64::from_str_radix(start, 16).ok()?,
                end: u64::from_str_radix(end, 16).ok()?,
                offset,
                inode,
                device: libc::makedev(
                    u32::from_str_radix(major, 16).ok()?,
                    u32::from_str_radix(minor, 16).ok()?,
                ),
                path: rest.trim_start().trim_end_matches(" (deleted)").into(),
                private: permissions.as_bytes().get(3) == Some(&b'p'),
            })
        })
        .collect())
}
fn tgid(tid: i32) -> Option<i32> {
    std::fs::read_to_string(format!("/proc/{tid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Tgid:")?.trim().parse().ok())
}
fn trap(tid: i32, status: i32) -> bool {
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP || status >> 16 != 0 {
        return false;
    }
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    control(
        libc::PTRACE_GETSIGINFO,
        tid,
        0,
        (&mut info as *mut libc::siginfo_t) as usize,
    )
    .is_ok()
        && matches!(info.si_code, libc::TRAP_BRKPT | libc::SI_KERNEL)
}
#[cfg(target_arch = "x86_64")]
fn trap_address(ip: u64) -> Option<u64> {
    ip.checked_sub(1)
}
#[cfg(target_arch = "aarch64")]
fn trap_address(ip: u64) -> Option<u64> {
    Some(ip)
}

#[derive(Clone)]
struct Semaphore {
    site: u64,
    identity: Identity,
}
#[derive(Clone, Default)]
struct AddressSpace {
    semaphores: BTreeMap<u64, Semaphore>,
    words: BTreeMap<u64, Word>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    active: bool,
    unresolved: bool,
}
pub struct Tracer {
    pid: i32,
    root: i32,
    follow: bool,
    spaces: BTreeMap<i32, AddressSpace>,
    owners: BTreeMap<i32, i32>,
    bindings: Vec<Binding>,
    tids: BTreeSet<i32>,
    stopped: BTreeSet<i32>,
    initial: BTreeSet<i32>,
    listening: BTreeSet<i32>,
    pending: VecDeque<(i32, i32)>,
    signals: BTreeMap<i32, i32>,
    semaphores: BTreeMap<u64, Semaphore>,
    words: BTreeMap<u64, Word>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    calls: BTreeMap<i32, Vec<Call>>,
    stack_ranges: BTreeMap<i32, Vec<(u64, u64)>>,
    active_hit: Option<(i32, u64)>,
    vfork: BTreeMap<i32, i32>,
    foreign: BTreeSet<i32>,
    active: bool,
    syscalls: bool,
    track_loads: bool,
    decoder: crate::syscall::Decoder,
    discovered: Vec<i32>,
    unresolved: bool,
    refreshed: Instant,
    pub exits: BTreeMap<i32, i32>,
}
impl Tracer {
    pub fn seize(
        pid: i32,
        tids: impl IntoIterator<Item = i32>,
        specs: &[Spec],
        launched: bool,
    ) -> Result<Self> {
        Self::seize_tree(pid, tids, specs, launched, false)
    }
    pub fn seize_tree(
        pid: i32,
        tids: impl IntoIterator<Item = i32>,
        specs: &[Spec],
        launched: bool,
        include_descendants: bool,
    ) -> Result<Self> {
        Self::seize_group(pid, tids, specs, launched, include_descendants, &[])
    }
    pub fn seize_group(
        pid: i32,
        tids: impl IntoIterator<Item = i32>,
        specs: &[Spec],
        launched: bool,
        include_descendants: bool,
        extra_pids: &[i32],
    ) -> Result<Self> {
        if extra_pids.len() > 1024 || extra_pids.iter().any(|pid| *pid <= 0) {
            return Err("shared-mm PID list requires at most 1024 positive PIDs".into());
        }
        let mut tasks: BTreeSet<i32> = tids.into_iter().collect();
        for extra in extra_pids {
            if tgid(*extra) != Some(*extra) {
                return Err(format!(
                    "shared-mm PID {extra} must name a live process leader"
                ));
            }
            for task in std::fs::read_dir(format!("/proc/{extra}/task"))
                .map_err(|e| format!("shared-mm PID {extra}: {e}"))?
            {
                let task = task.map_err(|e| e.to_string())?;
                if let Ok(tid) = task.file_name().to_string_lossy().parse::<i32>() {
                    tasks.insert(tid);
                }
            }
        }
        if tasks.len() > 4096 {
            return Err("initial thread limit (4096) exceeded".into());
        }
        if include_descendants {
            tasks.extend(crate::syscall::descendant_tasks(pid)?);
        }
        if tasks.len() > 4096 {
            return Err("initial thread limit (4096) exceeded".into());
        }
        if specs.len() > 256 {
            return Err("function tracing supports at most 256 probe bindings".into());
        }
        let mut bindings = Vec::new();
        for spec in specs {
            let resolved = crate::uprobe::locate(pid, &spec.path, &spec.function, spec.ret)?;
            let path = resolved.path.to_str().map_err(|e| e.to_string())?;
            let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
            bindings.push(Binding {
                usdt: crate::usdt::encoded(&spec.function)?,
                offset: resolved.offset,
                inode: meta.ino(),
                device: meta.dev(),
                ret: spec.ret,
            });
        }
        let mut tracer = Self {
            pid,
            root: pid,
            follow: include_descendants || !extra_pids.is_empty(),
            spaces: BTreeMap::new(),
            owners: BTreeMap::from([(pid, pid)]),
            bindings,
            tids: BTreeSet::new(),
            stopped: BTreeSet::new(),
            initial: BTreeSet::new(),
            listening: BTreeSet::new(),
            pending: VecDeque::new(),
            signals: BTreeMap::new(),
            semaphores: BTreeMap::new(),
            words: BTreeMap::new(),
            breakpoints: BTreeMap::new(),
            calls: BTreeMap::new(),
            stack_ranges: BTreeMap::new(),
            active_hit: None,
            vfork: BTreeMap::new(),
            foreign: BTreeSet::new(),
            active: !launched,
            syscalls: false,
            track_loads: false,
            decoder: crate::syscall::Decoder::default(),
            discovered: Vec::new(),
            unresolved: true,
            refreshed: Instant::now(),
            exits: BTreeMap::new(),
        };
        let flags = libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACEVFORKDONE
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACESYSGOOD;
        for tid in tasks {
            control(libc::PTRACE_SEIZE, tid, 0, flags as usize)?;
            tracer.tids.insert(tid);
            tracer.initial.insert(tid);
            if include_descendants || !extra_pids.is_empty() {
                let group = tgid(tid).unwrap_or(tid);
                tracer.owners.entry(group).or_insert(group);
            }
        }
        tracer.stop_world()?;
        for extra in extra_pids {
            if *extra == pid {
                continue;
            }
            let result =
                unsafe { libc::syscall(libc::SYS_kcmp, pid, *extra, 1usize, 0usize, 0usize) };
            if result < 0 {
                return Err(format!(
                    "cannot prove shared address-space ownership for PID {extra}: kcmp(KCMP_VM): {} (host ptrace/kcmp policy applies)",
                    std::io::Error::last_os_error()
                ));
            }
            if result != 0 {
                return Err(format!(
                    "PID {extra} does not share the address space of PID {pid}"
                ));
            }
            tracer.owners.insert(*extra, pid);
        }
        if include_descendants || !extra_pids.is_empty() {
            // kcmp is a read-only identity check. Some hosts deny it even to a
            // ptracer; in that case existing trap validation still fails safely
            // rather than adopting another group's patched text as original.
            let mut representatives: Vec<i32> = Vec::new();
            let mut groups = vec![pid];
            groups.extend(tracer.owners.keys().copied().filter(|group| *group != pid));
            for group in groups {
                let shared = representatives.iter().copied().find(|other| unsafe {
                    libc::syscall(libc::SYS_kcmp, group, *other, 1usize, 0usize, 0usize) == 0
                });
                if let Some(owner) = shared {
                    tracer.owners.insert(group, owner);
                } else {
                    representatives.push(group);
                }
            }
        }
        if tracer.active {
            tracer.refresh()?;
            if include_descendants || !extra_pids.is_empty() {
                for tid in tracer.stopped.clone() {
                    let group = tgid(tid).unwrap_or(tid);
                    if group != tracer.pid {
                        tracer.select(tid);
                        tracer.refresh()?;
                    }
                }
                if let Some(tid) = tracer
                    .stopped
                    .iter()
                    .find(|tid| tgid(**tid) == Some(pid))
                    .copied()
                {
                    tracer.select(tid);
                }
            }
        }
        Ok(tracer)
    }
    pub fn take_discovered(&mut self) -> Vec<i32> {
        std::mem::take(&mut self.discovered)
    }
    pub fn follow_forks(&mut self, follow: bool) {
        self.follow = follow || self.owners.len() > 1;
    }
    /// Declare a coroutine/fiber stack region when several stacks occupy one VMA.
    pub fn register_stack_range(&mut self, tid: i32, low: u64, high: u64) -> Result<()> {
        if !self.tids.contains(&tid) || low >= high || high - low > 1024 * 1024 * 1024 {
            return Err(
                "stack range requires an attached TID and a valid region at most 1 GiB".into(),
            );
        }
        let maps = memory_maps(tid)?;
        if !maps.iter().any(|m| m.start <= low && high <= m.end) {
            return Err("declared stack range is outside a single target memory mapping".into());
        }
        let ranges = self.stack_ranges.entry(tid).or_default();
        if ranges.len() >= 256 || ranges.iter().any(|(a, b)| low < *b && *a < high) {
            return Err("declared stack ranges overlap or exceed 256 ranges".into());
        }
        ranges.push((low, high));
        Ok(())
    }
    fn snapshot(&self) -> AddressSpace {
        AddressSpace {
            semaphores: self.semaphores.clone(),
            words: self.words.clone(),
            breakpoints: self.breakpoints.clone(),
            active: self.active,
            unresolved: self.unresolved,
        }
    }
    fn select(&mut self, tid: i32) {
        if !self.follow {
            return;
        }
        let group = tgid(tid).unwrap_or(tid);
        let owner = *self.owners.get(&group).unwrap_or(&group);
        if owner == self.pid {
            return;
        }
        self.spaces.insert(self.pid, self.snapshot());
        let state = self.spaces.remove(&owner).unwrap_or(AddressSpace {
            active: true,
            unresolved: true,
            ..Default::default()
        });
        self.pid = owner;
        self.semaphores = state.semaphores;
        self.words = state.words;
        self.breakpoints = state.breakpoints;
        self.active = state.active;
        self.unresolved = state.unresolved;
    }
    /// Observe mapping syscalls so short-lived DSOs are bound before returning to userspace.
    pub fn track_loads(&mut self, enabled: bool) {
        self.track_loads = enabled;
    }
    pub fn trace_syscalls(&mut self, enabled: bool) {
        self.syscalls = enabled;
    }
    pub fn targets(&self) -> BTreeSet<i32> {
        self.tids.iter().filter_map(|tid| tgid(*tid)).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.tids.is_empty()
    }
    fn queue(&mut self, tid: i32, status: i32) -> Result<()> {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.tids.remove(&tid);
            self.stopped.remove(&tid);
            self.initial.remove(&tid);
            self.listening.remove(&tid);
            self.calls.remove(&tid);
            let foreign = self.foreign.remove(&tid);
            if foreign {
                self.vfork.retain(|_, child| *child != tid);
            }
            if !foreign || self.follow {
                self.exits.insert(
                    tid,
                    if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else {
                        128 + libc::WTERMSIG(status)
                    },
                );
            }
            return Ok(());
        }
        if !libc::WIFSTOPPED(status) {
            return Ok(());
        }
        self.tids.insert(tid);
        self.stopped.insert(tid);
        self.listening.remove(&tid);
        let event = status >> 16;
        if event == libc::PTRACE_EVENT_EXEC {
            self.stack_ranges.remove(&tid);
            let mut old = 0usize;
            control(
                libc::PTRACE_GETEVENTMSG,
                tid,
                0,
                (&mut old as *mut usize) as usize,
            )?;
            if old as i32 != tid {
                self.forget(old as i32);
            }
        }
        if matches!(
            event,
            libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK
        ) {
            let mut child = 0usize;
            control(
                libc::PTRACE_GETEVENTMSG,
                tid,
                0,
                (&mut child as *mut usize) as usize,
            )?;
            self.tids.insert(child as i32);
            self.initial.insert(child as i32);
            if event != libc::PTRACE_EVENT_VFORK
                && tgid(child as i32).is_some_and(|tgid| tgid != self.root)
            {
                let regs = Registers::read(tid)?;
                let flags = if regs.syscall_number() == libc::SYS_clone {
                    regs.args()[0]
                } else if regs.syscall_number() == libc::SYS_clone3 {
                    control(libc::PTRACE_PEEKDATA, tid, regs.args()[0] as usize, 0)? as u64
                } else {
                    0
                };
                if flags & libc::CLONE_VM as u64 != 0 {
                    self.foreign.insert(child as i32);
                }
            }
            if event == libc::PTRACE_EVENT_VFORK {
                self.vfork.insert(tid, child as i32);
                self.foreign.insert(child as i32);
            }
        }
        if self.follow
            && matches!(
                event,
                libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK
            )
        {
            let mut child = 0usize;
            control(
                libc::PTRACE_GETEVENTMSG,
                tid,
                0,
                (&mut child as *mut usize) as usize,
            )?;
            if self.owners.len() >= 1024 {
                return Err("followed process limit (1024) exceeded".into());
            }
            let child = child as i32;
            let group = tgid(child).unwrap_or(child);
            let parent = tgid(tid).unwrap_or(tid);
            let parent_owner = *self.owners.get(&parent).unwrap_or(&parent);
            if group != parent {
                if self.foreign.contains(&child) {
                    self.owners.insert(group, parent_owner);
                } else {
                    let state = if parent_owner == self.pid {
                        self.snapshot()
                    } else {
                        self.spaces.get(&parent_owner).cloned().unwrap_or_default()
                    };
                    let mut state = state;
                    for breakpoint in state.breakpoints.values_mut() {
                        breakpoint.returns = 0;
                    }
                    if let Some(calls) = self.calls.get(&tid).cloned() {
                        for call in &calls {
                            if let Some(breakpoint) = state.breakpoints.get_mut(&call.address) {
                                breakpoint.returns += 1;
                            }
                        }
                        self.calls.insert(child, calls);
                    }
                    self.spaces.insert(group, state);
                    self.owners.insert(group, group);
                }
            }
        }
        self.pending.push_back((tid, status));
        Ok(())
    }
    fn forget(&mut self, tid: i32) {
        self.tids.remove(&tid);
        self.stopped.remove(&tid);
        self.initial.remove(&tid);
        self.listening.remove(&tid);
        self.signals.remove(&tid);
        self.calls.remove(&tid);
        self.stack_ranges.remove(&tid);
        self.decoder.clear(tid);
    }
    fn stop_world(&mut self) -> Result<()> {
        for &tid in &self.tids {
            if !self.stopped.contains(&tid)
                && !self.listening.contains(&tid)
                && !self.vfork.contains_key(&tid)
            {
                let _ = control(libc::PTRACE_INTERRUPT, tid, 0, 0);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.tids.iter().any(|tid| {
            !self.stopped.contains(tid)
                && !self.listening.contains(tid)
                && !self.vfork.contains_key(tid)
        }) {
            let vanished: Vec<_> = self
                .tids
                .iter()
                .filter(|tid| !std::path::Path::new(&format!("/proc/{tid}")).exists())
                .copied()
                .collect();
            for tid in vanished {
                self.forget(tid);
            }
            if self.tids.iter().all(|tid| {
                self.stopped.contains(tid)
                    || self.listening.contains(tid)
                    || self.vfork.contains_key(tid)
            }) {
                break;
            }
            let mut status = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if tid > 0 {
                self.queue(tid, status)?;
            } else if tid < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    self.tids.clear();
                    break;
                }
                if error.raw_os_error() != Some(libc::EINTR) {
                    return Err(error.to_string());
                }
            } else {
                if Instant::now() >= deadline {
                    return Err(
                        "timed out stopping target threads for a function breakpoint".into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
    /// Stop all tracked tasks and prove that no visible sibling was missed.
    /// Kernel group stops and vfork-blocked parents are quiescent as well.
    pub fn pause_for_snapshot(&mut self) -> Result<()> {
        self.stop_world()?;
        for pid in self.targets() {
            let tasks = match std::fs::read_dir(format!("/proc/{pid}/task")) {
                Ok(tasks) => tasks,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("reliable thread coverage PID {pid}: {error}")),
            };
            for task in tasks {
                let task = task.map_err(|e| e.to_string())?;
                let tid: i32 = task
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "invalid task ID")?;
                if !self.tids.contains(&tid) {
                    return Err(format!(
                        "reliable snapshot cannot proceed: untraced sibling TID {tid}"
                    ));
                }
            }
        }
        Ok(())
    }
    /// Pending stop events must be processed by poll before their tasks resume.
    pub fn release_snapshot(&mut self) -> Result<()> {
        if self.pending.is_empty() && self.active_hit.is_none() {
            self.resume_all()?;
        }
        Ok(())
    }
    /// Registers are read only from observed ptrace stops, never running tasks.
    pub fn snapshot_registers(&self) -> Result<Vec<(i32, UserRegs)>> {
        if !self.active {
            return Ok(Vec::new()); // A launched child has not executed its target yet.
        }
        self.stopped
            .iter()
            .filter(|tid| self.follow || !self.foreign.contains(tid))
            .map(|&tid| Registers::read(tid).map(|regs| (tid, regs.user())))
            .collect()
    }
    fn current_maps(&self) -> Result<Vec<Mapping>> {
        match maps(self.pid) {
            Ok(current) if !current.is_empty() => Ok(current),
            _ => maps(self.memory_tid()?),
        }
    }
    fn memory_tid(&self) -> Result<i32> {
        self.stopped
            .iter()
            .find(|tid| {
                if self.follow {
                    let group = tgid(**tid).unwrap_or(**tid);
                    self.owners.get(&group).copied().unwrap_or(group) == self.pid
                } else {
                    !self.foreign.contains(tid)
                }
            })
            .copied()
            .or_else(|| self.stopped.first().copied())
            .ok_or_else(|| "no stopped thread for breakpoint memory access".into())
    }
    fn identity(address: u64, maps: &[Mapping]) -> Option<Identity> {
        let map = maps
            .iter()
            .find(|map| address >= map.start && address < map.end)?;
        Some(Identity {
            inode: map.inode,
            device: map.device,
            offset: map.offset + address - map.start,
        })
    }
    fn patch(&self, word: u64) -> Result<()> {
        let original = self
            .words
            .get(&word)
            .ok_or("missing original breakpoint word")?
            .original;
        let mut bytes = original.to_ne_bytes();
        for (&address, breakpoint) in self.breakpoints.range(word..word + 8) {
            if breakpoint.enabled {
                let offset = (address - word) as usize;
                #[cfg(target_arch = "x86_64")]
                {
                    bytes[offset] = 0xcc;
                }
                #[cfg(target_arch = "aarch64")]
                {
                    bytes[offset..offset + 4].copy_from_slice(&0xd4200000u32.to_le_bytes());
                }
            }
        }
        control(
            libc::PTRACE_POKEDATA,
            self.memory_tid()?,
            word as usize,
            u64::from_ne_bytes(bytes) as usize,
        )
        .map(|_| ())
    }
    fn ensure(&mut self, address: u64) -> Result<()> {
        if self.breakpoints.contains_key(&address) {
            return Ok(());
        }
        if self.breakpoints.len() >= 1024 {
            return Err("function breakpoint limit (1024) reached".into());
        }
        let word = address & !7;
        if !self.words.contains_key(&word) {
            let current = self.current_maps()?;
            if !current
                .iter()
                .any(|map| word >= map.start && word < map.end && map.private)
            {
                return Err("ptrace function probes require private executable mappings".into());
            }
            let identity =
                Self::identity(word, &current).ok_or("breakpoint is outside executable memory")?;
            let original =
                control(libc::PTRACE_PEEKDATA, self.memory_tid()?, word as usize, 0)? as u64;
            // Validate before adopting a word. A pre-existing CLONE_VM group
            // may expose another group's patch; retaining it as original text
            // would reintroduce that trap during error cleanup.
            let bytes = original.to_ne_bytes();
            let slot = (address - word) as usize;
            #[cfg(target_arch = "x86_64")]
            if bytes[slot] == 0xcc {
                return Err(
                    "probe point already contains INT3 (possibly an existing shared address space)"
                        .into(),
                );
            }
            #[cfg(target_arch = "aarch64")]
            if u32::from_le_bytes(bytes[slot..slot + 4].try_into().unwrap()) & 0xffe0001f
                == 0xd4200000
            {
                return Err(
                    "probe point already contains BRK (possibly an existing shared address space)"
                        .into(),
                );
            }
            self.words.insert(word, Word { original, identity });
        }
        let original = self.words[&word].original.to_ne_bytes();
        let offset = (address - word) as usize;
        #[cfg(target_arch = "x86_64")]
        if original[offset] == 0xcc {
            return Err("probe point already contains an INT3 breakpoint".into());
        }
        #[cfg(target_arch = "aarch64")]
        if u32::from_le_bytes(original[offset..offset + 4].try_into().unwrap()) & 0xffe0001f
            == 0xd4200000
        {
            return Err("probe point already contains a BRK instruction".into());
        }
        self.breakpoints.insert(
            address,
            Breakpoint {
                entries: Vec::new(),
                returns: 0,
                enabled: true,
            },
        );
        self.patch(word)
    }
    fn refresh(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let current = self.current_maps()?;
        let mapped = memory_maps(self.memory_tid()?)?;
        let inactive: Vec<_> = self
            .semaphores
            .iter()
            .filter(|(_, semaphore)| {
                Self::identity(semaphore.site, &current) != Some(semaphore.identity)
            })
            .map(|(&address, _)| address)
            .collect();
        for address in inactive {
            if let Some(semaphore) = self.semaphores.remove(&address) {
                if Self::identity(semaphore.site, &mapped) == Some(semaphore.identity) {
                    adjust_semaphore(self.memory_tid()?, address, -1)?;
                }
            }
        }
        // Never restore stale bytes into an unmapped/replaced image.
        let stale: Vec<_> = self
            .words
            .iter()
            .filter(|(address, word)| Self::identity(**address, &current) != Some(word.identity))
            .map(|(&address, _)| address)
            .collect();
        for word in stale {
            if let Some(original) = self.words.get(&word) {
                if Self::identity(word, &mapped) == Some(original.identity) {
                    control(
                        libc::PTRACE_POKEDATA,
                        self.memory_tid()?,
                        word as usize,
                        original.original as usize,
                    )?;
                }
            }
            self.words.remove(&word);
            self.breakpoints.retain(|address, _| *address & !7 != word);
        }
        for breakpoint in self.breakpoints.values_mut() {
            breakpoint.entries.clear();
            breakpoint.returns = 0;
        }
        self.unresolved = false;
        for index in 0..self.bindings.len() {
            let binding = &self.bindings[index];
            let addresses: Vec<_> = current
                .iter()
                .filter(|map| {
                    map.inode == binding.inode
                        && map.device == binding.device
                        && binding.offset >= map.offset
                        && binding.offset - map.offset < map.end - map.start
                })
                .map(|map| map.start + binding.offset - map.offset)
                .collect();
            if addresses.is_empty() {
                self.unresolved = true;
            }
            for address in addresses {
                if let Some(delta) = self.bindings[index]
                    .usdt
                    .as_ref()
                    .and_then(|s| s.semaphore_delta)
                {
                    let semaphore = address.wrapping_add(delta as u64);
                    if !self.semaphores.contains_key(&semaphore) {
                        let identity =
                            Self::identity(address, &current).ok_or("SDT site mapping vanished")?;
                        adjust_semaphore(self.memory_tid()?, semaphore, 1)?;
                        self.semaphores.insert(
                            semaphore,
                            Semaphore {
                                site: address,
                                identity,
                            },
                        );
                    }
                }
                self.ensure(address)?;
                self.breakpoints
                    .get_mut(&address)
                    .unwrap()
                    .entries
                    .push(index);
            }
        }
        // A still-active frame can survive a temporary removal of execute
        // permission. Reinstall its return trap only in the original image.
        let pending: Vec<_> = self
            .calls
            .iter()
            .filter(|(tid, _)| {
                let group = tgid(**tid).unwrap_or(**tid);
                self.owners.get(&group).copied().unwrap_or(group) == self.pid
            })
            .flat_map(|(_, calls)| calls.iter().map(|call| (call.address, call.image)))
            .collect();
        for (address, image) in pending {
            if Self::identity(address & !7, &current) == Some(image) {
                self.ensure(address)?;
                self.breakpoints.get_mut(&address).unwrap().returns += 1;
            }
        }
        let unused: Vec<_> = self
            .breakpoints
            .iter()
            .filter(|(_, bp)| bp.entries.is_empty() && bp.returns == 0)
            .map(|(&address, _)| address)
            .collect();
        for address in unused {
            self.breakpoints.remove(&address);
            self.patch(address & !7)?;
            if self
                .breakpoints
                .range((address & !7)..(address & !7) + 8)
                .next()
                .is_none()
            {
                self.words.remove(&(address & !7));
            }
        }
        self.refreshed = Instant::now();
        Ok(())
    }
    fn resume_all(&mut self) -> Result<()> {
        for tid in self.stopped.clone() {
            let signal = self.signals.remove(&tid).unwrap_or(0);
            let (request, signal) = if self.listening.contains(&tid) {
                (libc::PTRACE_LISTEN, 0)
            } else {
                let op = if !self.active || self.unresolved || self.syscalls || self.track_loads {
                    libc::PTRACE_SYSCALL
                } else {
                    libc::PTRACE_CONT
                };
                (op, signal)
            };
            if let Err(error) = control_io(request, tid, 0, signal as usize) {
                // Resuming one thread can execute exit_group before its siblings
                // are resumed. A previously observed ptrace stop then ceases to
                // be resumable. Accept ESRCH only with a terminal wait status or
                // an explicitly dead/zombie task; retain unreaped tasks so poll
                // still collects their actual exit status.
                let mut terminal = false;
                if error.raw_os_error() == Some(libc::ESRCH) {
                    let deadline = Instant::now() + Duration::from_millis(20);
                    loop {
                        let mut status = 0;
                        let waited = unsafe {
                            libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG)
                        };
                        if waited == tid {
                            terminal = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                            self.queue(tid, status)?;
                            break;
                        }
                        let wait_error = std::io::Error::last_os_error().raw_os_error();
                        match std::fs::read_to_string(format!("/proc/{tid}/stat")) {
                            Ok(stat) => {
                                terminal = stat.rsplit_once(')').is_some_and(|(_, tail)| {
                                    matches!(tail.split_whitespace().next(), Some("Z" | "X" | "x"))
                                });
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                terminal = true;
                                // A non-leader may already have been reaped by
                                // its exiting group. There is no remaining task
                                // or address space to restore through this TID.
                                if waited < 0 && wait_error == Some(libc::ECHILD) {
                                    self.forget(tid);
                                }
                            }
                            Err(_) => {}
                        }
                        if terminal || Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_micros(50));
                    }
                }
                if !terminal {
                    return Err(format!(
                        "function ptrace request {request} TID {tid}: {error}"
                    ));
                }
            }
            self.stopped.remove(&tid);
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<Vec<Event>> {
        if self.active_hit.is_some() {
            return Err("function event must be resumed before polling".into());
        }
        if self.pending.is_empty() {
            let mut status = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
            if tid > 0 {
                self.queue(tid, status)?;
                self.stop_world()?;
            } else if tid < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
            {
                return Err(std::io::Error::last_os_error().to_string());
            } else if self.active && self.refreshed.elapsed() >= Duration::from_millis(100) {
                self.stop_world()?;
                if !self.stopped.is_empty() {
                    if self.follow
                        && !self.stopped.iter().any(|tid| {
                            tgid(*tid).is_some_and(|group| {
                                self.owners.get(&group).copied().unwrap_or(group) == self.pid
                            })
                        })
                    {
                        if let Some(&tid) = self.stopped.first() {
                            self.select(tid);
                        }
                    }
                    self.refresh()?;
                }
            }
        }
        while let Some((tid, status)) = self.pending.pop_front() {
            if !self.tids.contains(&tid) || !self.stopped.contains(&tid) {
                continue;
            }
            self.select(tid);
            let initial = self.initial.remove(&tid);
            let event = status >> 16;
            let signal = libc::WSTOPSIG(status);
            if initial
                && !self.follow
                && tgid(tid).is_some_and(|tgid| tgid != self.root)
                && !self.foreign.contains(&tid)
            {
                for (&address, word) in &self.words {
                    let _ = control(
                        libc::PTRACE_POKEDATA,
                        tid,
                        address as usize,
                        word.original as usize,
                    );
                }
                for &semaphore in self.semaphores.keys() {
                    let _ = adjust_semaphore(tid, semaphore, -1);
                }
                control(libc::PTRACE_DETACH, tid, 0, 0)?;
                self.tids.remove(&tid);
                self.stopped.remove(&tid);
                continue;
            }
            if event == libc::PTRACE_EVENT_EXEC {
                if self.follow {
                    let group = tgid(tid).unwrap_or(tid);
                    // Exec creates a fresh mm even for a vfork/CLONE_VM child.
                    let old_owner = self.owners.get(&group).copied().unwrap_or(group);
                    if old_owner != group {
                        self.spaces.insert(self.pid, self.snapshot());
                        self.pid = group;
                        self.owners.insert(group, group);
                    } else {
                        let aliases: Vec<_> = self
                            .owners
                            .iter()
                            .filter(|(other, owner)| **other != group && **owner == old_owner)
                            .map(|(other, _)| *other)
                            .collect();
                        if let Some(&keeper) = aliases.first() {
                            self.spaces.insert(keeper, self.snapshot());
                            for alias in aliases {
                                self.owners.insert(alias, keeper);
                            }
                        }
                    }
                    self.foreign.remove(&tid);
                    self.semaphores.clear();
                    self.words.clear();
                    self.breakpoints.clear();
                    self.calls
                        .retain(|task, _| tgid(*task).unwrap_or(*task) != group);
                    self.active = true;
                    self.unresolved = true;
                    self.decoder.clear(tid);
                    self.refresh()?;
                    continue;
                }
                if self.foreign.remove(&tid) {
                    control(libc::PTRACE_DETACH, tid, 0, 0)?;
                    self.tids.remove(&tid);
                    self.stopped.remove(&tid);
                    continue;
                }
                // A non-thread CLONE_VM child can retain the old mm across our exec.
                let mut restored_semaphores = false;
                for child in self.foreign.clone() {
                    if self.stopped.contains(&child) {
                        if let Ok(current) = maps(child) {
                            if !restored_semaphores {
                                for (&address, semaphore) in &self.semaphores {
                                    if Self::identity(semaphore.site, &current)
                                        == Some(semaphore.identity)
                                    {
                                        let _ = adjust_semaphore(child, address, -1);
                                    }
                                }
                                restored_semaphores = true;
                            }
                            if let Ok(mut regs) = Registers::read(child) {
                                if let Some(address) = trap_address(regs.user().ip)
                                    .filter(|address| self.breakpoints.contains_key(address))
                                {
                                    regs.set_ip(address);
                                    let _ = regs.write(child);
                                }
                            }
                            for (&address, word) in &self.words {
                                if Self::identity(address, &current) == Some(word.identity) {
                                    let _ = control(
                                        libc::PTRACE_POKEDATA,
                                        child,
                                        address as usize,
                                        word.original as usize,
                                    );
                                }
                            }
                        }
                        control(
                            libc::PTRACE_DETACH,
                            child,
                            0,
                            self.signals.remove(&child).unwrap_or(0) as usize,
                        )?;
                        self.tids.remove(&child);
                        self.stopped.remove(&child);
                        self.foreign.remove(&child);
                    }
                }
                self.semaphores.clear();
                self.words.clear();
                self.breakpoints.clear();
                self.calls.clear();
                self.active = true;
                self.decoder.clear(tid);
                self.refresh()?;
                continue;
            }
            if event == libc::PTRACE_EVENT_VFORK_DONE {
                self.vfork.remove(&tid);
                continue;
            }
            if matches!(
                event,
                libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK
            ) {
                continue;
            }
            if initial && event == libc::PTRACE_EVENT_STOP && signal == libc::SIGTRAP {
                self.discovered.push(tid);
                self.pending.push_front((tid, status));
                return Ok(Vec::new());
            }
            if event == libc::PTRACE_EVENT_STOP {
                if signal != libc::SIGTRAP {
                    self.listening.insert(tid);
                }
                continue;
            }
            if signal == (libc::SIGTRAP | 0x80) {
                if self.active {
                    let mapping_change = if self.track_loads {
                        let number = Registers::read(tid)?.syscall_number();
                        matches!(
                            number,
                            libc::SYS_mmap
                                | libc::SYS_mprotect
                                | libc::SYS_munmap
                                | libc::SYS_mremap
                        )
                    } else {
                        false
                    };
                    if self.unresolved || mapping_change {
                        self.refresh()?;
                    }
                    if self.syscalls && (self.follow || !self.foreign.contains(&tid)) {
                        if let Some(event) = self.decoder.stop(tid)? {
                            return Ok(vec![Event {
                                binding: usize::MAX,
                                args: event.args,
                                retval: event.retval,
                                latency: event.latency,
                                regs: Registers::read(tid)?.user(),
                                tid,
                                syscall: Some(event),
                            }]);
                        }
                    }
                }
                continue;
            }
            if trap(tid, status) {
                let mut regs = Registers::read(tid)?;
                let Some(address) = trap_address(regs.user().ip)
                    .filter(|address| self.breakpoints.contains_key(address))
                else {
                    self.signals.insert(tid, signal);
                    continue;
                };
                regs.set_ip(address);
                regs.write(tid)?;
                self.breakpoints.get_mut(&address).unwrap().enabled = false;
                self.patch(address & !7)?;
                self.active_hit = Some((tid, address));
                let user = regs.user();
                let args = regs.args();
                let mut output = Vec::new();
                if self.follow || !self.foreign.contains(&tid) {
                    let declared = self
                        .stack_ranges
                        .get(&tid)
                        .and_then(|ranges| {
                            ranges.iter().find(|(a, b)| *a <= user.sp && user.sp < *b)
                        })
                        .copied();
                    let calls = self.calls.entry(tid).or_default();
                    // Downward-growing stacks unwind past abandoned calls after
                    // longjmp/exception unwinding. Do not report these as returns.
                    // Limit pruning to the same observed mapping: switched stacks
                    // can have unrelated numerical SP order.
                    if calls.iter().any(|call| call.sp < user.sp) {
                        let map = declared.or_else(|| {
                            std::fs::read_to_string(format!("/proc/{tid}/maps"))
                                .ok()
                                .filter(|text| text.len() <= 1024 * 1024)
                                .and_then(|text| {
                                    text.lines().find_map(|line| {
                                        let (a, b) =
                                            line.split_whitespace().next()?.split_once('-')?;
                                        let (a, b) = (
                                            u64::from_str_radix(a, 16).ok()?,
                                            u64::from_str_radix(b, 16).ok()?,
                                        );
                                        (a <= user.sp && user.sp < b).then_some((a, b))
                                    })
                                })
                        });
                        let mut index = 0;
                        while index < calls.len() {
                            if calls[index].sp < user.sp
                                && map.is_some_and(|(a, b)| {
                                    a <= calls[index].sp && calls[index].sp < b
                                })
                            {
                                let call = calls.remove(index);
                                if let Some(bp) = self.breakpoints.get_mut(&call.address) {
                                    bp.returns = bp.returns.saturating_sub(1);
                                }
                            } else {
                                index += 1;
                            }
                        }
                    }
                    while let Some(index) = calls
                        .iter()
                        .rposition(|call| call.address == address && call.sp == user.sp)
                    {
                        let call = calls.remove(index);
                        if let Some(bp) = self.breakpoints.get_mut(&address) {
                            bp.returns = bp.returns.saturating_sub(1);
                        }
                        output.push(Event {
                            binding: call.binding,
                            syscall: None,
                            tid,
                            args: call.args,
                            retval: regs.retval(),
                            latency: call.start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                            regs: user,
                        });
                    }
                    let entries = self.breakpoints[&address].entries.clone();
                    for index in entries {
                        if self.bindings[index].ret {
                            if self.calls.values().map(Vec::len).sum::<usize>() >= 4096 {
                                return Err("pending function return limit (4096) reached".into());
                            }
                            #[cfg(target_arch = "x86_64")]
                            let (return_address, sp) = (
                                control(libc::PTRACE_PEEKDATA, tid, user.sp as usize, 0)? as u64,
                                user.sp.checked_add(8).ok_or("return stack overflow")?,
                            );
                            #[cfg(target_arch = "aarch64")]
                            let (return_address, sp) = (user.lr, user.sp);
                            if return_address != 0 {
                                self.ensure(return_address)?;
                                self.breakpoints.get_mut(&return_address).unwrap().returns += 1;
                                self.calls.entry(tid).or_default().push(Call {
                                    binding: index,
                                    address: return_address,
                                    image: self.words[&(return_address & !7)].identity,
                                    sp,
                                    args,
                                    start: Instant::now(),
                                });
                            }
                        } else {
                            output.push(Event {
                                binding: index,
                                syscall: None,
                                tid,
                                args: if let Some(site) = &self.bindings[index].usdt {
                                    sdt_arguments(tid, &regs, site)?
                                } else {
                                    args
                                },
                                retval: 0,
                                latency: 0,
                                regs: user,
                            });
                        }
                    }
                }
                if !output.is_empty() {
                    output.sort_by_key(|event| event.binding);
                    return Ok(output);
                }
                self.resume_hit()?;
            } else {
                self.signals.insert(tid, signal);
            }
        }
        self.resume_all()?;
        Ok(Vec::new())
    }
    pub fn resume_hit(&mut self) -> Result<()> {
        let Some((tid, address)) = self.active_hit.take() else {
            return Ok(());
        };
        control(libc::PTRACE_SINGLESTEP, tid, 0, 0)?;
        self.stopped.remove(&tid);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
            if result == tid {
                // A queued PTRACE_INTERRUPT can stop SINGLESTEP before the
                // original instruction executes. Complete the step before
                // re-arming the breakpoint, otherwise this becomes a duplicate hit.
                if libc::WIFSTOPPED(status)
                    && status >> 16 == libc::PTRACE_EVENT_STOP
                    && libc::WSTOPSIG(status) == libc::SIGTRAP
                {
                    control(libc::PTRACE_SINGLESTEP, tid, 0, 0)?;
                    continue;
                }
                if libc::WIFSTOPPED(status)
                    && libc::WSTOPSIG(status) == libc::SIGTRAP
                    && status >> 16 == 0
                    && step_trap(tid)
                {
                    self.stopped.insert(tid);
                    break;
                }
                self.queue(tid, status)?;
                if !self.tids.contains(&tid) {
                    break;
                }
                if libc::WIFSTOPPED(status) && status >> 16 == 0 {
                    self.signals.insert(tid, libc::WSTOPSIG(status));
                    control(libc::PTRACE_SINGLESTEP, tid, 0, 0)?;
                    self.stopped.remove(&tid);
                    continue;
                }
                break;
            }
            if result < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if Instant::now() >= deadline {
                return Err("timed out single-stepping a function probe instruction".into());
            }
            std::thread::sleep(Duration::from_micros(50));
        }
        if let Some(breakpoint) = self.breakpoints.get_mut(&address) {
            if breakpoint.entries.is_empty() && breakpoint.returns == 0 {
                self.breakpoints.remove(&address);
            } else {
                breakpoint.enabled = true;
            }
        }
        if !self.stopped.is_empty() {
            self.patch(address & !7)?;
            if self
                .breakpoints
                .range((address & !7)..(address & !7) + 8)
                .next()
                .is_none()
            {
                self.words.remove(&(address & !7));
            }
        }
        Ok(())
    }
}
impl Tracer {
    pub fn detach(&mut self) {
        for tid in self.listening.clone() {
            let _ = control(libc::PTRACE_INTERRUPT, tid, 0, 0);
            self.listening.remove(&tid);
        }
        let _ = self.stop_world();
        // Queued INT3 stops have advanced RIP. Rewind before restoring their bytes.
        let mut owned_traps = BTreeSet::new();
        for (tid, status) in self.pending.clone() {
            self.select(tid);
            if trap(tid, status) {
                if let Ok(mut regs) = Registers::read(tid) {
                    if let Some(address) = trap_address(regs.user().ip)
                        .filter(|address| self.breakpoints.contains_key(address))
                    {
                        owned_traps.insert(tid);
                        regs.set_ip(address);
                        let _ = regs.write(tid);
                    }
                }
            }
        }
        // Restore each address space, including fork children still pending their
        // initial stop. Thread groups share an mm; CLONE_VM groups may share too.
        let mut restored = BTreeSet::new();
        for tid in self.stopped.clone() {
            self.select(tid);
            let group = tgid(tid).unwrap_or(tid);
            let owner =
                self.owners
                    .get(&group)
                    .copied()
                    .unwrap_or(if self.foreign.contains(&tid) {
                        self.root
                    } else {
                        group
                    });
            if !restored.insert(owner) {
                continue;
            }
            if let Ok(current) = memory_maps(tid) {
                for (&address, semaphore) in &self.semaphores {
                    if Self::identity(semaphore.site, &current) == Some(semaphore.identity) {
                        let _ = adjust_semaphore(tid, address, -1);
                    }
                }
                for (&address, word) in &self.words {
                    if Self::identity(address, &current) == Some(word.identity) {
                        let _ = control(
                            libc::PTRACE_POKEDATA,
                            tid,
                            address as usize,
                            word.original as usize,
                        );
                    }
                }
            }
        }
        for &(tid, status) in &self.pending {
            if libc::WIFSTOPPED(status) && status >> 16 == 0 {
                let signal = libc::WSTOPSIG(status);
                let our_trap = owned_traps.contains(&tid);
                if signal != (libc::SIGTRAP | 0x80) && !our_trap {
                    self.signals.entry(tid).or_insert(signal);
                }
            }
        }
        for tid in self.stopped.clone() {
            let _ = control(
                libc::PTRACE_DETACH,
                tid,
                0,
                self.signals.remove(&tid).unwrap_or(0) as usize,
            );
        }
        self.tids.clear();
        self.stopped.clear();
        self.pending.clear();
        self.words.clear();
        self.breakpoints.clear();
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if !self.tids.is_empty() {
            self.detach();
        }
    }
}

fn step_trap(tid: i32) -> bool {
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    control(
        libc::PTRACE_GETSIGINFO,
        tid,
        0,
        (&mut info as *mut libc::siginfo_t) as usize,
    )
    .is_ok()
        && info.si_code == libc::TRAP_TRACE
}

/// Read native user unwind registers while the task is ptrace-stopped.
pub fn user_registers(tid: i32) -> Result<UserRegs> {
    Ok(Registers::read(tid)?.user())
}

fn adjust_semaphore(tid: i32, address: u64, delta: i16) -> Result<()> {
    if address % 2 != 0 {
        return Err("SDT semaphore must be 2-byte aligned".into());
    }
    let aligned = address & !7;
    let at = (address & 7) as usize;
    let mut bytes =
        (control(libc::PTRACE_PEEKDATA, tid, aligned as usize, 0)? as u64).to_ne_bytes();
    let count = u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap());
    let next = if delta > 0 {
        count.checked_add(1).ok_or("SDT semaphore overflow")?
    } else {
        count.saturating_sub(1)
    };
    bytes[at..at + 2].copy_from_slice(&next.to_ne_bytes());
    control(
        libc::PTRACE_POKEDATA,
        tid,
        aligned as usize,
        u64::from_ne_bytes(bytes) as usize,
    )?;
    Ok(())
}

impl Registers {
    fn named(&self, name: &str) -> Result<u64> {
        let name = name.trim().trim_start_matches('%');
        #[cfg(target_arch = "aarch64")]
        {
            if name == "sp" {
                return Ok(self.user().sp);
            }
            if name == "wsp" {
                return Ok(self.user().sp & 0xffff_ffff);
            }
            if name == "fp" {
                return Ok(self.data[29]);
            }
            if name == "lr" {
                return Ok(self.data[30]);
            }
            if name == "xzr" || name == "wzr" {
                return Ok(0);
            }
            if let Some(index) = name
                .strip_prefix('x')
                .or_else(|| name.strip_prefix('w'))
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|i| *i <= 30)
            {
                return Ok(if name.starts_with('w') {
                    self.data[index] & 0xffff_ffff
                } else {
                    self.data[index]
                });
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            let names = [
                ("r15", 0),
                ("r14", 1),
                ("r13", 2),
                ("r12", 3),
                ("rbp", 4),
                ("rbx", 5),
                ("r11", 6),
                ("r10", 7),
                ("r9", 8),
                ("r8", 9),
                ("rax", 10),
                ("rcx", 11),
                ("rdx", 12),
                ("rsi", 13),
                ("rdi", 14),
                ("rip", 16),
                ("rsp", 19),
            ];
            if let Some((_, index)) = names.iter().find(|(n, _)| *n == name) {
                return Ok(self.data[*index]);
            }
            let alias = match name {
                "eax" => "rax",
                "ebx" => "rbx",
                "ecx" => "rcx",
                "edx" => "rdx",
                "esi" => "rsi",
                "edi" => "rdi",
                "ebp" => "rbp",
                "esp" => "rsp",
                _ => "",
            };
            if !alias.is_empty() {
                return Ok(self.named(alias)? & 0xffff_ffff);
            }
            let short = match name {
                "ax" => ("rax", 16, 0),
                "al" => ("rax", 8, 0),
                "ah" => ("rax", 8, 8),
                "bx" => ("rbx", 16, 0),
                "bl" => ("rbx", 8, 0),
                "bh" => ("rbx", 8, 8),
                "cx" => ("rcx", 16, 0),
                "cl" => ("rcx", 8, 0),
                "ch" => ("rcx", 8, 8),
                "dx" => ("rdx", 16, 0),
                "dl" => ("rdx", 8, 0),
                "dh" => ("rdx", 8, 8),
                "si" => ("rsi", 16, 0),
                "sil" => ("rsi", 8, 0),
                "di" => ("rdi", 16, 0),
                "dil" => ("rdi", 8, 0),
                "bp" => ("rbp", 16, 0),
                "bpl" => ("rbp", 8, 0),
                "sp" => ("rsp", 16, 0),
                "spl" => ("rsp", 8, 0),
                _ => ("", 0, 0),
            };
            if !short.0.is_empty() {
                return Ok((self.named(short.0)? >> short.2) & ((1u64 << short.1) - 1));
            }
            for (suffix, bits) in [('w', 16), ('b', 8)] {
                if let Some(base) = name.strip_suffix(suffix) {
                    if base.starts_with('r') {
                        return Ok(self.named(base)? & ((1u64 << bits) - 1));
                    }
                }
            }
            if let Some(base) = name.strip_suffix('d') {
                if base.starts_with('r') {
                    return Ok(self.named(base)? & 0xffff_ffff);
                }
            }
        }
        Err(format!("unsupported SDT register {name}"))
    }
}
fn sdt_arguments(tid: i32, regs: &Registers, site: &crate::usdt::Site) -> Result<[u64; 6]> {
    fn integer(s: &str) -> Result<u64> {
        let s = s.trim().trim_start_matches(['$', '#']);
        let (negative, n) = s.strip_prefix('-').map(|n| (true, n)).unwrap_or((false, s));
        let n = if let Some(n) = n.strip_prefix("0x") {
            u64::from_str_radix(n, 16)
        } else {
            n.parse()
        }
        .map_err(|e| e.to_string())?;
        Ok(if negative { n.wrapping_neg() } else { n })
    }
    let mut out = [0; 6];
    for (index, arg) in site.arguments.iter().enumerate() {
        let expression = arg.expression.trim();
        let mut address = None;
        let mut value = if expression.starts_with(['$', '#']) {
            integer(expression)?
        } else if expression.starts_with('[') && expression.ends_with(']') {
            let pieces: Vec<_> = expression[1..expression.len() - 1]
                .split(',')
                .map(str::trim)
                .collect();
            let offset = if pieces.len() == 2 {
                integer(pieces[1])?
            } else if pieces.len() == 1 {
                0
            } else {
                return Err("unsupported SDT ARM addressing".into());
            };
            address = Some(regs.named(pieces[0])?.wrapping_add(offset));
            0
        } else if let Some((offset, operand)) = expression.split_once('(') {
            let operand = operand
                .strip_suffix(')')
                .ok_or("invalid SDT memory operand")?;
            let pieces: Vec<_> = operand.split(',').collect();
            if pieces.len() > 3 {
                return Err("unsupported SDT memory operand".into());
            }
            let mut at = if pieces[0].is_empty() {
                0
            } else {
                regs.named(pieces[0])?
            };
            if pieces.len() > 1 && !pieces[1].is_empty() {
                let scale = if pieces.len() > 2 {
                    integer(pieces[2])?
                } else {
                    1
                };
                if ![1, 2, 4, 8].contains(&scale) {
                    return Err("invalid SDT memory scale".into());
                }
                at = at.wrapping_add(regs.named(pieces[1])?.wrapping_mul(scale));
            }
            address = Some(at.wrapping_add(if offset.is_empty() {
                0
            } else {
                integer(offset)?
            }));
            0
        } else {
            regs.named(expression)?
        };
        if let Some(address) = address {
            let bytes =
                crate::memory::read(tid as u32, address, arg.size.unsigned_abs() as usize, false)?;
            let mut raw = [0; 8];
            raw[..bytes.len()].copy_from_slice(&bytes);
            value = u64::from_ne_bytes(raw);
        }
        let bits = arg.size.unsigned_abs() as u32 * 8;
        out[index] = if bits == 64 {
            value
        } else if arg.size < 0 {
            ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
        } else {
            value & ((1u64 << bits) - 1)
        };
    }
    Ok(out)
}

/// Read an FP/SIMD argument register at a ptrace stop; return its raw low bits.
pub fn floating_argument(tid: i32, index: usize, single: bool) -> Result<u64> {
    if index >= 8 {
        return Err("floating register index must be 0..7".into());
    }
    let mut bytes = [0u8; 528];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    control(
        libc::PTRACE_GETREGSET,
        tid,
        2,
        (&mut iov as *mut libc::iovec) as usize,
    )?;
    #[cfg(target_arch = "x86_64")]
    let offset = 160 + index * 16;
    #[cfg(target_arch = "aarch64")]
    let offset = index * 16;
    let size = if single { 4 } else { 8 };
    if offset + size > iov.iov_len {
        return Err("incomplete FP register set".into());
    }
    let mut value = [0; 8];
    value[..size].copy_from_slice(&bytes[offset..offset + size]);
    Ok(u64::from_ne_bytes(value))
}

/// Read a native integer/pointer argument register at a ptrace function-entry stop.
/// Stack arguments are deliberately separate because aggregate ABIs consume slots differently.
pub fn integer_argument(tid: i32, index: usize) -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        let register = [14, 13, 12, 11, 9, 8]
            .get(index)
            .copied()
            .ok_or("integer register index must be 0..5 on x86-64")?;
        Ok(Registers::read(tid)?.data[register])
    }
    #[cfg(target_arch = "aarch64")]
    {
        if index >= 8 {
            return Err("integer register index must be 0..7 on AArch64".into());
        }
        Ok(Registers::read(tid)?.data[index])
    }
}

/// Read the complete native 128-bit SIMD argument register at a ptrace stop.
pub fn floating_argument_bits(tid: i32, index: usize) -> Result<[u8; 16]> {
    if index >= 8 {
        return Err("floating register index must be 0..7".into());
    }
    let mut bytes = [0u8; 528];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    control(
        libc::PTRACE_GETREGSET,
        tid,
        2,
        (&mut iov as *mut libc::iovec) as usize,
    )?;
    #[cfg(target_arch = "x86_64")]
    let offset = 160 + index * 16;
    #[cfg(target_arch = "aarch64")]
    let offset = index * 16;
    if offset + 16 > iov.iov_len {
        return Err("incomplete FP register set".into());
    }
    Ok(bytes[offset..offset + 16].try_into().unwrap())
}

/// Read a native DWARF-numbered register at a ptrace stop. SIMD registers expose
/// their low 64 bits; expressions requiring wider values must use pieces.
pub fn dwarf_register(tid: i32, register: u16) -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(index) =
            [10, 12, 11, 5, 13, 14, 4, 19, 9, 8, 7, 6, 3, 2, 1, 0, 16].get(register as usize)
        {
            return Ok(Registers::read(tid)?.data[*index]);
        }
        if (17..=32).contains(&register) {
            return simd_register_low(tid, (register - 17) as usize);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if register <= 32 {
            return Ok(Registers::read(tid)?.data[register as usize]);
        }
        if (64..=95).contains(&register) {
            return simd_register_low(tid, (register - 64) as usize);
        }
    }
    Err(format!("unsupported native DWARF register {register}"))
}
fn simd_register_low(tid: i32, index: usize) -> Result<u64> {
    let mut bytes = [0u8; 528];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    control(
        libc::PTRACE_GETREGSET,
        tid,
        2,
        (&mut iov as *mut libc::iovec) as usize,
    )?;
    #[cfg(target_arch = "x86_64")]
    let offset = 160 + index * 16;
    #[cfg(target_arch = "aarch64")]
    let offset = index * 16;
    let raw = bytes
        .get(offset..offset + 8)
        .filter(|_| offset + 8 <= iov.iov_len)
        .ok_or("incomplete SIMD register set")?;
    Ok(u64::from_ne_bytes(raw.try_into().unwrap()))
}
