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
struct Word {
    original: u64,
    identity: Identity,
}
struct Call {
    binding: usize,
    address: u64,
    sp: u64,
    args: [u64; 6],
    start: Instant,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub binding: usize,
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
        }
    }
    #[cfg(target_arch = "aarch64")]
    fn user(&self) -> UserRegs {
        UserRegs {
            ip: self.data[32],
            sp: self.data[31],
            fp: self.data[29],
            lr: self.data[30],
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
fn control(request: libc::c_uint, tid: i32, address: usize, data: usize) -> Result<libc::c_long> {
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
        Err(format!(
            "function ptrace TID {tid}: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(value)
    }
}
fn maps(pid: i32) -> Result<Vec<Mapping>> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|text| text.lines().filter_map(Mapping::parse).collect())
        .map_err(|e| e.to_string())
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

pub struct Tracer {
    pid: i32,
    bindings: Vec<Binding>,
    tids: BTreeSet<i32>,
    stopped: BTreeSet<i32>,
    initial: BTreeSet<i32>,
    listening: BTreeSet<i32>,
    pending: VecDeque<(i32, i32)>,
    signals: BTreeMap<i32, i32>,
    words: BTreeMap<u64, Word>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    calls: BTreeMap<i32, Vec<Call>>,
    active_hit: Option<(i32, u64)>,
    vfork: BTreeMap<i32, i32>,
    foreign: BTreeSet<i32>,
    active: bool,
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
        if specs.is_empty() || specs.len() > 256 {
            return Err("function tracing supports 1..256 probe bindings".into());
        }
        let mut bindings = Vec::new();
        for spec in specs {
            let resolved = crate::uprobe::locate(pid, &spec.path, &spec.function, spec.ret)?;
            let path = resolved.path.to_str().map_err(|e| e.to_string())?;
            let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
            bindings.push(Binding {
                offset: resolved.offset,
                inode: meta.ino(),
                device: meta.dev(),
                ret: spec.ret,
            });
        }
        let mut tracer = Self {
            pid,
            bindings,
            tids: BTreeSet::new(),
            stopped: BTreeSet::new(),
            initial: BTreeSet::new(),
            listening: BTreeSet::new(),
            pending: VecDeque::new(),
            signals: BTreeMap::new(),
            words: BTreeMap::new(),
            breakpoints: BTreeMap::new(),
            calls: BTreeMap::new(),
            active_hit: None,
            vfork: BTreeMap::new(),
            foreign: BTreeSet::new(),
            active: !launched,
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
        for tid in tids {
            control(libc::PTRACE_SEIZE, tid, 0, flags as usize)?;
            tracer.tids.insert(tid);
            tracer.initial.insert(tid);
        }
        tracer.stop_world()?;
        if tracer.active {
            tracer.refresh()?;
        }
        Ok(tracer)
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
            if self.foreign.remove(&tid) {
                self.vfork.retain(|_, child| *child != tid);
            } else {
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
                && tgid(child as i32).is_some_and(|tgid| tgid != self.pid)
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
        self.pending.push_back((tid, status));
        Ok(())
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
    fn current_maps(&self) -> Result<Vec<Mapping>> {
        match maps(self.pid) {
            Ok(current) if !current.is_empty() => Ok(current),
            _ => maps(self.memory_tid()?),
        }
    }
    fn memory_tid(&self) -> Result<i32> {
        self.stopped
            .iter()
            .find(|tid| !self.foreign.contains(tid))
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
        // Never restore stale bytes into an unmapped/replaced image.
        let stale: Vec<_> = self
            .words
            .iter()
            .filter(|(address, word)| Self::identity(**address, &current) != Some(word.identity))
            .map(|(&address, _)| address)
            .collect();
        for word in stale {
            self.words.remove(&word);
            self.breakpoints.retain(|address, _| *address & !7 != word);
        }
        for breakpoint in self.breakpoints.values_mut() {
            breakpoint.entries.clear();
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
                self.ensure(address)?;
                self.breakpoints
                    .get_mut(&address)
                    .unwrap()
                    .entries
                    .push(index);
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
            if self.listening.contains(&tid) {
                control(libc::PTRACE_LISTEN, tid, 0, 0)?;
            } else {
                let op = if !self.active || self.unresolved {
                    libc::PTRACE_SYSCALL
                } else {
                    libc::PTRACE_CONT
                };
                control(op, tid, 0, signal as usize)?;
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
                    self.refresh()?;
                }
            }
        }
        while let Some((tid, status)) = self.pending.pop_front() {
            if !self.tids.contains(&tid) || !self.stopped.contains(&tid) {
                continue;
            }
            let initial = self.initial.remove(&tid);
            let event = status >> 16;
            let signal = libc::WSTOPSIG(status);
            if initial
                && tgid(tid).is_some_and(|tgid| tgid != self.pid)
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
                control(libc::PTRACE_DETACH, tid, 0, 0)?;
                self.tids.remove(&tid);
                self.stopped.remove(&tid);
                continue;
            }
            if event == libc::PTRACE_EVENT_EXEC {
                if self.foreign.remove(&tid) {
                    control(libc::PTRACE_DETACH, tid, 0, 0)?;
                    self.tids.remove(&tid);
                    self.stopped.remove(&tid);
                    continue;
                }
                // A non-thread CLONE_VM child can retain the old mm across our exec.
                for child in self.foreign.clone() {
                    if self.stopped.contains(&child) {
                        if let Ok(current) = maps(child) {
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
                self.words.clear();
                self.breakpoints.clear();
                self.calls.clear();
                self.active = true;
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
            if event == libc::PTRACE_EVENT_STOP {
                if signal != libc::SIGTRAP {
                    self.listening.insert(tid);
                }
                continue;
            }
            if signal == (libc::SIGTRAP | 0x80) {
                if self.active {
                    self.refresh()?;
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
                if !self.foreign.contains(&tid) {
                    let calls = self.calls.entry(tid).or_default();
                    while calls
                        .last()
                        .is_some_and(|call| call.address == address && call.sp == user.sp)
                    {
                        let call = calls.pop().unwrap();
                        if let Some(bp) = self.breakpoints.get_mut(&address) {
                            bp.returns = bp.returns.saturating_sub(1);
                        }
                        output.push(Event {
                            binding: call.binding,
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
                                    sp,
                                    args,
                                    start: Instant::now(),
                                });
                            }
                        } else {
                            output.push(Event {
                                binding: index,
                                tid,
                                args,
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
        for &(tid, status) in &self.pending {
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
        for &tid in &self.stopped {
            if !restored.insert(tgid(tid).unwrap_or(tid)) {
                continue;
            }
            if let Ok(current) = maps(tid) {
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
