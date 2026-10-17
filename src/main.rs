use clap::Parser;
use poortrace::{
    Result,
    codegen::Program,
    language::{HARDWARE, Probe, SOFTWARE},
    perf::{PerfEvent, Record},
    runtime::{Event, State},
};
use std::{
    collections::BTreeSet,
    ffi::CString,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "LLVM JIT tracing scripts over unprivileged, user-mode Linux perf events",
    after_help = "Examples:\n  poortrace -e 'interval:ms:100 { @ticks = count(); }' --duration 1\n  poortrace -e 'profile:hz:99 { @[comm, ip] = count(); }' -- ./workload\n  poortrace -p 1234 -e 'profile:hz:99 { @[ustack] = count(); }'\n  poortrace -p 1234 -e 'software:page-faults:1 { @[tid] = count(); }'\n\nPerf policy and PMU support are enforced by the host. No BPF programs are loaded."
)]
struct Args {
    /// Inline script (otherwise supply a script file)
    #[arg(short = 'e', long, conflicts_with = "script")]
    expression: Option<String>,
    /// Script file; '-' reads standard input
    script: Option<PathBuf>,
    /// Attach to all currently visible threads of this process
    #[arg(short = 'p', long, value_parser = clap::value_parser!(i32).range(1..), conflicts_with_all = ["command", "shell_command"])]
    pid: Option<i32>,
    /// Launch a command through /bin/sh -c
    #[arg(short = 'c', long = "command", conflicts_with = "command")]
    shell_command: Option<String>,
    /// Stop after this many wall-clock seconds
    #[arg(short = 'd', long, value_parser = duration)]
    duration: Option<Duration>,
    /// Compile and verify the script without opening perf events
    #[arg(long)]
    check: bool,
    /// Print generated LLVM IR and exit
    #[arg(long)]
    emit_llvm: bool,
    /// List supported probes/events
    #[arg(short = 'l', long)]
    list: bool,
    /// Data pages per thread/event; power of two, 1..1024
    #[arg(long, default_value_t = 8)]
    mmap_pages: usize,
    /// Maximum entries in each aggregation map
    #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(1..))]
    max_map_entries: u32,
    /// Do not print maps automatically at shutdown
    #[arg(long)]
    no_print_maps: bool,
    /// Suppress attachment status
    #[arg(short, long)]
    quiet: bool,
    /// Launch an executable and arguments after '--'
    #[arg(last = true)]
    command: Vec<String>,
}
fn duration(s: &str) -> std::result::Result<Duration, String> {
    let n: f64 = s
        .parse()
        .map_err(|_| "duration must be a positive number".to_string())?;
    if !n.is_finite() || n <= 0.0 || n > 365.0 * 86400.0 {
        return Err("duration must be positive and at most one year".into());
    }
    let d = Duration::from_secs_f64(n);
    if d.is_zero() {
        return Err("duration is below one nanosecond".into());
    }
    Ok(d)
}
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupt(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
fn install_signals() -> Result<()> {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = interrupt as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }
    }
    Ok(())
}

fn main() {
    match run(Args::parse()) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("poortrace: {e}");
            std::process::exit(1);
        }
    }
}
fn run(args: Args) -> Result<i32> {
    if args.list {
        println!("BEGIN\nEND\ninterval:{{ns,us,ms,s,hz}}:N\nprofile:{{ns,us,ms,s,hz}}:N");
        for (name, _) in SOFTWARE {
            println!("software:{name}[:period]");
        }
        for (name, _) in HARDWARE {
            println!("hardware:{name}[:period]");
        }
        return Ok(0);
    }
    if !args.mmap_pages.is_power_of_two() || args.mmap_pages > 1024 {
        return Err("--mmap-pages must be a power of two from 1 to 1024".into());
    }
    let source = if let Some(s) = &args.expression {
        s.clone()
    } else if let Some(path) = &args.script {
        if path.as_os_str() == "-" {
            use std::io::Read;
            let mut src = String::new();
            io::stdin()
                .take(256 * 1024 + 1)
                .read_to_string(&mut src)
                .map_err(|e| format!("stdin: {e}"))?;
            src
        } else {
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
    } else {
        return Err("provide -e SCRIPT or a script file (see --help)".into());
    };
    let program = Program::compile(&source)?;
    if args.emit_llvm {
        print!("{}", program.ir);
        return Ok(0);
    }
    if args.check {
        println!(
            "OK: {} clause(s), LLVM {}",
            program.clauses.len(),
            env!("POORTRACE_LLVM_VERSION")
        );
        return Ok(0);
    }
    if program.has_perf()
        && args.pid.is_none()
        && args.command.is_empty()
        && args.shell_command.is_none()
    {
        return Err("perf probes require -p PID, -c COMMAND, or -- EXECUTABLE [ARGS...]".into());
    }
    install_signals()?;
    let command = args
        .shell_command
        .as_ref()
        .map(|s| vec!["/bin/sh".into(), "-c".into(), s.clone()])
        .unwrap_or_else(|| args.command.clone());
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(&command)?)
    };
    let target = child.as_ref().map(|c| c.pid).or(args.pid);
    if target.is_some_and(|pid| !alive(pid)) {
        return Err("target process does not exist or has exited".into());
    }
    let mut streams = Vec::new();
    if let Some(pid) = target {
        attach(
            &program,
            pid,
            args.mmap_pages,
            &mut streams,
            false,
            child.is_some(),
        )?;
    }
    if !args.quiet {
        eprintln!(
            "Attaching {} probe(s), {} perf stream(s){}",
            program
                .clauses
                .iter()
                .map(|c| c.probes.len())
                .sum::<usize>(),
            streams.len(),
            target.map(|p| format!(" to PID {p}")).unwrap_or_default()
        );
    }
    let stdout = io::stdout();
    let mut state = program.state(io::BufWriter::new(stdout.lock()));
    state.max_entries = args.max_map_entries as usize;
    invoke_kind(&program, &mut state, target, true);
    state.flush()?;
    if !state.stopped {
        for s in &streams {
            if !s.on_exec {
                s.event.enable()?;
            }
        }
        if let Some(c) = &mut child {
            c.start()?;
        }
    }
    let start = Instant::now();
    let mut timers: Vec<_> = program
        .clauses
        .iter()
        .enumerate()
        .flat_map(|(clause, c)| {
            c.probes.iter().filter_map(move |(name, p)| {
                if let Probe::Interval(period) = p {
                    Some((clause, name.clone(), *period, start + *period))
                } else {
                    None
                }
            })
        })
        .collect();
    let mut lost = 0u64;
    let result = (|| -> Result<()> {
        let mut refresh = Instant::now();
        loop {
            let child_done = if let Some(c) = &mut child {
                c.check()?.is_some()
            } else {
                false
            };
            drain(&program, &mut state, &mut streams, &mut lost)?;
            if state.stopped || INTERRUPTED.load(Ordering::Relaxed) || child_done {
                break;
            }
            if args.duration.is_some_and(|d| start.elapsed() >= d) {
                break;
            }
            if target.is_some_and(|p| !alive(p)) {
                break;
            }
            if refresh.elapsed() >= Duration::from_millis(100) {
                if let Some(pid) = target {
                    attach(&program, pid, args.mmap_pages, &mut streams, true, false)?;
                }
                refresh = Instant::now();
            }
            let now = Instant::now();
            for (clause, name, period, deadline) in &mut timers {
                if now >= *deadline {
                    invoke(&program, *clause, &mut state, target, name, None, None);
                    // Coalesce missed wall-clock ticks; never busy-loop to catch up.
                    *deadline = now + *period;
                    if state.stopped {
                        break;
                    }
                }
            }
            state.flush()?;
            if state.stopped {
                break;
            }
            if streams.is_empty() && timers.is_empty() && target.is_none() {
                break;
            }
            let mut wait = Duration::from_millis(20);
            for (_, _, _, deadline) in &timers {
                wait = wait.min(deadline.saturating_duration_since(Instant::now()));
            }
            if let Some(d) = args.duration {
                wait = wait.min(d.saturating_sub(start.elapsed()));
            }
            let mut fds: Vec<_> = streams
                .iter()
                .map(|s| libc::pollfd {
                    fd: s.event.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect();
            let ms = wait.as_millis().max(u128::from(!wait.is_zero())) as i32;
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) } < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EINTR) {
                    return Err(format!("poll: {e}"));
                }
            }
            // A dead task's fd remains readable with HUP; remove it after draining
            // at the next iteration rather than spinning until the next scan.
            for (stream, fd) in streams.iter_mut().zip(fds) {
                stream.hup = fd.revents & libc::POLLHUP != 0;
            }
        }
        for stream in &streams {
            stream.event.disable()?;
        }
        if !state.stopped {
            drain(&program, &mut state, &mut streams, &mut lost)?;
        }
        Ok(())
    })();
    // END handlers still run after exit(), target exit, or an interrupt.
    state.stopped = false;
    invoke_kind(&program, &mut state, target, false);
    if !args.no_print_maps {
        state.print_all();
    }
    state.flush()?;
    if lost != 0 {
        eprintln!(
            "poortrace: lost {lost} perf samples; increase --mmap-pages or reduce sample frequency"
        );
    }
    result?;
    Ok(child.as_ref().and_then(|c| c.status).unwrap_or(0))
}

struct Stream {
    clause: usize,
    name: String,
    tid: i32,
    event: PerfEvent,
    hup: bool,
    comm: CString,
    on_exec: bool,
}
fn threads(pid: i32) -> Result<BTreeSet<i32>> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map_err(|e| format!("cannot inspect PID {pid}: {e}"))?
        .map(|entry| {
            entry.map_err(|e| e.to_string()).and_then(|e| {
                e.file_name()
                    .to_string_lossy()
                    .parse::<i32>()
                    .map_err(|e| e.to_string())
            })
        })
        .collect()
}
fn attach(
    program: &Program,
    pid: i32,
    pages: usize,
    streams: &mut Vec<Stream>,
    enabled: bool,
    on_exec: bool,
) -> Result<()> {
    if !program.has_perf() {
        if !alive(pid) {
            return Err(format!("PID {pid} does not exist or has exited"));
        }
        return Ok(());
    }
    let tids = match threads(pid) {
        Ok(t) => t,
        Err(_) if !alive(pid) => return Ok(()),
        Err(e) => return Err(e),
    };
    streams.retain(|s| !s.hup && tids.contains(&s.tid));
    for (clause, c) in program.clauses.iter().enumerate() {
        for (name, probe) in &c.probes {
            if !matches!(probe, Probe::Perf { .. }) {
                continue;
            }
            for tid in &tids {
                if streams
                    .iter()
                    .any(|s| s.clause == clause && s.name == *name && s.tid == *tid)
                {
                    continue;
                }
                let event = if program.needs_ustack() {
                    PerfEvent::open_with_ustack(*tid, probe, pages, on_exec)
                } else if on_exec {
                    PerfEvent::open_on_exec(*tid, probe, pages)
                } else {
                    PerfEvent::open(*tid, probe, pages)
                };
                match event {
                    Ok(event) => {
                        if enabled {
                            event.enable()?;
                        }
                        streams.push(Stream {
                            clause,
                            name: name.clone(),
                            tid: *tid,
                            event,
                            hup: false,
                            comm: task_comm(pid, *tid),
                            on_exec,
                        });
                    }
                    Err(_)
                        if !std::path::Path::new(&format!("/proc/{pid}/task/{tid}")).exists() => {}
                    Err(e) => return Err(format!("{name}: {e}")),
                }
            }
        }
    }
    Ok(())
}
fn drain(
    program: &Program,
    state: &mut State<'_>,
    streams: &mut Vec<Stream>,
    lost: &mut u64,
) -> Result<()> {
    for stream in streams.iter_mut() {
        for record in stream.event.drain()? {
            match record {
                Record::Sample(sample) if !state.stopped => invoke(
                    program,
                    stream.clause,
                    state,
                    Some(sample.pid as i32),
                    &stream.name,
                    Some(&sample),
                    Some(&stream.comm),
                ),
                Record::Comm { tid, name, .. } if tid as i32 == stream.tid => {
                    stream.comm = CString::new(name).unwrap()
                }
                Record::Lost(n) => *lost = lost.saturating_add(n),
                _ => {}
            }
        }
    }
    streams.retain(|s| !s.hup);
    Ok(())
}
fn monotonic_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t);
    }
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
fn task_comm(pid: i32, tid: i32) -> CString {
    let comm = std::fs::read(format!("/proc/{pid}/task/{tid}/comm"))
        .unwrap_or_else(|_| b"<exited>".to_vec());
    CString::new(
        comm.into_iter()
            .filter(|b| *b != 0 && *b != b'\n')
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn invoke(
    program: &Program,
    clause: usize,
    state: &mut State<'_>,
    target: Option<i32>,
    name: &str,
    sample: Option<&poortrace::perf::Sample>,
    comm: Option<&std::ffi::CStr>,
) {
    let pid = target.unwrap_or_else(|| std::process::id() as i32);
    let tid = sample.map(|s| s.tid as i32).unwrap_or(pid);
    let fallback;
    let comm = match comm {
        Some(c) => c,
        None => {
            fallback = task_comm(pid, tid);
            &fallback
        }
    };
    let name = CString::new(name).unwrap();
    let mut event =
        Event::new(comm, &name).with_ustack(sample.map(|s| s.callchain.as_slice()).unwrap_or(&[]));
    event.pid = pid as u64;
    event.tid = tid as u64;
    event.cpu = sample.map(|s| s.cpu as u64).unwrap_or(0);
    event.nsecs = sample.map(|s| s.time).unwrap_or_else(monotonic_ns);
    event.ip = sample.map(|s| s.ip).unwrap_or(0);
    event.period = sample.map(|s| s.period).unwrap_or(0);
    program.invoke(clause, state, &event);
}
fn invoke_kind(program: &Program, state: &mut State<'_>, target: Option<i32>, begin: bool) {
    for (id, c) in program.clauses.iter().enumerate() {
        for (name, p) in &c.probes {
            if matches!((p, begin), (Probe::Begin, true) | (Probe::End, false)) {
                invoke(program, id, state, target, name, None, None);
            }
            if state.stopped {
                return;
            }
        }
    }
}
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .is_some_and(|(_, rest)| !rest.starts_with(" Z") && !rest.starts_with(" X"))
    })
}

struct Child {
    pid: i32,
    gate: Option<OwnedFd>,
    status: Option<i32>,
}
impl Child {
    fn spawn(args: &[String]) -> Result<Self> {
        let args: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_str()).map_err(|_| "command contains NUL".to_string()))
            .collect::<Result<_>>()?;
        let mut argv: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(format!("pipe: {}", io::Error::last_os_error()));
        }
        let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(format!("fork: {}", io::Error::last_os_error()));
        }
        if pid == 0 {
            // Only async-signal-safe operations between fork and exec. The pipe
            // gate holds the child until perf streams and BEGIN handlers are ready.
            unsafe {
                libc::setpgid(0, 0);
                libc::close(write.as_raw_fd());
                let mut byte = 0u8;
                loop {
                    let n = libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                    if n == 1 {
                        break;
                    }
                    if n < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    libc::_exit(125);
                }
                libc::close(read.as_raw_fd());
                // Restore dispositions changed by the tracer before exec.
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::execvp(args[0].as_ptr(), argv.as_ptr());
                let msg = b"poortrace: cannot execute command\n";
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::_exit(127);
            }
        }
        unsafe {
            libc::setpgid(pid, pid);
        }
        drop(read);
        Ok(Self {
            pid,
            gate: Some(write),
            status: None,
        })
    }
    fn start(&mut self) -> Result<()> {
        if let Some(fd) = self.gate.take() {
            let byte = 1u8;
            if unsafe { libc::write(fd.as_raw_fd(), (&byte as *const u8).cast(), 1) } != 1 {
                return Err(format!("starting command: {}", io::Error::last_os_error()));
            }
        }
        Ok(())
    }
    fn check(&mut self) -> Result<Option<i32>> {
        if self.status.is_some() {
            return Ok(self.status);
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                return Ok(None);
            }
            return Err(format!("waitpid: {}", io::Error::last_os_error()));
        }
        if result == self.pid {
            self.status = Some(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                128 + libc::WTERMSIG(status)
            });
            // Also release any background descendants left in this owned group.
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
        Ok(self.status)
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if self.status.is_none() {
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
                libc::kill(self.pid, libc::SIGKILL);
            }
            loop {
                if unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) } >= 0
                    || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
        }
    }
}
