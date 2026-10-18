use clap::Parser;
use poortrace::{
    Result,
    codegen::Program,
    language::{HARDWARE, Probe, SOFTWARE},
    perf::{Capture, PerfEvent, Record},
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
    about = "LLVM JIT scripts over user-mode perf and ptrace tracing",
    after_help = "Examples:\n  poortrace -e 'interval:ms:100 { @ticks = count(); }' --duration 1\n  poortrace -e 'profile:hz:99 { @[comm, ip] = count(); }' -- ./workload\n  poortrace -p 1234 -e 'profile:hz:99 { @[ustack] = count(); }'\n  poortrace -p 1234 -e 'software:page-faults:1 { @[tid] = count(); }'\n\nPerf/ptrace policy and PMU support are enforced by the host. No BPF programs are loaded."
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
    /// Trace all online CPUs; requires host permission and perf-only probes
    #[arg(long, conflicts_with_all=["pid","command","shell_command","track_threads","follow_forks","attach_descendants"])]
    system_wide: bool,
    /// Include kernel execution in perf counters/sampling (host policy applies)
    #[arg(long)]
    include_kernel: bool,
    /// Also seize descendants that already exist when attaching with -p
    #[arg(long, requires = "pid")]
    attach_descendants: bool,
    /// Refresh function bindings at mapping syscall stops (adds ptrace overhead)
    #[arg(long)]
    track_loads: bool,
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
    /// Save handler events and helper results for offline replay
    #[arg(long, conflicts_with_all=["replay","stat"])]
    record: Option<PathBuf>,
    /// Replay a recording without attaching to a live target
    #[arg(long, conflicts_with_all=["pid","shell_command","command","stat","check","emit_llvm","list","list_functions","list_usdt","track_threads","follow_forks","attach_descendants","system_wide","track_loads","live","window","duration"])]
    replay: Option<PathBuf>,
    /// Sort recorded events globally by monotonic timestamp during replay
    #[arg(long, requires = "replay")]
    sort_events: bool,
    /// List SystemTap SDT probes without attaching
    #[arg(long)]
    list_usdt: Option<String>,
    /// List ELF functions and file offsets without attaching
    #[arg(long)]
    list_functions: Option<String>,
    /// Glob used by --list-functions (raw or demangled names)
    #[arg(long, default_value = "*")]
    function_filter: String,
    /// Track thread creation with ptrace instead of periodic discovery
    #[arg(long)]
    track_threads: bool,
    /// Follow child processes (uses ptrace lifecycle tracking)
    #[arg(short = 'f', long)]
    follow_forks: bool,
    /// Function probe backend: ptrace works without privileged perf uprobes
    #[arg(long,default_value="ptrace",value_parser=["ptrace","perf"])]
    uprobe_backend: String,
    /// Read grouped counters instead of sampling (no script)
    #[arg(long, conflicts_with_all=["expression","script","check","emit_llvm"])]
    stat: bool,
    /// Counter probes for --stat, comma separated
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "hardware:cycles,hardware:instructions",
        requires = "stat"
    )]
    stat_events: Vec<String>,
    /// Report encoding; script printf output is separate when --output is used
    #[arg(long, default_value="text",value_parser=["text","json","folded","speedscope","speedscope-timeline","flamegraph"])]
    output_format: String,
    /// Write the final report to a file
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
    /// Show the largest N entries in each map
    #[arg(long,value_parser=clap::value_parser!(u32).range(1..))]
    top: Option<u32>,
    /// Histogram quantiles (0..1); reports the bucket containing each rank
    #[arg(long, value_delimiter = ',')]
    quantiles: Vec<f64>,
    /// Add percentages to text map reports
    #[arg(long)]
    percent: bool,
    /// Add per-second rates to text map reports
    #[arg(long)]
    rate: bool,
    /// Refresh cumulative text maps at this interval; redraw terminals in place
    #[arg(long,value_parser=duration,conflicts_with_all=["window","output"])]
    live: Option<Duration>,
    /// Print and clear text maps on this wall-clock interval
    #[arg(long,value_parser=duration)]
    window: Option<Duration>,
    /// Compare map values with a previous --output-format json report
    #[arg(long)]
    compare: Option<PathBuf>,
    /// Stack unwinder: frame pointers or sampled-stack DWARF CFI
    #[arg(long,default_value="fp",value_parser=["fp","dwarf"])]
    stack_mode: String,
    /// Bytes of target stack captured for DWARF/jsstack; multiple of 8
    #[arg(long,default_value_t=16384,value_parser=clap::value_parser!(u32).range(8..=32768))]
    stack_bytes: u32,
    /// Capture user branch history where the PMU supports it
    #[arg(long)]
    branch_stack: bool,
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
fn run(mut args: Args) -> Result<i32> {
    if args.attach_descendants {
        args.follow_forks = true;
    }
    if args.output_format == "speedscope-timeline" && args.replay.is_none() {
        return Err("--output-format speedscope-timeline requires --replay".into());
    }
    if let Some(path) = &args.list_usdt {
        for site in poortrace::usdt::sites(args.pid.unwrap_or(std::process::id() as i32), path)? {
            println!(
                "{}:{} 0x{:x} args={} semaphore={:?}",
                site.provider,
                site.name,
                site.offset,
                site.arguments.len(),
                site.semaphore_delta
            );
        }
        return Ok(0);
    }
    if let Some(path) = &args.list_functions {
        for function in poortrace::uprobe::functions(
            args.pid.unwrap_or(std::process::id() as i32),
            path,
            &args.function_filter,
        )? {
            println!(
                "0x{:x} {} [{}]",
                function.offset, function.name, function.demangled
            );
        }
        return Ok(0);
    }
    if args.list {
        println!(
            "BEGIN\nEND\ntracepoint:CATEGORY:EVENT\nkprobe:FUNCTION\nkretprobe:FUNCTION\ninterval:{{ns,us,ms,s,hz}}:N\nprofile:{{ns,us,ms,s,hz}}:N\nwait:{{ms,s,hz}}:N\nwakeup:{{ms,s,hz}}:N\nuprobe:PATH:FUNCTION\nuretprobe:PATH:FUNCTION\nusdt:PATH:PROVIDER:NAME"
        );
        println!(
            "offcpu\nwatchpoint:ADDRESS:LENGTH:{{r,w,rw,x}}\nraw:CONFIG[:PERIOD]\npmu:NAME:CONFIG[:PERIOD]\ncache:CACHE:OP:RESULT[:PERIOD]\nsyscall:{{enter,exit}}:{{NAME,NUMBER,*}}"
        );
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
    if args.stack_bytes % 8 != 0 {
        return Err("--stack-bytes must be a multiple of 8".into());
    }
    if args.live.is_some() && args.output_format != "text" {
        return Err("--live requires text output".into());
    }
    if args.window.is_some() && (args.output_format != "text" || args.output.is_some()) {
        return Err("--window supports text reports on stdout; omit --output".into());
    }
    if !args.quantiles.is_empty() && args.output_format != "text" {
        return Err("--quantiles applies to text reports".into());
    }
    if args
        .quantiles
        .iter()
        .any(|n| !n.is_finite() || *n < 0.0 || *n > 1.0)
    {
        return Err("--quantiles must be finite values from 0 to 1".into());
    }
    if args.compare.is_some()
        && !matches!(args.output_format.as_str(), "text" | "json" | "flamegraph")
    {
        return Err("--compare supports signed text, JSON, or flamegraph reports".into());
    }
    if (args.percent || args.rate) && args.output_format != "text" {
        return Err("--percent and --rate apply to text reports".into());
    }
    if let Some(path) = &args.replay {
        return run_replay(&args, path);
    }
    if args.stat {
        return run_stat(&args);
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
    let mut program = Program::compile(&source)?;
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
    for clause in &mut program.clauses {
        let mut probes = Vec::new();
        for (name, probe) in &clause.probes {
            if let Probe::Uprobe {
                path,
                function,
                ret,
            } = probe
            {
                if let Some(selector) = function.strip_prefix("__usdt__") {
                    if args.uprobe_backend != "ptrace" {
                        return Err("SDT probes require --uprobe-backend ptrace".into());
                    }
                    let (provider, marker) = selector
                        .split_once(':')
                        .ok_or("SDT requires PROVIDER:NAME")?;
                    for site in
                        poortrace::usdt::sites(args.pid.unwrap_or(std::process::id() as i32), path)?
                    {
                        if poortrace::uprobe::matches(provider, &site.provider)
                            && poortrace::uprobe::matches(marker, &site.name)
                        {
                            probes.push((
                                format!("usdt:{path}:{}:{}", site.provider, site.name),
                                Probe::Uprobe {
                                    path: path.clone(),
                                    function: format!(
                                        "__sdt__{}",
                                        serde_json::to_string(&site).map_err(|e| e.to_string())?
                                    ),
                                    ret: false,
                                },
                            ));
                        }
                    }
                    if probes.is_empty() {
                        return Err(format!("no SDT probes matched {selector} in {path}"));
                    }
                } else if function.contains(['*', '?']) {
                    let matches = poortrace::uprobe::functions(
                        args.pid.unwrap_or(std::process::id() as i32),
                        path,
                        function,
                    )?;
                    if matches.is_empty() {
                        return Err(format!(
                            "function pattern {function:?} matched no symbols in {path}"
                        ));
                    }
                    let mut offsets = BTreeSet::new();
                    for found in matches {
                        if offsets.insert(found.offset) {
                            probes.push((
                                format!(
                                    "{}:{path}:{}",
                                    if *ret { "uretprobe" } else { "uprobe" },
                                    found.name
                                ),
                                Probe::Uprobe {
                                    path: path.clone(),
                                    function: format!("0x{:x}", found.offset),
                                    ret: *ret,
                                },
                            ));
                        }
                    }
                } else {
                    probes.push((name.clone(), probe.clone()));
                }
            } else {
                probes.push((name.clone(), probe.clone()));
            }
            if probes.len() > 256 {
                return Err("expanded probe limit (256) exceeded".into());
            }
        }
        clause.probes = probes;
    }
    if args.system_wide
        && program.clauses.iter().any(|c| {
            c.probes.iter().any(|(_, p)| {
                matches!(
                    p,
                    Probe::Syscall { .. }
                        | Probe::Uprobe { .. }
                        | Probe::Wait(_)
                        | Probe::Wakeup(_)
                        | Probe::OffCpu
                )
            })
        })
    {
        return Err("--system-wide supports perf sampling, tracepoint/kernel probes, and lifecycle/timer handlers; ptrace, wait/wakeup, uprobes and offcpu require a target".into());
    }
    if args.track_loads && args.uprobe_backend != "ptrace" {
        return Err("--track-loads requires --uprobe-backend ptrace".into());
    }
    if args.track_loads
        && !program.clauses.iter().any(|c| {
            c.probes
                .iter()
                .any(|(_, p)| matches!(p, Probe::Uprobe { .. }))
        })
    {
        return Err("--track-loads requires ptrace function/USDT probes".into());
    }
    if (program.has_perf()
        || program.has_syscalls()
        || program.clauses.iter().any(|c| {
            c.probes
                .iter()
                .any(|(_, p)| matches!(p, Probe::Wait(_) | Probe::Wakeup(_)))
        }))
        && !args.system_wide
        && args.pid.is_none()
        && args.command.is_empty()
        && args.shell_command.is_none()
    {
        return Err("perf probes require -p PID, -c COMMAND, or -- EXECUTABLE [ARGS...]".into());
    }
    if program.clauses.iter().any(|clause| {
        clause
            .probes
            .iter()
            .any(|(_, probe)| matches!(probe, Probe::Uprobe { .. }))
    }) && args.uprobe_backend == "ptrace"
    {
        return run_functions(&args, &program);
    }
    if program.has_syscalls() || args.follow_forks || args.track_threads {
        return run_syscalls(&args, &program);
    }
    let capture = Capture {
        addr: true,
        kernel: args.include_kernel,
        callchain: program.needs_ustack() || args.record.is_some(),
        dwarf_stack: if (args.stack_mode == "dwarf" && program.needs_ustack())
            || program.needs_jsstack()
            || args.record.is_some()
        {
            args.stack_bytes
        } else {
            0
        },
        branches: args.branch_stack || program.needs_branches(),
        ..Capture::default()
    };
    install_signals()?;
    let command = args
        .shell_command
        .as_ref()
        .map(|s| vec!["/bin/sh".into(), "-c".into(), s.clone()])
        .unwrap_or_else(|| args.command.clone());
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(&command, args.follow_forks)?)
    };
    let target = child
        .as_ref()
        .map(|c| c.pid)
        .or(args.pid)
        .or(args.system_wide.then_some(-1));
    if target.is_some_and(|pid| pid != -1 && !alive(pid)) {
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
            capture,
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
    configure_report(&mut state, &args)?;
    configure_record(&mut state, &args, &program)?;
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
    let mut window_start = Instant::now();
    let mut live_start = Instant::now();
    let mut waits =
        poortrace::wait::Poller::new(&program, args.stack_bytes as usize, args.record.is_some());
    let result = (|| -> Result<()> {
        let mut refresh = Instant::now();
        loop {
            let child_done = if let Some(c) = &mut child {
                c.check()?.is_some()
            } else {
                false
            };
            dispatch_waits(&program, &mut state, &mut waits, target)?;
            drain(&program, &mut state, &mut streams, &mut lost)?;
            if state.stopped || INTERRUPTED.load(Ordering::Relaxed) || child_done {
                break;
            }
            if args.duration.is_some_and(|d| start.elapsed() >= d) {
                break;
            }
            if target.is_some_and(|p| p != -1 && !alive(p)) {
                break;
            }
            if refresh.elapsed() >= Duration::from_millis(100) {
                if let Some(pid) = target {
                    attach(
                        &program,
                        pid,
                        args.mmap_pages,
                        &mut streams,
                        true,
                        false,
                        capture,
                    )?;
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
            if args
                .window
                .is_some_and(|period| window_start.elapsed() >= period)
            {
                state.report.elapsed = window_start.elapsed().as_secs_f64();
                state.print_all();
                state.clear_all();
                window_start = Instant::now();
            }
            if args
                .live
                .is_some_and(|period| live_start.elapsed() >= period)
            {
                state.report.elapsed = start.elapsed().as_secs_f64();
                state.live_snapshot();
                live_start = Instant::now();
            }
            state.flush()?;
            if state.stopped {
                break;
            }
            if streams.is_empty() && timers.is_empty() && target.is_none() {
                break;
            }
            let mut wait = Duration::from_millis(20).min(waits.delay());
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
    finish_report(&mut state, &args, window_start.elapsed())?;
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
    switched_out: Option<(u64, bool)>,
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
    capture: Capture,
) -> Result<()> {
    if !program.has_perf() {
        return Ok(());
    }
    let tids = if pid == -1 {
        poortrace::kernel::online_cpus()?.into_iter().collect()
    } else {
        match threads(pid) {
            Ok(t) => t,
            Err(_) if !alive(pid) => return Ok(()),
            Err(e) => return Err(e),
        }
    };
    for (clause, c) in program.clauses.iter().enumerate() {
        for (name, probe) in &c.probes {
            if !probe.is_perf() || capture.ptrace_functions && matches!(probe, Probe::Uprobe { .. })
            {
                continue;
            }
            for tid in &tids {
                if streams
                    .iter()
                    .any(|s| s.clause == clause && s.name == *name && s.tid == *tid)
                {
                    continue;
                }
                let actual_tid = if pid == -1 { -1 } else { *tid };
                let event_capture = Capture {
                    cpu: if pid == -1 { Some(*tid) } else { None },
                    ..capture
                };
                let event =
                    PerfEvent::try_open_config(actual_tid, probe, pages, on_exec, event_capture);
                match event {
                    Ok(Some(event)) => {
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
                            switched_out: None,
                        });
                    }
                    Ok(None) => {}
                    Err(_) if pid != -1 && !alive(*tid) => {}
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
    let mut fds: Vec<_> = streams
        .iter()
        .map(|s| libc::pollfd {
            fd: s.event.fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) };
    if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
        return Err(io::Error::last_os_error().to_string());
    }
    for (stream, fd) in streams.iter_mut().zip(fds) {
        stream.hup |= fd.revents & libc::POLLHUP != 0;
    }
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
                    if stream.event.system_wide() {
                        None
                    } else {
                        Some(&stream.comm)
                    },
                ),
                Record::Comm { tid, name, .. } if tid as i32 == stream.tid => {
                    stream.comm = CString::new(name).unwrap()
                }
                Record::Switch {
                    out,
                    preempt,
                    pid,
                    tid,
                    cpu,
                    time,
                } => {
                    if out {
                        stream.switched_out = Some((time, preempt));
                    } else if let Some((start, preempt)) = stream.switched_out.take() {
                        if time >= start && !state.stopped {
                            let sample = poortrace::perf::Sample {
                                pid,
                                tid,
                                cpu,
                                time,
                                period: time - start,
                                offcpu_ns: time - start,
                                preempt,
                                ..Default::default()
                            };
                            invoke(
                                program,
                                stream.clause,
                                state,
                                Some(pid as i32),
                                &stream.name,
                                Some(&sample),
                                Some(&stream.comm),
                            );
                        }
                    }
                }
                Record::Lost(n) => {
                    *lost = lost.saturating_add(n);
                    stream.switched_out = None;
                }
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
    let pid = target
        .filter(|pid| *pid >= 0)
        .unwrap_or_else(|| std::process::id() as i32);
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
    let frames = if program.needs_ustack() || state.recorder.is_some() {
        sample
            .map(|sample| state.unwind_sample(sample))
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut event = Event::new(comm, &name).with_ustack(&frames).with_branches(
        sample
            .map(|sample| sample.branches.as_slice())
            .unwrap_or(&[]),
    );
    event.args = sample.map(|s| s.args).unwrap_or([0; 6]);
    event.retval = sample.map(|s| s.retval).unwrap_or(0);
    event.addr = sample.map(|s| s.addr).unwrap_or(0);
    event.offcpu_ns = sample.map(|s| s.offcpu_ns).unwrap_or(0);
    event.preempt = sample.map(|s| u64::from(s.preempt)).unwrap_or(0);
    event.pid = pid as u64;
    event.tid = tid as u64;
    event.cpu = sample.map(|s| s.cpu as u64).unwrap_or(0);
    event.nsecs = sample.map(|s| s.time).unwrap_or_else(monotonic_ns);
    event.ip = sample.map(|s| s.ip).unwrap_or(0);
    event.period = sample.map(|s| s.period).unwrap_or(0);
    state.trace_fields = sample
        .and_then(|sample| sample.trace.as_ref())
        .map(|trace| trace.fields.clone())
        .unwrap_or_default();
    state.js_snapshot = if program.needs_jsstack() || state.recorder.is_some() {
        sample.and_then(|sample| sample.regs.map(|regs| (regs, sample.stack.clone())))
    } else {
        None
    };
    program.invoke(clause, state, &event);
    state.js_snapshot = None;
    state.trace_fields.clear();
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
    descendants: std::collections::BTreeMap<i32, OwnedFd>,
}
impl Child {
    fn spawn(args: &[String], follow: bool) -> Result<Self> {
        if follow && unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
            return Err(format!(
                "enabling owned descendant reaping: {}",
                io::Error::last_os_error()
            ));
        }
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
            descendants: std::collections::BTreeMap::new(),
        })
    }
    fn kill_descendants(&self) {
        for fd in self.descendants.values() {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                );
            }
        }
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
        self.kill_descendants();
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
        if !self.descendants.is_empty() {
            loop {
                let result = unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) };
                if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
        }
    }
}

fn command_for(args: &Args) -> Vec<String> {
    args.shell_command
        .as_ref()
        .map(|s| vec!["/bin/sh".into(), "-c".into(), s.clone()])
        .unwrap_or_else(|| args.command.clone())
}
fn configure_report(state: &mut State<'_>, args: &Args) -> Result<()> {
    state.report = poortrace::report::Options {
        format: args.output_format.clone(),
        top: args.top.map(|n| n as usize),
        percent: args.percent,
        rate: args.rate,
        quantiles: args.quantiles.clone(),
        baseline: args
            .compare
            .as_ref()
            .map(|path| poortrace::report::baseline(path))
            .transpose()?
            .unwrap_or_default(),
        ..Default::default()
    };
    Ok(())
}
fn finish_report(state: &mut State<'_>, args: &Args, elapsed: Duration) -> Result<()> {
    if let Some(recorder) = &mut state.recorder {
        recorder.flush()?;
    }
    state.report.elapsed = elapsed.as_secs_f64();
    if let Some(path) = &args.output {
        let report = state.render_report()?;
        std::fs::write(path, report).map_err(|e| format!("{}: {e}", path.display()))?;
    } else if !args.no_print_maps {
        state.print_all();
    }
    Ok(())
}
fn run_stat(args: &Args) -> Result<i32> {
    if !matches!(args.output_format.as_str(), "text" | "json")
        || args.compare.is_some()
        || args.window.is_some()
        || args.live.is_some()
        || !args.quantiles.is_empty()
        || args.percent
        || args.rate
    {
        return Err("--stat supports final text or JSON counter reports".into());
    }
    install_signals()?;
    let command = command_for(args);
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(&command, args.follow_forks)?)
    };
    let pid = child
        .as_ref()
        .map(|c| c.pid)
        .or(args.pid)
        .or(args.system_wide.then_some(-1))
        .ok_or("--stat requires -p PID, a command, or --system-wide")?;
    let open_group = |id: i32, on_exec: bool| {
        if args.system_wide {
            poortrace::counters::Group::open_on_cpu(id, &args.stat_events, args.include_kernel)
        } else {
            poortrace::counters::Group::open_with_kernel(
                id,
                &args.stat_events,
                on_exec,
                args.include_kernel,
            )
        }
    };
    let mut monitor = if !args.system_wide && (args.follow_forks || args.track_threads) {
        let mut monitor = poortrace::syscall::Tracer::seize_tree(
            pid,
            threads(pid)?,
            child.is_some(),
            args.attach_descendants,
        )?;
        monitor.follow_forks(args.follow_forks);
        monitor.trace_syscalls(false);
        Some(monitor)
    } else {
        None
    };
    let mut groups = std::collections::BTreeMap::new();
    let initial_targets = monitor
        .as_ref()
        .map(|monitor| monitor.targets())
        .unwrap_or_else(|| BTreeSet::from([pid]));
    let initial_tids: BTreeSet<_> = if args.system_wide {
        poortrace::kernel::online_cpus()?.into_iter().collect()
    } else {
        initial_targets
            .into_iter()
            .flat_map(|pid| threads(pid).unwrap_or_default())
            .collect()
    };
    for tid in initial_tids {
        groups.insert(tid, open_group(tid, child.is_some())?);
    }
    for group in groups.values() {
        if child.is_none() {
            group.enable()?;
        }
    }
    if let Some(child) = &mut child {
        child.start()?;
    }
    let start = Instant::now();
    let mut refresh = Instant::now();
    let mut readings = Vec::new();
    loop {
        let done = if let Some(monitor) = &mut monitor {
            monitor.poll()?;
            track_owned_descendants(&mut child, args.follow_forks, monitor.targets())?;
            for tid in monitor.take_discovered() {
                if let std::collections::btree_map::Entry::Vacant(entry) = groups.entry(tid) {
                    let group = open_group(tid, false)?;
                    group.enable()?;
                    entry.insert(group);
                }
                monitor.resume(tid)?;
            }
            if let Some(child) = &mut child {
                if let Some(code) = (!monitor.targets().contains(&child.pid))
                    .then(|| monitor.exits.remove(&child.pid))
                    .flatten()
                {
                    child.status = Some(code);
                    if !args.follow_forks {
                        unsafe {
                            libc::kill(-child.pid, libc::SIGKILL);
                        }
                    }
                }
            }
            monitor.is_empty()
                || !args.follow_forks && child.as_ref().is_some_and(|child| child.status.is_some())
        } else if let Some(child) = &mut child {
            child.check()?.is_some()
        } else {
            !args.system_wide && !alive(pid)
        };
        if done
            || INTERRUPTED.load(Ordering::Relaxed)
            || args.duration.is_some_and(|d| start.elapsed() >= d)
        {
            break;
        }
        if refresh.elapsed() >= Duration::from_millis(100) {
            let targets = monitor
                .as_ref()
                .map(|monitor| monitor.targets())
                .unwrap_or_else(|| BTreeSet::from([pid]));
            let tids: BTreeSet<_> = if args.system_wide {
                poortrace::kernel::online_cpus()?.into_iter().collect()
            } else {
                targets
                    .into_iter()
                    .flat_map(|target| threads(target).unwrap_or_default())
                    .collect()
            };
            let dead: Vec<_> = groups
                .keys()
                .filter(|tid| !tids.contains(tid))
                .copied()
                .collect();
            for tid in dead {
                let group = groups.remove(&tid).unwrap();
                group.disable()?;
                readings.extend(group.read()?);
            }
            for tid in tids {
                if let std::collections::btree_map::Entry::Vacant(entry) = groups.entry(tid) {
                    match open_group(tid, false) {
                        Ok(group) => {
                            group.enable()?;
                            entry.insert(group);
                        }
                        Err(_)
                            if !args.system_wide
                                && !std::path::Path::new(&format!("/proc/{tid}")).exists() => {}
                        Err(_)
                            if args.system_wide
                                && !poortrace::kernel::online_cpus()?.contains(&tid) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            refresh = Instant::now();
        }
        unsafe {
            libc::poll(
                std::ptr::null_mut(),
                0,
                if monitor.is_some() { 1 } else { 20 },
            );
        }
    }
    if let Some(monitor) = &mut monitor {
        kill_owned_descendants(child.as_ref(), args.follow_forks, monitor.targets());
        monitor.detach();
        if let Some(child) = &mut child {
            if let Some(code) = (!monitor.targets().contains(&child.pid))
                .then(|| monitor.exits.remove(&child.pid))
                .flatten()
            {
                child.status = Some(code);
            }
        }
    }
    for group in groups.values() {
        group.disable()?;
        readings.extend(group.read()?);
    }
    let mut totals = std::collections::BTreeMap::<String, (u128, u128, u128, Option<f64>)>::new();
    for reading in readings {
        let total = totals.entry(reading.event).or_insert((0, 0, 0, Some(0.0)));
        total.0 += reading.raw as u128;
        total.1 += reading.enabled_ns as u128;
        total.2 += reading.running_ns as u128;
        total.3 = total.3.zip(reading.scaled).map(|(a, b)| a + b);
    }
    let rows:Vec<_>=totals.iter().map(|(event,(raw,enabled,running,scaled))|serde_json::json!({"event":event,"raw":raw,"enabled_ns":enabled,"running_ns":running,"scaled":scaled})).collect();
    let text = if args.output_format == "json" {
        serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())? + "\n"
    } else {
        let mut out = String::new();
        for (event, (raw, enabled, running, scaled)) in &totals {
            out.push_str(&format!(
                "{event}: raw={raw} scaled={} running={running}/{enabled} ns\n",
                scaled
                    .map(|v| format!("{v:.3}"))
                    .unwrap_or_else(|| "unavailable".into())
            ));
        }
        if let (Some(cycles), Some(instructions)) = (
            totals
                .get("hardware:cycles")
                .or_else(|| totals.get("hardware:cpu-cycles")),
            totals.get("hardware:instructions"),
        ) {
            if let (Some(cycles), Some(instructions)) = (cycles.3, instructions.3) {
                if cycles > 0.0 {
                    out.push_str(&format!("IPC: {:.4}\n", instructions / cycles));
                }
            }
        }
        out
    };
    if let Some(path) = &args.output {
        std::fs::write(path, text).map_err(|e| e.to_string())?;
    } else {
        use std::io::Write;
        io::stdout()
            .write_all(text.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    Ok(child.as_ref().and_then(|child| child.status).unwrap_or(0))
}
fn run_syscalls(args: &Args, program: &Program) -> Result<i32> {
    install_signals()?;
    let command = command_for(args);
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(&command, args.follow_forks)?)
    };
    let pid = child
        .as_ref()
        .map(|child| child.pid)
        .or(args.pid)
        .ok_or("syscall probes require a target")?;
    let mut tracer = poortrace::syscall::Tracer::seize_tree(
        pid,
        threads(pid)?,
        child.is_some(),
        args.attach_descendants,
    )?;
    tracer.follow_forks(args.follow_forks);
    tracer.trace_syscalls(program.has_syscalls());
    let capture = Capture {
        ptrace_functions: false,
        addr: true,
        kernel: args.include_kernel,
        callchain: program.needs_ustack() || args.record.is_some(),
        dwarf_stack: if (args.stack_mode == "dwarf" && program.needs_ustack())
            || program.needs_jsstack()
            || args.record.is_some()
        {
            args.stack_bytes
        } else {
            0
        },
        branches: args.branch_stack || program.needs_branches(),
        ..Default::default()
    };
    let mut streams = Vec::new();
    if args.attach_descendants {
        for target in tracer.targets() {
            if target != pid {
                attach(
                    program,
                    target,
                    args.mmap_pages,
                    &mut streams,
                    false,
                    false,
                    capture,
                )?;
            }
        }
    }
    attach(
        program,
        pid,
        args.mmap_pages,
        &mut streams,
        false,
        child.is_some(),
        capture,
    )?;
    let mut lost = 0;
    let mut refresh = Instant::now();
    let stdout = io::stdout();
    let mut state = program.state(io::BufWriter::new(stdout.lock()));
    configure_report(&mut state, args)?;
    configure_record(&mut state, args, program)?;
    state.max_entries = args.max_map_entries as usize;
    invoke_kind(program, &mut state, Some(pid), true);
    state.flush()?;
    if !state.stopped {
        for stream in &streams {
            if !stream.on_exec {
                stream.event.enable()?;
            }
        }
        if let Some(child) = &mut child {
            child.start()?;
        }
    }
    let start = Instant::now();
    let mut window_start = start;
    let mut live_start = start;
    let mut waits =
        poortrace::wait::Poller::new(program, args.stack_bytes as usize, args.record.is_some());
    let mut timers: Vec<_> = program
        .clauses
        .iter()
        .enumerate()
        .flat_map(|(id, clause)| {
            clause.probes.iter().filter_map(move |(name, probe)| {
                if let Probe::Interval(period) = probe {
                    Some((id, name.clone(), *period, Instant::now() + *period))
                } else {
                    None
                }
            })
        })
        .collect();
    let result = (|| -> Result<()> {
        while !state.stopped
            && !INTERRUPTED.load(Ordering::Relaxed)
            && !args
                .duration
                .is_some_and(|duration| start.elapsed() >= duration)
        {
            dispatch_waits(program, &mut state, &mut waits, tracer.targets())?;
            drain(program, &mut state, &mut streams, &mut lost)?;
            if state.stopped {
                break;
            }
            if refresh.elapsed() >= Duration::from_millis(10) {
                for target in tracer.targets() {
                    attach(
                        program,
                        target,
                        args.mmap_pages,
                        &mut streams,
                        true,
                        false,
                        capture,
                    )?;
                }
                refresh = Instant::now();
            }
            let events = tracer.poll()?;
            track_owned_descendants(&mut child, args.follow_forks, tracer.targets())?;
            for tid in tracer.take_discovered() {
                attach(
                    program,
                    poortrace::syscall::tgid(tid).unwrap_or(tid),
                    args.mmap_pages,
                    &mut streams,
                    true,
                    false,
                    capture,
                )?;
                tracer.resume(tid)?;
            }
            let idle = events.is_empty();
            for event in events {
                let selected = program.clauses.iter().any(|clause| {
                    clause.probes.iter().any(|(_, probe)| {
                        matches!(probe, Probe::Syscall { enter, number }
                            if *enter == event.enter
                                && number.is_none_or(|number| number == event.number))
                    })
                });
                if !selected {
                    tracer.resume(event.tid)?;
                    continue;
                }
                let name = poortrace::syscall::name(event.number);
                let syscall_name = CString::new(name).unwrap();
                let event_pid = poortrace::syscall::tgid(event.tid).unwrap_or(pid);
                let comm = task_comm(event_pid, event.tid);
                let frames = if program.needs_ustack() || args.record.is_some() {
                    let regs = poortrace::functions::user_registers(event.tid)?;
                    let stack = poortrace::memory::read_stack(
                        event.tid as u32,
                        regs.sp,
                        args.stack_bytes as usize,
                    )
                    .unwrap_or_default();
                    state.unwind_sample(&poortrace::perf::Sample {
                        pid: event_pid as u32,
                        tid: event.tid as u32,
                        ip: regs.ip,
                        regs: Some(regs),
                        stack,
                        callchain: vec![regs.ip],
                        ..Default::default()
                    })
                } else {
                    Vec::new()
                };
                let event_nsecs = monotonic_ns();
                for (id, clause) in program.clauses.iter().enumerate() {
                    for (probe_name, probe) in &clause.probes {
                        if let Probe::Syscall { enter, number } = probe {
                            if *enter != event.enter
                                || number.is_some_and(|number| number != event.number)
                            {
                                continue;
                            }
                            let probe_name = CString::new(probe_name.as_str()).unwrap();
                            let mut sample = Event::new(&comm, &probe_name)
                                .with_syscall(&syscall_name)
                                .with_ustack(&frames);
                            sample.pid = event_pid as u64;
                            sample.tid = event.tid as u64;
                            sample.nsecs = event_nsecs;
                            sample.ip = event.ip;
                            sample.sysno = event.number as u64;
                            sample.retval = event.retval;
                            sample.latency = event.latency;
                            sample.args = event.args;
                            program.invoke(id, &mut state, &sample);
                            if state.stopped {
                                break;
                            }
                        }
                    }
                    if state.stopped {
                        break;
                    }
                }
                if !state.stopped {
                    tracer.resume(event.tid)?;
                }
            }
            if let Some(child) = &mut child {
                if let Some(code) = (!tracer.targets().contains(&child.pid))
                    .then(|| tracer.exits.remove(&child.pid))
                    .flatten()
                {
                    child.status = Some(code);
                    if !args.follow_forks {
                        unsafe {
                            libc::kill(-child.pid, libc::SIGKILL);
                        }
                        break;
                    }
                }
            }
            if tracer.is_empty() || (!args.follow_forks && !tracer.targets().contains(&pid)) {
                break;
            }
            for (id, name, period, deadline) in &mut timers {
                if Instant::now() >= *deadline {
                    invoke(program, *id, &mut state, Some(pid), name, None, None);
                    *deadline = Instant::now() + *period;
                }
            }
            if args
                .window
                .is_some_and(|duration| window_start.elapsed() >= duration)
            {
                state.report.elapsed = window_start.elapsed().as_secs_f64();
                state.print_all();
                state.clear_all();
                window_start = Instant::now();
            }
            if args
                .live
                .is_some_and(|period| live_start.elapsed() >= period)
            {
                state.report.elapsed = start.elapsed().as_secs_f64();
                state.live_snapshot();
                live_start = Instant::now();
            }
            state.flush()?;
            if idle {
                unsafe {
                    libc::poll(std::ptr::null_mut(), 0, 1);
                }
            }
        }
        Ok(())
    })();
    // Detach before dropping an owned child or returning to an attached target.
    let drain_result = (|| -> Result<()> {
        for stream in &streams {
            stream.event.disable()?;
        }
        if !state.stopped {
            drain(program, &mut state, &mut streams, &mut lost)?;
        }
        Ok(())
    })();
    kill_owned_descendants(child.as_ref(), args.follow_forks, tracer.targets());
    tracer.detach();
    if let Some(child) = &mut child {
        if child.status.is_none() {
            if let Some(code) = (!tracer.targets().contains(&child.pid))
                .then(|| tracer.exits.remove(&child.pid))
                .flatten()
            {
                child.status = Some(code);
                unsafe {
                    libc::kill(-child.pid, libc::SIGKILL);
                }
            }
        }
    }
    drop(tracer);
    state.stopped = false;
    invoke_kind(program, &mut state, Some(pid), false);
    finish_report(&mut state, args, window_start.elapsed())?;
    state.flush()?;
    result?;
    drain_result?;
    if lost != 0 {
        eprintln!("poortrace: lost {lost} perf samples");
    }
    Ok(child.as_ref().and_then(|child| child.status).unwrap_or(0))
}

fn run_functions(args: &Args, program: &Program) -> Result<i32> {
    install_signals()?;
    let command = command_for(args);
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(&command, args.follow_forks)?)
    };
    let pid = child
        .as_ref()
        .map(|child| child.pid)
        .or(args.pid)
        .ok_or("function probes require a target")?;
    let mut bindings = Vec::new();
    let mut specs = Vec::new();
    for (id, clause) in program.clauses.iter().enumerate() {
        for (name, probe) in &clause.probes {
            if let Probe::Uprobe {
                path,
                function,
                ret,
            } = probe
            {
                bindings.push((id, name.clone()));
                specs.push(poortrace::functions::Spec {
                    path: path.clone(),
                    function: function.clone(),
                    ret: *ret,
                });
            }
        }
    }
    let mut tracer = poortrace::functions::Tracer::seize_tree(
        pid,
        threads(pid)?,
        &specs,
        child.is_some(),
        args.attach_descendants,
    )?;
    tracer.trace_syscalls(program.has_syscalls());
    tracer.track_loads(args.track_loads);
    tracer.follow_forks(args.follow_forks);
    let capture = Capture {
        ptrace_functions: true,
        addr: true,
        kernel: args.include_kernel,
        callchain: program.needs_ustack() || args.record.is_some(),
        dwarf_stack: if (args.stack_mode == "dwarf" && program.needs_ustack())
            || program.needs_jsstack()
            || args.record.is_some()
        {
            args.stack_bytes
        } else {
            0
        },
        branches: args.branch_stack || program.needs_branches(),
        ..Default::default()
    };
    let mut streams = Vec::new();
    if args.attach_descendants {
        for target in tracer.targets() {
            if target != pid {
                attach(
                    program,
                    target,
                    args.mmap_pages,
                    &mut streams,
                    false,
                    false,
                    capture,
                )?;
            }
        }
    }
    attach(
        program,
        pid,
        args.mmap_pages,
        &mut streams,
        false,
        child.is_some(),
        capture,
    )?;
    let mut lost = 0;
    let mut refresh = Instant::now();
    let stdout = io::stdout();
    let mut state = program.state(io::BufWriter::new(stdout.lock()));
    configure_report(&mut state, args)?;
    configure_record(&mut state, args, program)?;
    state.max_entries = args.max_map_entries as usize;
    invoke_kind(program, &mut state, Some(pid), true);
    state.flush()?;
    if !state.stopped {
        for stream in &streams {
            if !stream.on_exec {
                stream.event.enable()?;
            }
        }
        if let Some(child) = &mut child {
            child.start()?;
        }
    }
    let start = Instant::now();
    let mut window_start = start;
    let mut live_start = start;
    let mut waits =
        poortrace::wait::Poller::new(program, args.stack_bytes as usize, args.record.is_some());
    let mut timers: Vec<_> = program
        .clauses
        .iter()
        .enumerate()
        .flat_map(|(id, clause)| {
            clause.probes.iter().filter_map(move |(name, probe)| {
                if let Probe::Interval(period) = probe {
                    Some((id, name.clone(), *period, Instant::now() + *period))
                } else {
                    None
                }
            })
        })
        .collect();
    let result = (|| -> Result<()> {
        while !state.stopped
            && !INTERRUPTED.load(Ordering::Relaxed)
            && !args
                .duration
                .is_some_and(|duration| start.elapsed() >= duration)
        {
            dispatch_waits(program, &mut state, &mut waits, tracer.targets())?;
            drain(program, &mut state, &mut streams, &mut lost)?;
            if state.stopped {
                break;
            }
            if refresh.elapsed() >= Duration::from_millis(10) {
                for target in tracer.targets() {
                    attach(
                        program,
                        target,
                        args.mmap_pages,
                        &mut streams,
                        true,
                        false,
                        capture,
                    )?;
                }
                refresh = Instant::now();
            }
            let events = tracer.poll()?;
            track_owned_descendants(&mut child, args.follow_forks, tracer.targets())?;
            for tid in tracer.take_discovered() {
                attach(
                    program,
                    poortrace::syscall::tgid(tid).unwrap_or(tid),
                    args.mmap_pages,
                    &mut streams,
                    true,
                    false,
                    capture,
                )?;
            }
            let idle = events.is_empty();
            for event in events {
                let destinations: Vec<(usize, String)> = if let Some(syscall) = &event.syscall {
                    program
                        .clauses
                        .iter()
                        .enumerate()
                        .flat_map(|(id, clause)| {
                            clause
                                .probes
                                .iter()
                                .filter_map(move |(name, probe)| match probe {
                                    Probe::Syscall { enter, number }
                                        if *enter == syscall.enter
                                            && number.is_none_or(|n| n == syscall.number) =>
                                    {
                                        Some((id, name.clone()))
                                    }
                                    _ => None,
                                })
                        })
                        .collect()
                } else {
                    vec![bindings[event.binding].clone()]
                };
                if destinations.is_empty() {
                    continue;
                }
                let syscall_name = CString::new(
                    event
                        .syscall
                        .as_ref()
                        .map(|e| poortrace::syscall::name(e.number))
                        .unwrap_or_default(),
                )
                .unwrap();
                let event_pid = poortrace::syscall::tgid(event.tid).unwrap_or(pid);
                let comm = task_comm(event_pid, event.tid);
                let frames = if program.needs_ustack() || args.record.is_some() {
                    let stack = poortrace::memory::read_stack(
                        event.tid as u32,
                        event.regs.sp,
                        args.stack_bytes as usize,
                    )
                    .unwrap_or_default();
                    state.unwind_sample(&poortrace::perf::Sample {
                        pid: event_pid as u32,
                        tid: event.tid as u32,
                        ip: event.regs.ip,
                        regs: Some(event.regs),
                        stack,
                        callchain: vec![event.regs.ip],
                        ..Default::default()
                    })
                } else {
                    Vec::new()
                };
                let event_nsecs = monotonic_ns();
                for (id, name) in destinations {
                    let name = CString::new(name).unwrap();
                    let mut sample = Event::new(&comm, &name)
                        .with_ustack(&frames)
                        .with_syscall(&syscall_name);
                    sample.sysno = event.syscall.as_ref().map(|e| e.number as u64).unwrap_or(0);
                    sample.pid = event_pid as u64;
                    sample.tid = event.tid as u64;
                    sample.nsecs = event_nsecs;
                    sample.ip = event.regs.ip;
                    sample.args = event.args;
                    sample.retval = event.retval;
                    sample.latency = event.latency;
                    program.invoke(id, &mut state, &sample);
                    if state.stopped {
                        break;
                    }
                }
                if state.stopped {
                    break;
                }
            }
            if !state.stopped {
                tracer.resume_hit()?;
            }
            if let Some(child) = &mut child {
                if let Some(code) = (!tracer.targets().contains(&child.pid))
                    .then(|| tracer.exits.remove(&child.pid))
                    .flatten()
                {
                    child.status = Some(code);
                    if !args.follow_forks {
                        unsafe {
                            libc::kill(-child.pid, libc::SIGKILL);
                        }
                        break;
                    }
                }
            }
            if tracer.is_empty() || (!args.follow_forks && !tracer.targets().contains(&pid)) {
                break;
            }
            for (id, name, period, deadline) in &mut timers {
                if Instant::now() >= *deadline {
                    invoke(program, *id, &mut state, Some(pid), name, None, None);
                    *deadline = Instant::now() + *period;
                }
            }
            if args
                .window
                .is_some_and(|duration| window_start.elapsed() >= duration)
            {
                state.report.elapsed = window_start.elapsed().as_secs_f64();
                state.print_all();
                state.clear_all();
                window_start = Instant::now();
            }
            if args
                .live
                .is_some_and(|period| live_start.elapsed() >= period)
            {
                state.report.elapsed = start.elapsed().as_secs_f64();
                state.live_snapshot();
                live_start = Instant::now();
            }
            state.flush()?;
            if idle {
                unsafe {
                    libc::poll(std::ptr::null_mut(), 0, 1);
                }
            }
        }
        Ok(())
    })();
    let drain_result = (|| -> Result<()> {
        for stream in &streams {
            stream.event.disable()?;
        }
        if !state.stopped {
            drain(program, &mut state, &mut streams, &mut lost)?;
        }
        Ok(())
    })();
    kill_owned_descendants(child.as_ref(), args.follow_forks, tracer.targets());
    tracer.detach();
    if let Some(child) = &mut child {
        if child.status.is_none() {
            if let Some(code) = (!tracer.targets().contains(&child.pid))
                .then(|| tracer.exits.remove(&child.pid))
                .flatten()
            {
                child.status = Some(code);
                unsafe {
                    libc::kill(-child.pid, libc::SIGKILL);
                }
            }
        }
    }
    drop(tracer);
    state.stopped = false;
    invoke_kind(program, &mut state, Some(pid), false);
    finish_report(&mut state, args, window_start.elapsed())?;
    state.flush()?;
    result?;
    drain_result?;
    if lost != 0 {
        eprintln!("poortrace: lost {lost} perf samples");
    }
    Ok(child.as_ref().and_then(|child| child.status).unwrap_or(0))
}

fn configure_record(state: &mut State<'_>, args: &Args, program: &Program) -> Result<()> {
    if let Some(path) = &args.record {
        state.recorder = Some(poortrace::recording::Recorder::create(
            path,
            &program.source,
        )?);
    }
    Ok(())
}
fn run_replay(args: &Args, path: &std::path::Path) -> Result<i32> {
    let (header, mut events) = poortrace::recording::read(path)?;
    let alternate = args.expression.is_some() || args.script.is_some();
    if args.output_format == "speedscope-timeline" {
        if alternate {
            return Err("timeline export uses captured stacks; omit an alternate script".into());
        }
        let report = poortrace::recording::timeline_speedscope(&events)?;
        if let Some(path) = &args.output {
            std::fs::write(path, report).map_err(|e| e.to_string())?;
        } else {
            use std::io::Write;
            io::stdout()
                .write_all(report.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        return Ok(0);
    }
    if alternate {
        events = poortrace::recording::coalesce(events);
        let pid = events.first().map(|e| e.pid).unwrap_or(0);
        let tid = events.first().map(|e| e.tid).unwrap_or(0);
        let first = events.iter().map(|e| e.nsecs).min().unwrap_or(0);
        let last = events.iter().map(|e| e.nsecs).max().unwrap_or(first);
        let mut begin = poortrace::recording::Saved::lifecycle("BEGIN", pid, tid, first);
        let mut end = poortrace::recording::Saved::lifecycle("END", pid, tid, last);
        let mut middle = Vec::new();
        for event in events {
            match event.probe.as_str() {
                "BEGIN" => begin.helpers.extend(event.helpers),
                "END" => end.helpers.extend(event.helpers),
                _ => middle.push(event),
            }
        }
        if args.sort_events {
            middle.sort_by_key(|e| e.nsecs);
        }
        events = std::iter::once(begin)
            .chain(middle)
            .chain(std::iter::once(end))
            .collect();
    }
    let source = if let Some(expression) = &args.expression {
        expression.clone()
    } else if let Some(script) = &args.script {
        use std::io::Read;
        let mut source = String::new();
        if script.as_os_str() == "-" {
            io::stdin()
                .take(262145)
                .read_to_string(&mut source)
                .map_err(|e| e.to_string())?;
        } else {
            std::fs::File::open(script)
                .map_err(|e| e.to_string())?
                .take(262145)
                .read_to_string(&mut source)
                .map_err(|e| e.to_string())?;
        }
        source
    } else {
        header.source
    };
    let program = Program::compile(&source)?;
    if args.sort_events && !alternate {
        events.sort_by_key(|event| event.nsecs);
    }
    let mut state = program.state(io::stdout());
    configure_report(&mut state, args)?;
    state.max_entries = args.max_map_entries as usize;
    let mut first = u64::MAX;
    let mut last = 0;
    let mut exited = false;
    for saved in events {
        if alternate && exited && saved.probe != "END" {
            continue;
        }
        let actual_probe = saved.actual_probe();
        let destinations: Vec<usize> = if alternate {
            program
                .clauses
                .iter()
                .enumerate()
                .filter_map(|(id, clause)| {
                    clause
                        .probes
                        .iter()
                        .any(|(name, probe)| match probe {
                            Probe::Syscall { enter, number } => {
                                actual_probe.starts_with(if *enter {
                                    "syscall:enter:"
                                } else {
                                    "syscall:exit:"
                                }) && number.is_none_or(|number| number as u64 == saved.sysno)
                            }
                            _ => {
                                name == &actual_probe
                                    || poortrace::uprobe::matches(name, &actual_probe)
                            }
                        })
                        .then_some(id)
                })
                .collect()
        } else {
            if saved.clause >= program.clauses.len() {
                return Err("recording clause index is out of range".into());
            }
            vec![saved.clause]
        };
        if destinations.is_empty() {
            continue;
        }
        let comm = CString::new(saved.comm).map_err(|e| e.to_string())?;
        let probe = CString::new(if alternate { actual_probe } else { saved.probe })
            .map_err(|e| e.to_string())?;
        let syscall = CString::new(saved.syscall).map_err(|e| e.to_string())?;
        let branches: Vec<_> = saved
            .branches
            .iter()
            .map(|p| poortrace::perf::Branch {
                from: p[0],
                to: p[1],
            })
            .collect();
        let mut event = Event::new(&comm, &probe)
            .with_syscall(&syscall)
            .with_ustack(&saved.stack)
            .with_branches(&branches);
        event.pid = saved.pid;
        event.tid = saved.tid;
        event.cpu = saved.cpu;
        event.nsecs = saved.nsecs;
        event.ip = saved.ip;
        event.period = saved.period;
        event.addr = saved.addr;
        event.offcpu_ns = saved.offcpu_ns;
        event.preempt = saved.preempt;
        event.sysno = saved.sysno;
        event.retval = saved.retval;
        event.latency = saved.latency;
        event.args = saved.args;
        first = first.min(event.nsecs);
        last = last.max(event.nsecs);
        state.trace_fields = saved.trace_fields;
        state.js_snapshot = saved.raw.and_then(|raw| {
            (raw.architecture == std::env::consts::ARCH).then(|| {
                (
                    poortrace::perf::UserRegs {
                        ip: raw.registers[0],
                        sp: raw.registers[1],
                        fp: raw.registers[2],
                        lr: raw.registers[3],
                        runtime_g: raw.runtime_g,
                    },
                    raw.stack_bytes,
                )
            })
        });
        for id in destinations {
            state.stopped = if alternate { false } else { saved.stopped };
            if alternate {
                state.replay_captured_helpers(saved.helpers.clone());
            } else {
                state.replay_helpers(saved.helpers.clone());
            }
            program.invoke(id, &mut state, &event);
            state.flush()?;
            if alternate && state.stopped {
                exited = true;
                break;
            }
        }
    }
    finish_report(
        &mut state,
        args,
        Duration::from_nanos(last.saturating_sub(first)),
    )?;
    state.flush()?;
    Ok(0)
}

fn dispatch_waits(
    program: &Program,
    state: &mut State<'_>,
    waits: &mut poortrace::wait::Poller,
    targets: impl IntoIterator<Item = i32>,
) -> Result<()> {
    for snapshot in waits.poll(targets)? {
        if state.stopped {
            break;
        }
        let frames = if program.needs_ustack() || state.recorder.is_some() {
            let stack = (*snapshot.stack).clone();
            state.unwind_sample(&poortrace::perf::Sample {
                pid: snapshot.pid,
                tid: snapshot.tid,
                ip: snapshot.ip,
                regs: Some(snapshot.regs),
                stack,
                callchain: vec![snapshot.ip],
                ..Default::default()
            })
        } else {
            Vec::new()
        };
        let comm = task_comm(snapshot.pid as i32, snapshot.tid as i32);
        let probe = CString::new(snapshot.probe).map_err(|e| e.to_string())?;
        let syscall = CString::new(poortrace::syscall::name(snapshot.number)).unwrap();
        let mut event = Event::new(&comm, &probe)
            .with_ustack(&frames)
            .with_syscall(&syscall);
        event.pid = snapshot.pid as u64;
        event.tid = snapshot.tid as u64;
        event.ip = snapshot.ip;
        event.nsecs = monotonic_ns();
        event.period = snapshot.period;
        event.latency = snapshot.latency;
        event.args = snapshot.args;
        event.sysno = snapshot.number as u64;
        state.wait_reason = Some(snapshot.reason);
        if program.needs_jsstack() {
            state.js_snapshot = Some((snapshot.regs, (*snapshot.stack).clone()));
        }
        program.invoke(snapshot.clause, state, &event);
        state.js_snapshot = None;
        state.wait_reason = None;
    }
    Ok(())
}

fn kill_owned_descendants(child: Option<&Child>, follow: bool, _targets: BTreeSet<i32>) {
    if follow {
        if let Some(child) = child {
            child.kill_descendants();
        }
    }
}
fn track_owned_descendants(
    child: &mut Option<Child>,
    follow: bool,
    targets: BTreeSet<i32>,
) -> Result<()> {
    if !follow {
        return Ok(());
    }
    let Some(child) = child else {
        return Ok(());
    };
    child.descendants.retain(|pid, fd| {
        if targets.contains(pid) {
            return true;
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        (unsafe { libc::poll(&mut poll, 1, 0) }) <= 0 || poll.revents & libc::POLLIN == 0
    });
    for pid in targets {
        if pid == child.pid || child.descendants.contains_key(&pid) {
            continue;
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(format!("pidfd_open for owned descendant {pid}: {error}"));
        }
        child
            .descendants
            .insert(pid, unsafe { OwnedFd::from_raw_fd(fd as i32) });
    }
    Ok(())
}
