//! Explicit synchronous snapshots: no perf descriptors or asynchronous handlers.

use super::events::dispatch_function_events;
use super::{
    cli::Args,
    events::{invoke, invoke_kind, monotonic_ns},
    process::{
        Child, INTERRUPTED, command_for, finalize_recorded_child, install_signals,
        kill_owned_descendants, threads, track_owned_descendants,
    },
    report::{configure_report, finish_report},
};
use poortrace::{Result, codegen::Program, language::Probe};
use std::{
    io,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn profile_period(probe: &Probe) -> Option<Duration> {
    match probe {
        Probe::Perf {
            kind: 1,
            config: 0,
            period,
            frequency: true,
        } => Some(Duration::from_nanos(1_000_000_000 / period)),
        _ => None,
    }
}

pub(super) fn run(args: &Args, program: &Program) -> Result<i32> {
    if args.uprobe_backend != "ptrace" || program.needs_kstack() {
        return Err("--reliable requires ptrace and supports user stacks only".into());
    }
    for clause in &program.clauses {
        for (_, probe) in &clause.probes {
            if !matches!(
                probe,
                Probe::Begin
                    | Probe::End
                    | Probe::Interval(_)
                    | Probe::Syscall { .. }
                    | Probe::Uprobe { .. }
            ) && profile_period(probe).is_none()
            {
                return Err("--reliable supports BEGIN/END, interval, profile:hz, syscall and ptrace function/USDT probes; asynchronous perf and wait/wakeup probes are unsupported".into());
            }
        }
    }
    let command = command_for(args);
    if command.is_empty() && args.pid.is_none() {
        return Err("--reliable requires -p PID or a launched command".into());
    }
    install_signals()?;
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(
            &command,
            args.follow_forks,
            args.record_output,
        )?)
    };
    let pid = child.as_ref().map(|c| c.pid).or(args.pid).unwrap();
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
    let mut tracer = poortrace::functions::Tracer::seize_group(
        pid,
        threads(pid)?,
        &specs,
        child.is_some(),
        args.attach_descendants,
        &args.shared_mm_pids,
    )?;
    tracer.trace_syscalls(program.has_syscalls());
    tracer.track_loads(args.track_loads);
    tracer.follow_forks(args.follow_forks);
    for specification in &args.stack_range {
        let parts: Vec<_> = specification.split(':').collect();
        if parts.len() != 3 {
            return Err("stack range needs TID:LOW:HIGH".into());
        }
        let integer = |value: &str| -> Result<u64> {
            value
                .strip_prefix("0x")
                .map(|v| u64::from_str_radix(v, 16))
                .unwrap_or_else(|| value.parse())
                .map_err(|e| e.to_string())
        };
        tracer.register_stack_range(
            parts[0].parse::<i32>().map_err(|e| e.to_string())?,
            integer(parts[1])?,
            integer(parts[2])?,
        )?;
    }
    let stdout = io::stdout();
    let mut state = program.state(io::BufWriter::new(stdout.lock()));
    configure_report(&mut state, args)?;
    state.max_entries = args.max_map_entries as usize;
    if let Some(path) = &args.record {
        state.recorder = Some(poortrace::recording::Recorder::create_with_mode(
            path,
            &program.source,
            Some("stopped-target-wall-clock"),
        )?);
    }
    if !args.quiet {
        eprintln!(
            "poortrace: reliable mode stops all tracked threads; profile samples are wall-clock snapshots, not CPU-time samples"
        );
    }
    let start = Instant::now();
    let mut window_start = start;
    let mut live_start = start;
    let mut timers: Vec<_> = program
        .clauses
        .iter()
        .enumerate()
        .flat_map(|(id, clause)| {
            clause.probes.iter().filter_map(move |(name, probe)| {
                let (period, all_threads) = if let Probe::Interval(period) = probe {
                    (*period, false)
                } else {
                    (profile_period(probe)?, true)
                };
                Some((
                    id,
                    name.clone(),
                    period,
                    Instant::now() + period,
                    all_threads,
                ))
            })
        })
        .collect();
    let result = (|| -> Result<()> {
        tracer.pause_for_snapshot()?;
        state.target_paused = true;
        invoke_kind(program, &mut state, Some(pid), true);
        state.flush()?;
        if !state.stopped {
            if let Some(child) = &mut child {
                child.start()?;
            }
        }
        while !state.stopped
            && !INTERRUPTED.load(Ordering::Relaxed)
            && !args.duration.is_some_and(|d| start.elapsed() >= d)
        {
            if let Some(child) = &mut child {
                child.poll_output(state.recorder.as_mut())?;
            }
            let events = tracer.poll()?;
            track_owned_descendants(&mut child, args.follow_forks, tracer.targets())?;
            if !events.is_empty() {
                tracer.pause_for_snapshot()?;
                state.target_paused = true;
                dispatch_function_events(
                    program,
                    &mut state,
                    events,
                    &bindings,
                    pid,
                    args.stack_bytes,
                )?;
            }
            if !state.stopped {
                tracer.resume_hit()?;
            }
            if let Some(child) = &mut child {
                if !tracer.targets().contains(&child.pid) {
                    if let Some(status) = tracer.exits.remove(&child.pid) {
                        child.status = Some(status);
                    }
                }
            }
            if tracer.is_empty() || (!args.follow_forks && !tracer.targets().contains(&pid)) {
                break;
            }
            if !state.stopped && timers.iter().any(|timer| Instant::now() >= timer.3) {
                tracer.pause_for_snapshot()?;
                state.target_paused = true;
                let registers = tracer.snapshot_registers()?;
                for (id, name, period, deadline, all_threads) in &mut timers {
                    if Instant::now() < *deadline {
                        continue;
                    }
                    for &(tid, regs) in &registers {
                        if !*all_threads && tid != pid {
                            continue;
                        }
                        let target = poortrace::syscall::tgid(tid).unwrap_or(tid);
                        let stack = if program.needs_ustack()
                            || program.needs_jsstack()
                            || state.recorder.is_some()
                        {
                            poortrace::memory::read_stack(
                                tid as u32,
                                regs.sp,
                                args.stack_bytes as usize,
                            )?
                        } else {
                            Vec::new()
                        };
                        let sample = poortrace::perf::Sample {
                            pid: target as u32,
                            tid: tid as u32,
                            ip: regs.ip,
                            cpu: std::fs::read_to_string(format!("/proc/{tid}/stat"))
                                .ok()
                                .and_then(|stat| {
                                    stat.rsplit_once(')').and_then(|(_, tail)| {
                                        tail.split_whitespace().nth(36)?.parse().ok()
                                    })
                                })
                                .unwrap_or(u32::MAX),
                            time: monotonic_ns(),
                            period: period.as_nanos() as u64,
                            regs: Some(regs),
                            stack,
                            callchain: vec![regs.ip],
                            ..Default::default()
                        };
                        invoke(
                            program,
                            *id,
                            &mut state,
                            Some(target),
                            name,
                            Some(&sample),
                            None,
                        );
                        if state.stopped {
                            break;
                        }
                    }
                    *deadline = Instant::now() + *period;
                    if state.stopped {
                        break;
                    }
                }
            }
            if !state.stopped {
                tracer.release_snapshot()?;
                state.target_paused = false;
            }
            if args.window.is_some_and(|d| window_start.elapsed() >= d) {
                state.report.elapsed = window_start.elapsed().as_secs_f64();
                state.print_all();
                state.clear_all();
                window_start = Instant::now();
            }
            if args.live.is_some_and(|d| live_start.elapsed() >= d) {
                state.report.elapsed = start.elapsed().as_secs_f64();
                state.live_snapshot();
                live_start = Instant::now();
            }
            state.flush()?;
            unsafe {
                libc::poll(std::ptr::null_mut(), 0, 1);
            }
        }
        Ok(())
    })();
    // END also runs with a verified pause. Detach always precedes owned cleanup.
    let end_result = tracer.pause_for_snapshot();
    if end_result.is_ok() {
        state.stopped = false;
        state.target_paused = true;
        invoke_kind(program, &mut state, Some(pid), false);
    }
    tracer.detach();
    state.target_paused = false;
    if let Some(child) = &child {
        if child.status.is_some() && !args.follow_forks {
            unsafe {
                libc::kill(-child.pid, libc::SIGKILL);
            }
        }
    }
    kill_owned_descendants(child.as_ref(), args.follow_forks, tracer.targets());
    drop(tracer);
    let child_result = finalize_recorded_child(&mut state, child.as_mut());
    finish_report(&mut state, args, window_start.elapsed())?;
    state.flush()?;
    result?;
    end_result?;
    child_result?;
    Ok(child
        .as_ref()
        .filter(|c| !c.terminated_by_tracer)
        .and_then(|c| c.status)
        .unwrap_or(0))
}
