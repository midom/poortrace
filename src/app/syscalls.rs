//! Syscall and lifecycle tracing with optional perf streams.

use super::perf::{attach, drain};
use super::{
    cli::Args,
    events::{dispatch_waits, invoke, invoke_kind, monotonic_ns, task_comm},
    process::{
        Child, INTERRUPTED, command_for, finalize_recorded_child, install_signals,
        kill_owned_descendants, threads, track_owned_descendants,
    },
    report::{configure_record, configure_report, finish_report},
};
use poortrace::{Result, codegen::Program, language::Probe, perf::Capture, runtime::Event};
use std::{
    ffi::CString,
    io,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(super) fn run_syscalls(args: &Args, program: &Program) -> Result<i32> {
    install_signals()?;
    let command = command_for(args);
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(
            &command,
            args.follow_forks,
            args.record_output,
        )?)
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
        kernel: args.include_kernel || program.needs_kstack(),
        kernel_callchain: program.needs_kstack() || args.include_kernel && args.record.is_some(),
        record_raw: args.record_raw,
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
    if args.attach_descendants || !args.shared_mm_pids.is_empty() {
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
            if let Some(child) = &mut child {
                child.poll_output(state.recorder.as_mut())?;
            }
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
                            state.kernel_frames.clear();
                            state.capture_event_memory(&sample);
                            if !state.stopped {
                                program.invoke(id, &mut state, &sample);
                            }
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
    let child_record_result = finalize_recorded_child(&mut state, child.as_mut());
    state.stopped = false;
    invoke_kind(program, &mut state, Some(pid), false);
    finish_report(&mut state, args, window_start.elapsed())?;
    state.flush()?;
    result?;
    child_record_result?;
    drain_result?;
    if lost != 0 {
        eprintln!("poortrace: lost {lost} perf samples");
    }
    Ok(child
        .as_ref()
        .filter(|child| !child.terminated_by_tracer)
        .and_then(|child| child.status)
        .unwrap_or(0))
}
