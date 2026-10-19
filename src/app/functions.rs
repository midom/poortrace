//! Ptrace function tracing with optional perf streams.

use super::{
    cli::Args,
    events::{dispatch_waits, invoke, invoke_kind},
    process::{
        Child, INTERRUPTED, command_for, finalize_recorded_child, install_signals,
        kill_owned_descendants, threads, track_owned_descendants,
    },
    report::{configure_record, configure_report, finish_report},
};
use super::{
    events::{capture_function_events, dispatch_captured_function_events},
    perf::{attach, drain},
};
use poortrace::{Result, codegen::Program, language::Probe};
use std::{
    io,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(super) fn run_functions(args: &Args, program: &Program) -> Result<i32> {
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
    let mut tracer = poortrace::functions::Tracer::seize_group_with_limits(
        pid,
        threads(pid)?,
        &specs,
        child.is_some(),
        args.attach_descendants,
        &args.shared_mm_pids,
        poortrace::functions::Limits {
            probes: args.max_probes,
            breakpoints: args.max_breakpoints,
        },
    )?;
    for specification in &args.stack_range {
        let components: Vec<_> = specification.split(':').collect();
        if components.len() != 3 {
            return Err("stack range needs TID:LOW:HIGH".into());
        }
        let tid = components[0].parse::<i32>().map_err(|e| e.to_string())?;
        let parse = |s: &str| -> Result<u64> {
            if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
            } else {
                s.parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())
            }
        };
        tracer.register_stack_range(tid, parse(components[1])?, parse(components[2])?)?;
    }
    tracer.trace_syscalls(program.has_syscalls());
    tracer.track_loads(args.track_loads);
    tracer.follow_forks(args.follow_forks);
    let capture = super::session::capture(args, program, true);
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
                    (capture, &std::collections::BTreeSet::new()),
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
        (capture, &std::collections::BTreeSet::new()),
    )?;
    let mut lost = 0;
    let has_perf_streams = program
        .clauses
        .iter()
        .flat_map(|clause| &clause.probes)
        .any(|(_, probe)| probe.is_perf() && !matches!(probe, Probe::Uprobe { .. }));
    let mut refresh = Instant::now();
    let stdout = io::stdout();
    let mut state = program.state(io::BufWriter::new(stdout.lock()));
    configure_report(&mut state, args, program, "functions")?;
    configure_record(&mut state, args, program)?;
    state.child_pid = child.as_ref().map(|child| child.pid as u64);
    if let Some(pid) = state.child_pid {
        state.register_target_identity(pid as u32)?;
    }
    state.max_entries = args.max_map_entries as usize;
    for target in tracer.targets() {
        state.register_target_identity(target as u32)?;
    }
    invoke_kind(program, &mut state, Some(pid), true);
    state.flush()?;
    super::perf::apply_unwatched(&mut streams, &state.unwatched)?;
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
    let mut reports = super::session::Reports::new();
    let mut waits =
        poortrace::wait::Poller::new(program, args.stack_bytes as usize, args.record.is_some());
    let mut timers = super::session::intervals(program, start);
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
            if waits.delay().is_zero() {
                dispatch_waits(program, &mut state, &mut waits, tracer.targets())?;
            }
            drain(program, &mut state, &mut streams, &mut lost)?;
            if state.stopped {
                break;
            }
            if has_perf_streams && refresh.elapsed() >= Duration::from_millis(10) {
                for target in tracer.targets() {
                    if !state.has_target_identity(target as u32) {
                        state.register_target_identity(target as u32)?;
                    }
                    attach(
                        program,
                        target,
                        args.mmap_pages,
                        &mut streams,
                        true,
                        false,
                        (capture, &state.unwatched),
                    )?;
                }
                refresh = Instant::now();
            }
            let events = tracer.poll()?;
            if args.follow_forks {
                track_owned_descendants(&mut child, true, tracer.targets())?;
            }
            for tid in tracer.take_discovered() {
                attach(
                    program,
                    poortrace::syscall::tgid(tid).unwrap_or(tid),
                    args.mmap_pages,
                    &mut streams,
                    true,
                    false,
                    (capture, &state.unwatched),
                )?;
            }
            let idle = events.is_empty();
            let captured = capture_function_events(
                program,
                &mut state,
                events,
                &bindings,
                pid,
                args.stack_bytes,
            )?;
            let resumed = !state.stopped
                && state.recorder.is_none()
                && state.capture_requests.is_empty()
                && captured.iter().all(|event| event.can_run_resumed(program));
            if resumed {
                tracer.resume_hit()?;
                tracer.release_for_processing()?;
            }
            dispatch_captured_function_events(program, &mut state, captured)?;
            if !state.stopped && !resumed {
                tracer.resume_hit()?;
                tracer.release_for_processing()?;
            }
            if let Some(child) = &mut child {
                if let Some(code) = (!tracer.has_target(child.pid))
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
            if tracer.is_empty() || (!args.follow_forks && !tracer.has_target(pid)) {
                break;
            }
            for (id, name, period, deadline) in &mut timers {
                if Instant::now() >= *deadline {
                    invoke(program, *id, &mut state, Some(pid), name, None, None);
                    *deadline = Instant::now() + *period;
                }
            }
            if !state.stopped {
                tracer.release_snapshot()?;
            }
            reports.refresh(&mut state, args);
            state.flush()?;
            if idle && !state.stopped {
                tracer.wait_ready(Duration::from_millis(1))?;
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
            if let Some(code) = (!tracer.has_target(child.pid))
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
    finish_report(&mut state, args, reports.window_elapsed())?;
    state.flush()?;
    result?;
    child_record_result?;
    drain_result?;
    if lost != 0 {
        eprintln!("poortrace: lost {lost} perf samples");
    }
    if state.exit_set {
        return Ok(state.exit_code);
    }
    Ok(child
        .as_ref()
        .filter(|child| !child.terminated_by_tracer)
        .and_then(|child| child.status)
        .unwrap_or(0))
}
