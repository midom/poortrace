//! Perf stream attachment, draining, and asynchronous tracing loop.

use super::{
    cli::Args,
    events::{dispatch_waits, invoke, invoke_kind, monotonic_ns, task_comm},
    process::{Child, INTERRUPTED, alive, finalize_recorded_child, install_signals, threads},
    report::{configure_record, configure_report, finish_report},
};
use poortrace::perf::{Capture, PerfEvent, Record};
use poortrace::{Result, codegen::Program, language::Probe, runtime::State};
use std::{
    collections::BTreeSet,
    ffi::CString,
    io,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(super) fn run(args: Args, program: Program) -> Result<i32> {
    let capture = super::session::capture(&args, &program, false);
    install_signals()?;
    let command = args
        .shell_command
        .as_ref()
        .map(|s| vec!["/bin/sh".into(), "-c".into(), s.clone()])
        .unwrap_or_else(|| args.command.clone());
    let mut child = if command.is_empty() {
        None
    } else {
        Some(Child::spawn(
            &command,
            args.follow_forks,
            args.record_output,
        )?)
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
    configure_report(&mut state, &args, &program, "perf")?;
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
    let coverage = if args.system_wide && state.recorder.is_some() {
        let clause=program.clauses.iter().position(|clause|clause.probes.iter().any(|(_,p)|matches!(p,Probe::Tracepoint{category,event}if category=="sched"&&event=="sched_switch")));
        clause.map(|clause| {
            let generations: Vec<_> = streams
                .iter()
                .filter(|s| s.clause == clause && s.name == "tracepoint:sched:sched_switch")
                .map(|s| (s.tid, s.generation))
                .collect();
            (clause, generations, monotonic_ns())
        })
    } else {
        None
    };
    let mut coverage_end = 0;
    let start = Instant::now();
    let mut timers = super::session::intervals(&program, start);
    let mut lost = 0u64;
    let mut reports = super::session::Reports::new();
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
            if let Some(child) = &mut child {
                child.poll_output(state.recorder.as_mut())?;
            }
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
            reports.refresh(&mut state, &args);
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
        coverage_end = monotonic_ns();
        for stream in &streams {
            stream.event.disable()?;
        }
        if !state.stopped {
            drain(&program, &mut state, &mut streams, &mut lost)?;
        }
        Ok(())
    })();
    // END handlers still run after exit(), target exit, or an interrupt.
    if let Some((clause, generations, start)) = coverage {
        let cpus = poortrace::kernel::online_cpus().ok();
        let covered: BTreeSet<_> = generations.iter().map(|(cpu, _)| *cpu).collect();
        let unchanged = generations.iter().all(|(cpu, generation)| {
            streams.iter().any(|s| {
                s.tid == *cpu
                    && s.clause == clause
                    && s.name == "tracepoint:sched:sched_switch"
                    && s.generation == *generation
                    && !s.hup
                    && !s.discontinuous
            })
        });
        let complete = result.is_ok()
            && !state.stopped
            && lost == 0
            && unchanged
            && cpus.is_some_and(|cpus| cpus.into_iter().collect::<BTreeSet<_>>() == covered)
            && coverage_end >= start;
        if let Some(recorder) = &mut state.recorder {
            recorder.metadata(&poortrace::recording::Metadata::SchedulerCoverage {
                cpus: covered.into_iter().map(|c| c as u32).collect(),
                start,
                end: coverage_end.max(start),
                complete,
                clause: Some(clause),
            })?;
        }
    }
    let child_record_result = finalize_recorded_child(&mut state, child.as_mut());
    state.stopped = false;
    invoke_kind(&program, &mut state, target, false);
    finish_report(&mut state, &args, reports.window_elapsed())?;
    state.flush()?;
    if lost != 0 {
        eprintln!(
            "poortrace: lost {lost} perf samples; increase --mmap-pages or reduce sample frequency"
        );
    }
    result?;
    child_record_result?;
    Ok(child
        .as_ref()
        .filter(|c| !c.terminated_by_tracer)
        .and_then(|c| c.status)
        .unwrap_or(0))
}
pub(super) struct Stream {
    clause: usize,
    name: String,
    pub(super) tid: i32,
    pub(super) event: PerfEvent,
    pub(super) hup: bool,
    comm: CString,
    pub(super) on_exec: bool,
    switched_out: Option<(u64, bool)>,
    generation: u64,
    discontinuous: bool,
}
pub(super) fn attach(
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
                            generation: monotonic_ns(),
                            discontinuous: false,
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
pub(super) fn drain(
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
        let records = stream.event.drain()?;
        let mut raw_records = stream.event.take_raw_records().into_iter();
        for record in records {
            let cpu = if stream.event.system_wide() {
                stream.tid as u32
            } else {
                u32::MAX
            };
            if let Some(bytes) = raw_records.next() {
                let (pid, tid, cpu, nsecs) = match &record {
                    Record::Sample(s) => (s.pid as u64, s.tid as u64, s.cpu, s.time),
                    Record::Switch {
                        pid,
                        tid,
                        cpu,
                        time,
                        ..
                    } => (*pid as u64, *tid as u64, *cpu, *time),
                    Record::Comm { pid, tid, .. } => {
                        (*pid as u64, *tid as u64, cpu, monotonic_ns())
                    }
                    _ => (0, 0, cpu, monotonic_ns()),
                };
                if let Some(recorder) = &mut state.recorder {
                    recorder.metadata(&poortrace::recording::Metadata::RawPerf{pid,tid,cpu,nsecs,probe:stream.name.clone(),bytes,capture:Some(serde_json::json!({"architecture":std::env::consts::ARCH,"endianness":if cfg!(target_endian="little"){"little"}else{"big"},"layout":stream.event.capture(),"trace_format":stream.event.trace_format(),"clause":stream.clause}))})?;
                }
            }
            if let Record::Lost(count) = &record {
                if let Some(metadata) = &mut state.report.provenance {
                    metadata.lost_samples = metadata.lost_samples.map(|n| n.saturating_add(*count));
                }
                if let Some(recorder) = &mut state.recorder {
                    recorder.metadata(&poortrace::recording::Metadata::Lost {
                        cpu,
                        nsecs: monotonic_ns(),
                        count: *count,
                    })?;
                }
            }
            if let Record::Throttle { time, throttled } = &record {
                if let Some(metadata) = &mut state.report.provenance {
                    metadata.discontinuities =
                        metadata.discontinuities.map(|n| n.saturating_add(1));
                }
                stream.discontinuous = true;
                stream.switched_out = None;
                if let Some(recorder) = &mut state.recorder {
                    recorder.metadata(&poortrace::recording::Metadata::Discontinuity {
                        cpu,
                        nsecs: *time,
                        reason: if *throttled {
                            "perf throttled"
                        } else {
                            "perf unthrottled"
                        }
                        .into(),
                    })?;
                }
            }
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
