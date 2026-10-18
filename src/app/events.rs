//! Event construction and handler dispatch shared by tracing backends.

use poortrace::{
    Result,
    codegen::Program,
    language::Probe,
    runtime::{Event, State},
};
use std::ffi::CString;

pub(super) fn monotonic_ns() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t);
    }
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}
pub(super) fn task_comm(pid: i32, tid: i32) -> CString {
    let comm = std::fs::read(format!("/proc/{pid}/task/{tid}/comm"))
        .unwrap_or_else(|_| b"<exited>".to_vec());
    CString::new(
        comm.into_iter()
            .filter(|b| *b != 0 && *b != b'\n')
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
pub(super) fn invoke(
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
    let ptrace_observation = state.target_paused
        || name.starts_with("syscall:")
            && state.report.provenance.as_ref().is_some_and(|p| {
                matches!(p.backend.as_str(), "syscalls" | "functions" | "reliable")
            });
    if sample.is_some() && ptrace_observation && !state.has_target_identity(pid as u32) {
        if let Err(error) = state.register_target_identity(pid as u32) {
            state.error = Some(error);
            state.stopped = true;
            return;
        }
    }

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
    state.register_snapshot = sample.and_then(|sample| sample.kernel_regs.or(sample.regs));
    state.trace_fields = sample
        .and_then(|sample| sample.trace.as_ref())
        .map(|trace| trace.fields.clone())
        .unwrap_or_default();
    state.js_snapshot =
        if program.needs_jsstack() || program.needs_registers() || state.recorder.is_some() {
            sample.and_then(|sample| sample.regs.map(|regs| (regs, sample.stack.clone())))
        } else {
            None
        };
    state.kernel_frames = sample
        .map(|s| s.kernel_callchain.clone())
        .unwrap_or_default();
    if sample.is_some() {
        state.capture_event_memory(&event);
    } else {
        state.captured_memory.clear();
    }
    if !state.stopped {
        program.invoke(clause, state, &event);
    }
    state.js_snapshot = None;
    state.register_snapshot = None;
    state.trace_fields.clear();
}
pub(super) fn invoke_kind(
    program: &Program,
    state: &mut State<'_>,
    target: Option<i32>,
    begin: bool,
) {
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
pub(super) fn dispatch_function_events(
    program: &Program,
    state: &mut State<'_>,
    events: Vec<poortrace::functions::Event>,
    bindings: &[(usize, String)],
    pid: i32,
    stack_bytes: u32,
) -> Result<()> {
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
        let frames = if program.needs_ustack() || state.recorder.is_some() {
            let stack = poortrace::memory::read_stack(
                event.tid as u32,
                event.regs.sp,
                stack_bytes as usize,
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
            if !state.has_target_identity(event_pid as u32) {
                state.register_target_identity(event_pid as u32)?;
            }
            sample.tid = event.tid as u64;
            sample.nsecs = event_nsecs;
            sample.ip = event.regs.ip;
            sample.args = event.args;
            sample.retval = event.retval;
            sample.latency = event.latency;
            state.kernel_frames.clear();
            state.js_snapshot = Some((event.regs, Vec::new()));
            state.register_snapshot = Some(event.regs);
            state.capture_event_memory(&sample);
            if !state.stopped {
                program.invoke(id, state, &sample);
            }
            state.js_snapshot = None;
            state.register_snapshot = None;
            if state.stopped {
                break;
            }
        }
        if state.stopped {
            break;
        }
    }

    Ok(())
}
pub(super) fn dispatch_waits(
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
        state.kernel_frames.clear();
        state.capture_event_memory(&event);
        if !state.stopped {
            program.invoke(snapshot.clause, state, &event);
        }
        state.js_snapshot = None;
        state.wait_reason = None;
    }
    Ok(())
}
