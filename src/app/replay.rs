//! Offline replay and captured timeline exports.

use super::{
    cli::Args,
    report::{configure_report, finish_report},
};
use poortrace::{Result, codegen::Program, language::Probe, runtime::Event};
use std::{ffi::CString, io, time::Duration};

pub(super) fn run_replay(args: &Args, path: &std::path::Path) -> Result<i32> {
    let mut recording = poortrace::recording::read_full(path)?;
    let mut provenance =
        recording
            .header
            .provenance
            .clone()
            .unwrap_or_else(|| poortrace::report::Provenance {
                backend: "legacy-recording".into(),
                capture_mode: recording
                    .header
                    .capture_mode
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                stack_mode: "unknown".into(),
                ..Default::default()
            });
    provenance.replay = true;
    provenance.lost_samples = (recording.header.version >= 3).then_some(0);
    provenance.discontinuities = (recording.header.version >= 3).then_some(0);
    for item in &recording.metadata {
        match item {
            poortrace::recording::Metadata::Lost { count, .. } => {
                provenance.lost_samples = provenance.lost_samples.map(|n| n.saturating_add(*count))
            }
            poortrace::recording::Metadata::Discontinuity { .. } => {
                provenance.discontinuities = provenance.discontinuities.map(|n| n.saturating_add(1))
            }
            _ => {}
        }
    }
    if let (Some(first), Some(last)) = (
        recording.events.iter().map(|e| e.nsecs).min(),
        recording.events.iter().map(|e| e.nsecs).max(),
    ) {
        provenance.elapsed_seconds = last.saturating_sub(first) as f64 / 1e9;
    }
    if args.output_format == "speedscope-scheduler" {
        if args.expression.is_some() || args.script.is_some() {
            return Err("scheduler export uses recorded switches; omit alternate script".into());
        }
        let report = poortrace::report::annotate_profile(
            poortrace::recording::scheduler_speedscope(&recording)?,
            &args.output_format,
            &provenance,
        )?;
        super::report::write_metadata(args, &provenance)?;
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
    let captured_status = recording.metadata.iter().find_map(|item| {
        if let poortrace::recording::Metadata::Exit { status, .. } = item {
            Some(*status)
        } else {
            None
        }
    });
    let mut replayed_output = Vec::new();
    if args.replay_output {
        for item in &recording.metadata {
            if let poortrace::recording::Metadata::Output {
                nsecs,
                stream,
                bytes,
                ..
            } = item
            {
                replayed_output.push((*nsecs, stream.clone(), bytes.clone()));
            }
        }
        replayed_output.sort_by_key(|row| row.0);
    }
    let mut events = if args.replay_raw {
        poortrace::recording::observations_from_raw(&recording)?
    } else {
        std::mem::take(&mut recording.events)
    };
    let header = recording.header;
    if header.endianness.as_ref().is_some_and(|value| {
        value
            != if cfg!(target_endian = "little") {
                "little"
            } else {
                "big"
            }
    }) {
        return Err("recording memory byte order differs from this host".into());
    }

    let alternate = args.replay_raw || args.expression.is_some() || args.script.is_some();
    if args.output_format == "speedscope-timeline" {
        if args.expression.is_some() || args.script.is_some() {
            return Err("timeline export uses captured stacks; omit an alternate script".into());
        }
        let report = poortrace::report::annotate_profile(
            poortrace::recording::timeline_speedscope(&events)?,
            &args.output_format,
            &provenance,
        )?;
        super::report::write_metadata(args, &provenance)?;
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
        events = poortrace::recording::coalesce(events)?;
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
    configure_report(&mut state, args, &program, "replay")?;
    state.report.provenance = Some(provenance);
    state.max_entries = args.max_map_entries as usize;
    let mut first = u64::MAX;
    let mut last = 0;
    let mut exited = false;
    let mut replayed_output = replayed_output.into_iter().peekable();
    for saved in events {
        while replayed_output
            .peek()
            .is_some_and(|item| item.0 <= saved.nsecs)
        {
            let (_, stream, bytes) = replayed_output.next().unwrap();
            write_replayed_output(&stream, &bytes)?;
        }
        if alternate && exited && saved.probe != "END" {
            continue;
        }
        let actual_probe = saved.actual_probe();
        if super::perf::watch_address(&actual_probe)
            .is_some_and(|address| state.unwatched.contains(&address))
        {
            continue;
        }

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
                            Probe::Uprobe {
                                path,
                                function,
                                ret,
                            } => {
                                if let Ok(Probe::Uprobe {
                                    path: actual_path,
                                    function: actual_function,
                                    ret: actual_ret,
                                }) = Probe::parse(&actual_probe)
                                {
                                    *ret == actual_ret
                                        && (path.is_empty()
                                            || poortrace::uprobe::matches(path, &actual_path)
                                            || !path.contains('/')
                                                && std::path::Path::new(&actual_path)
                                                    .file_name()
                                                    .and_then(|p| p.to_str())
                                                    .is_some_and(|base| {
                                                        poortrace::uprobe::matches(path, base)
                                                    }))
                                        && poortrace::uprobe::matches_function(
                                            function,
                                            &actual_function,
                                        )
                                } else {
                                    false
                                }
                            }
                            _ => {
                                let actual =
                                    poortrace::language::canonical_probe_name(&actual_probe);
                                name == actual.as_ref() || poortrace::uprobe::matches(name, &actual)
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
        state.replay_memory = saved.memory;
        state.kernel_frames = saved.kernel_stack;
        state.js_snapshot = saved.raw.and_then(|raw| {
            (raw.architecture == std::env::consts::ARCH).then(|| {
                (
                    poortrace::perf::UserRegs {
                        ip: raw.registers[0],
                        sp: raw.registers[1],
                        fp: raw.registers[2],
                        lr: raw.registers[3],
                        runtime_g: raw.runtime_g,
                        extra: raw.extra,
                        valid: raw.valid,
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
    for (_, stream, bytes) in replayed_output {
        write_replayed_output(&stream, &bytes)?;
    }
    finish_report(
        &mut state,
        args,
        Duration::from_nanos(last.saturating_sub(first)),
    )?;
    state.flush()?;
    Ok(if state.exit_set {
        state.exit_code
    } else if args.replay_exit_status {
        captured_status.unwrap_or(0)
    } else {
        0
    })
}
fn write_replayed_output(stream: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    match stream {
        "stdout" => io::stdout().write_all(bytes),
        "stderr" => io::stderr().write_all(bytes),
        _ => return Err("unknown recorded output stream".into()),
    }
    .map_err(|e| e.to_string())
}
