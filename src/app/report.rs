//! Shared runtime configuration, recording setup, and final reports.

use super::cli::Args;
use poortrace::{Result, codegen::Program, runtime::State};
use std::time::Duration;

pub(super) fn provenance(
    args: &Args,
    probes: Vec<String>,
    backend: &str,
) -> poortrace::report::Provenance {
    poortrace::report::Provenance {
        backend: backend.into(),
        capture_mode: if args.reliable {
            "stopped-target-wall-clock"
        } else {
            "mixed-observations"
        }
        .into(),
        stack_mode: args.stack_mode.clone(),
        probes,
        lost_samples: Some(0),
        discontinuities: Some(0),
        ..Default::default()
    }
}

pub(super) fn write_metadata(args: &Args, metadata: &poortrace::report::Provenance) -> Result<()> {
    if let Some(path) = &args.report_metadata {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(metadata).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub(super) fn configure_report(
    state: &mut State<'_>,
    args: &Args,
    program: &Program,
    backend: &str,
) -> Result<()> {
    state.allow_unsafe = args.allow_unsafe;
    if let Some(pid) = args.pid {
        state.register_target_identity(pid as u32)?;
    }
    if args.script_args.len() > 256 {
        return Err("--script-arg exceeds 256 named options".into());
    }
    for argument in &args.script_args {
        if argument.len() > 4096 {
            return Err("script argument exceeds 4096 bytes".into());
        }
        let (name, value) = argument
            .split_once('=')
            .ok_or("--script-arg requires NAME=VALUE")?;
        if name.is_empty() {
            return Err("script argument name is empty".into());
        }
        state.script_args.insert(name.into(), value.into());
    }
    state.stack_mode = if args.stack_mode == "dwarf" || program.needs_dwarf() {
        poortrace::runtime::StackMode::Dwarf
    } else {
        poortrace::runtime::StackMode::FramePointer
    };
    state.capture_requests = args.capture_memory.clone();
    if let Some(path) = &args.btf {
        state.configure_btf(path.clone());
    }
    if let Some(path) = &args.managed_snapshot {
        state.managed.configure(path.clone())?;
    }
    state.managed.set_max_age(args.managed_max_age)?;
    let mut context = provenance(
        args,
        program
            .clauses
            .iter()
            .flat_map(|c| c.probes.iter().map(|(name, _)| name.clone()))
            .collect(),
        backend,
    );
    if program.needs_dwarf() {
        context.stack_mode = "dwarf".into();
    }
    for (name, probe) in program.clauses.iter().flat_map(|c| &c.probes) {
        use poortrace::language::Probe;
        let meaning = match probe {
            Probe::Begin | Probe::End => "lifecycle",
            Probe::Interval(_) => "wall-clock-timer",
            Probe::Wait(_) | Probe::Wakeup(_) => "polling-observation",
            _ if args.reliable => "stopped-target-wall-clock",
            Probe::Syscall { .. } => "ptrace-event-stop",
            Probe::Uprobe { .. } if args.uprobe_backend == "ptrace" => "ptrace-event-stop",
            Probe::OffCpu => "completed-switch-pair",
            Probe::Perf {
                kind: 1,
                config: 0 | 1,
                ..
            } => "cpu-time-sample",
            _ => "asynchronous-perf-event",
        };
        context
            .observation_semantics
            .insert(name.clone(), meaning.into());
    }
    if !args.reliable {
        let modes: std::collections::BTreeSet<_> = context
            .observation_semantics
            .values()
            .filter(|mode| mode.as_str() != "lifecycle")
            .cloned()
            .collect();
        context.capture_mode = match modes.len() {
            0 => "lifecycle".into(),
            1 => modes.into_iter().next().unwrap(),
            _ => "mixed-observations".into(),
        };
    }
    state.report = poortrace::report::Options {
        format: args.output_format.clone(),
        provenance: Some(context),
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
pub(super) fn finish_report(state: &mut State<'_>, args: &Args, elapsed: Duration) -> Result<()> {
    if let Some(recorder) = &mut state.recorder {
        recorder.flush()?;
    }
    state.report.elapsed = elapsed.as_secs_f64();
    if let Some(metadata) = &mut state.report.provenance {
        metadata.elapsed_seconds = state.report.elapsed;
        write_metadata(args, metadata)?;
    }
    if let Some(path) = &args.output {
        let report = state.render_report()?;
        std::fs::write(path, report).map_err(|e| format!("{}: {e}", path.display()))?;
    } else if !args.no_print_maps {
        state.print_all();
    }
    Ok(())
}
pub(super) fn configure_record(
    state: &mut State<'_>,
    args: &Args,
    program: &Program,
) -> Result<()> {
    if let Some(path) = &args.record {
        state.recorder = Some(poortrace::recording::Recorder::create_with_provenance(
            path,
            &program.source,
            state.report.provenance.as_ref(),
        )?);
    }
    Ok(())
}
