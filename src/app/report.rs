//! Shared runtime configuration, recording setup, and final reports.

use super::cli::Args;
use poortrace::{Result, codegen::Program, runtime::State};
use std::time::Duration;

pub(super) fn configure_report(state: &mut State<'_>, args: &Args) -> Result<()> {
    state.capture_requests = args.capture_memory.clone();
    if let Some(path) = &args.btf {
        state.configure_btf(path.clone());
    }
    if let Some(path) = &args.managed_snapshot {
        state.managed.configure(path.clone())?;
    }
    state.managed.set_max_age(args.managed_max_age)?;
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
pub(super) fn finish_report(state: &mut State<'_>, args: &Args, elapsed: Duration) -> Result<()> {
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
pub(super) fn configure_record(
    state: &mut State<'_>,
    args: &Args,
    program: &Program,
) -> Result<()> {
    if let Some(path) = &args.record {
        state.recorder = Some(poortrace::recording::Recorder::create(
            path,
            &program.source,
        )?);
    }
    Ok(())
}
