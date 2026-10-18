//! Shared capture plans and periodic report refresh, independent of backend stops.
use super::cli::Args;
use poortrace::{codegen::Program, perf::Capture, runtime::State};
use std::time::{Duration, Instant};

pub(super) fn capture(args: &Args, program: &Program, ptrace_functions: bool) -> Capture {
    Capture {
        ptrace_functions,
        addr: true,
        kernel: args.include_kernel || program.needs_kstack(),
        kernel_callchain: program.needs_kstack() || args.include_kernel && args.record.is_some(),
        record_raw: args.record_raw,
        callchain: args.stack_mode == "fp" && (program.needs_ustack() || args.record.is_some()),
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
    }
}

pub(super) struct Reports {
    started: Instant,
    window: Instant,
    live: Instant,
}
impl Reports {
    pub(super) fn new() -> Self {
        let started = Instant::now();
        Self {
            started,
            window: started,
            live: started,
        }
    }
    pub(super) fn refresh(&mut self, state: &mut State<'_>, args: &Args) {
        if args
            .window
            .is_some_and(|period| self.window.elapsed() >= period)
        {
            state.report.elapsed = self.window.elapsed().as_secs_f64();
            state.print_all();
            state.clear_all();
            self.window = Instant::now();
        }
        if args
            .live
            .is_some_and(|period| self.live.elapsed() >= period)
        {
            state.report.elapsed = self.started.elapsed().as_secs_f64();
            state.live_snapshot();
            self.live = Instant::now();
        }
    }
    pub(super) fn window_elapsed(&self) -> std::time::Duration {
        self.window.elapsed()
    }
}

/// Each backend coalesces missed ticks using its own stop/resume rules.
pub(super) fn intervals(
    program: &Program,
    started: Instant,
) -> Vec<(usize, String, Duration, Instant)> {
    program
        .clauses
        .iter()
        .enumerate()
        .flat_map(|(id, clause)| {
            clause.probes.iter().filter_map(move |(name, probe)| {
                if let poortrace::language::Probe::Interval(period) = probe {
                    Some((id, name.clone(), *period, started + *period))
                } else {
                    None
                }
            })
        })
        .collect()
}
