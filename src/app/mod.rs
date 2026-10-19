//! CLI orchestration; backend and lifecycle details live in dedicated modules.

mod cli;
mod events;
mod functions;
mod perf;
mod probes;
mod process;
mod reliable;
mod replay;
mod report;
mod session;
mod stat;
mod syscalls;

use clap::Parser;
use cli::Args;
use functions::run_functions;
use poortrace::{
    Result,
    codegen::Program,
    language::{HARDWARE, Probe, SOFTWARE},
};
use replay::run_replay;
use stat::run_stat;
use std::io;
use syscalls::run_syscalls;

pub(super) fn run() -> Result<i32> {
    run_with_args(Args::parse())
}

fn run_with_args(mut args: Args) -> Result<i32> {
    if let Some(binary) = &args.build_index {
        let output = args.index_output.as_ref()
            .ok_or("--build-index requires --index-output")?;
        let count = poortrace::binary_index::build(
            args.pid.unwrap_or(std::process::id() as i32),
            binary,
            output,
        )?;
        println!("Indexed {count} functions in {}", output.display());
        return Ok(0);
    }
    poortrace::binary_index::configure(&args.binary_index)?;
    for event in &mut args.stat_events {
        *event = poortrace::language::canonical_probe_name(event).into_owned();
    }
    if let Some(sidecar) = &args.report_metadata {
        use std::os::unix::fs::MetadataExt;
        for other in [&args.output, &args.record, &args.replay, &args.script]
            .into_iter()
            .flatten()
        {
            let same_path = std::path::absolute(sidecar).ok() == std::path::absolute(other).ok();
            let same_file = std::fs::metadata(sidecar)
                .ok()
                .zip(std::fs::metadata(other).ok())
                .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino());
            if same_path || same_file {
                return Err("--report-metadata must differ from report, recording, replay, and script paths".into());
            }
        }
    }
    if args.attach_descendants {
        args.follow_forks = true;
    }
    if matches!(
        args.output_format.as_str(),
        "speedscope-timeline" | "speedscope-scheduler"
    ) && args.replay.is_none()
    {
        return Err("timeline and scheduler output formats require --replay".into());
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
        if let Some(pid) = args.pid {
            let listing = poortrace::discovery::process(pid, &args.function_filter)?;
            for warning in listing.warnings {
                eprintln!("poortrace: {warning}");
            }
            for probe in listing.probes {
                println!("{probe}");
            }
            return Ok(0);
        }
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
    if args.max_breakpoints.is_some_and(|limit| limit != 0)
        && args.uprobe_backend == "perf"
        && !args.reliable
    {
        return Err("--max-breakpoints requires the ptrace function backend; it does not limit perf descriptors".into());
    }
    probes::expand(&mut program, &args)?;
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
    if (!args.shared_mm_pids.is_empty() || !args.stack_range.is_empty())
        && !args.reliable
        && (args.uprobe_backend != "ptrace"
            || !program.clauses.iter().any(|c| {
                c.probes
                    .iter()
                    .any(|(_, p)| matches!(p, Probe::Uprobe { .. }))
            }))
    {
        return Err("shared-mm groups and stack ranges require ptrace function probes".into());
    }
    if args.record_output && args.command.is_empty() && args.shell_command.is_none() {
        return Err("--record-output requires a launched command".into());
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
    if args.reliable {
        return reliable::run(&args, &program);
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
    perf::run(args, program)
}
