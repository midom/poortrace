//! Command-line options and value parsers.

use clap::Parser;
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "LLVM JIT scripts over user-mode perf and ptrace tracing",
    after_help = "Examples:\n  poortrace -e 'interval:ms:100 { @ticks = count(); }' --duration 1\n  poortrace -e 'profile:hz:99 { @[comm, ip] = count(); }' -- ./workload\n  poortrace -p 1234 -e 'profile:hz:99 { @[ustack] = count(); }'\n  poortrace -p 1234 -e 'software:page-faults:1 { @[tid] = count(); }'\n\nPerf/ptrace policy and PMU support are enforced by the host. No BPF programs are loaded."
)]
pub(super) struct Args {
    /// Inline script (otherwise supply a script file)
    #[arg(short = 'e', long, conflicts_with = "script")]
    pub(super) expression: Option<String>,
    /// Script file; '-' reads standard input
    pub(super) script: Option<PathBuf>,
    /// Attach to all currently visible threads of this process
    #[arg(short = 'p', long, value_parser = clap::value_parser!(i32).range(1..), conflicts_with_all = ["command", "shell_command"])]
    pub(super) pid: Option<i32>,
    /// Trace all online CPUs; requires host permission and perf-only probes
    #[arg(long, conflicts_with_all=["pid","command","shell_command","track_threads","follow_forks","attach_descendants"])]
    pub(super) system_wide: bool,
    /// Stop all tracked threads during handlers; profile probes use wall-clock snapshots
    #[arg(long, conflicts_with_all=["system_wide","stat","replay","record_raw","branch_stack","include_kernel","managed_snapshot"])]
    pub(super) reliable: bool,
    /// Include kernel execution in perf counters/sampling (host policy applies)
    #[arg(long)]
    pub(super) include_kernel: bool,
    /// Also seize descendants that already exist when attaching with -p
    #[arg(long, requires = "pid")]
    pub(super) attach_descendants: bool,
    /// Refresh function bindings at mapping syscall stops (adds ptrace overhead)
    #[arg(long)]
    pub(super) track_loads: bool,
    /// Launch a command through /bin/sh -c
    #[arg(short = 'c', long = "command", conflicts_with = "command")]
    pub(super) shell_command: Option<String>,
    /// Stop after this many wall-clock seconds
    #[arg(short = 'd', long, value_parser = duration)]
    pub(super) duration: Option<Duration>,
    /// Compile and verify the script without opening perf events
    #[arg(long)]
    pub(super) check: bool,
    /// Print generated LLVM IR and exit
    #[arg(long)]
    pub(super) emit_llvm: bool,
    /// List supported probes/events
    #[arg(short = 'l', long)]
    pub(super) list: bool,
    /// Save handler events and helper results for offline replay
    #[arg(long, conflicts_with_all=["replay","stat"])]
    pub(super) record: Option<PathBuf>,
    /// Archive original perf records and their capture layout
    #[arg(long, requires = "record")]
    pub(super) record_raw: bool,
    /// Capture target output while forwarding it to stdout/stderr
    #[arg(long, requires = "record")]
    pub(super) record_output: bool,
    /// Capture ADDRESS:LENGTH, argN:LENGTH, sp:LENGTH or ip:LENGTH at each event
    #[arg(long, requires = "record")]
    pub(super) capture_memory: Vec<poortrace::capture::MemoryRequest>,
    /// Replay captured target stdout/stderr as well as tracing handlers
    #[arg(long, requires = "replay")]
    pub(super) replay_output: bool,
    /// Re-decode archived raw perf samples for offline analysis
    #[arg(long, requires = "replay")]
    pub(super) replay_raw: bool,
    /// Return the captured launched command's exit status during replay
    #[arg(long, requires = "replay")]
    pub(super) replay_exit_status: bool,
    /// Explicit opt-in cooperative VM/async snapshot file
    #[arg(long)]
    pub(super) managed_snapshot: Option<PathBuf>,
    /// Maximum age in seconds of a cooperative managed snapshot
    #[arg(long, default_value="10", value_parser=duration)]
    pub(super) managed_max_age: Duration,
    /// BTF metadata file (defaults to /sys/kernel/btf/vmlinux)
    #[arg(long)]
    pub(super) btf: Option<PathBuf>,
    /// Additional stopped process groups proven to share the target's mm
    #[arg(long, requires="pid",value_delimiter=',',value_parser=clap::value_parser!(i32).range(1..))]
    pub(super) shared_mm_pids: Vec<i32>,
    /// Declare a coroutine stack TID:LOW:HIGH for return matching (repeatable)
    #[arg(long)]
    pub(super) stack_range: Vec<String>,
    /// Replay a recording without attaching to a live target
    #[arg(long, conflicts_with_all=["pid","shell_command","command","stat","check","emit_llvm","list","list_functions","list_usdt","track_threads","follow_forks","attach_descendants","system_wide","track_loads","live","window","duration"])]
    pub(super) replay: Option<PathBuf>,
    /// Sort recorded events globally by monotonic timestamp during replay
    #[arg(long, requires = "replay")]
    pub(super) sort_events: bool,
    /// List SystemTap SDT probes without attaching
    #[arg(long)]
    pub(super) list_usdt: Option<String>,
    /// List ELF functions and file offsets without attaching
    #[arg(long)]
    pub(super) list_functions: Option<String>,
    /// Glob used by --list-functions (raw or demangled names)
    #[arg(long, default_value = "*")]
    pub(super) function_filter: String,
    /// Track thread creation with ptrace instead of periodic discovery
    #[arg(long)]
    pub(super) track_threads: bool,
    /// Follow child processes (uses ptrace lifecycle tracking)
    #[arg(short = 'f', long)]
    pub(super) follow_forks: bool,
    /// Function probe backend: ptrace works without privileged perf uprobes
    #[arg(long,default_value="ptrace",value_parser=["ptrace","perf"])]
    pub(super) uprobe_backend: String,
    /// Read grouped counters instead of sampling (no script)
    #[arg(long, conflicts_with_all=["expression","script","check","emit_llvm"])]
    pub(super) stat: bool,
    /// Counter probes for --stat, comma separated
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "hardware:cycles,hardware:instructions",
        requires = "stat"
    )]
    pub(super) stat_events: Vec<String>,
    /// Report encoding; script printf output is separate when --output is used
    #[arg(long, default_value="text",value_parser=["text","json","folded","speedscope","speedscope-timeline","speedscope-scheduler","flamegraph"])]
    pub(super) output_format: String,
    /// Write the final report to a file
    #[arg(short = 'o', long)]
    pub(super) output: Option<PathBuf>,
    /// Show the largest N entries in each map
    #[arg(long,value_parser=clap::value_parser!(u32).range(1..))]
    pub(super) top: Option<u32>,
    /// Histogram quantiles (0..1); reports the bucket containing each rank
    #[arg(long, value_delimiter = ',')]
    pub(super) quantiles: Vec<f64>,
    /// Add percentages to text map reports
    #[arg(long)]
    pub(super) percent: bool,
    /// Add per-second rates to text map reports
    #[arg(long)]
    pub(super) rate: bool,
    /// Refresh cumulative text maps at this interval; redraw terminals in place
    #[arg(long,value_parser=duration,conflicts_with_all=["window","output"])]
    pub(super) live: Option<Duration>,
    /// Print and clear text maps on this wall-clock interval
    #[arg(long,value_parser=duration)]
    pub(super) window: Option<Duration>,
    /// Compare map values with a previous --output-format json report
    #[arg(long)]
    pub(super) compare: Option<PathBuf>,
    /// Stack unwinder: frame pointers or sampled-stack DWARF CFI
    #[arg(long,default_value="fp",value_parser=["fp","dwarf"])]
    pub(super) stack_mode: String,
    /// Bytes of target stack captured for DWARF/jsstack; multiple of 8
    #[arg(long,default_value_t=16384,value_parser=clap::value_parser!(u32).range(8..=32768))]
    pub(super) stack_bytes: u32,
    /// Capture user branch history where the PMU supports it
    #[arg(long)]
    pub(super) branch_stack: bool,
    /// Data pages per thread/event; power of two, 1..1024
    #[arg(long, default_value_t = 8)]
    pub(super) mmap_pages: usize,
    /// Maximum entries in each aggregation map
    #[arg(long, default_value_t = 65536, value_parser = clap::value_parser!(u32).range(1..))]
    pub(super) max_map_entries: u32,
    /// Do not print maps automatically at shutdown
    #[arg(long)]
    pub(super) no_print_maps: bool,
    /// Suppress attachment status
    #[arg(short, long)]
    pub(super) quiet: bool,
    /// Launch an executable and arguments after '--'
    #[arg(last = true)]
    pub(super) command: Vec<String>,
}
fn duration(s: &str) -> std::result::Result<Duration, String> {
    let n: f64 = s
        .parse()
        .map_err(|_| "duration must be a positive number".to_string())?;
    if !n.is_finite() || n <= 0.0 || n > 365.0 * 86400.0 {
        return Err("duration must be positive and at most one year".into());
    }
    let d = Duration::from_secs_f64(n);
    if d.is_zero() {
        return Err("duration is below one nanosecond".into());
    }
    Ok(d)
}
