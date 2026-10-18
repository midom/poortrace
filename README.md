# poortrace

A bpftrace-inspired tracing tool written in Rust. It compiles script predicates,
arithmetic, and control flow to native machine code with LLVM MCJIT, then runs
those handlers over Linux `perf_event_open` samples, ptrace syscall/function
stops, timers, and polling observations in userspace. It also supports offline
replay. It does not load eBPF programs; host perf and ptrace access checks apply.

```sh
cargo build --release
./target/release/poortrace -e 'profile:hz:99 { @[comm, ip] = count(); }' -- ./my-program
./target/release/poortrace -p 1234 -d 10 -e 'software:page-faults:100 { @[tid] = count(); }'
./target/release/poortrace examples/interval.pt
```

This implements the subset described below, rather than full bpftrace language
or probe compatibility. poortrace has no build or runtime dependency on bpftrace.

## Build

Requires 64-bit Linux on **x86-64 or AArch64**, Rust 1.85 or newer, a C linker,
and LLVM 15 or newer with development files and its shared library (or static
archives for static builds). CI uses LLVM 18 on x86-64 and AArch64; live tracing and
static builds have also been tested on AArch64. LLVM's stable C API is bound directly;
no C++ bindings or particular `llvm-sys` crate version are required.

On Ubuntu with LLVM 18 available:

```sh
sudo apt install build-essential llvm-18-dev
LLVM_CONFIG=llvm-config-18 cargo build --release --locked
./target/release/poortrace --help
```

`LLVM_CONFIG` defaults to `llvm-config`. In the default shared-LLVM build, the
selected library directory is embedded in the executable's runtime library
search path. Deployment requires the corresponding LLVM shared library.
`cargo install --path . --locked` installs the binary in Cargo's bin directory.

To embed LLVM's static component libraries instead of depending on `libLLVM.so`:

```sh
LLVM_CONFIG=llvm-config-18 cargo build --release --locked --features static-llvm
```

This requires LLVM's static archives and a C++ standard library development
package. LLVM's system dependencies and the C/C++ runtimes remain dynamically
linked in this mode. The LLVM runtime search path is omitted.

For a fully static executable on a native GNU/Linux toolchain, enable Rust's
`crt-static` target feature; this selects static LLVM automatically:

```sh
sudo apt install build-essential llvm-18-dev zlib1g-dev libzstd-dev libtinfo-dev libxml2-dev
LLVM_CONFIG=llvm-config-18 RUSTFLAGS='-C target-feature=+crt-static' \
  cargo build --release --locked --target x86_64-unknown-linux-gnu
./target/x86_64-unknown-linux-gnu/release/poortrace --check examples/counters.pt
```

Use `aarch64-unknown-linux-gnu` on AArch64. The explicit `--target` keeps
`crt-static` out of host-side procedural macros. All libraries reported by
`llvm-config --link-static --system-libs`, plus the C/C++ runtimes, must be
available as static archives; required packages depend on the LLVM installation.
Cross-compilation additionally requires a matching target LLVM and linker;
switching to a musl target requires LLVM and its dependencies built for musl.
GNU libc may emit linker warnings about dynamic loading and name-service
functions in static executables; static linking does not make those glibc
facilities portable across systems.

## Perf access

Default perf sampling attaches to specific target threads with `cpu=-1`,
`exclude_kernel=1`, and `exclude_hv=1`. `--system-wide` instead opens streams on
online CPUs; `--include-kernel` includes kernel execution. Tracepoint and kernel
function probes also request kernel events. These modes require the corresponding
host permissions; the default user-mode path remains available without them. Access remains subject to
kernel checks: target ownership/credentials, `perf_event_paranoid`, resource
limits, and container policies. The tool reports the syscall error and current
paranoid value when opening an event fails. It never changes policy or requests
privilege escalation.

Upstream Linux permits user-mode per-process monitoring at paranoid level 2.
Some distributions impose stricter restrictions above 2; sandboxes may block
the syscall regardless of the sysctl. Hardware events also require a supported
PMU; virtualization can make them unavailable. See the
[kernel perf access documentation](https://www.kernel.org/doc/html/latest/admin-guide/perf-security.html)
and [perf_event_open manual](https://man7.org/linux/man-pages/man2/perf_event_open.2.html).

`BEGIN`, `END`, interval-only scripts, ptrace-only syscall/function/USDT scripts,
and polling wait/wakeup scripts do not open perf events. Ptrace and target-memory
access checks still apply where needed. `--check`, `--emit-llvm`, `--list`,
`--list-functions`, and `--list-usdt` do not attach to a target. Compilation checks
validate language syntax and types; function globs, ELF/USDT sites, DWARF layouts,
and host event availability are resolved later. `--list` shows recognized event
names, not a guarantee that the host supports every event. Kernel tracepoints
also need readable tracefs event formats.

`profile:hz:N` must fit the host limit in
`/proc/sys/kernel/perf_event_max_sample_rate`. For example, a limit of 1000
rejects `profile:hz:1001`; use `profile:hz:1000` or a lower rate such as 99.
Above-limit errors report the requested frequency and the host ceiling.

## Probes

| Probe | Behavior |
| --- | --- |
| `BEGIN` / `END` | Once at startup / shutdown |
| `interval:ns:N`, `:us:N`, `:ms:N`, `:s:N`, `:hz:N` | Wall-clock timer, once per tracer |
| `profile:hz:N` | Per-thread CPU-clock sampling with kernel frequency adjustment |
| `profile:ns:N`, `:us:N`, `:ms:N`, `:s:N` | Per-thread CPU-clock sampling every N units of CPU time |
| `software:EVENT[:PERIOD]` | Samples every PERIOD software-counter occurrences |
| `hardware:EVENT[:PERIOD]` | Samples every PERIOD hardware-counter occurrences |
| `raw:CONFIG[:PERIOD]` | CPU-specific raw PMU event, decimal or hexadecimal config |
| `pmu:NAME:CONFIG[:PERIOD]` | Event from a named `/sys/bus/event_source/devices` PMU |
| `cache:CACHE:OP:RESULT[:PERIOD]` | Cache/TLB event (`l1d`, `l1i`, `ll`, `dtlb`, `itlb`, `branch`, `node`) |
| `watchpoint:ADDRESS:LENGTH:MODE` | User hardware breakpoint: lengths 1/2/4/8, modes `r`, `w`, `rw`, `x` |
| `uprobe:PATH:FUNCTION`, `uretprobe:PATH:FUNCTION` | Native user function entry/return stops |
| `usdt:PATH:PROVIDER:NAME` | SystemTap SDT markers using ptrace, with scalar arguments and semaphores |
| `wait:UNIT:N`, `wakeup:UNIT:N` | Sleeping-thread snapshots and observed sleeping-to-runnable transitions; units `ns`, `us`, `ms`, `s`, `hz`, minimum interval 1 ms |
| `tracepoint:CATEGORY:EVENT` | Perf tracepoint records with fields decoded from tracefs metadata |
| `kprobe:FUNCTION`, `kretprobe:FUNCTION` | Dynamic kernel function probes through the perf kprobe PMU |
| `offcpu` | Completed switch-out/switch-in intervals for target threads |
| `syscall:enter:NAME`, `syscall:exit:NAME` | Native syscall stops using ptrace; names, numbers, or `*` |

Periods and rates must be positive decimal integers. Use `--list` for names,
including `cpu-clock`, `task-clock`, `page-faults`, `minor-faults`, `major-faults`,
`context-switches`, `cpu-migrations`, `cycles`, `instructions`, `cache-misses`,
and `branch-misses`. The default period is 1,000,000 for hardware events and
software clock events (nanoseconds for the latter), and 1 for other software
events. Cache operations are `read`, `write`, or `prefetch`; results are `access`
or `miss`. Cache/raw/PMU probes default to period 1,000,000. Config encodings,
read-only watchpoints, breakpoint lengths/alignment, and event availability
are CPU/kernel specific. Watchpoint addresses are runtime virtual addresses;
account for ASLR. These probes apply to the target's threads and open no BPF
programs. Host perf policy continues to apply.

Separate probe specs with commas to share one handler. Put an optional predicate
between slashes:

```text
profile:hz:99 / comm == "worker" && ip != 0 / {
    @[comm, tid] = count();
    @addresses[ip] = count();
}
interval:s:1 { print(@addresses); clear(@addresses); }
END { printf("finished\n"); }
```

## Language

* Signed 64-bit decimal integers, hexadecimal bit patterns, finite decimal or
  exponent float literals, UTF-8 strings,
  `true`, `false`, parentheses, `//` and `/* */` comments.
* Integer builtins: `pid`, `tid`, `cpu`, `nsecs`, `ip`, `period`. `nsecs` uses
  `CLOCK_MONOTONIC`; `period` is the sample's perf counter period. String
  builtins: `comm`, `probe`, `syscall` (a syscall name in syscall/wait/wakeup
  handlers, otherwise empty), and `wait_reason` (empty without a wait snapshot).
  Additional integers: `addr` (sampled data address when provided), `offcpu_ns`,
  `preempt`, `sysno`, `retval`, `latency`, and `arg0` through `arg5`. Values that
  do not apply to a handler are zero; `latency` and `offcpu_ns` are nanoseconds.
* User stacks: `ustack` or `ustack()` captures up to 127 user frames;
  `ustack(N)` limits output to a constant depth from 1 to 127. Stacks can be map
  keys or arguments to `printf("%s", ...)`. They have a distinct key type and
  print as indented frames, leaf first. They cannot be used as integers.
  `pystack`, `jsstack`, and `gostack` provide supported managed-runtime frames; see
  [Managed frames and JIT symbols](#managed-frames-and-jit-symbols).
* Arithmetic `+ - * / %`, bitwise `& | ^ ~ << >>`, comparisons, unary `!`,
  and short-circuit `&& ||`. Strings support `==` and `!=` by content.
* `$local = expression`, `+=`, `-=`, `++`, `--`, and `if (...) { ... } else { ... }`.
  Locals hold consistently typed integers, floats, strings, or stack values, start at
  zero/empty, and reset on each handler invocation.
* Persistent maps: `@`, `@name`, and `@name[key, ...]`. Keys may mix strings, stacks, integers, and finite floats. A map's key types and aggregation must be consistent throughout
  the script. Missing scalar entries read as zero.
* Map assignment, `+=`, `-=`, `++`, `--`, and direct aggregation assignments:
  `count()`, `sum(expr)`, `min(expr)`, `max(expr)`, `avg(expr)`, `hist(expr)`,
  `lhist(expr, min, max, step)`. Linear bounds must be integer constants with
  min < max, positive step, and at most 1024 buckets. Underflow and overflow
  get separate buckets; the final ordinary bucket ends at max.
  Average rounds toward zero. Histograms use power-of-two buckets, a zero bucket,
  and one negative bucket; use `print` to inspect a histogram. Finite float keys
  and scalar float values support assignment, `sum`, `min`, `max`, and `avg`;
  local arrays, and float `hist`/`lhist` inputs are supported. Float histograms
  include subnormal power-of-two buckets; linear bounds/steps must be finite
  constants and fit the 1024-bucket limit. Nonfinite map keys/values and float
  histogram inputs fail through State.
* `printf("literal format", ...)`: `%d`, `%i`, `%u`, `%x`, `%X`, `%o`, `%s`,
  `%c`, `%p`, `%f`, `%e`, `%g`, `%%`, optional `l`/`ll`, width up to 200, `-` and zero padding.
  Argument counts and types are checked before execution. Escapes: `\n`, `\r`,
  `\t`, `\\`, `\"`. C varargs are not used.
* `usym(address)` resolves an individual user address using the current PID.
  `str(address[, length])` reads a string up to NUL or the bounded length
  (default 256). `buf(address, length)` renders bytes as hexadecimal.
  Lengths must be constants from 1 to 4096. `read_u8`, `read_u16`, `read_u32`,
  and `read_u64` return native-endian unsigned bit patterns as integers. String
  helpers work as map keys or `%s` arguments; numeric reads work in expressions.
  Memory access uses `process_vm_readv` with the kernel's ptrace permission
  checks. Errors end the trace through State; partial strings may be truncated,
  while buffers and numeric reads require a complete read. Async perf handlers
  read current memory, not memory frozen at sample time. Even at ptrace stops,
  sibling threads can modify shared memory unless `--reliable` is selected.
* `branches` is an indented list of sampled user branch source/destination
  symbols. Using it, or `--branch-stack`, requests branch history. The PMU must
  support it; `examples/branches.pt` uses a hardware branch event. The most
  recent 128 branch entries are retained. This is history, not a call stack.
* `print(@map)`, `clear(@map)`, `exit()`. Maps are also printed automatically
  at shutdown unless `--no-print-maps` is given. Clear a map after an explicit
  final print if duplicate output is undesirable.

Integer arithmetic wraps; integer division/remainder by zero returns zero; `INT64_MIN / -1`
wraps to `INT64_MIN`; shift amounts are masked to 0..63. Script strings cannot
be used as raw pointers. Default map output is sorted by key; `--top` ranks
entries by absolute value. Each map is limited to 65,536 entries by default; `--max-map-entries` changes that limit. Exceeding it
ends the trace with an error. Scripts are limited to 256 KiB, nesting to 128
levels, each expression to 128 operators per precedence level, and calls/keys
to 16 arguments.

For lifecycle and interval handlers, `pid` and `tid` are the target process ID
(or the tracer ID without a target); `cpu`, `ip`, and `period` are zero. Timer
callbacks are scheduled in userspace and missed ticks coalesce. They do not
provide hard real-time timing.

## User stacks

```sh
./target/release/poortrace -p 1234 -d 10 \
  -e 'profile:hz:99 { @[comm, ustack(32)] = count(); }'
./target/release/poortrace examples/stacks.pt -- ./my-program
```

Perf callchain capture is enabled when the script uses `ustack`, including in
predicates. It uses the kernel's user frame-pointer unwinder; compile C/C++
targets with `-fno-omit-frame-pointer`, or Rust targets with
`RUSTFLAGS='-C force-frame-pointers=yes'`, for useful caller frames. On AArch64,
also use `-mno-omit-leaf-frame-pointer` with C/C++ compilers that otherwise omit
leaf frames. The kernel's
`perf_event_max_stack` also limits captured depth. Omitted frame pointers,
inlining, tail calls, or interrupted prologues can truncate stacks.

Use `--stack-mode dwarf --stack-bytes 16384 --mmap-pages 128` to unwind sampled
user registers and stack bytes through ELF `.eh_frame`/`.debug_frame` CFI,
including ordinary native code compiled without frame pointers. `--stack-bytes`
is a multiple of 8 from 8 to 32768. Only the captured stack bytes are read by
the unwinder; insufficient bytes, missing/unsupported CFI, and stack switches
can truncate results. Frame-pointer fallback is available. Large stack samples
need larger rings or lower sample rates. Native CFI unwinding needs unwind
metadata. `pystack` and `jsstack` separately decode supported managed-runtime
frames; perf-map files can name native JIT frames (see below).

Perf, ptrace syscall/function stops, and polling wait/wakeup snapshots support
the full `--stack-bytes` range, including the 16384-byte default. Stack snapshots
have a separate 32768-byte read limit; script-visible memory helpers retain
their 4096-byte limit. Partial stack reads retain the accessible prefix.
Ptrace `jsstack` reads frame slots directly.

Frames resolve against the target's `/proc/PID/maps` and ELF regular/dynamic
symbol tables, accounting for PIE/ASLR and shared-library segment offsets.
Rust and C++ names are demangled. Available symbols print as
`function+0xOFFSET (/path/to/module)`; unavailable symbols retain their raw
address and module/file offset when possible. Stripped binaries may expose
only exported symbols. GNU debuglink files (CRC checked), conventional build-ID
files under `/usr/lib/debug/.build-id`, and DWARF in the executable supply source
locations and inline chains where available. Offsets are included when known
from the ELF symbol table; inline chains are displayed within a physical frame. Symbol lookup uses pure Rust libraries and needs no external
symbolizer executable or additional shared libraries in a static build.

Resolution is best effort: mappings refresh at most every 100 ms while handling
stacks, so unloading/replacing modules before samples are processed can prevent
or invalidate resolution. Access restrictions, deleted/unreadable files, and
anonymous mappings fall back to addresses. ELF reads are limited to 128 MiB per
file and 250,000 text symbols; symbol caches are bounded. DWARF unwinding uses at most 128 executable mappings
per process. Stack keys own their
rendered frames so maps remain printable after the target exits. Lifecycle and
interval events have no sampled stack and print `<no user stack>`.

## Stopped-target mode

`--reliable` runs handlers while all tracked target threads are stopped through
ptrace. It supports syscall, ptrace function/USDT, interval, and `profile:hz`
probes, including mixtures of these probes. No perf access is required.

```sh
poortrace --reliable -p PID -e 'profile:hz:99 { @[pystack] = count(); }'
poortrace --reliable -p PID -e 'profile:hz:99 { @[jsstack] = count(); }'
poortrace --reliable -e 'syscall:enter:write { printf("%s",str(arg1)); }' -- app
poortrace --reliable -p PID -e 'interval:ms:100 { @[ustack] = count(); }'
```

In this mode, `profile:hz` takes **wall-clock snapshots** of each stopped tracked
thread, including sleeping threads. It is a different measurement from default
perf CPU-time profiling. `period` is the requested snapshot interval in
nanoseconds; `nsecs` is the snapshot observation time. Snapshot `cpu` is the
thread's last reported processor, or 4294967295 when unavailable.
Missed deadlines coalesce,
and actual rates depend on stop and handler overhead. Launched-command snapshots
start after exec. Interval handlers run once per tick on the stopped root thread
when its registers are available. Native stack registers and stack bytes are read
at that stop; Python/V8/Go helpers read the paused target's heap. BEGIN and END
also run under a verified pause when a target remains.

The tracer verifies visible sibling coverage and fails instead of invoking a
handler if it cannot stop the tracked set or finds an untraced sibling. Existing
tree attachment can therefore fail during a concurrent thread-creation race;
retry after the process has stabilized. `--follow-forks`, `--attach-descendants`,
and declared `--shared-mm-pids` extend the tracked set. Attached targets are
detached without termination signals, including on handler errors or interrupts;
launched commands retain the usual owned-process cleanup behavior.

Stopping threads perturbs scheduling and timing. It prevents writes by those
threads during the handler, but does not make an interrupted runtime operation a
valid interpreter/GC safepoint. Unsupported frames can still be unavailable.
Kernel activity, devices, and untracked processes writing shared mappings are
outside this guarantee. Asynchronous perf/tracepoint/kernel/watchpoint/off-CPU
probes, polling wait/wakeup probes, branch sampling, counters, and external
cooperative snapshots are rejected in this mode. Recordings label the capture
mode `stopped-target-wall-clock` and retain helper results for offline replay.

## Reports and profile exports

```sh
# SVG flamegraph with hover labels; also supports folded and speedscope formats.
./target/release/poortrace -p 1234 -d 10 examples/flamegraph.pt \
  --output-format flamegraph -o cpu.svg
./target/release/poortrace -p 1234 -d 10 examples/flamegraph.pt \
  --output-format speedscope -o cpu.speedscope.json
# Store numeric map values and typed keys, then compare another observation.
./target/release/poortrace -p 1234 -d 10 examples/stacks.pt \
  --output-format json -o baseline.json
./target/release/poortrace -p 1234 -d 10 examples/stacks.pt \
  --compare baseline.json --top 20 --percent --rate
# Independent text snapshots: print and clear maps each second.
./target/release/poortrace -p 1234 -d 10 examples/stacks.pt --window 1 --top 10
```

`--output-format` accepts `text` (default), `json`, `folded`, `speedscope`,
`flamegraph` (standalone SVG), or replay-only `speedscope-timeline`. `-o/--output` writes the final report to a file;
script `printf`/`print` and launched-command output still go to stdout, so use
an output file for machine-readable reports when they might print. Exported
stack profiles use nonnegative numeric map values as weights, root first, with
map names and other keys as labels. Speedscope exports are **aggregated weights**,
not a time-ordered recording; use `speedscope-timeline` for captured observation
order. Float map rows are supported in text/JSON reports, including comparisons
and rates; weighted profile formats require integer weights. JSON float rows
carry an optional `float_value` field. Exports allow at most 256 frames per row including
labels. Empty captures produce empty profiles.

`--top N` ranks final entries by absolute value within each map; `--percent`
uses the absolute-value total before top-N filtering; `--rate` divides numeric
values by elapsed wall time. These two annotations apply to text map reports.
`--window SECONDS` emits text snapshots on stdout and clears all maps, including
maps used by the script; it cannot be combined with `--output` or other report
formats. Script `print(@map)` retains its normal immediate rendering.

`--compare FILE` subtracts numeric map values from a previous poortrace JSON
report, matching map names and typed rendered keys; missing current keys appear
as negative values. It supports text, JSON, and differential flamegraphs, and
also subtracts histogram buckets by label in text/JSON. Stack comparisons depend
on consistent resolved labels; unavailable
symbols or changed modules can change those labels. Reports show delivered
sample/aggregation weights, not exact CPU utilization or uncertainty bounds.

## Counter reads

```sh
./target/release/poortrace --stat --stat-events hardware:cycles,hardware:instructions -- ./my-program
./target/release/poortrace --stat --stat-events software:cpu-clock,software:page-faults -p 1234 -d 5
./target/release/poortrace --system-wide --stat --stat-events software:cpu-clock -d 5
```

`--stat` needs no script. It reads groups of 1..16 hardware, software, raw,
cache, or named-PMU counters per thread, or per online CPU with `--system-wide`.
CPU groups are summed, and CPU hotplug discovery polls every 100 ms.
The default is cycles and instructions;
choose software events on hosts without a suitable hardware PMU. Reports include
raw values and summed enabled/running times. Scaling is computed per group
before summing; a group that never ran has an unavailable scaled value.
Multiplexed totals are estimates. Text reports include IPC when cycles and
instructions are present in the group. `--output-format json` and `--output`
are supported. By default, new threads have the same 100 ms discovery limitation
as sampling. `--track-threads` uses ptrace clone stops to attach counters before
new threads resume; `--follow-forks` also follows newly created child processes
and exec transitions. Initial attachment races remain. Counters are read before
descriptors are dropped.

## User function probes

```sh
# Default backend: unprivileged ptrace software breakpoints.
./target/release/poortrace -p 1234 \
  -e 'uprobe:/path/to/program:my_function { @calls = count(); @args = hist(arg0); }'
./target/release/poortrace \
  -e 'uretprobe:/path/to/program:my_function { @returns = sum(retval); @time = hist(latency); }' \
  -- /path/to/program
# Quote paths with spaces or complete demangled C++ names inside the script.
./target/release/poortrace -p 1234 \
  -e 'uprobe:"/path/with spaces/libfoo.so":"ns::work(int)" { @[ustack] = count(); }'
```

Function probes accept exact regular/dynamic ELF symbols, exact demangled names,
`SYMBOL+OFFSET`, or `0xFILE_OFFSET`. Offsets are **file offsets**, not runtime
addresses; symbol addresses are translated through executable ELF segments.
Ambiguous overloads must use a precise signature, mangled name, or file offset.
Offsets must be instruction boundaries (4-byte aligned on AArch64); return probes
must select function entries. Inlined functions without a distinct symbol/entry
cannot be probed this way. Targets must be native 64-bit ELF files up to 128 MiB.
Absolute paths are resolved in the target's filesystem root; relative paths use
the tracer's working directory. Stripped functions need a known file offset.

`--uprobe-backend ptrace` is the default. It requires ordinary ptrace access,
not a privileged perf uprobe PMU. The tracer stops the target's threads while
patching, handling hits, and single-stepping original instructions; code bytes
are restored on normal/error/interrupt cleanup before detach. Executable mappings
must be private. This backend is intrusive and can substantially change timing;
it is for native function tracing, not transparent high-rate profiling. Abruptly
killing the tracer with SIGKILL prevents its cleanup. Do not probe an instruction
that already contains a software breakpoint. Existing debuggers and ptracers
cannot share the target. Pre-existing processes sharing the address space can be
attached together with `--shared-mm-pids PID1,PID2 -p ROOT_PID`. All declared
groups stop before patching; `kcmp(KCMP_VM)` must prove their shared address
space. A denied comparison or undeclared/unknown trap fails explicitly before
unsafe adoption.

Entry probes expose the first six integer/pointer arguments in `arg0..arg5` under
the native calling convention. At ptrace stops, `farg` reads scalar FP registers
and `sarg` reads raw stack slots (see below). Vector, language-specific, and
aggregate calling conventions are available through bounded DWARF-backed
`args()` decoding below. Return probes preserve entry argument
register values and provide raw signed `retval` plus `latency` including debugger
overhead; only normal matched returns generate events. Recursion and threads are
tracked separately. Tail-call chains sharing a return site emit their matched
returns from inner to outer. Observable stack-pointer unwinding prunes abandoned
returns after operations such as `longjmp`; disjoint stack mappings remain
separate. For coroutines allocating stacks in one mapping, declare each range
with repeatable `--stack-range TID:LOW:HIGH` (hex addresses accepted). Return
traps are restored after temporary execute-permission loss only when the original
image identity still matches. Unregistered same-mapping stacks and genuinely
unobservable nonlocal exits can still prevent matching returns; at most 4096 pending returns,
1024 active breakpoints, and 256 probe bindings are allowed. `ustack` uses a
bounded snapshot of the stopped thread's stack and native CFI, controlled by
`--stack-bytes`.

Loaded instances are located through target mappings, accounting for PIE/ASLR
and shared libraries. The loader is traced until initial bindings appear;
subsequent mappings are rescanned every 100 ms, so brief load/unload activity can
be missed. `--track-loads` refreshes bindings at mapping syscall stops before the
thread resumes, including brief library loads; this adds ptrace overhead.
Patched bytes and SDT semaphores are restored when an existing mapping loses
executable permission, and bindings can be reinstalled when permission returns. Thread clones are followed. By default, child processes do not produce
script events; fork/vfork children are briefly controlled as needed to restore
inherited breakpoints safely. `--follow-forks` includes descendant events and exec
transitions. BEGIN/END/interval, syscall, and perf probes can share the same
ptrace-backed run. Perf events still require host permission; ptrace timing
changes also affect mixed samples.

`--uprobe-backend perf` selects kernel uprobes instead and allows mixing with
other perf probes. It registers dynamic uprobe/uretprobe perf descriptors directly,
without BPF or tracefs writes. This interface commonly requires CAP_SYS_ADMIN
independently of `perf_event_paranoid`; it is **not** the unprivileged default.
This path uses asynchronous samples, can lose hits, and
exposes argument registers on entry and the return-value register on return;
it does not retain entry arguments or function latency for return probes.

## Kernel tracepoints and system-wide sampling

```sh
poortrace --system-wide -d 5 -e 'software:cpu-clock:1000000 { @[comm] = count(); }'
poortrace --system-wide -d 5 -e 'tracepoint:sched:sched_wakeup { @[tid, tp("pid"), tpstr("comm")] = count(); }'
poortrace -p PID -e 'kprobe:do_sys_openat2 { @calls = count(); }'
poortrace --system-wide -d 5 --record sched.jsonl examples/scheduler.pt
poortrace --replay sched.jsonl --sort-events examples/scheduler.pt
```

Kernel probes use the dynamic perf kprobe PMU and do not write global tracefs
probe registrations. `arg0..arg5` expose native argument registers at the probe
point; kernel return probes expose the sampled raw return register, without
retaining entry arguments. Tracepoints decode scalar, string, byte-array, and
bounded dynamic-location fields from the event's tracefs `format`. `tp("field")`
reads integer fields; `tpstr("field")` renders strings or integer values. The
kernel controls tracepoint and function availability and access. No BPF is loaded,
and the tool never changes host perf policy. See the kernel's
[event format documentation](https://www.kernel.org/doc/html/latest/trace/events.html).

Perf samples now explicitly use `CLOCK_MONOTONIC`, matching ptrace/timer events.
Kernel scheduler tracepoints expose event timestamps, scheduler state, and waking
context, allowing event-based analysis beyond polling. Live CPU streams are still
not globally ordered; correlate across CPUs through ordered recording replay.
`examples/scheduler.pt` estimates wake-to-run latency from delivered complete
pairs. Lost events, prior-to-attach events, and missing boundaries limit causal
claims and totals; the waking task context is not a higher-level blocking cause.
Live kernel capture requires a host granting the necessary permissions. Decoder
and offline replay tests do not require those permissions.

Kernel callchains are available as `kstack` or `kstack(DEPTH)` (1..127),
including alongside DWARF user stacks. `ksym(address)` resolves a kernel address
through `/proc/kallsyms`; restricted or missing symbols retain raw addresses.
Requesting kernel frames also requests kernel execution in the perf event, so
host permissions still apply.

```sh
poortrace --system-wide -d 5 -e 'profile:hz:99 { @[kstack(32)] = count(); }'
poortrace -e 'BEGIN { printf("task_struct=%d pid_offset=%d\n", btf_sizeof("task_struct"), btf_offsetof("task_struct","pid")); }'
```

BTF metadata defaults to `/sys/kernel/btf/vmlinux`; `--btf FILE` selects another
BTF file. `btf_sizeof("TYPE")` and `btf_offsetof("TYPE","FIELD")` inspect types
without reading kernel memory. `kfield(address,"TYPE","FIELD")` reads a numeric
field, and `kfieldstr(...)` renders a character array or scalar. Field paths
support nested members and array indices; pointer traversal requires a separate
explicit read. Memory reads use `/proc/kcore` and fail when the host denies access.
BTF metadata access alone does not grant kernel memory or tracing access.

## Off-CPU and syscall tracing

```sh
./target/release/poortrace -p 1234 -d 5 examples/offcpu.pt
./target/release/poortrace examples/syscalls.pt -- ./my-program
./target/release/poortrace examples/files.pt -- ./my-program
./target/release/poortrace -e 'syscall:exit:read / retval < 0 / { @[retval] = count(); }' -- ./my-program
```

`offcpu` consumes per-thread perf switch records. `offcpu_ns` (also `period`)
is the duration of a complete switch-out/switch-in pair; `preempt` reports the
switch-out preemption flag when the kernel supplies it. This includes both
blocking and time awaiting a CPU. It does not establish a blocking reason or
provide a user stack at the switch. Incomplete boundary intervals are omitted;
a loss record discards pending pairs rather than joining across a gap.

Syscall probes select an explicit **ptrace** backend, using seize/interrupt
without sending SIGSTOP. They require Linux 5.3+ and access to the target under
ptrace/Yama/credential/container rules. Native 64-bit syscall names/numbers and
`*` are accepted. Entry handlers get six raw arguments; exit handlers get the
saved arguments, signed raw `retval` (negative errno on failure), and elapsed
`latency`. Timing includes ptrace overhead and scheduling while stopped. Syscall
stops can capture `ustack` using native CFI unwinding and the full configured
stack snapshot size. PMU branch history belongs to perf samples.

Syscall probes can share scripts with BEGIN/END/interval, function, and perf
probes. Launch gating and BEGIN still precede command execution;
launcher syscalls before exec are omitted. Existing threads are seized and
subsequent thread clones are followed; initial attachment races remain possible.
`--follow-forks` follows child processes across exec; otherwise only threads are
followed. Signals and group stops are preserved; cleanup detaches attached
targets and cleans up owned command groups. No privilege or
host-policy changes are performed. See [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)
and [process_vm_readv](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
for their separate access checks.

## Target lifecycle and limits

Perf, syscall/function/USDT, and wait/wakeup probes require `-p PID`,
`-c 'shell command'`, or `-- executable args...`.
Launched commands wait behind a pipe gate until streams are attached and
`BEGIN` has completed. Their initial perf streams enable at exec so launcher
setup work is excluded. The launched command's exit status becomes the tracer's
exit status. `-c` uses `/bin/sh -c`; use `-c 'exec my-program ...'` to replace
the shell when the workload would otherwise be a separate child process.

The tracer stops on target exit (or completion of the followed process tree),
`exit()`, Ctrl-C/SIGTERM, or `--duration SECONDS`. `END` runs at shutdown and
remaining maps are printed. Early termination cleans up the launched process
group and, with `--follow-forks`, tracked owned descendants. Cleanup never sends
termination signals to attached targets. An exit from `BEGIN` prevents command
execution. Command stdout shares the tracer's stdout.
Launched commands run in a separate process group and are intended for
non-interactive workloads.

Existing target threads are attached individually. New threads are discovered
every 100 ms, so their early events, and threads shorter than the scan interval,
can be missed in perf-only runs without lifecycle tracking. Syscall and ptrace
function probes already follow thread clones. `--track-threads` uses ptrace
lifecycle stops to attach new perf streams before new threads resume;
`--follow-forks` also includes children created after attachment and waits for
them after the original process exits. `--attach-descendants -p PID` also takes
a bounded snapshot of pre-existing descendants and implies `--follow-forks`.
Attached descendants are detached without termination signals. Pre-existing
shared address spaces are coordinated when kernel identity checks permit it;
otherwise unsafe breakpoint adoption fails explicitly. These options require ptrace access and introduce
stops. Launched process trees use pidfds and a tracer-local subreaper for
descendant cleanup, requiring Linux 5.3+; attached process trees are detached
without termination signals. Initial attachment races remain, and this is not
an atomic attach to an existing process tree. The default avoids perf's
`inherit`/`cpu=-1` mmap restriction and limits the number of streams to one per
thread/probe rather than one per CPU. System-wide sampling is explicitly
selected with `--system-wide`; it supports perf/tracepoint/kernel probes plus
BEGIN/END/interval handlers, without a PID or launched command.

Perf samples are buffered and handled asynchronously in userspace; ptrace
syscall/function handlers run while their event thread is stopped. Per-stream
perf order is preserved, but live streams are not globally timestamp-sorted.
Offline replay can optionally sort recorded invocations by timestamp. `ip`
remains a raw user address; user callchains and ELF/DWARF symbols are available
through `ustack`. Bounded
read-only memory helpers and optional perf-backed kernel probes are available.
BTF-backed kernel type lookup and bounded field reads are available; complete
bpftrace language compatibility remains outside this implementation. Bounded loops and selected DWARF structure reads are available
as described below. Counter samples are not exact counter totals: `count()`
counts delivered samples, while `sum(period)` sums their recorded periods; neither includes lost samples or PMU multiplexing
corrections.

The mmap consumer handles wraparound, validates record sizes, uses the kernel's
head/tail memory ordering, and reports received loss records. High rates can
overrun buffers or trigger kernel throttling. Increase `--mmap-pages` (a power
of two, default 8), increase event periods, or reduce profile frequency. Host
mlock/file descriptor limits can constrain many threads/events. Command-name
changes are consumed from perf records so buffered samples keep their names
even after the thread exits.

## Function discovery, SDT markers, and typed reads

```sh
poortrace --list-functions /path/app --function-filter 'work*'
poortrace --list-usdt /path/app
poortrace -e 'uprobe:/path/app:work* { @[probe] = count(); }' -- /path/app
poortrace -e 'usdt:/path/app:provider:request* { @[probe, arg0] = count(); }' -- /path/app
poortrace -f -e 'syscall:enter:write { @[pid, ustack] = count(); }' -- /path/app
```

Function globs match raw or demangled names, deduplicate aliases by file offset,
and expand to at most 256 probes per clause. Quote paths containing spaces.
SDT supports native 64-bit SystemTap `.note.stapsdt` markers. Provider and marker
selectors accept `*`/`?`; all matching locations are attached. Up to six scalar
1/2/4/8-byte arguments are decoded from native registers, constants, or supported
register-relative memory operands. Unsupported operand forms fail explicitly.
SDT semaphores are incremented while the marker is active and decremented on
cleanup; fork copies and separate address spaces are handled. These probes use
the ptrace backend. See the [SystemTap semaphore documentation](https://www.sourceware.org/systemtap/man/dtrace.1.html).

At a ptrace function stop, `farg(N, "f32")` / `farg(N, "f64")` render the first
eight FP/SIMD argument registers (N=0..7) as strings; FP register zero also holds
ordinary scalar FP returns. `sarg(N)` reads one of the first sixteen raw 8-byte stack
argument slots (N=0..15): immediately above the return address on x86-64, at
entry SP on AArch64. These are ABI-level reads; signatures, varargs, vector arguments, and
aggregate calling conventions are not inferred by these raw helpers. Return-time stack slots do not
necessarily contain the original entry arguments.

`field(address, "Type", "member")` reads a DWARF integer/pointer member, including
signed extension. Dotted member paths traverse nested inline structures.
`fieldstr` renders integer or floating-point members as strings. `sizeof("Type")`
and `offsetof("Type", "member")` inspect layout. An optional leading literal ELF
path selects a library/debug image; otherwise the target executable is used:

```text
uprobe:/path/app:inspect {
    @quantity = field(arg0, "Payload", "quantity");
    printf("%s\n", fieldstr(arg0, "Payload", "ratio"));
}
```

Layout lookup requires DWARF in the selected image. Typedefs, qualifiers, and
cross-unit `debug_info` type references are followed; scalar reads are limited to
1/2/4/8 bytes, with 1..8-byte storage for bitfields. Signed/unsigned DWARF 4/5
bitfields and pointer member paths such
as `child->value` are supported. Multidimensional array paths such as
`matrix[1][2]` support up to eight dimensions and 4096 total elements; individual
dimensions are limited to 128 and formatted/argument output remains bounded. `offsetof` rejects paths requiring pointer
dereferences or bitfield selection. Nonconstant member-location expressions and
ambiguous layouts remain rejected. `fieldf` returns a floating-point field for
arithmetic; `value(address, "Type")` renders a bounded structured value. ELF input is bounded to 128 MiB,
expanded DWARF sections to 256 MiB, and type traversal to 32 levels.

`args()` at a ptrace function entry reconstructs a bounded DWARF C signature
using the native System V AMD64 or AAPCS64 ABI. It renders named scalar,
structure, supported vector, indirect, and stack arguments as a string:

```text
uprobe:/path/app:inspect { printf("%s\n", args()); }
```

A C/C++ DWARF compilation unit must describe the entry signature; other language
ABIs and explicit non-native calling conventions are rejected. Supported classification includes mixed
integer/FP aggregates, AArch64 homogeneous FP aggregates, and supported vector
registers. At most 32 arguments, 128 flattened members, and 4096-byte objects are
accepted. Automatic C signature decoding rejects variadic functions and layouts
that cannot be classified safely. Explicit varargs and other languages use the
interfaces below. `args()` is for entry stops; it
does not infer arguments at arbitrary instruction offsets or reconstruct a
signature from stripped machine code.

`args_as("fixed=i32,...,small=i32,ratio=f64,large=i64")` supplies an explicit
native C ABI signature, including variadic argument types. Apply C default
promotions (`i32` for small integers and `f64` for floats after `...`). Supported
shapes include pointers, scalar integers/floats, 64/128-bit vectors such as
`v4f32`, and named DWARF types. An optional `->ReturnType` describes hidden large
return storage. An optional first ELF path selects the named types' image. The
caller is responsible for supplying the real signature.

`args_native()` and `args_native("ELF", "function")` decode parameters from
current-PC DWARF locations, including actual register mappings, pieces, stack
values, and frame-base/CFA information. This supports tested Rust and Go
signatures without assuming their calling convention is C. Optimized-away
parameters, unsupported expressions, and not-yet-initialized entry spills are
labeled unavailable; stripped functions need an explicit supported signature.

## Extended language

```text
fn label($s) = strcat($s, "!");
fn twice($x) = $x * 2;
BEGIN {
    $name = label("worker");
    $i = 0;
    repeat(4) { $values[$i] = twice($i + 1); $i++; }
    @counts[$name]++;
    delete(@counts[$name]);
    printf("%s %d\n", $name, $values[3]);
}
```

Expression functions take at most sixteen parameters and evaluate arguments
once. Recursive calls compile to native LLVM functions; `condition ? yes : no`
short-circuits and supports recursive base cases. Each invocation has a shared
4096-iteration/call budget, recursion depth 64, and a conservative 512 KiB native
frame budget. Compilation limits each function to 128 KiB estimated frame cost,
256 typed function instances, and 8 MiB generated native-function IR. `repeat(N)` accepts a constant 1..1024, with a shared
4096-iteration budget per handler invocation, including nested repeats. Local
numeric arrays hold consistently integer or float elements, with 256 zero-initialized
elements each, reset on invocation;
out-of-bounds access ends the trace. At most 128 local array names are allowed.
`delete(@map[key,...])` removes an individual entry.

`while (condition) { ... }` supports variable conditions under the same shared
4096-iteration budget. `for ($key, $value in @map) { ... }` visits a sorted
snapshot of a scalar map; `for (($key1,$key2),$value in @map)` destructures
multiple keys (up to 16). Mutations do not change that walk. Snapshot
storage is capped at 65,536 entries per invocation. Keys can be integer, float,
string, or stack values; values can be integers or floats.

`f64(expr)` / `f32(expr)` convert scalar values for float arithmetic. Mixed
integer/float arithmetic promotes the signed integer. Float division follows
IEEE behavior, and float-to-integer casts are explicit. Float values work in
locals, expression functions, scalar maps, comparisons, and `%f/%e/%g` output.
Float format precision is 0..200; `%g` uses significant digits (default 6, with
precision 0 treated as 1), while `%f`/`%e` default to 6 fractional digits.
See `examples/advanced.pt`.

`strlen`, `strcontains`, `startswith`, `endswith`, `strcat`, and
`substr(string, constant_start, constant_length)` operate on strings.
`substr` indexes UTF-8 bytes and replaces incomplete sequences; bounds are 0..4096.
Concatenated results are limited to 4096 bytes. Integer casts `i8/i16/i32/i64` and
`u8/u16/u32/u64` explicitly truncate and sign/zero extend within the language's
64-bit bit patterns. Locals retain one type throughout their handler.

## Managed frames and JIT symbols

`pystack` / `pystack(N)` produce stack keys for **CPython 3.11–3.14 release builds** on
native 64-bit Linux, without injecting code into Python:

```sh
poortrace -p PID -d 10 -e 'profile:hz:99 { @[pystack] = count(); }'
```

The reader locates `_PyRuntime` and `Py_Version`, walks interpreter/thread lists,
and selects the sampled native TID. Python 3.13/3.14 use validated runtime debug
offset metadata. Function names, filenames, and current bytecode source lines
are decoded from bounded line tables. Reads
occur while processing an event, so asynchronous perf samples may observe a later
Python frame. Races, unsupported versions/build layouts, missing runtime symbols,
and access restrictions produce an explicit unavailable frame. Trace-reference
builds are rejected. Other physical Python frame layouts remain unavailable.
Suspended coroutine chains and Java/.NET logical stacks use explicit cooperative
adapters described below. CPython layout references:
[runtime](https://github.com/python/cpython/blob/v3.12.0/Include/internal/pycore_runtime.h),
[frames](https://github.com/python/cpython/blob/v3.12.0/Include/internal/pycore_frame.h).

`jsstack` / `jsstack(N)` read physical JavaScript frames from Node/V8:

```sh
poortrace -p PID -d 10 --mmap-pages 128 -e 'profile:hz:99 { @[jsstack] = count(); }'
poortrace -e 'syscall:enter:write { printf("%s", jsstack(20)); }' -- node app.js
```

Function and script names are decoded using exported `v8dbg_*` postmortem
metadata. Verified ScopeInfo schemas cover **Node 20/22/24 (V8 11.3/12.4/13.6)**.
Native 64-bit layouts and ordinary compressed heap fields are decoded; compressed
heap decoding has synthetic coverage and live validation with a compressed
Node 24.15 ARM build; CI also exercises a checksum-pinned compressed Node 20 x86
fixture. Other compatibility tests use uncompressed Node builds. Sequential one/two-byte, cons, thin, and
sliced UTF-16 strings and larger context scopes are supported. External strings,
missing metadata, and unknown schemas produce unavailable labels.
No Inspector connection, runtime flags, perf-map file, or injected code is needed.

Both interpreted and compiled frames can be read. Verified uncompressed V8
11.3/12.4/13.6 layouts reconstruct optimized inline chains and current source lines from
source-position/deoptimization metadata when available, and current interpreted
lines from bytecode positions. Inlined frames are labeled explicitly. Other
supported frames show marked function-start lines when available. Compressed
current/optimized source-position decoding still uses the cooperative Inspector
path below. Async ancestry and WebAssembly frames use that same explicit adapter.
Perf probes capture FP and bounded stack bytes automatically even in the default
stack mode; `--stack-bytes` controls the limit. Heap objects are read when the
handler runs, so GC/mutation races can make a sampled frame unavailable. Ptrace
syscall/function probes read the stopped thread. Polling wait/wakeup probes lack
FP registers and cannot provide `jsstack`. Missing, truncated, and unsupported
stacks produce an explicit unavailable label. Depth is 1..127 (default 127).
Recordings retain resolved stacks, allowing replay after the process exits.
V8 references: [metadata](https://github.com/nodejs/node/blob/v22.23.0/deps/v8/tools/gen-postmortem-metadata.py),
[ScopeInfo](https://github.com/nodejs/node/blob/v22.23.0/deps/v8/src/objects/scope-info.tq).

`gostack` / `gostack(N)` decode the running Go goroutine using the native Go
register, verified DWARF layouts for `runtime.g`/`runtime.m`, and captured stack
bounds. Native DWARF/CFI supplies function names, source lines, and available
inline chains. Goroutine identity and thread ownership are checked before and
after reading. `goroutines()` / `goroutines(depth, limit)` render bounded parked
goroutine snapshots (defaults 32/128, maxima 127/1024). Reads are best-effort
observations, not an atomic stop of all goroutines. These readers need retained
Go DWARF and ELF symbols for the general path. Stripped Go 1.22–1.25 executables,
including PIE, instead use verified reflection typelinks for runtime field
offsets and bounded `pclntab`/PC-SP tables for physical frames and source lines.
The parked-goroutine fallback requires a uniquely validated `allgs` candidate.
Unknown stripped schemas or ambiguous metadata report unavailable. Live stripped
tests cover Go 1.22–1.25; CI exercises 1.22/1.24 on both architectures.

Native frame symbolization also reads target-owned `/tmp/perf-PID.map` files
inside the target mount/PID namespace. This names JIT code when the runtime writes
perf maps; it does not manufacture unwind information or interpreter frames.
Maps refresh with native mappings, are limited to 16 MiB and 250,000 entries,
and fall back to raw addresses when unavailable.

## Cooperative logical stacks

Optional adapters provide suspended Python await chains, JVM and .NET diagnostic
stacks, and JavaScript async/WebAssembly frames. These require explicit target
cooperation or an enabled diagnostic interface. They produce bounded JSON
snapshots; poortrace checks PID, process start identity, age, frame limits, and
native TID association before using them. `--managed-max-age SECONDS` defaults
to 10 seconds. A stale snapshot fails explicitly.

```sh
# Start an asyncio application through the explicit startup adapter.
PYTHONPATH=adapters python3 adapters/python_async.py --output /tmp/python-stacks.json -- app.py
# In another terminal, use the application's PID.
poortrace -p PID --managed-snapshot /tmp/python-stacks.json -e 'interval:ms:100 { printf("%s\n", managedstacks(20)); }'

# Collect JVM or .NET stacks with the corresponding installed diagnostic tool.
python3 adapters/vm_snapshot.py java --pid PID --output /tmp/java-stacks.json
python3 adapters/vm_snapshot.py dotnet --pid PID --output /tmp/dotnet-stacks.json
# --tool PATH selects jcmd or dotnet-stack explicitly.

# Start Node with an explicitly enabled local Inspector endpoint.
node --inspect-brk=127.0.0.1:0 app.js
npm ci --prefix adapters --ignore-scripts
node adapters/node_inspector.mjs --pid PID --url ws://127.0.0.1:PORT/ID --output /tmp/js-stacks.json --run --resume --pause-ms 100
# Add --runtime wasm for WebAssembly frames.
```

`asyncstack(N)`, `jstack(N)`, `dotnetstack(N)`, and `wasmstack(N)` return a stack
for the observation's native thread when the adapter supplies that association.
`managedstacks(N)` returns labeled text for all snapshot threads and is useful
with interval probes. Inspector snapshots explicitly label process-level data;
they do not claim an arbitrary native TID. JVM virtual-thread dumps may omit
unmounted threads. Python walks suspended await/generator chains, without
inventing task creation ancestry. Inspector uses the debugger's async ancestry,
verifies that the socket belongs to the specified process, and does not evaluate
injected target code. `--pause-ms` explicitly requests periodic pauses; these
perturb the target. Node 20 uses the pinned `ws` dependency installed above.

Snapshots describe the adapter's collection time, which can differ from the
tracing observation. They are not exact CPU samples or causal execution totals.
Helper results are journaled and replay after the target and snapshot file are
gone. Native Python/Node/Go stack readers remain available independently.

## Sleeping-thread observations

```sh
poortrace -p PID -e 'wait:ms:10 { @[wait_reason, ustack] = count(); }'
poortrace -p PID -e 'wakeup:ms:5 { @wait[wait_reason] = hist(latency); }'
```

`wait` polls threads currently in sleeping/uninterruptible states and reads
`/proc/TID/syscall` and `wchan`. `wait_reason` labels the observed state, kernel wait
channel (when permitted), and syscall. `ustack` uses bounded stack bytes captured
with the observed syscall SP/IP; other registers are unavailable, so unwinding may
truncate. Stack reads support the full configured `--stack-bytes` range.
`wakeup` emits when a previously observed sleeping thread is observed
runnable; `latency` is elapsed time between those observations. Its native stack
bytes come from the initial sleeping snapshot.

These are **polling observations**, not scheduler events or exact off-CPU totals.
Short waits, intermediate wakeups, and threads between polls can be missed;
intervals must be at least 1 ms. Wakeup latency includes polling error. Waker
identity and exact causal blocking reasons are unavailable through this backend.
Ptrace probes can perturb observations. `period` is the requested polling interval;
`offcpu_ns` stays zero. Each batch has bounded thread/event/stack storage.
The separate `offcpu` probe retains its complete-switch-pair semantics.

## Recordings, live views, and comparisons

```sh
poortrace --record run.jsonl -e 'profile:hz:99 { @[ustack] = count(); }' -- /path/app
poortrace --replay run.jsonl --output-format flamegraph -o replay.svg
poortrace --replay run.jsonl --sort-events --output-format json -o ordered.json
poortrace --replay run.jsonl -e 'profile:hz:99 { @[pid] = count(); }'
poortrace --replay run.jsonl --output-format speedscope-timeline -o timeline.json
poortrace -p PID --live 1 --top 20 -e 'profile:hz:99 { @[ustack] = count(); }'
poortrace -p PID --compare baseline.json --output-format flamegraph -o difference.svg examples/stacks.pt
poortrace --quantiles 0.5,0.9,0.99 -e 'BEGIN { @h=hist(42); }'
```

Recordings are versioned newline-delimited JSON containing the original script,
per-handler timestamps and fields, native frames/branches, captured unwind
registers and stack bytes, tracepoint fields, and helper results (including
rendered managed stacks and memory reads). New recordings use version 3 and
record architecture/byte order; versions 1 and 2 remain readable. Default replay executes the original script and validates
helper order/types. `--replay FILE -e SCRIPT` or a script file selects an alternate
script over captured observations. It matches recorded probes, runs BEGIN/END
once, and coalesces duplicate handler observations with the same event identity.
Pure helpers and captured tracepoint fields can be recomputed; memory/runtime
helpers require a matching captured result. Native stacks/branches can fall back
to recorded raw addresses without reading a current target. Optional captured
memory regions allow new primitive reads entirely offline; conflicting captures
and uncaptured addresses fail explicitly. Replay uses the same native JIT; shared-LLVM binaries
still need their LLVM shared library, while static builds retain standalone
deployment. File/event limits are 256 MiB/1 MiB. Raw perf archiving, selected
memory, target output, and exit status are opt-in; entirely uncaptured events,
addresses, runtime state, and debug types cannot be manufactured during replay. `--sort-events` gives a stable global timestamp order; this can change the
results of order-sensitive aggregations. Per-thread events otherwise retain
recorded dispatch order.

Optional capture extensions are selected at recording time:

```sh
poortrace --record run.jsonl --record-raw -e 'profile:hz:99 { @[ustack] = count(); }' -- app
poortrace --replay run.jsonl --replay-raw -e 'profile:hz:99 { @[tid] = count(); }'
poortrace --record io.jsonl --record-output --capture-memory arg1:8 -e 'syscall:enter:write {}' -- app
poortrace --replay io.jsonl --replay-output --replay-exit-status
```

`--record-raw` preserves perf records, capture layout, and tracepoint formats.
`--replay-raw` decodes those records offline on a compatible architecture and
byte order, using archived formats rather than the current host's tracefs.
It retains sideband and loss/discontinuity records as well as samples.
`--capture-memory ADDRESS:LENGTH` can be repeated; addresses can also be `arg0`
through `arg5`, `sp`, or `ip`. Each region is 1..4096 bytes, with at most 256
regions and 256 KiB per observation. Capture errors stop the trace. Replay can
satisfy new primitive reads from these regions, with checked bounds and overlap
consistency; it cannot reconstruct uncaptured memory or type information.

`--record-output` forwards and archives a launched command's stdout/stderr;
exit status is recorded for launched commands. Output timestamps reflect receipt
by the tracer, and output inherited by descendants is attributed to the launch
PID. `--replay-output` emits those bytes and `--replay-exit-status` returns the
recorded status, including termination by tracer cleanup when applicable.

`--output-format speedscope-scheduler` exports observed CPU execution intervals
from a system-wide recording of `tracepoint:sched:sched_switch`. It requires
complete per-CPU coverage metadata and adjacent matching switch pairs. Missing
CPUs, lost events, throttling, discontinuities, or inconsistent pairs reject this
export. It does not extrapolate intervals at capture boundaries. This stricter
export is separate from the interpolated stack observation timeline below.

`--live SECONDS` redraws cumulative text maps in a terminal (or emits successive
snapshots when redirected); it does not clear script maps and cannot be combined
with `--window` or `--output`. `--window` continues to print and clear maps.
`--quantiles` applies to text reports and reports the containing histogram bucket
rather than an exact percentile; rows with negative bucket counts omit quantiles.
Histogram comparisons subtract matching bucket labels, including removed entries. Differential flamegraphs use absolute numeric
changes for widths, red for increases and blue for decreases; they are not CPU
utilization measurements. Text/JSON preserve signed differences.

Timeline Speedscope exports group captured stack observations by PID/TID,
order each thread by timestamp, and deduplicate repeated handler copies. Weights
span the time until the next observation of that thread (the last gets 1 ns).
This is an interpolated observation timeline, not exact execution or CPU time.
Captured stack strings preserve resolved names after the target exits; otherwise
frames retain raw addresses.

## Development and validation

The library modules in `src/` implement the tracing language, JIT, runtime,
collectors, and recording formats. The binary entry point is `src/main.rs`;
private CLI modules live in `src/app/`. Start with `app/mod.rs` for probe
preparation and backend selection, `app/cli.rs` for options, and the `perf`,
`syscalls`, `functions`, `reliable`, or `stat` module for a backend's event loop.
Shared process ownership, event dispatch, replay, and reporting live in
`app/process.rs`, `app/events.rs`, `app/replay.rs`, and `app/report.rs`.

```sh
cargo fmt --check
LLVM_CONFIG=llvm-config-18 cargo clippy --locked --all-targets -- -D warnings
LLVM_CONFIG=llvm-config-18 cargo test --locked
LLVM_CONFIG=llvm-config-18 cargo test --locked --features static-llvm
# Opt-in native tests require host perf/ptrace access and the fixture compilers.
LLVM_CONFIG=llvm-config-18 cargo test --locked --test cli -- --ignored --nocapture
LLVM_CONFIG=llvm-config-18 cargo test --locked --test process_coverage -- --ignored
LLVM_CONFIG=llvm-config-18 cargo test --locked --test reliable -- --ignored
LLVM_CONFIG=llvm-config-18 cargo test --locked --test arguments -- --ignored
# Select managed tests for the runtimes actually installed.
LLVM_CONFIG=llvm-config-18 cargo test --locked --test managed node_ -- --ignored --skip cooperative_
# Compressed V8 requires an actual pointer-compressed Node build.
POORTRACE_NODE_BIN=/path/to/compressed/node LLVM_CONFIG=llvm-config-18 cargo test --locked --test managed compressed_scope -- --ignored

LLVM_CONFIG=llvm-config-18 cargo build --release --locked --bins --examples
./target/release/poortrace examples/profile.pt -- ./target/release/examples/workload 2
./target/release/poortrace examples/faults.pt -- ./target/release/examples/workload 2
./target/release/poortrace --check examples/counters.pt
./target/release/poortrace --emit-llvm examples/interval.pt
```

The tests execute actual native JIT handlers with synthetic events, including
typed formatting, predicates, aggregation, arithmetic edge cases, output
failures, and capacity limits. They also exercise real process startup,
shutdown, timers, CLI errors, ring wraparound, and malformed perf records. Opt-in
live tests cover perf capture, native stacks, syscall/function probes, fork/exec
lifecycle and cleanup, USDT semaphores, typed reads, CPython frames, and Node
interpreted/optimized/worker frames and replay. CI runs shared/static LLVM tests,
selected ptrace/runtime tests, fully static builds on x86-64 and AArch64,
managed runtime compatibility jobs, cooperative JVM/.NET/Python/JS/Wasm adapter
tests, a checksum-pinned compressed V8 fixture, and Rust 1.85 checks. Stripped Go
fixtures cover executables and PIE builds; the compatibility matrix includes Go
1.22 and 1.24. Cooperative tests require Java 21 tools, .NET 8 with dotnet-stack,
Python, and Node; ordinary managed tests do not assume these adapters are installed.

See [AGENTS.md](AGENTS.md#source-map) for the complete source map, build checks,
and implementation invariants.

MIT licensed. Inspired by [bpftrace](https://github.com/bpftrace/bpftrace).
