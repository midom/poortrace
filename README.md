# poortrace

A bpftrace-inspired tracing tool written in Rust. It compiles script predicates,
arithmetic, and control flow to native machine code with LLVM MCJIT, then runs
those handlers over Linux `perf_event_open` samples in userspace. It does not load
eBPF programs and needs no BPF privileges.

```sh
cargo build --release
./target/release/poortrace -e 'profile:hz:99 { @[comm, ip] = count(); }' -- ./my-program
./target/release/poortrace -p 1234 -d 10 -e 'software:page-faults:100 { @[tid] = count(); }'
./target/release/poortrace examples/interval.pt
```

This implements the subset described below, rather than full bpftrace language
or probe compatibility. `~/bpftrace` was used as a local reference for probe and
language conventions; poortrace has no build or runtime dependency on it.

## Build

Requires 64-bit Linux on **x86-64 or AArch64**, Rust 1.85 or newer, a C linker,
and LLVM 15 or newer with development files and its shared library (or static
archives for static builds). LLVM 18 is
tested on AArch64. LLVM's stable C API is bound directly; no C++ bindings or
particular `llvm-sys` crate version are required.

On Ubuntu with LLVM 18 available:

```sh
sudo apt install build-essential llvm-18-dev
LLVM_CONFIG=llvm-config-18 cargo build --release --locked
./target/release/poortrace --help
```

`LLVM_CONFIG` defaults to `llvm-config`. The selected library directory is
embedded in the executable's runtime library search path. Deployment still
requires the corresponding LLVM shared library. `cargo install --path . --locked`
installs the binary in Cargo's bin directory.

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

Use your normal user account. All perf events attach to specific target threads
with `cpu=-1`, `exclude_kernel=1`, and `exclude_hv=1`. Access remains subject to
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

`BEGIN`, `END`, interval-only scripts, `--check`, and `--emit-llvm` do not open
perf events. `--list` shows recognized event names, not a guarantee that the host
supports every event.

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
| `wait:ms:N`, `wakeup:ms:N` | Sleeping-thread snapshots and observed sleeping-to-runnable transitions |
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

* Signed 64-bit decimal integers, hexadecimal bit patterns, UTF-8 strings,
  `true`, `false`, parentheses, `//` and `/* */` comments.
* Integer builtins: `pid`, `tid`, `cpu`, `nsecs`, `ip`, `period`. `nsecs` uses
  `CLOCK_MONOTONIC`; `period` is the sample's perf counter period. String
  builtins: `comm`, `probe`, and `syscall` (empty outside syscall handlers).
  Additional integers: `addr` (sampled data address when provided), `offcpu_ns`,
  `preempt`, `sysno`, `retval`, `latency`, and `arg0` through `arg5`. Values that
  do not apply to a handler are zero; `latency` and `offcpu_ns` are nanoseconds.
* User stacks: `ustack` or `ustack()` captures up to 127 user frames;
  `ustack(N)` limits output to a constant depth from 1 to 127. Stacks can be map
  keys or arguments to `printf("%s", ...)`. They have a distinct key type and
  print as indented frames, leaf first. They cannot be used as integers.
* Arithmetic `+ - * / %`, bitwise `& | ^ ~ << >>`, comparisons, unary `!`,
  and short-circuit `&& ||`. Strings support `==` and `!=` by content.
* `$local = expression`, `+=`, `-=`, `++`, `--`, and `if (...) { ... } else { ... }`.
  Locals hold consistently typed integers, strings, or stack values, start at zero/empty, and reset on each handler invocation.
* Persistent maps: `@`, `@name`, and `@name[key, ...]`. Keys may mix strings
  and integers. A map's key types and aggregation must be consistent throughout
  the script. Missing scalar entries read as zero.
* Map assignment, `+=`, `-=`, `++`, `--`, and direct aggregation assignments:
  `count()`, `sum(expr)`, `min(expr)`, `max(expr)`, `avg(expr)`, `hist(expr)`,
  `lhist(expr, min, max, step)`. Linear bounds must be integer constants with
  min < max, positive step, and at most 1024 buckets. Underflow and overflow
  get separate buckets; the final ordinary bucket ends at max.
  Average rounds toward zero. Histograms use power-of-two buckets, a zero bucket,
  and one negative bucket; use `print` to inspect a histogram.
* `printf("literal format", ...)`: `%d`, `%i`, `%u`, `%x`, `%X`, `%o`, `%s`,
  `%c`, `%p`, `%%`, optional `l`/`ll`, width up to 200, `-` and zero padding.
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
  sibling threads can modify shared memory.
* `branches` is an indented list of sampled user branch source/destination
  symbols. Using it, or `--branch-stack`, requests branch history. The PMU must
  support it; `examples/branches.pt` uses a hardware branch event. The most
  recent 128 branch entries are retained. This is history, not a call stack.
* `print(@map)`, `clear(@map)`, `exit()`. Maps are also printed automatically
  at shutdown unless `--no-print-maps` is given. Clear a map after an explicit
  final print if duplicate output is undesirable.

Arithmetic wraps; division/remainder by zero returns zero; `INT64_MIN / -1`
wraps to `INT64_MIN`; shift amounts are masked to 0..63. Script strings cannot
be used as raw pointers. Map output is sorted by key. Each map is limited to
65,536 entries by default; `--max-map-entries` changes that limit. Exceeding it
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
need larger rings or lower sample rates. Native unwinding needs native unwind metadata. `pystack` separately reads supported CPython frames; perf-map files can name native JIT frames (see below).

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

`--output-format` accepts `text` (default), `json`, `folded`, `speedscope`, or
`flamegraph` (standalone SVG). `-o/--output` writes the final report to a file;
script `printf`/`print` and launched-command output still go to stdout, so use
an output file for machine-readable reports when they might print. Exported
stack profiles use nonnegative numeric map values as weights, root first, with
map names and other keys as labels. Speedscope exports are **aggregated weights**,
not a time-ordered recording. Exports allow at most 256 frames per row including
labels. Empty captures produce empty profiles.

`--top N` ranks final entries by absolute value within each map; `--percent`
uses the absolute-value total before top-N filtering; `--rate` divides numeric
values by elapsed wall time. These two annotations apply to text map reports.
`--window SECONDS` emits text snapshots on stdout and clears all maps, including
maps used by the script; it cannot be combined with `--output` or other report
formats. Script `print(@map)` retains its normal immediate rendering.

`--compare FILE` subtracts numeric map values from a previous poortrace JSON
report, matching map names and typed rendered keys; missing current keys appear
as negative values. It supports text, JSON, and differential flamegraphs, and also subtracts histogram buckets by label in text/JSON. Stack comparisons depend on consistent resolved labels; unavailable
symbols or changed modules can change those labels. Reports show delivered
sample/aggregation weights, not exact CPU utilization or uncertainty bounds.

## Counter reads

```sh
./target/release/poortrace --stat --stat-events hardware:cycles,hardware:instructions -- ./my-program
./target/release/poortrace --stat --stat-events software:cpu-clock,software:page-faults -p 1234 -d 5
```

`--stat` needs no script. It reads groups of 1..16 hardware, software, raw,
cache, or named-PMU counters per thread. The default is cycles and instructions;
choose software events on hosts without a suitable hardware PMU. Reports include
raw values and summed enabled/running times. Scaling is computed per thread
before summing; a group that never ran has an unavailable scaled value.
Multiplexed totals are estimates. Text reports include IPC when cycles and
instructions are present in the group. `--output-format json` and `--output`
are supported. Existing/new threads use the same 100 ms discovery limitation
as sampling; counters are read before descriptors are dropped.

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
cannot share the target. Pre-existing processes sharing its address space outside
the target thread group are not supported.

Entry probes expose the first six integer/pointer arguments in `arg0..arg5` under
the native calling convention. Floating-point/vector, stack-passed, language ABI,
and aggregate arguments are not decoded. Return probes preserve entry argument
register values and provide raw signed `retval` plus `latency` including debugger
overhead; only normal matched returns generate events. Recursion and threads are
tracked separately. Nonlocal unwinding, tail-call transformations, and unusual
stack switching can prevent matching returns; at most 4096 pending returns,
1024 active breakpoints, and 256 probe bindings are allowed. `ustack` uses a
bounded snapshot of the stopped thread's stack and native CFI, limited by
`--stack-bytes`.

Loaded instances are located through target mappings, accounting for PIE/ASLR
and shared libraries. The loader is traced until initial bindings appear;
subsequent mappings are rescanned every 100 ms, so brief load/unload activity can
be missed. Thread clones are followed. By default, child processes do not produce script events; fork/vfork children are briefly controlled as needed to restore inherited breakpoints safely. `--follow-forks` includes descendant events and exec transitions. BEGIN/END/interval, syscall, and perf probes can share the same ptrace-backed run. Perf events still require host permission; ptrace timing changes also affect mixed samples.

`--uprobe-backend perf` selects kernel uprobes instead and allows mixing with
other perf probes. It registers dynamic uprobe/uretprobe perf descriptors directly,
without BPF or tracefs writes. Linux kernels including 6.17 require CAP_SYS_ADMIN
for this interface, independently of `perf_event_paranoid`; it is **not** the
unprivileged default. This path uses asynchronous samples, can lose hits, and
exposes argument registers on entry and the return-value register on return;
it does not retain entry arguments or function latency for return probes.

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
`latency`. Timing includes ptrace overhead and scheduling while stopped. Syscall stops can capture `ustack` from the stopped thread with bounded native CFI unwinding. PMU branch history belongs to perf samples.

Syscall probes can share scripts with BEGIN/END/interval, function, and perf probes. Launch gating and BEGIN still precede command execution;
launcher syscalls before exec are omitted. Existing threads are seized and
subsequent thread clones are followed; initial attachment races remain possible.
`--follow-forks` follows child processes across exec; otherwise only threads are followed. Signals and group stops are preserved; cleanup
detaches attached targets and cleans up owned command groups. No privilege or
host-policy changes are performed. See [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)
and [process_vm_readv](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
for their separate access checks.

## Target lifecycle and limits

Perf and syscall probes require `-p PID`, `-c 'shell command'`, or `-- executable args...`.
Launched commands wait behind a pipe gate until streams are attached and
`BEGIN` has completed. Their initial perf streams enable at exec so launcher
setup work is excluded. The launched command's exit status becomes the tracer's
exit status. `-c` uses `/bin/sh -c`; use `-c 'exec my-program ...'` to replace
the shell when the workload would otherwise be a separate child process.

The tracer stops on target exit, `exit()`, Ctrl-C/SIGTERM, or `--duration SECONDS`.
`END` runs at shutdown and remaining maps are printed. Early termination cleans
up the launched process group; an attached PID is never signaled. An exit from
`BEGIN` prevents command execution. Command stdout shares the tracer's stdout.
Launched commands run in a separate process group and are intended for
non-interactive workloads.

Existing target threads are attached individually. New threads are discovered
every 100 ms, so their early events, and threads shorter than the scan interval,
can be missed. `--track-threads` uses ptrace lifecycle stops to attach new perf streams before new threads resume; `--follow-forks` also includes children created after attachment and waits for them after the original process exits. Pre-existing descendant processes are not automatically attached. These options require ptrace access and introduce stops. Launched process trees use pidfds and a tracer-local subreaper for descendant cleanup, requiring Linux 5.3+; attached process trees are detached without termination signals. Initial attachment races remain, and this is not an atomic attach to an existing process tree. The default avoids perf's
`inherit`/`cpu=-1` mmap restriction and limits the number of streams to one per
thread/probe rather than one per CPU. There is no system-wide mode.

Samples are buffered and handled asynchronously in userspace; this is not a
synchronous debugger or kernel probe engine. Per-stream order is preserved,
but streams are not globally timestamp-sorted. `ip` remains a raw user address;
user callchains and ELF/DWARF symbols are available through `ustack`. Bounded
read-only memory helpers are available, but kprobes, tracepoints,
BTF and complete bpftrace language compatibility remain outside this implementation. Bounded loops and selected DWARF structure reads are available as described below. Counter samples are not exact
counter totals: `count()` counts delivered samples, while `sum(period)` sums
their recorded periods; neither includes lost samples or PMU multiplexing
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
eight FP/SIMD argument registers as strings; FP register zero also holds ordinary
scalar FP returns. `sarg(N)` reads one of the first sixteen raw 8-byte stack
argument slots: immediately above the return address on x86-64, at entry SP on
AArch64. These are ABI-level reads; signatures, varargs, vector arguments, and
aggregate calling conventions are not inferred. Return-time stack slots do not
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

Layout lookup requires DWARF in the selected image. Typedefs and qualifiers are
followed; scalar reads are limited to 1/2/4/8 bytes. Bitfields, nonconstant
member-location expressions, cross-unit type references, automatic aggregate ABI
decoding, and ambiguous layouts are rejected. ELF input is bounded to 128 MiB,
expanded DWARF sections to 256 MiB, and type traversal to 32 levels.

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

Expression functions must be defined before use, take at most sixteen parameters,
and evaluate each argument once. Recursion and forward references are unsupported;
expansion is resource-limited. `repeat(N)` accepts a constant 1..1024, with a shared
4096-iteration budget per handler invocation, including nested repeats. Local
numeric arrays have 256 zero-initialized elements each, reset on invocation;
out-of-bounds access ends the trace. At most 128 local array names are allowed.
`delete(@map[key,...])` removes an individual entry.

`strlen`, `strcontains`, `startswith`, `endswith`, `strcat`, and
`substr(string, constant_start, constant_length)` operate on strings.
`substr` indexes UTF-8 bytes and replaces incomplete sequences; bounds are 0..4096.
Concatenated results are limited to 4096 bytes. Integer casts `i8/i16/i32/i64` and
`u8/u16/u32/u64` explicitly truncate and sign/zero extend within the language's
64-bit bit patterns. Locals retain one type throughout their handler.

## Managed frames and JIT symbols

`pystack` / `pystack(N)` produce stack keys for **CPython 3.12 release builds** on
native 64-bit Linux, without injecting code into Python:

```sh
poortrace -p PID -d 10 -e 'profile:hz:99 { @[pystack] = count(); }'
```

The reader locates `_PyRuntime` and `Py_Version`, walks interpreter/thread lists,
and selects the sampled native TID. Function names, filenames, and **function
starting lines** are shown; these are not current bytecode line numbers. Reads
occur while processing an event, so asynchronous perf samples may observe a later
Python frame. Races, unsupported versions/build layouts, missing runtime symbols,
and access restrictions produce an explicit unavailable frame. Trace-reference
builds are rejected. Other Python versions, suspended coroutine logical stacks,
and Java stacks are not implemented. CPython layout references:
[runtime](https://github.com/python/cpython/blob/v3.12.0/Include/internal/pycore_runtime.h),
[frames](https://github.com/python/cpython/blob/v3.12.0/Include/internal/pycore_frame.h).

`jsstack` / `jsstack(N)` read physical JavaScript frames from Node/V8:

```sh
poortrace -p PID -d 10 --mmap-pages 128 -e 'profile:hz:99 { @[jsstack] = count(); }'
poortrace -e 'syscall:enter:write { printf("%s", jsstack(20)); }' -- node app.js
```

Function and script names are decoded using exported `v8dbg_*` postmortem
metadata. ScopeInfo names currently require **V8 12.4 (Node 22)**; tested against
Node 22.23.3 on AArch64. Native 64-bit builds with 8-byte tagged pointers are
supported; pointer-compressed builds and binaries without metadata report an
unavailable frame. Sequential one/two-byte, cons, and thin strings are decoded;
external/sliced strings and scopes with over 32 context locals are unsupported.
No Inspector connection, runtime flags, perf-map file, or injected code is needed.

Both interpreted and compiled physical frames can be read. Inlined functions,
async ancestry, source line numbers, and WebAssembly frames are not reconstructed.
Perf probes capture FP and bounded stack bytes automatically even in the default
stack mode; `--stack-bytes` controls the limit. Heap objects are read when the
handler runs, so GC/mutation races can make a sampled frame unavailable. Ptrace
syscall/function probes read the stopped thread. Polling wait/wakeup probes lack
FP registers and cannot provide `jsstack`. Missing, truncated, and unsupported
stacks produce an explicit unavailable label. Depth is 1..127 (default 127).
Recordings retain resolved stacks, allowing replay after the process exits.
V8 references: [metadata](https://github.com/nodejs/node/blob/v22.23.0/deps/v8/tools/gen-postmortem-metadata.py),
[ScopeInfo](https://github.com/nodejs/node/blob/v22.23.0/deps/v8/src/objects/scope-info.tq).

Native frame symbolization also reads target-owned `/tmp/perf-PID.map` files
inside the target mount/PID namespace. This names JIT code when the runtime writes
perf maps; it does not manufacture unwind information or interpreter frames.
Maps refresh with native mappings, are limited to 16 MiB and 250,000 entries,
and fall back to raw addresses when unavailable.

## Sleeping-thread observations

```sh
poortrace -p PID -e 'wait:ms:10 { @[wait_reason, ustack] = count(); }'
poortrace -p PID -e 'wakeup:ms:5 { @wait[wait_reason] = hist(latency); }'
```

`wait` polls threads currently in sleeping/uninterruptible states and reads
`/proc/TID/syscall` and `wchan`. `wait_reason` labels the observed state, kernel wait
channel (when permitted), and syscall. `ustack` uses bounded stack bytes captured
with the observed syscall SP/IP; other registers are unavailable, so unwinding may
truncate. `wakeup` emits when a previously observed sleeping thread is observed
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
poortrace -p PID --live 1 --top 20 -e 'profile:hz:99 { @[ustack] = count(); }'
poortrace -p PID --compare baseline.json --output-format flamegraph -o difference.svg examples/stacks.pt
poortrace --quantiles 0.5,0.9,0.99 -e 'BEGIN { @h=hist(42); }'
```

Recordings are versioned newline-delimited JSON containing the original script,
per-handler timestamps and fields, and captured helper results (including rendered
stacks and memory reads). Replay executes the same script offline and never reads
live target memory for those helpers. Target stdout is not recorded. File/event
limits are 256 MiB/1 MiB. This is a handler-invocation log, not a raw perf record
archive; scripts cannot be replaced during replay. Replay checks helper order and
types. `--sort-events` gives a stable global timestamp order; this can change the
results of order-sensitive aggregations. Per-thread events otherwise retain
recorded dispatch order.

`--live SECONDS` redraws cumulative text maps in a terminal (or emits successive
snapshots when redirected); it does not clear script maps. `--window` continues to
print and clear them. `--quantiles` reports the containing histogram bucket rather
than an invented exact percentile. Histogram comparisons subtract matching bucket
labels, including removed entries. Differential flamegraphs use absolute numeric
changes for widths, red for increases and blue for decreases; they are not CPU
utilization measurements. Text/JSON preserve signed differences.

## Development and validation

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
# Optional live perf tests; requires a host allowing unprivileged sampling:
cargo test --test cli -- --ignored --nocapture

cargo build --release --examples
./target/release/poortrace examples/profile.pt -- ./target/release/examples/workload 2
./target/release/poortrace examples/faults.pt -- ./target/release/examples/workload 2
./target/release/poortrace --check examples/counters.pt
./target/release/poortrace --emit-llvm examples/interval.pt
```

The tests execute actual native JIT handlers with synthetic events, including
typed formatting, predicates, aggregation, arithmetic edge cases, output
failures, and capacity limits. They also exercise real process startup,
shutdown, timers, CLI errors, ring wraparound, and malformed perf records. Live
tests cover command launching and attachment to an existing PID.

Source layout: `language.rs` (lexer/parser and probe specs), `codegen.rs` (typed
AST to LLVM IR), `llvm.rs` (C API and MCJIT lifetime), `perf.rs` (syscall and mmap
ring), `runtime.rs` (map/output callbacks), `main.rs` (CLI and event loop).

MIT licensed. Inspired by [bpftrace](https://github.com/bpftrace/bpftrace).
