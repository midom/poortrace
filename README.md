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

Periods and rates must be positive decimal integers. Use `--list` for names,
including `cpu-clock`, `task-clock`, `page-faults`, `minor-faults`, `major-faults`,
`context-switches`, `cpu-migrations`, `cycles`, `instructions`, `cache-misses`,
and `branch-misses`. The default period is 1,000,000 for hardware events and
software clock events (nanoseconds for the latter), and 1 for other software
events. Availability and user-mode filtering semantics depend on the kernel/PMU.

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
  builtins: `comm` and `probe`.
* Arithmetic `+ - * / %`, bitwise `& | ^ ~ << >>`, comparisons, unary `!`,
  and short-circuit `&& ||`. Strings support `==` and `!=` by content.
* `$local = expression`, `+=`, `-=`, `++`, `--`, and `if (...) { ... } else { ... }`.
  Locals hold integers, start at zero, and reset on each handler invocation.
* Persistent maps: `@`, `@name`, and `@name[key, ...]`. Keys may mix strings
  and integers. A map's key types and aggregation must be consistent throughout
  the script. Missing scalar entries read as zero.
* Map assignment, `+=`, `-=`, `++`, `--`, and direct aggregation assignments:
  `count()`, `sum(expr)`, `min(expr)`, `max(expr)`, `avg(expr)`, `hist(expr)`.
  Average rounds toward zero. Histograms use power-of-two buckets, a zero bucket,
  and one negative bucket; use `print` to inspect a histogram.
* `printf("literal format", ...)`: `%d`, `%i`, `%u`, `%x`, `%X`, `%o`, `%s`,
  `%c`, `%p`, `%%`, optional `l`/`ll`, width up to 200, `-` and zero padding.
  Argument counts and types are checked before execution. Escapes: `\n`, `\r`,
  `\t`, `\\`, `\"`. C varargs are not used.
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

## Target lifecycle and limits

Perf probes require `-p PID`, `-c 'shell command'`, or `-- executable args...`.
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
can be missed. Child **processes** are not followed. This avoids perf's
`inherit`/`cpu=-1` mmap restriction and limits the number of streams to one per
thread/probe rather than one per CPU. There is no system-wide mode.

Samples are buffered and handled asynchronously in userspace; this is not a
synchronous debugger or kernel probe engine. Per-stream order is preserved,
but streams are not globally timestamp-sorted. IPs are raw user addresses;
stack unwinding, symbolization, arbitrary process-memory access, kprobes,
uprobes, tracepoints, USDT, BTF, loops, structs, and the rest of bpftrace's
language are outside this implementation. Counter samples are not exact
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
