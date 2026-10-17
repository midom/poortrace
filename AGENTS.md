# Project guide

## Purpose and scope

poortrace is a bpftrace-inspired userspace tracer written in Rust. It parses a
small tracing language, compiles handlers to native code with LLVM MCJIT, and
invokes those handlers for Linux `perf_event_open` samples, ptrace stops, timers,
and polling observations. Recorded invocations can also be replayed offline.
It does not load BPF programs. See `README.md` for supported syntax, probes,
examples, and limitations.

Supported targets are 64-bit Linux on x86-64 and AArch64. The crate uses Rust
edition 2024 with a minimum Rust version of 1.85. Runtime dependencies are `libc`
and `clap`, ELF/DWARF readers (`object`, `addr2line`, `framehop`), demanglers, and
Serde for profile/report formats; LLVM is accessed through direct C API bindings.

## Source map

- `src/language.rs`: lexer, parser, AST, probe specifications, and event names.
- `src/codegen.rs`: type checking, map declarations, LLVM IR generation, and the
  public `Program` compilation/invocation interface.
- `src/llvm.rs`: LLVM C API bindings, native target initialization, MCJIT, callback
  registration, and engine/context ownership.
- `src/runtime.rs`: event ABI, typed map keys, aggregations, formatting, output,
  and callbacks called by generated code.
- `src/symbols.rs`: target mappings, ELF/DWARF symbol lookup, sampled-stack CFI
  unwinding, perf-map JIT names, and user-stack rendering.
- `src/recording.rs`: bounded, versioned invocation/helper journals and offline replay.
- `src/python.rs`: read-only, version-checked CPython frame walking.
- `src/javascript.rs`: V8 metadata discovery and read-only JavaScript frames.
- `src/types.rs`: bounded DWARF scalar/structure layout reads.
- `src/usdt.rs`: SystemTap SDT notes and native argument descriptors.
- `src/wait.rs`: sleeping-thread snapshots and observed wakeup transitions, not exact scheduler events.
- `src/report.rs`: text/JSON reports, comparisons, folded stacks, Speedscope, and SVG flamegraphs.
- `src/memory.rs`: bounded read-only process_vm_readv helpers.
- `src/counters.rs`: grouped per-thread counter reads and scheduling-time scaling.
- `src/functions.rs`: all-stop ptrace function breakpoints, return matching, fork handling, and text restoration.
- `src/uprobe.rs`: ELF symbol/file-offset resolution and optional dynamic perf uprobe registration data.
- `src/syscall.rs`: ptrace syscall/lifecycle tracking and detach cleanup; native
  syscall-name tables live in `src/syscalls/{x86_64,aarch64}.txt`.
- `src/perf.rs`: perf attributes, event descriptors, mmap ring consumption,
  record decoding, and perf access diagnostics.
- `src/main.rs`: CLI, signal handling, process launch gate, thread discovery,
  stream attachment, polling, timers, and shutdown.
- `build.rs`: discovers LLVM through `llvm-config`, selects shared or static
  linking, and embeds its version and (for shared builds) runtime library path.
- `tests/jit.rs`: native JIT integration tests using synthetic events.
- `tests/cli.rs`: CLI, timers, process lifecycle, and opt-in live perf tests.
- `examples/*.pt`: sample tracing scripts. `examples/workload.rs` provides CPU
  and allocation work on the main thread and dynamically created worker threads.

The data path is script → AST → typed LLVM IR → MCJIT handler → runtime callbacks.
The CLI dispatches perf records, ptrace syscall/function stops, timers, wait
snapshots, or recorded invocations serially with an `Event` and the compiled
program's `State`.

## Build and validation

Install a C linker and LLVM 15 or newer with development files and its shared
library (or static archives for static builds). `LLVM_CONFIG` defaults to
`llvm-config`; CI uses LLVM 18:

```sh
LLVM_CONFIG=llvm-config-18 cargo build --locked
cargo fmt --check
LLVM_CONFIG=llvm-config-18 cargo clippy --locked --all-targets -- -D warnings
LLVM_CONFIG=llvm-config-18 cargo test --locked
```

`--features static-llvm` links LLVM component archives; `RUSTFLAGS='-C
target-feature=+crt-static'` with an explicit native `--target` selects a fully
static build, including LLVM. See `README.md` for archive prerequisites. CI
tests shared LLVM, static LLVM, and fully static builds.

Run checks appropriate to the change. Parser and perf decoder unit tests live
alongside their implementations. Language and runtime changes should also be
covered by synthetic-event JIT tests. CLI and lifecycle changes belong in
`tests/cli.rs`.

Live tests are ignored by default because perf/ptrace access, native C/C++
compilers, and runtime installations vary by host. The complete suite needs
CPython 3.12 and Node 22 (V8 12.4), as well as permitted software perf sampling
and hardware watchpoint support:

```sh
LLVM_CONFIG=llvm-config-18 cargo test --locked --test cli -- --ignored --nocapture
```

Smoke tests that need no perf access:

```sh
cargo run --locked -- --check examples/counters.pt
cargo run --locked -- --emit-llvm examples/interval.pt
cargo run --locked -- -q -d 0.1 -e 'interval:ms:10 { @ticks = count(); }'
```

Distinguish host permission or PMU limitations from implementation failures.
Do not change host perf policy to make tests pass.

## Tracing behavior and constraints

- Perf probes require an attached PID or a launched command. Each thread/probe
  has its own descriptor and mmap ring, with `cpu=-1`, kernel/hypervisor execution
  excluded, and inheritance disabled.
- In perf-only and counter runs without ptrace tracking, existing threads are
  attached individually and new threads are found by scanning `/proc/PID/task`
  every 100 ms. Early events and threads that finish between scans can be missed.
  Syscall/ptrace function backends already follow thread clones. Opt-in
  `--track-threads` attaches perf streams/counters at clone stops; `--follow-forks`
  also follows children created after attachment across exec and waits for the
  followed tree after root exit. Pre-existing descendants are not automatically
  attached; initial attachment races remain.
- Perf inheritance with `cpu=-1` has mmap sampling restrictions. Account for
  those restrictions when changing thread attachment.
- Launched commands wait behind a pipe gate until attachment and `BEGIN` finish.
  Initial events enable on exec to exclude launcher setup work.
- Shutdown runs `END` and prints maps unless disabled. Early termination cleans
  up the launched process group and, with `--follow-forks`, tracked owned
  descendants using pidfds and a tracer-local subreaper (Linux 5.3+). Cleanup must
  never send termination signals to attached processes; preserve signal delivery
  and detach behavior for ptrace targets.
- Perf samples are asynchronous, ordered within each stream, and not globally sorted.
- Syscall/function stops can share a run with perf samples. One ptracer owns
  each target; preserve signals/group stops, launch gating, and detach cleanup.
  Keep address-space breakpoint/semaphore state separate across private forks
  and exec, and coordinate CLONE_VM/vfork address spaces.
- Function probes default to ptrace. Restore patched text and rewind pending INT3
  stops before detach, coordinate all threads while stepping, and restore inherited
  breakpoints in fork children. Never silently fall back between intrusive backends.
  Restore active SDT semaphores only in their matching images. Kernel perf
  uprobes are an explicit privileged alternative; no BPF is loaded.
- Off-CPU intervals require complete switch pairs; clear pending pairs on loss.
  Switch records do not carry a blocking stack or establish why a task waited.
- Counter reads distinguish raw counts, scheduling times, and scaled estimates.
  Preserve unscheduled (unavailable) results and read groups before dropping them.
- Memory helpers are read-only, limited to 4096 bytes, and subject to ptrace checks.
  Current ptrace/polling native-stack reads share this limit: use
  `--stack-bytes 4096` or less; the 16384-byte default leaves those snapshots empty.
  Perf-sampled stack capture supports 8..32768 bytes. Ptrace `jsstack` reads frame
  slots directly; polling snapshots lack FP and cannot provide JS frames.
  `count()` counts delivered samples; `sum(period)` is not an exact counter total.

## Implementation invariants

- Keep Rust `repr(C)` event/key layouts, callback signatures, aggregate operation
  values, and LLVM declarations in sync. Event string pointers must remain valid
  throughout a handler invocation, and handlers must not outlive their engine.
- Invoke a handler only with `State` created by the same `Program`; its metadata
  determines callback indexing and types.
- Callbacks must not unwind through JIT frames. Report runtime/output errors
  through `State` and let the event loop observe them.
- Preserve perf ring head/tail memory ordering, wraparound handling, record-size
  validation, and final draining before dropping streams with buffered samples.
- Between `fork` and `exec`, use only async-signal-safe operations. Preserve the
  launch gate, signal restoration, child reaping, and cleanup on error paths.
- Preserve defined arithmetic behavior: wrapping integers, zero for division or
  remainder by zero, wrapping `INT64_MIN / -1`, and shift counts masked to 0..63.
- Retain parser/resource limits and type checks when extending the language.
  Update `README.md`, examples, CLI help, and tests when user-visible behavior
  changes.
- Script repeats share a 4096-iteration invocation budget; local arrays and
  inlined expression functions must retain parser, expansion, and type limits.
- Replay must validate helper result types before exposing pointers to JIT code.
  Never read current target memory to reconstruct a recorded helper result.
- `pystack` currently supports CPython 3.12 release layouts; `jsstack` requires
  exported V8 metadata and 8-byte tagged pointers, with ScopeInfo names gated to
  V8 12.4 (Node 22). Keep these layout gates explicit; unavailable/racy frames are
  observable labels. V8 heap reads are bounded and read-only; sampled
  stack slots must come from the captured stack rather than a later live stack.
- Polling wait/wakeup observations do not identify wakers or exact sleep times.
