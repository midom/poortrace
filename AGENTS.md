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
- `src/recording.rs`: bounded schema-3 invocation/helper/memory and metadata
  journals, archived perf decoding, alternate replay, and observation/scheduler
  Speedscope exports.
- `src/capture.rs`: explicit bounded event-time memory capture requests.
- `src/python.rs`: read-only, version-checked CPython frame walking.
- `src/javascript.rs`: V8 metadata discovery and read-only JavaScript frames.
- `src/golang.rs` and `src/golang_pcln.rs`: running/parked Go goroutine snapshots
  from DWARF or validated stripped-image metadata.
- `src/managed_bridge.rs`: bounded, identity-checked cooperative runtime snapshots.
- `adapters/`: explicit Python async, Node inspector/async/Wasm, JVM, and .NET
  snapshot producers; installing an adapter does not attach it automatically.
- `src/kernel.rs`: tracefs field metadata, raw payload decoding, kernel PMU setup,
  kernel symbols, and bounded online CPU enumeration.
- `src/btf.rs`: bounded kernel BTF type layouts and read-only typed fields.
- `src/arguments.rs`: native C ABI argument plans and stopped-register reads.
- `src/native_args.rs`: bounded native DWARF argument-location evaluation.
- `src/types.rs`: bounded DWARF scalar/structure layout reads.
- `src/usdt.rs`: SystemTap SDT notes and native argument descriptors.
- `src/wait.rs`: sleeping-thread snapshots and observed wakeup transitions, not exact scheduler events.
- `src/report.rs`: text/JSON reports, comparisons, folded stacks, Speedscope, and SVG flamegraphs.
- `src/memory.rs`: bounded read-only process_vm_readv helpers.
- `src/counters.rs`: grouped per-thread/per-CPU counters and scheduling-time scaling.
- `src/functions.rs`: all-stop ptrace function breakpoints, return matching, fork handling, and text restoration.
- `src/uprobe.rs`: ELF symbol/file-offset resolution and optional dynamic perf uprobe registration data.
- `src/syscall.rs`: ptrace syscall/lifecycle tracking and detach cleanup; native
  syscall-name tables live in `src/syscalls/{x86_64,aarch64}.txt`.
- `src/perf.rs`: perf attributes, event descriptors, mmap ring consumption,
  record decoding, and perf access diagnostics.
- `src/reliable.rs`: stopped-target CLI backend, wall-clock profile snapshots,
  and verified pauses around handlers; it never opens perf descriptors.
- `src/main.rs`: CLI, signal handling, process launch gate, thread discovery,
  stream attachment, polling, timers, and shutdown.
- `build.rs`: discovers LLVM through `llvm-config`, selects shared or static
  linking, and embeds its version and (for shared builds) runtime library path.
- `tests/jit.rs`: native JIT integration tests using synthetic events.
- `tests/cli.rs`: CLI, timers, process lifecycle, and opt-in live perf tests.
- `tests/{managed,process_coverage,arguments,kernel_cli,recording_features,float_reports,expansion,reliable}.rs`:
  focused runtime, lifecycle, ABI, kernel decoder/replay, and report regressions.
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
`tests/cli.rs` or the focused lifecycle suites.

Live tests are ignored by default because perf/ptrace access, native C/C++
compilers, and runtime installations vary by host. The complete suite needs
a supported CPython 3.11–3.14, Node 20/22/24, and Go compiler, as well as
permitted software perf sampling and hardware watchpoints. Adapter tests also
need their corresponding VM and diagnostic tools; see `adapters/` and README.
Kernel live tests separately require readable tracefs and kernel perf access:

```sh
LLVM_CONFIG=llvm-config-18 cargo test --locked --test cli -- --ignored --nocapture
LLVM_CONFIG=llvm-config-18 cargo test --locked --test process_coverage -- --ignored --nocapture
LLVM_CONFIG=llvm-config-18 cargo test --locked --test recording_features
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

- Default perf probes require an attached PID or a launched command. Each
  thread/probe has its own descriptor/ring with `cpu=-1` and inheritance disabled.
  `--system-wide` instead opens per-online-CPU streams; `--include-kernel`,
  tracepoints, and kernel probes request kernel execution with host-enforced
  permissions. Never suppress a CPU attachment error by testing it as a PID.
  Dynamic kprobes use the perf PMU without global tracefs registration or BPF.
- In perf-only and counter runs without ptrace tracking, existing threads are
  attached individually and new threads are found by scanning `/proc/PID/task`
  every 100 ms. Early events and threads that finish between scans can be missed.
  Syscall/ptrace function backends already follow thread clones. Opt-in
  `--track-threads` attaches perf streams/counters at clone stops; `--follow-forks`
  also follows children created after attachment across exec and waits for the
  followed tree after root exit. `--attach-descendants -p PID` takes a bounded
  snapshot of existing descendants and implies fork following. Initial attachment
  races remain. Function tracing can include declared `--shared-mm-pids` only
  after `kcmp(KCMP_VM)` proves shared ownership; stop every declared peer before
  patching. Permission failures or unproven ownership must fail safely.
- `--reliable` routes supported probes through the all-stop ptrace backend.
  Verify visible sibling coverage before handlers, retain pending stop events,
  skip pre-exec launcher snapshots, and detach on every error path. Profile
  probes in this mode are wall-clock thread snapshots, never CPU-time samples.
  External shared-memory writers and runtime safepoints are not guaranteed.
  Do not silently accept asynchronous or cooperative-snapshot probes in this mode.
- Perf inheritance with `cpu=-1` has mmap sampling restrictions. Account for
  those restrictions when changing thread attachment.
- Launched commands wait behind a pipe gate until attachment and `BEGIN` finish.
  Initial events enable on exec to exclude launcher setup work.
- Shutdown runs `END` and prints maps unless disabled. Early termination cleans
  up the launched process group and, with `--follow-forks`, tracked owned
  descendants using pidfds and a tracer-local subreaper (Linux 5.3+). Cleanup must
  never send termination signals to attached processes; preserve signal delivery
  and detach behavior for ptrace targets.
- Perf samples explicitly use `CLOCK_MONOTONIC`, matching ptrace/timer events.
  They remain asynchronous and ordered within each stream, not globally sorted.
  Cross-CPU scheduler correlations require ordered, complete recorded observations;
  raw tracepoint fields do not establish higher-level blocking causes.
- Syscall/function stops can share a run with perf samples. One ptracer owns
  each target; preserve signals/group stops, launch gating, and detach cleanup.
  Keep address-space breakpoint/semaphore state separate across private forks
  and exec, and coordinate CLONE_VM/vfork address spaces.
- Function probes default to ptrace. Restore patched text and rewind pending INT3
  stops before detach, coordinate all threads while stepping, and restore inherited
  breakpoints in fork children. Never silently fall back between intrusive backends.
  `--track-loads` refreshes on mapping syscall stops. Restore original words and
  active SDT semaphores for still-mapped matching images when execute permission
  disappears, using full mapping identity rather than executable mappings alone.
  Match tail-call returns and prune observable abandoned calls within their stack
  domain. Preserve suspended stacks in distinct VMAs or validated explicit
  `--stack-range TID:LOW:HIGH` ranges; unknown same-VMA stack allocation cannot
  be inferred safely. Never replace an unknown existing trap. Kernel perf uprobes
  are an explicit privileged alternative; no BPF is loaded.
- Off-CPU intervals require complete switch pairs; clear pending pairs on loss,
  throttling, or other recorded discontinuities.
  Switch records do not carry a blocking stack or establish why a task waited.
- Counter reads distinguish raw counts, scheduling times, and scaled estimates.
  Preserve unscheduled (unavailable) results and read groups before dropping them.
- Memory helpers are read-only, limited to 4096 bytes, and subject to ptrace checks.
  Stack snapshot reads have a separate 32768-byte bound, preserve accessible
  prefixes, and support the full CLI size range for perf, ptrace, and polling.
  Ptrace `jsstack` reads frame slots directly; polling snapshots lack FP and
  cannot provide JS frames.
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
- Repeat, while, map iteration, and recursive expression calls share invocation
  fuel of 4096. Recursion additionally has depth 64 and a conservative 512 KiB
  native-frame budget; keep per-call local scopes independent. Iteration uses
  bounded snapshots, so mutation cannot extend the current walk. Retain
  local-array, expression expansion, snapshot, and type limits.
- Float maps/keys require finite values; preserve float-key ordering and canonical
  zero equality. Scalar float operations follow IEEE behavior; integer arithmetic
  retains its defined wrapping and division behavior. Keep JSON/profile weight
  type restrictions explicit.
- Typed C ABI arguments require validated DWARF or an explicit supported
  signature, plus native register-bank/stack classification. Reject unsupported
  layouts, conventions, and variadic signatures.
  Validate alignment and register exhaustion across aggregates/vectors. `args()`
  uses the declared C calling convention; `args_native()` evaluates available
  DWARF locations without guessing Rust/Go ABIs. Reject unavailable entry spills,
  unsupported location operations, and unprovable register or memory pieces.
- Replay must validate helper result types before exposing pointers to JIT code.
  Never read current target memory or its current ELF files to reconstruct a
  recorded helper result. Alternate replay recomputes deterministic helpers and
  captured trace fields; other helpers need captured descriptors/results or an
  explicit raw-address stack/branch fallback. Honor new script exit semantics
  while running BEGIN/END once. Schema 3 retains architecture/endianness, raw
  perf layout/trace formats, captured memory, output bytes, exits, and loss/gap
  metadata; keep readers backward compatible with schemas 1 and 2. Raw replay
  decodes archived bytes and formats only, with matching native architecture and
  endianness. Coalesce exact event identities while preserving all handler
  captures; reject conflicting contexts or overlapping bytes when read. Bounded
  new memory reads require captured regions, never a current target process.
- Observation timelines interpolate samples; label them accordingly. Exact
  scheduler exports require an authoritative sched_switch clause, complete
  per-CPU coverage proof, matching adjacent next/previous tasks, and no loss,
  throttle, descriptor replacement, or other discontinuity. Do not extrapolate
  before the first or after the last switch or silently downgrade missing proof.
- `pystack` supports verified CPython 3.11–3.14 release layouts; newer versions
  use validated runtime debug offsets. `jsstack` uses exported V8 metadata and
  verified Node 20/22/24 schemas, including ordinary compressed heap fields.
  Verified uncompressed V8 12.4 layouts expose interpreted/optimized current
  lines and optimized inline chains when source/deoptimization metadata exists;
  other lines are marked function starts. Keep unknown layouts explicitly unavailable.
- `gostack`/`goroutines` use DWARF or validated Go 1.22–1.25 pclntab/reflection
  metadata; recover runtime structure offsets from metadata rather than guessing
  stripped layouts. Validate captured g registers, native TID/curg identity, stack
  bounds, and observed state before/after reads. V8 heap reads are bounded and
  read-only; sampled stack slots must come from the captured stack.
- Cooperative snapshot adapters require explicit configuration and matching PID,
  process start identity, timestamp freshness, runtime, and thread association.
  Preserve their snapshot/cooperative labels: they are not event-time stack reads
  or automatic arbitrary-process VM injection.
- Polling wait/wakeup observations do not identify wakers or exact sleep times.
