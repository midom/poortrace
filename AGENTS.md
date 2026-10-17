# Project guide

## Purpose and scope

poortrace is a bpftrace-inspired userspace tracer written in Rust. It parses a
small tracing language, compiles handlers to native code with LLVM MCJIT, and
invokes those handlers for Linux `perf_event_open` samples. It does not load BPF
programs. See `README.md` for supported syntax, probes, examples, and limitations.

Supported targets are 64-bit Linux on x86-64 and AArch64. The crate uses Rust
edition 2024 with a minimum Rust version of 1.85. Runtime dependencies are `libc`
and `clap`; LLVM is accessed through direct C API bindings.

## Source map

- `src/language.rs`: lexer, parser, AST, probe specifications, and event names.
- `src/codegen.rs`: type checking, map declarations, LLVM IR generation, and the
  public `Program` compilation/invocation interface.
- `src/llvm.rs`: LLVM C API bindings, native target initialization, MCJIT, callback
  registration, and engine/context ownership.
- `src/runtime.rs`: event ABI, typed map keys, aggregations, formatting, output,
  and callbacks called by generated code.
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
The CLI consumes perf records and invokes handlers serially with an `Event` and
the compiled program's `State`.

## Build and validation

Install a C linker and LLVM 15 or newer with development files and its shared
library. `LLVM_CONFIG` defaults to `llvm-config`; CI uses LLVM 18:

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

Live perf tests are ignored by default because host policy can deny sampling:

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
- Existing threads are attached individually; new threads are currently found
  by scanning `/proc/PID/task` every 100 ms. Early events and threads that finish
  between scans can be missed. Child processes are not followed. Do not describe
  this as complete or immediate thread coverage.
- Perf inheritance with `cpu=-1` has mmap sampling restrictions. Account for
  those restrictions when changing thread attachment.
- Launched commands wait behind a pipe gate until attachment and `BEGIN` finish.
  Initial events enable on exec to exclude launcher setup work.
- Shutdown runs `END` and prints maps unless disabled. Early termination cleans
  up a launched process group; attached processes must never be signaled.
- Samples are asynchronous, ordered within each stream, and not globally sorted.
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
