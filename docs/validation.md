# Measurement and validation

## Benchmarks

Build and measure a fixed amount of work, rather than comparing workloads that
run for the same duration:

```sh
LLVM_CONFIG=llvm-config-18 cargo bench --locked --bench pipeline > pipeline.json
LLVM_CONFIG=llvm-config-18 cargo build --release --locked --bins --example benchmark_workload
python3 scripts/benchmark.py --runs 5 > workload.json
```

The pipeline benchmark reports compilation median/p95 over 20 runs, handler
throughput, recording bytes/second, archive decode and replay times, and process
peak RSS and RSS before/after growing a bounded map. `POORTRACE_BENCH_EVENTS` sets the number of synthetic handler invocations.
Compilation timing includes engine construction/destruction. RSS is the process
high-water mark for the whole benchmark, not isolated per-operation allocations.

The workload harness measures CPU/allocation work with repeated `getpid` calls,
then repeats it under interval, syscall, reliable, perf, and recording modes.
It reports individual timings, medians, slowdown relative to an untraced run,
and the last run's report including observed loss. Failures are recorded with
diagnostics as unavailable; they do not turn into zero overhead or passing tests.
Startup and compilation are included in traced workload durations. This fixture
is a reproducible stress case, not a prediction for every application.

CI uploads both JSON artifacts on x86-64/AArch64. Compare the same architecture,
LLVM/compiler, event count, and machine configuration. Shared hosted runners are
noisy; initial baselines are measurements, not pass/fail performance thresholds.
Use an otherwise idle dedicated machine before asserting a regression budget.

An illustrative [AArch64/LLVM 18 baseline](baselines/aarch64-linux-llvm18.json)
is included with raw timings and capability results. It measured a 2.45 ms median
compile, 8.55 million synthetic handler invocations/second, and approximately
4.2 MiB of RSS growth while adding 16,384 integer map entries. On the fixed-work
fixture, median slowdown was 2.31x for perf, 2.28x for reliable snapshots, 9.39x
for syscall stops, and 19.36x for recorded syscall stops. These short-workload
figures include startup/JIT costs; use the raw artifact and rerun on your own
workload rather than treating these ratios as steady-state overhead estimates.

The function-probe harness compiles a small native workload and checks a fixed
number of delivered entry events, with one active thread and optional sleeping
siblings. It needs a C compiler and ptrace access, without perf privileges:

```sh
python3 scripts/benchmark-functions.py --runs 3 --hits 500 --threads 1 12 > functions.json
```

An illustrative [AArch64/LLVM 18 comparison](baselines/aarch64-ptrace-throughput.json)
measured approximately 707 to 10,535 events/second with one thread, and 330 to
4,918 events/second with 12 threads, after replacing the sleep-based waits and
removing redundant process scans. These are medians of three release runs,
including startup/JIT/cleanup, with every run delivering exactly 500 events.
The workload measures tracer overhead; application calls, stacks, recording,
sibling activity, and scheduling can change the result substantially.

## Fuzzing and generated invariants

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
mkdir -p fuzz/corpus/inputs
cp fuzz/seeds/inputs/* fuzz/corpus/inputs/
LLVM_CONFIG=llvm-config-18 cargo +nightly fuzz run inputs -- -max_total_time=60 -max_len=65536 -print_funcs=0 -print_final_stats=1 -timeout=5 -rss_limit_mb=2048
```

The independent `fuzz/` package has its own lockfile and seeds. Its selector byte
routes inputs to the language, perf record, recording journal, BTF, or encoded
SDT reader. All targets are bounded and avoid target-process memory access.
The recording target uses the same streaming parser and limits as file replay.
CI runs a bounded smoke campaign; longer local campaigns remain useful. Promote
minimized crashes into ordinary regression tests. See the
[Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html) for the runner.

`tests/invariants.rs` also runs deterministic generated arithmetic inputs against
Rust wrapping semantics on stable Rust, including zero divisors, signed overflow,
and masked shifts, plus truncated-decoder and captured-stack boundary cases.

## Live perf runner

The manually dispatched `Live perf validation` workflow requires a trusted Linux
runner labeled `poortrace-perf`, LLVM 18 development files, native C/C++ compilers,
Python 3.12, and administrator-provisioned perf/tracefs access. Node and Go are
installed by the workflow. Register runners for each architecture you intend to
validate; a result on one host does not validate the other architecture or PMUs.
Do not expose a privileged runner to untrusted pull-request code.

Preflight probes record actual software sampling, hardware counter, watchpoint,
tracepoint, and system-wide access in `capabilities.json`. Software perf is
required; missing optional capabilities are visible and their suites are skipped.
An available capability with a failing test fails the job. The workflow never
changes perf policy. Regular CI continues to exercise ptrace, replay, managed
runtimes, shared/static LLVM, fully static binaries, MSRV, and LLVM 15/18.

## Releases

A `vVERSION` tag matching `Cargo.toml` builds fully static GNU/Linux binaries on
native x86-64 and AArch64 runners. Each archive includes the executable, license,
README, changelog, example scripts, and mode guide, with a separate SHA-256 checksum. Packaging
checks for a dynamic loader/shared dependencies and runs compilation/JIT smoke
tests against the staged executable. The workflow assembles a **draft** release;
review its validation and publish it manually.

Before tagging, update the crate version, lockfile, and changelog, run the default
and applicable live suites, and review benchmark/capability artifacts. No tag or
release is created merely by building this checkout.

For a downloaded archive, obtain the archive and matching `.sha256` from the same
release, then run:

```sh
sha256sum -c poortrace-VERSION-TARGET.tar.gz.sha256
tar -xzf poortrace-VERSION-TARGET.tar.gz
install -m 755 poortrace-VERSION-TARGET/poortrace ~/.local/bin/poortrace
poortrace --version
poortrace -q -e 'BEGIN { printf("%d\n", 6*7); exit(); }'
```

Create `~/.local/bin` and put it on `PATH` if needed. Checksums detect corruption;
they are not independent publisher signatures. Static glibc retains the platform
limitations described in the README.
