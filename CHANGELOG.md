# Changelog

## Unreleased

- Expand userspace bpftrace helper support: map queries/stats/time series, strings and networking, identity/symbol/register helpers, diagnostics, script arguments, stack formats, and exit statuses. Add explicitly gated commands/signals/writes and session watchpoint removal, with captured-result replay and specific no-BPF capability errors. See the helper compatibility guide for limits and differences.

- Allow `print()` on scalar values, expressions, and map entries; add formatted wall-clock output with `time()` and capture its text for deterministic replay.

- Wake ptrace function loops on child-status notifications, resume targets immediately after safe breakpoint rearming, and avoid redundant per-hit thread scans. Add exact-count hot-loop regressions and a reproducible function throughput benchmark.

- Unlimited probe/breakpoint counts by default, optional `--max-probes` and `--max-breakpoints` budgets, and batched/indexed native function attachment for large wildcard matches.

- Accept short provider names (`u`, `ur`, `U`, `k`, `kr`, `t`, `i`, `p`, `s`, `h`, `w`) with canonical names in events and recordings.
- Resolve process-scoped function globs such as `u:*http*` and mapped-image globs with `-p PID`; support matching them during offline replay.

- Discover concrete native entry/return and USDT probes in an existing process with `-l -p PID`, including mapped libraries and function/marker filtering.

- Honor the selected native stack unwinder independently of recording and managed stack capture.
- Export versioned CLI JSON reports with measurement provenance; retain legacy JSON comparison imports.
- Preserve recording provenance during replay and label wall-clock profiles in exported files.
- Add `--report-metadata` for text/folded report sidecars.
- Share capture planning and periodic report refresh across tracing backends.
- Add generated arithmetic/decoder regressions, bounded fuzz targets, pipeline and workload benchmarks.
- Add LLVM 15/18 compatibility, benchmark/fuzz CI, opt-in live perf validation, and draft release packaging.

CLI JSON reports now use `{ "schema_version": 1, "metadata": { ... }, "rows": [...] }`.
Consumers of the previous top-level array should read `rows`. Library report calls
without provenance continue to return arrays. Recordings remain schema 3; older
schema 1/2/3 journals remain readable.

## 0.1.0

Initial tracing language, native LLVM JIT, perf/ptrace tracing, managed stack
readers, bounded memory capture, offline replay, and profile exports.
