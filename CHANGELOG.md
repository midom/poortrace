# Changelog

## Unreleased

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
