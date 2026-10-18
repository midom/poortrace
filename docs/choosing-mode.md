# Choosing a tracing mode

Start with the least expensive observation that answers your question, then
measure its effect on the workload with `scripts/benchmark.py`.

| Question | Mode | Interpretation and cost |
| --- | --- | --- |
| Where does this program consume CPU? | `profile:hz:99` | Asynchronous CPU-time samples. Start at a low rate; inspect reported loss. |
| How many events occurred? | `--stat` | Grouped counters with raw counts, enabled/running times, and scaled estimates. Unscheduled counters remain unavailable. |
| What happens at a syscall/function boundary? | `syscall:*`, `uprobe:*`, `usdt:*` | Ptrace stops; overhead grows with event rate. These stops change target timing. |
| Do sibling threads need to remain stopped during helpers? | `--reliable` | Verified pauses across tracked threads. Profiles are wall-clock snapshots; this mode can substantially perturb scheduling. |
| Can I inspect sleeping threads without scheduler events? | `wait:*`, `wakeup:*` | Polling observations, not exact sleep durations or waker identity. |
| Do I need CPU-wide scheduler transitions? | `--system-wide` plus `sched_switch` and raw recording | Requires host access. Exact scheduler exports require complete coverage proof and continuity. |
| Do I need the same evidence later? | `--record`, optionally `--record-raw` and bounded memory capture | Disk and allocation overhead. Replay uses archived evidence, never current target memory. |

For native stacks, use `--stack-mode fp` for targets with frame pointers, or
`--stack-mode dwarf` for captured-stack CFI unwinding. Recording and `jsstack`
can capture additional bytes but do not change this selection. Both algorithms
are bounded by available data and can return truncated stacks.

For perf-only runs, short-lived threads can escape the periodic discovery scan.
Use `--track-threads` when clone-stop attachment is worth its ptrace overhead.
Use `--follow-forks` for children created after attachment and
`--attach-descendants -p PID` to include a bounded initial descendant snapshot.

Export JSON to retain measurement provenance. Speedscope and SVG embed it;
text and folded output can use `--report-metadata run.metadata.json`.
`lost_samples: 0` means no loss records were received, not proof of complete
sampling. Missing legacy loss information is `null`. Only scheduler exports
with explicit coverage proof claim complete switch intervals.

Host perf/ptrace policy and PMU availability vary. Run
`python3 scripts/check-capabilities.py --binary /path/to/poortrace` to inspect
actual access. This command does not alter host policy. Do not compensate for
access failures by changing probe semantics.

Use durations, conservative sampling rates, and small scripts for a first run.
See the main README for the supported syntax and examples; the tracer is not a
sandbox for untrusted scripts and does not implement full bpftrace compatibility.
