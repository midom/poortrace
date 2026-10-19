#!/usr/bin/env python3
"""Measure fixed ptrace function hits with one active thread and sleeping siblings."""
import argparse
import json
import platform
import re
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", default="target/release/poortrace")
parser.add_argument("--runs", type=int, default=3)
parser.add_argument("--hits", type=int, default=500)
parser.add_argument("--threads", type=int, nargs="+", default=[1, 12])
args = parser.parse_args()
if args.runs < 1 or args.hits < 1 or any(t < 1 or t > 512 for t in args.threads):
    parser.error("runs/hits must be positive and thread counts must be 1..512")
binary = str(Path(args.binary).resolve())
fixture = Path(__file__).resolve().parents[1] / "tests/fixtures/function_throughput.c"
results = {}
with tempfile.TemporaryDirectory(prefix="poortrace-function-benchmark-") as directory:
    workload = Path(directory) / "workload"
    subprocess.run(["cc", "-O2", "-g", "-pthread", "-fno-omit-frame-pointer", str(fixture), "-o", str(workload)], check=True)
    script = f'u:{json.dumps(str(workload))}:throughput_hit {{ @hits=count(); }}'
    for threads in args.threads:
        elapsed = []
        for _ in range(args.runs):
            started = time.perf_counter()
            result = subprocess.run([binary, "-q", "-e", script, "--", str(workload), str(args.hits), str(threads)], capture_output=True, text=True, timeout=120)
            if result.returncode:
                raise SystemExit(result.stderr)
            count = re.search(r"^@hits: (\d+)$", result.stdout, re.MULTILINE)
            if not count or int(count[1]) != args.hits:
                raise SystemExit(f"incorrect delivered count: {result.stdout}")
            elapsed.append(time.perf_counter() - started)
        results[str(threads)] = {"elapsed_s": elapsed, "median_events_s": args.hits / statistics.median(elapsed)}
print(json.dumps({"platform": platform.platform(), "binary": binary, "hits": args.hits, "runs": args.runs, "threads": results}, indent=2))
