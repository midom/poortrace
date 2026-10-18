#!/usr/bin/env python3
"""Repeat fixed work, measuring slowdown against an untraced run; never change host policy."""
import argparse
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", default="target/release/poortrace")
parser.add_argument("--workload", default="target/release/examples/benchmark_workload")
parser.add_argument("--runs", type=int, default=5)
parser.add_argument("--rounds", type=int, default=2000)
parser.add_argument("--modes", nargs="+", choices=["interval", "syscall", "reliable", "perf", "record"], default=["interval", "syscall", "reliable", "perf", "record"])
args = parser.parse_args()
if args.runs < 1 or args.rounds < 1:
    parser.error("runs and rounds must be positive")
workload = [str(Path(args.workload).resolve()), str(args.rounds)]

def measure(command):
    samples = []
    for _ in range(args.runs):
        started = time.perf_counter_ns()
        result = subprocess.run(command, capture_output=True, timeout=120, check=False)
        elapsed = time.perf_counter_ns() - started
        if result.returncode:
            return {"status": "unavailable", "exit_status": result.returncode, "diagnostic": result.stderr.decode(errors="replace")[-4000:]}
        samples.append(elapsed)
    return {"status": "ok", "elapsed_ns": samples, "median_ns": statistics.median(samples)}

baseline = measure(workload)
if baseline["status"] != "ok":
    raise SystemExit(f"baseline failed: {baseline}")
cpu_model = {}
for line in Path("/proc/cpuinfo").read_text().splitlines():
    key, separator, value = line.partition(":")
    if separator and key.strip() in {"model name", "Hardware", "CPU implementer", "CPU part", "CPU architecture"}:
        cpu_model.setdefault(key.strip(), value.strip())
results = {}
with tempfile.TemporaryDirectory(prefix="poortrace-benchmark-") as directory:
    report = Path(directory) / "report.json"
    for mode in args.modes:
        script = {"interval": "interval:ms:10 { @samples=count(); }", "syscall": "syscall:enter:getpid { @samples=count(); }", "reliable": "profile:hz:99 { @samples=count(); }", "perf": "profile:hz:99 { @samples=count(); }", "record": "syscall:enter:getpid { @samples=count(); }"}[mode]
        command = [str(Path(args.binary).resolve()), "-q", "--output-format", "json", "--output", str(report), "-e", script]
        if mode == "reliable": command += ["--reliable"]
        if mode == "record": command += ["--record", str(Path(directory) / "recording.jsonl")]
        result = measure(command + ["--"] + workload)
        if result["status"] == "ok":
            result["slowdown"] = result["median_ns"] / baseline["median_ns"]
            result["last_run_report"] = json.loads(report.read_text())
        results[mode] = result
print(json.dumps({"schema_version": 1, "platform": platform.platform(), "architecture": platform.machine(), "cpu_count": os.cpu_count(), "cpu_model": cpu_model, "runs": args.runs, "rounds": args.rounds, "perf_event_paranoid": Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip(), "baseline": baseline, "modes": results}, indent=2))
