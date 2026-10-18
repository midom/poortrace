#!/usr/bin/env python3
"""Check actual tracing access without changing perf policy or requesting privileges."""
import argparse
import ctypes
import json
import os
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", default="target/debug/poortrace")
parser.add_argument("--output", default="capabilities.json")
args = parser.parse_args()
binary = str(Path(args.binary).resolve())
watched = ctypes.c_long(0)
checks = {
    "software_perf": ["-e", "profile:hz:99 {}", "--", "/bin/sleep", "0.03"],
    "hardware_perf": ["--stat", "--stat-events", "hardware:cycles", "--", "/bin/sleep", "0.03"],
    "kernel_tracepoint": ["-e", "tracepoint:syscalls:sys_enter_write {}", "--", "/bin/echo", "preflight"],
    "system_wide": ["--system-wide", "--stat", "--stat-events", "software:cpu-clock"],
    "watchpoint": ["-p", str(os.getpid()), "-e", f"watchpoint:{ctypes.addressof(watched)}:8:w {{}}"],
}
results = {}
for name, command in checks.items():
    try:
        result = subprocess.run([binary, "-q", "-d", "0.02"] + command, capture_output=True, timeout=10, check=False)
        diagnostic = result.stderr.decode(errors="replace")[-4000:]
        results[name] = {"available": result.returncode == 0, "exit_status": result.returncode, "diagnostic": diagnostic}
    except subprocess.TimeoutExpired:
        results[name] = {"available": False, "diagnostic": "capability check timed out"}
Path(args.output).write_text(json.dumps(results, indent=2) + "\n")
for name, result in results.items():
    print(f"{name}: {'available' if result['available'] else 'unavailable'} {result.get('diagnostic', '').strip()}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"{name}={str(result['available']).lower()}\n")
