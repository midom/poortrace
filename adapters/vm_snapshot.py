#!/usr/bin/env python3
"""Explicit supported JVM/.NET diagnostics to poortrace JSON snapshots."""
import argparse
import os
import re
import subprocess
import sys
import time
from snapshot_common import publish, start_ticks


def collect(command, timeout):
    import selectors
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("runtime diagnostic tool exceeded its deadline")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                data.extend(chunk)
                if len(data) > 8 * 1024 * 1024:
                    raise RuntimeError("runtime diagnostic output exceeds 8 MiB")
        child.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        selector.close()
        child.stdout.close()
        if child.poll() is None:
            child.kill()
        child.wait()
    output = data.decode("utf-8", "replace")
    if child.returncode:
        raise RuntimeError(output[:4096])
    return output


def java_threads(text):
    threads, current = [], None
    for line in text.splitlines():
        match = re.match(r'^"([^"]+)".*?\bnid=(0x[\da-fA-F]+|\d+)\b', line)
        if match:
            current = dict(tid=int(match[2], 0), name=match[1], state="JVM thread", frames=[])
            threads.append(current)
        elif current is not None:
            if "java.lang.Thread.State:" in line:
                current["state"] = line.split("java.lang.Thread.State:", 1)[1].strip()
            elif line.lstrip().startswith("at ") and len(current["frames"]) < 127:
                current["frames"].append(line.strip()[3:])
    return [thread for thread in threads if thread["frames"]]


def dotnet_threads(text):
    threads, current = [], None
    for line in text.splitlines():
        match = re.match(r'^Thread\s+\((0x[\da-fA-F]+|\d+)\)', line.strip())
        if match:
            current = dict(tid=int(match[1], 0), name=match[0], state=".NET diagnostic stack", frames=[])
            threads.append(current)
        elif current is not None and line.strip() and not line.startswith(" ") and not line.startswith("\t"):
            # Current dotnet-stack emits method lines without indentation.
            if len(current["frames"]) < 127 and not line.startswith(("---", "#")):
                current["frames"].append(line.strip())
        elif current is not None and line.strip() and len(current["frames"]) < 127:
            current["frames"].append(line.strip())
    return [thread for thread in threads if thread["frames"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime", choices=["java", "dotnet"])
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--tool", help="jcmd or dotnet-stack executable (uses PATH by default)")
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.pid <= 0 or not 0.1 <= args.interval <= 3600 or not 0.1 <= args.timeout <= 60:
        parser.error("invalid PID/interval/timeout")
    identity = start_ticks(args.pid)
    command = [args.tool or ("jcmd" if args.runtime == "java" else "dotnet-stack")]
    command += [str(args.pid), "Thread.print", "-l"] if args.runtime == "java" else ["report", "--process-id", str(args.pid)]
    while True:
        captured = int(time.time() * 1000)
        if start_ticks(args.pid) != identity:
            raise RuntimeError("target process identity changed")
        text = collect(command, args.timeout)
        threads = java_threads(text) if args.runtime == "java" else dotnet_threads(text)
        if not threads:
            raise RuntimeError("diagnostic tool returned no recognizable logical frames")
        if start_ticks(args.pid) != identity:
            raise RuntimeError("target process identity changed during collection")
        publish(args.output, args.pid, args.runtime, threads, captured_ms=captured)
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(f"poortrace VM adapter: {error}")
