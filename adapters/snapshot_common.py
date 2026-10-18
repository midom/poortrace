"""Versioned, atomic poortrace cooperative snapshots (no target injection)."""
import json
import os
import tempfile
import time


def start_ticks(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stream:
        return int(stream.read().rsplit(")", 1)[1].split()[19])


def publish(path, pid, runtime, threads, runtime_version="", captured_ms=None):
    snapshot = dict(version=1, pid=pid, start_ticks=start_ticks(pid),
                    captured_unix_ms=int(time.time() * 1000) if captured_ms is None else captured_ms,
                    runtime=runtime, runtime_version=runtime_version, threads=threads[:2048])
    for thread in snapshot["threads"]:
        thread["name"] = str(thread["name"])[:1024]
        thread["state"] = str(thread["state"])[:256]
        thread["frames"] = [str(frame)[:2048] for frame in thread["frames"][:127]]
    data = json.dumps(snapshot, ensure_ascii=True).encode()
    if len(data) > 1024 * 1024:
        raise ValueError("managed snapshot exceeds 1 MiB; reduce adapter thread/depth limits")
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=".poortrace-snapshot-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
