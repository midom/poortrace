"""Opt-in Python asyncio snapshots using Python-level frame/coroutine APIs."""
import asyncio
import inspect
import os
import sys
import threading

# The adapter directory is deliberately added only by an explicit launcher/import.
from snapshot_common import publish


def coroutine_frames(coroutine, depth=127):
    frames, seen = [], set()
    current = coroutine
    while current is not None and len(frames) < depth and id(current) not in seen:
        seen.add(id(current))
        if not (inspect.iscoroutine(current) or inspect.isgenerator(current) or inspect.isasyncgen(current)):
            break
        frame = getattr(current, "cr_frame", None) or getattr(current, "gi_frame", None) or getattr(current, "ag_frame", None)
        if frame is not None:
            frames.append(f"{frame.f_code.co_qualname} ({frame.f_code.co_filename}:{frame.f_lineno})")
        current = getattr(current, "cr_await", None) or getattr(current, "gi_yieldfrom", None) or getattr(current, "ag_await", None)
    frames.reverse()
    return frames


def snapshot(path, loop=None, depth=127, limit=128):
    loop = loop or asyncio.get_running_loop()
    threads = []
    tid = threading.get_native_id()
    for task in sorted(asyncio.all_tasks(loop), key=lambda task: task.get_name())[:limit]:
        frames = coroutine_frames(task.get_coro(), depth)
        if not frames:
            frames = [f"{frame.f_code.co_qualname} ({frame.f_code.co_filename}:{frame.f_lineno})" for frame in task.get_stack(limit=depth)]
        threads.append(dict(tid=tid, name=task.get_name(), state="cancelled" if task.cancelled() else "done" if task.done() else "suspended/running asyncio task", frames=frames))
    publish(path, os.getpid(), "python", threads, sys.version.split()[0])


def install(path, loop=None, interval=0.05, depth=127, limit=128):
    """Schedule observational snapshots on the supplied running event loop."""
    loop = loop or asyncio.get_running_loop()
    if not 0.01 <= interval <= 3600 or not 1 <= depth <= 127 or not 1 <= limit <= 2048:
        raise ValueError("adapter interval/depth/task limit is out of bounds")
    def capture():
        if loop.is_closed():
            return
        try:
            snapshot(path, loop, depth, limit)
        except (OSError, ValueError, RuntimeError) as error:
            print(f"poortrace asyncio snapshot: {error}", file=sys.stderr)
        if loop.is_running():
            loop.call_later(interval, capture)
    loop.call_soon(capture)
