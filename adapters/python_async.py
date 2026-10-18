#!/usr/bin/env python3
"""Explicit startup adapter: python python_async.py --output snap.json -- app.py."""
import argparse
import asyncio
import runpy
import sys
from poortrace_python import install

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", required=True)
parser.add_argument("--interval", type=float, default=0.05)
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
command = args.command[1:] if args.command[:1] == ["--"] else args.command
if not command:
    parser.error("provide a Python script after --")
# This wrapping happens only in the explicitly requested adapter launcher. It
# schedules a public loop callback; it neither traces bytecode nor changes tasks.
original = asyncio.BaseEventLoop.run_forever
installed = set()
def run_forever(loop):
    if id(loop) not in installed:
        installed.add(id(loop))
        install(args.output, loop, args.interval)
    return original(loop)
asyncio.BaseEventLoop.run_forever = run_forever
sys.argv = command
runpy.run_path(command[0], run_name="__main__")
