"""Callback flow audit (Python)."""
import os

def executor(cmd):
    os.system(cmd)  # SINK

def run(callback, value):
    callback(value)

def pass_to_callback():
    # POSITIVE: source flows through callback into sink.
    t = os.environ["CMD"]
    run(executor, t)
