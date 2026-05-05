"""Cross-file argument flow audit fixture (Python).

The fixture is split across four files to exercise transitive
cross-file propagation:

    app.py       -> reads source, calls into pipeline.py
    pipeline.py  -> wraps + forwards into transformer.py
    transformer.py -> identity transforms, calls executor.py
    executor.py  -> consumes the value at the cmdi sink

A working adapter must propagate taint across THREE module boundaries
(app -> pipeline -> transformer -> executor) for the chain to fire.
"""
import os
from pipeline import run_pipeline


def handler():
    # POSITIVE: source in app.py, sink three modules away.
    user = os.environ["CMD"]
    run_pipeline(user)


def handler_split():
    # POSITIVE: source split into two args, both flow.
    user = os.environ["FROM"]
    flag = os.environ["FLAG"]
    run_pipeline(user + ":" + flag)
