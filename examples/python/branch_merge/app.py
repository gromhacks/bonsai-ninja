"""Branch-merge precision audit (Python)."""
import os
CONST_OK = "ls /tmp"

def taint_one_leg(cond):
    # POSITIVE: tainted leg flows through merge to sink.
    if cond:
        x = os.environ["CMD"]
    else:
        x = "safe-static"
    os.system(x)

def taint_overwritten(cond):
    # NEGATIVE: both legs overwrite — taint must not survive.
    x = os.environ["CMD"]
    if cond:
        x = "clean-then"
    else:
        x = "clean-else"
    os.system(x)
