"""Assignment-chain stress fixture for the bonsai-ninja Python adapter.

Each `# POSITIVE: ...` comment marks a flow that MUST report.
Each `# NEGATIVE: ...` marks a clean twin / decoy that MUST NOT report.
The audit harness asserts both invariants.
"""
import os
from flask import request
from executor import run_in_other_file


CONST_OK = "ls /tmp"


def passthrough(x):
    return x


def wrap(x):
    return "wrapped:" + x


def combine(acc, item):
    return acc + ":" + item


class Bag:
    def __init__(self):
        self.payload = ""


def chain_simple(req):
    # POSITIVE: simplest tmp = source(); sink(tmp).
    tmp = req.args.get("c1")
    os.system(tmp)


def chain_multi_hop(req):
    # POSITIVE: 4-hop assignment chain through pure-passthrough functions.
    t1 = req.args.get("c2")
    t2 = passthrough(t1)
    t3 = wrap(t2)
    t4 = passthrough(t3)
    os.system(t4)


def chain_branch_join(req, cond):
    # POSITIVE on the tainted branch; the constant branch is a clean twin.
    if cond:
        t = req.args.get("c3")
    else:
        t = "safe-static"
    # The merge point joins both possibilities; engine should report only
    # the tainted leg as the source.
    os.system(t)


def chain_loop_carried(req, items):
    # POSITIVE: the accumulator starts tainted and is rebound each iteration
    # via combine(acc, item). The carried value is still tainted.
    acc = req.args.get("c4")
    for item in items:
        acc = combine(acc, item)
    os.system(acc)


def chain_field_write(req):
    # POSITIVE: container/field write. The sink reads obj.payload.
    bag = Bag()
    bag.payload = req.args.get("c5")
    os.system(bag.payload)


def chain_subscript_write(req):
    # POSITIVE: subscript write through dict.
    cmds = {}
    cmds["x"] = req.args.get("c6")
    os.system(cmds["x"])


# NOTE: per-instance field aliasing (`safe_bag.payload` clean while
# `tainted_bag.payload` is tainted) is a separate audit concern
# (Task #265, receiver-type resolution) and isn't tested here. This
# fixture scopes to assignment-chain propagation only.


def chain_clean_constant(req):
    # NEGATIVE: source is unused; sink reads a constant. No flow.
    _ = req.args.get("ignored")
    os.system(CONST_OK)


def chain_cross_file(req):
    # POSITIVE: passes tainted value across module boundary; the sink
    # lives in executor.py.
    t = req.args.get("c9")
    run_in_other_file(t)


def chain_shadowed_var(req):
    # The outer t is tainted; an inner re-binding shadows with a clean
    # constant; sink in inner scope must NOT fire (negative). The
    # outer-scope sink fires (positive).
    t = req.args.get("c10")
    def inner():
        t = "safe-shadowed"   # shadow
        os.system(t)          # NEGATIVE: reads shadowed clean local.
    inner()
    os.system(t)              # POSITIVE: outer t still tainted.
