"""False-positive audit fixture (Python).

Two functions exercise non-flowing source/sink coexistence:
- decoy: tainted value bound to an unused local; sink reads a constant.
- unrelated_chain: routine code with no source or sink at all.

Engine MUST report 0 findings.
"""
import os

CONST_OK = "ls /tmp"


def decoy():
    # NEGATIVE: tainted value in `_unused`, but sink reads CONST_OK.
    _unused = os.environ["IGNORED"]
    os.system(CONST_OK)


def unrelated_chain():
    # NEGATIVE: routine code, no source or sink.
    a = "hello"
    b = a.upper()
    return b
