"""Sanitizer credit audit (Python)."""
import os
import shlex

def unsanitized():
    # POSITIVE
    t = os.environ["CMD"]
    os.system(t)

def sanitized():
    # NEGATIVE — shlex.quote sanitizes for shell use.
    t = os.environ["CMD"]
    safe = shlex.quote(t)
    os.system(safe)
