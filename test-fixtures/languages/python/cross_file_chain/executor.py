"""Cross-file pipeline stage 3 — sink."""
import os


def execute(cmd):
    # POSITIVE (terminal cross-file sink)
    os.system(cmd)
