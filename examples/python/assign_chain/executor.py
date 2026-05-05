"""Cross-file sink target for the assignment-chain audit fixture."""
import os


def run_in_other_file(cmd):
    # POSITIVE (cross-file): caller passes tainted value as argument;
    # this function consumes it as a cmdi sink.
    os.system(cmd)
