"""Cross-file pipeline stage 2 — identity-ish transforms then forward."""
from executor import execute


def transform_and_forward(value):
    upper = value.upper()
    execute(upper)
