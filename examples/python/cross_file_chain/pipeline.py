"""Cross-file pipeline stage 1 — wraps and forwards."""
from transformer import transform_and_forward


def run_pipeline(payload):
    wrapped = "[" + payload + "]"
    transform_and_forward(wrapped)
