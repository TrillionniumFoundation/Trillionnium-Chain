"""Candidate-only G2F light-client and state-sync conformance harness.

The package intentionally lives outside the Rust protocol crates.  It is a
reviewable, deterministic test seam for the interfaces requested by G2F; it
does not grant node, signer, voting, activation, or release authority.
"""

__all__ = [
    "atomicity",
    "client_a",
    "client_b",
    "fixture",
    "state_sync",
    "state_tree",
    "wire",
]
