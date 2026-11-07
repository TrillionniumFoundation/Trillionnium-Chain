"""Exact input scopes for existing full/restricted W1 classical preprocessing.

Compare canonical templates, then resume SHA from a byte-identical fixed prefix.
Input identity is a sufficient reuse condition, not a lower bound: unequal inputs
do not rule out other caches or algorithms. AB excludes R/noise parameters; its
inputs are A, B, N and q. The task hash binds matrix bytes, not the field modulus.
This diagnostic computes its own checkpoints; it measures no saved time, energy,
amortization frequency, quantum advantage or consensus admission.
"""
import hashlib
import struct

from w1_quantum_oracle import FixedTemplate, h_bytes
from w1_quantum_primitives import INITIAL_STATE, digest_bytes, message_value, sha_compress

SCHEMA = "trnm-w1-preprocessing-reuse-v1"
FIXED_BLOCKS = 5


def _canonical_template(value):
    if type(value) is not FixedTemplate:
        raise ValueError("PREPROCESS_TEMPLATE_TYPE")
    for name, expected in (("header", bytes), ("a", tuple), ("b", tuple),
                           ("target", int), ("nonce_offset", int),
                           ("profile", str), ("challenge_tag", bytes)):
        if type(getattr(value, name)) is not expected:
            raise ValueError("PREPROCESS_NONCANONICAL_TEMPLATE")
    rebuilt = FixedTemplate.from_header(value.header, value.a, value.b,
                                        value.nonce_bits, value.shape)
    if value != rebuilt:
        raise ValueError("PREPROCESS_NONCANONICAL_TEMPLATE")
    return rebuilt


def _padded(frame):
    return frame + b"\x80" + bytes((55 - len(frame)) % 64) + (8 * len(frame)).to_bytes(8, "big")


def _prefix_states(frame):
    states = [INITIAL_STATE]
    for block in range(FIXED_BLOCKS):
        states.append(sha_compress(message_value(frame[64 * block:64 * (block + 1)]), states[-1]))
    return states


def _continue(frame, state, blocks):
    padded = _padded(frame)
    for offset in range(64 * blocks, len(padded), 64):
        state = sha_compress(message_value(padded[offset:offset + 64]), state)
    return digest_bytes(state)


def compare_preprocessing(left_template, right_template, left_nonce=0, right_nonce=0):
    """Recompute both checkpoints and verify legal prefix reuse against hashlib.

    Equality checks use actual framed bytes, never equality of fingerprints.
    Complete challenge identity alone makes no claim about later W1 intermediates
    when relation parameters differ. Context eligibility is outside this contract.
    """
    templates = tuple(map(_canonical_template, (left_template, right_template)))
    frames, task_inputs = [], []
    for template, nonce in zip(templates, (left_nonce, right_nonce)):
        frame = h_bytes(template.challenge_tag, template.header_for(nonce))
        if len(frame) - len(template.header) + template.nonce_offset < 64 * FIXED_BLOCKS:
            raise ValueError("NONCE_IN_FIXED_PREPROCESSING")
        frames.append(frame)
        fields = [struct.pack("<" + "I" * len(values), *values)
                  for values in (template.a, template.b)]
        task_inputs.append(h_bytes(b"task", *fields))
    left, right = frames
    shared = 0
    for block in range(FIXED_BLOCKS):
        if left[64 * block:64 * (block + 1)] != right[64 * block:64 * (block + 1)]:
            break
        shared += 1
    left_states, right_states = map(_prefix_states, frames)
    resumed = _continue(right, left_states[shared], shared)
    expected = hashlib.sha256(right).digest()
    if resumed != expected:
        raise ValueError("PREPROCESS_SHA_CONTINUATION_MISMATCH")
    ab_inputs = [(t.a, t.b, t.shape.n, t.shape.q) for t in templates]
    return {
        "schema": SCHEMA,
        "ab_inputs_equal": ab_inputs[0] == ab_inputs[1],
        "task_commitment_input_equal": task_inputs[0] == task_inputs[1],
        "matching_fixed_prefix_blocks": shared,
        "fixed_five_block_input_equal": shared == FIXED_BLOCKS,
        "challenge_input_equal": left == right,
        "left_five_block_chaining_state_hex": digest_bytes(left_states[-1]).hex(),
        "right_five_block_chaining_state_hex": digest_bytes(right_states[-1]).hex(),
        "left_challenge_sha256": hashlib.sha256(left).hexdigest(),
        "resumed_challenge_sha256": resumed.hex(),
        "expected_challenge_sha256": expected.hex(),
        "continuation_matches_hashlib": True,
        "sha_compressions_after_checkpoint": len(_padded(right)) // 64 - shared,
        "claims": {
            "native_context_admission_checked": False,
            "quantum_hardware_executed": False,
            "physical_resources_calibrated": False,
            "cpu_qpu_time_savings_measured": False,
            "energy_savings_measured": False,
            "preprocessing_amortization_calibrated": False,
            "same_budget_advantage_proved": False,
            "attacker_minimum_cost_proved": False,
            "consensus_security_theorem": False,
        },
    }
