"""Test input assembly and terminal observations for the linked HIA shadow."""
import struct

from hia.platform.release_pq_shadow.build import ENTRY
from hia.tests.test_release_pq_signing import pack_signatures

STATE = 334
KEY_WIDTH = 2006
PHASES = ("", "wire", "outer", "unsigned", "identity_mismatch", "locator",
          "locator_mismatch", "quorum", "state", "internal")
CONTROL_CASES = (
    ("truncated_private_wire", 100, "wire", 100),
    ("nonzero_reserved", 100, "wire", 100),
    ("output_below_extent", 102, "wire", 102),
    ("unknown_role_pins_before_unsigned", 209, "outer", 209),
    ("anchor_refused_after_genuine_quorum", 111, "state", 111),
    ("wrong_locator_before_old_anchor", 2, "locator_mismatch", 0),
    ("valid_after_refusals", 0, "state", 0),
)


def request(bundle, state, pins, signatures, *, threshold=2):
    if len(pins) % KEY_WIDTH:
        raise ValueError("Invalid typed pin extent")
    return (struct.pack("<4sIIHHHHI", b"RSO1", len(state), len(bundle), len(pins) // KEY_WIDTH,
                        threshold, len(signatures), 0, 0)
            + state + bundle + pins + pack_signatures(signatures))


def observe(owner, cases):
    rows = [(ENTRY, [frame, b"\x4e" * out]) for frame, out in cases]
    outcomes = owner.call_many(rows, timeout=45)
    observations = []
    for (frame, out), result in zip(cases, outcomes, strict=True):
        result.require_returned()
        value = result.value
        phase, code, detail = (value >> 8) & 255, value & 255, value >> 16
        if not 0 < phase < len(PHASES) or detail > 255:
            raise ValueError("Malformed linked bridge terminal value")
        data = result.arguments[1]
        if result.arguments[0] != frame or data[(0 if code else 64):] != b"\x4e" * (out if code else out - 64):
            raise ValueError("Linked bridge mutated input or published an incomplete result")
        observations.append((code, PHASES[phase], detail, None if code else data[:64]))
    return observations


def private_controls(owner, bundle, state, pins, signatures, expected_output):
    base = request(bundle, state, pins, signatures)
    reserved = bytearray(base)
    reserved[18] = 1
    invalid_unsigned = bytearray(bundle)
    invalid_unsigned[298] = 1
    wrong_locator = bytearray(bundle)
    wrong_locator[74] ^= 1
    stale_anchor = bytearray(state)
    stale_anchor[155] ^= 1
    requests = [(base[:-1], 72), (bytes(reserved), 72), (base, 63),
                (request(bytes(invalid_unsigned), state, b"", signatures, threshold=0), 72),
                (request(bundle, bytes(stale_anchor), pins, signatures), 72),
                (request(bytes(wrong_locator), bytes(stale_anchor), pins, signatures), 72), (base, 72)]
    receipts = []
    for (label, code, phase, detail), readback in zip(CONTROL_CASES, observe(owner, requests), strict=True):
        if readback != (code, phase, detail, None if code else expected_output):
            raise ValueError(f"Linked shadow control differs: {label}")
        receipts.append({"label": label, "status": code, "stage": phase, "detail": detail})
    return receipts
