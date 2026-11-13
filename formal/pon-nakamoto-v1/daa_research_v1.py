"""Independent, non-activated reference model for PoN lease/DAA research.

Stdlib only. These computations are NOT W1 proofs, blocks, mining results,
a source-signature verifier or evidence of permissionless security.
Historical consensus::retarget and Q4 bytes remain authoritative.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Sequence

MAX_U64 = (1 << 64) - 1
MAX_U256 = (1 << 256) - 1
RADIX = 1 << 16
A = 195_766_423_245_049
B = 971_821_376
C = 5_127
MAX_ABS_RESIDUAL = 1 << 118


class ResearchInputError(ValueError):
    """Malformed research input; never a consensus validity verdict."""


def _uint(value: int, bits: int, name: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ResearchInputError(name)
    return value


def _target(value: int, name: str) -> int:
    _uint(value, 256, name)
    if value == 0:
        raise ResearchInputError(name)
    return value


def legacy_target(parent: int, first: int, last: int, *, interval: int = 16,
                  spacing: int = 10, pow_limit: int = (1 << 255) - 1) -> int:
    """Bit-exact *integer* transcription of the installed 16-block retarget."""
    _target(parent, "parent")
    _target(pow_limit, "pow_limit")
    _uint(first, 64, "first")
    _uint(last, 64, "last")
    if parent > pow_limit or interval < 16 or spacing <= 0:
        raise ResearchInputError("legacy-parameters")
    desired = (interval - 1) * spacing
    if desired > MAX_U64 // 4:
        raise ResearchInputError("legacy-overflow")
    low = (desired + 3) // 4
    observed = min(4 * desired, max(low, max(1, last - first)))
    return max(1, min(pow_limit, parent * observed // desired))


def median11(parent_first: Sequence[int]) -> int:
    """Caller must supply 1..11 verified ancestors, most recent first."""
    if not 1 <= len(parent_first) <= 11:
        raise ResearchInputError("mtp-length")
    for time in parent_first:
        _uint(time, 64, "ancestor-time")
    ordered = sorted(parent_first)
    return ordered[len(ordered) // 2]


def check_header_time(candidate: int, parent_first: Sequence[int],
                      observed_now: int, *, future_skew: int = 120) -> str:
    """Return valid/deferred/invalid. Deferral is NOT invalidity."""
    _uint(candidate, 64, "candidate")
    _uint(observed_now, 64, "now")
    _uint(future_skew, 64, "skew")
    if candidate <= median11(parent_first):
        return "invalid"
    if candidate > observed_now + future_skew:
        return "deferred"
    return "valid"


def _trunc_div(numerator: int, denominator: int) -> int:
    """ASERT needs signed division toward zero, unlike Python //."""
    quotient = abs(numerator) // denominator
    return -quotient if numerator < 0 else quotient


def asert_target(anchor_target: int, *, anchor_height: int,
                 anchor_parent_time: int, parent_height: int, parent_time: int,
                 spacing: int = 10, half_life: int = 7200,
                 pow_limit: int = MAX_U256) -> int:
    """BCH ASERT cubic polynomial, adapted to PoN's *full 256-bit target*.

    No nBits compact-target normalization; truncation and clamp are an explicit
    separate research contract. ASERT input may be a raw header clock or MTP11,
    but both anchor and parent must use the SAME chosen clock definition.
    """
    _target(anchor_target, "anchor-target")
    _target(pow_limit, "pow-limit")
    _uint(anchor_height, 64, "anchor-height")
    _uint(parent_height, 64, "parent-height")
    _uint(anchor_parent_time, 64, "anchor-parent-time")
    _uint(parent_time, 64, "parent-time")
    _uint(spacing, 64, "spacing")
    _uint(half_life, 64, "half-life")
    if (anchor_target > pow_limit or not anchor_height or
            parent_height < anchor_height or not spacing or not half_life):
        raise ResearchInputError("asert-parameters")
    steps = parent_height - anchor_height + 1
    ideal = steps * spacing
    if ideal > MAX_U64:
        raise ResearchInputError("asert-span-overflow")
    residual = parent_time - anchor_parent_time - ideal
    if not -MAX_ABS_RESIDUAL < residual < MAX_ABS_RESIDUAL:
        raise ResearchInputError("asert-residual-range")
    exponent = _trunc_div(residual * RADIX, half_life)
    shifts = exponent >> 16  # arithmetic/floor shift, including negative
    fractional = exponent - shifts * RADIX
    assert 0 <= fractional < RADIX
    factor = (A * fractional + B * fractional**2 + C * fractional**3
              + (1 << 47)) >> 48
    factor += RADIX
    if shifts >= 512:
        return pow_limit
    if shifts <= -512:
        return 1
    widened = anchor_target * factor
    widened = widened << shifts if shifts >= 0 else widened >> -shifts
    return max(1, min(pow_limit, widened >> 16))


@dataclass(frozen=True)
class VerifiedWindowFacts:
    """Already-authenticated Q4 lease-window facts, NOT signatures or grants."""
    not_before: int
    expires: int
    available_until: int
    sequence: int
    slot: int


def renewal_window_eligible(old: VerifiedWindowFacts,
                            successor: VerifiedWindowFacts,
                            containing_height: int) -> bool:
    """Checks only Q4's overlapping window. Upstream crypto is mandatory."""
    for value in (old.not_before, old.expires, old.available_until, old.sequence,
                  old.slot, successor.not_before, successor.expires,
                  successor.available_until, successor.sequence, successor.slot,
                  containing_height):
        _uint(value, 64, "lease-int")
    return (
        old.slot == successor.slot
        and old.sequence + 1 == successor.sequence
        and 0 <= old.not_before <= successor.not_before <= containing_height <= old.expires
        and successor.expires > old.expires
        and successor.expires - successor.not_before <= 1000
        and successor.not_before <= old.expires
        and successor.expires <= MAX_U64 - 100
        and successor.available_until == successor.expires + 100
        and old.available_until == old.expires + 100
    )


def old_slot_recyclable(old: VerifiedWindowFacts, containing_height: int) -> bool:
    """Necessary height boundary, NOT sufficient for authorization/new open."""
    _uint(containing_height, 64, "height")
    return containing_height > old.available_until


def endpoint_schedule(blocks: int = 80, *, spike: int = 2000) -> list[int]:
    """One explicitly modelled time-warp hypothesis, NOT mined PoN blocks.

    The high timestamp occurs at the END of each 16-block period, while the
    non-spike timestamps use MTP11+1. All checks use one hypothetical clock.
    """
    _uint(spike, 64, "spike")
    if type(blocks) is not int or not 1 <= blocks <= 4096:
        raise ResearchInputError("blocks")
    out = [0]  # genesis timestamp
    for h in range(1, blocks + 1):
        candidate = spike if h % 16 == 15 else median11(list(reversed(out[-11:]))) + 1
        if check_header_time(candidate, list(reversed(out[-11:])), spike) != "valid":
            raise ResearchInputError("schedule-not-admissible")
        out.append(candidate)
    return out


def effective_work_share(resource_fraction: Fraction, legal_speedup: Fraction) -> Fraction:
    """Conditional *economic sensitivity*, not an observed hashpower fraction."""
    if not (0 <= resource_fraction <= 1 and legal_speedup > 0):
        raise ResearchInputError("work-model")
    return resource_fraction * legal_speedup / (
        1 - resource_fraction + resource_fraction * legal_speedup
    )


def scenario_summary() -> dict[str, object]:
    """Reproducible arithmetic schedule; no signing, work search or validation."""
    time = endpoint_schedule()
    start = 1 << 128
    limit = (1 << 255) - 1
    legacy = start
    retargets = []
    for height in range(1, 81):
        if height % 16 == 0:
            legacy = legacy_target(
                legacy, time[height - 16], time[height - 1], pow_limit=limit,
            )
            retargets.append({"height": height, "target_hex": f"{legacy:064x}",
                              "ratio_to_anchor": str(Fraction(legacy, start))})
    raw = asert_target(start, anchor_height=1, anchor_parent_time=0,
                       parent_height=79, parent_time=time[79], pow_limit=limit)
    mtp = asert_target(start, anchor_height=1, anchor_parent_time=0,
                       parent_height=79, parent_time=median11(list(reversed(time[69:80]))),
                       pow_limit=limit)
    return {
        "schema": "pon-daa-lease-research-v1",
        "claims": "pure arithmetic only; no mined blocks, WAN, work hardness or new consensus",
        "header_checks": 80,
        "all_header_times_valid_at_hypothetical_now": True,
        "retargets": retargets,
        "asert_raw_target_hex": f"{raw:064x}",
        "asert_mtp_target_hex": f"{mtp:064x}",
        "last_mtp": median11(list(reversed(time[69:80]))),
        "maintenance_without_external_lease": "revision12-declared-not-reproved-here",
        "production_eligible": False,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(scenario_summary(), indent=2, sort_keys=True))
