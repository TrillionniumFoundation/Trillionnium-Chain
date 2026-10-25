"""Independent Python integer oracle for isolated Trillionnium PoN DAA research.

NOT a consensus activation, Node verifier, work-hardness proof, or deployment receipt.
The ASERT polynomial matches aserti3-2d's fixed-point target computation, without
Bitcoin Cash's compact-nBits rounding because PoN uses exact unsigned targets.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

UINT64_MAX = (1 << 64) - 1
UINT256_MAX = (1 << 256) - 1
I128_MAX = (1 << 127) - 1
I128_MIN = -(1 << 127)
RADIX = 1 << 16


def _u64(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= UINT64_MAX:
        raise ValueError(name)
    return value


def _target(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= UINT256_MAX:
        raise ValueError(name)
    return value


def trunc_div(a: int, b: int) -> int:
    """Truncate toward zero like Rust i128 division, not Python floor division."""
    if b <= 0:
        raise ValueError("denominator")
    return a // b if a >= 0 else -((-a) // b)


def legacy_retarget(parent_target: int, first: int, last: int,
                    interval: int, spacing: int, pow_limit: int) -> int:
    parent_target = _target(parent_target, "parent target")
    pow_limit = _target(pow_limit, "pow limit")
    first = _u64(first, "first time")
    last = _u64(last, "last time")
    interval = _u64(interval, "interval")
    spacing = _u64(spacing, "spacing")
    if interval < 16 or spacing == 0 or parent_target > pow_limit:
        raise ValueError("retarget parameters")
    desired = (interval - 1) * spacing
    if desired * 4 > UINT64_MAX:
        raise ValueError("retarget overflow")
    observed = max(1, last - first) if last >= first else 1
    observed = max((desired + 3) // 4, min(observed, desired * 4))
    return max(1, min(pow_limit, parent_target * observed // desired))


def asert_target(anchor_target: int, anchor_parent_time: int,
                 parent_time: int, anchor_height: int, candidate_height: int,
                 spacing: int, half_life: int, pow_limit: int) -> int:
    """Exact target in PoN's integer representation; research only.

    anchor_height names the first anchored block. The time offset is measured
    from its PARENT. `parent_time` is caller-selected raw timestamp or MTP11.
    Old and median variants differ in caller-provided time observations, not math.
    """
    anchor_target = _target(anchor_target, "anchor target")
    pow_limit = _target(pow_limit, "pow limit")
    params = [anchor_parent_time, parent_time, anchor_height,
              candidate_height, spacing, half_life]
    for n, value in zip(("anchor_parent_time", "parent_time", "anchor_height",
                          "candidate_height", "spacing", "half_life"), params):
        _u64(value, n)
    if not 0 < anchor_height < candidate_height or not spacing or not half_life:
        raise ValueError("ASERT heights/spacing/half-life")
    if anchor_target > pow_limit:
        raise ValueError("ASERT anchor exceeds limit")
    elapsed_blocks = candidate_height - anchor_height
    work_time = elapsed_blocks * spacing
    if work_time > I128_MAX:
        raise ValueError("ASERT ideal span overflows i128")
    deviation = parent_time - anchor_parent_time - work_time
    if not I128_MIN <= deviation <= I128_MAX:
        raise ValueError("ASERT deviation overflows i128")
    scaled = deviation * RADIX
    if not I128_MIN <= scaled <= I128_MAX:
        raise ValueError("ASERT exponent overflows i128")
    exponent = trunc_div(scaled, half_life)
    shifts, fractional = divmod(exponent, RADIX)
    factor = (195_766_423_245_049 * fractional +
              971_821_376 * fractional**2 +
              5_127 * fractional**3 + (1 << 47)) // (1 << 48) + RADIX
    # Match native saturation before allocating shifted Python integers:
    # a legal u64 parent time with short half-life can otherwise allocate
    # an astronomically large integer and exhaust the research verifier.
    if shifts >= 256:
        return pow_limit
    if shifts <= -512:
        return 1
    value = anchor_target * factor
    value = value << shifts if shifts >= 0 else value >> -shifts
    value >>= 16
    return min(pow_limit, max(1, value))


def mtp11(ancestors_parent_first: Sequence[int]) -> int:
    if not 1 <= len(ancestors_parent_first):
        raise ValueError("missing ancestors")
    vals = [_u64(t, "timestamp") for t in ancestors_parent_first[:11]]
    vals.sort()
    return vals[len(vals) // 2]


def valid_time(candidate: int, parent_first: Sequence[int], now: int, skew: int = 120) -> bool:
    _u64(candidate, "candidate")
    _u64(now, "now")
    _u64(skew, "skew")
    return candidate > mtp11(parent_first) and candidate <= now + skew


@dataclass(frozen=True)
class Lease:
    """Finite model of Q4 guards; no signatures or actual Node State authority."""
    starts: int
    expires: int
    available_until: int
    source_sequence: int

    def __post_init__(self) -> None:
        for k in ("starts", "expires", "available_until", "source_sequence"):
            _u64(getattr(self, k), k)
        if (self.starts > self.expires or
                self.expires - self.starts > 1000 or
                self.expires > UINT64_MAX - 100 or
                self.available_until != self.expires + 100 or
                not self.source_sequence):
            raise ValueError("Q4 lease invariant")


def q4_atomic_renew(old: Lease, successor: Lease, actual_height: int,
                    requester_signed: bool, source_signed: bool) -> bool:
    """Checks ONLY temporal/sequence authorization preconditions, not crypto."""
    _u64(actual_height, "actual_height")
    return (requester_signed is True and source_signed is True
            and old.starts <= successor.starts <= actual_height <= old.expires
            and successor.expires > old.expires
            and successor.source_sequence == old.source_sequence + 1)


def q4_slot_reclaimable(old: Lease, height: int, status: str) -> bool:
    """Mirror M06 open: expiry + retention height, NOT stored status.

    A currently recorded "active" lease may be safely replaced once its
    retention horizon has passed. This predicate is not authorization to open:
    a fresh signed requester operation, generation, nonce and fee remain necessary.
    """
    _u64(height, "height")
    if status not in {"active", "revoked", "expired"}:
        raise ValueError("unknown research lease status")
    return height > old.available_until
