"""Independent Python arithmetic on the native consensus input domain.

This versioned reference is separate from reference.py, whose broader integer
model remains pinned by historical work-cost studies. Python big integers compute
exact results here, but do not enlarge the native u64/u256 input or u64 retarget
intermediate domains. Native future-clock comparison uses a wider sum.

These arithmetic decisions do not verify W1, admit a block, change native rules,
or establish a consensus security or work-cost bound.
"""
from __future__ import annotations

from typing import Sequence


SCHEMA = 'pon-native-consensus-reference-v1'
U64_MAX = (1 << 64) - 1
U256_MAX = (1 << 256) - 1


def work(target: int) -> int:
    """Inclusive-target credited work, for the native nonzero u256 domain."""
    if type(target) is not int or not 1 <= target <= U256_MAX:
        raise ValueError('TARGET')
    return (1 << 256) // (target + 1)


def retarget(parent_target: int, first_time: int, last_time: int, interval: int,
             spacing: int, pow_limit: int) -> int:
    """Native input refusals and exact clamped periodic retarget arithmetic."""
    if (type(parent_target) is not int or type(pow_limit) is not int
            or not 1 <= parent_target <= pow_limit <= U256_MAX
            or any(type(value) is not int or not 0 <= value <= U64_MAX
                   for value in (first_time, last_time, interval, spacing))
            or interval < 16 or spacing < 1):
        raise ValueError('TARGET_PARAMETERS')
    desired = (interval - 1) * spacing
    # Both checked native u64 products precede the wider target multiplication.
    if desired > U64_MAX or 4 * desired > U64_MAX:
        raise ValueError('TARGET_PARAMETERS')
    observed = max(1, last_time - first_time)
    bounded = min(4 * desired, max((desired + 3) // 4, observed))
    return min(pow_limit, max(1, parent_target * bounded // desired))


def timestamp_state(candidate: int, ancestors: Sequence[int], now: int,
                    future_skew: int) -> str:
    """Chronological ancestry, including genesis when the recent window needs it."""
    if not ancestors:
        raise ValueError('UNKNOWN_PARENT')
    if any(type(value) is not int or not 0 <= value <= U64_MAX
           for value in (candidate, now, future_skew, *ancestors)):
        raise ValueError('TIMESTAMP_DOMAIN')
    recent = sorted(ancestors[-11:])
    if candidate <= recent[len(recent) // 2]:
        return 'invalid-median'
    # Native u128 addition allows a future bound above u64::MAX without wrapping.
    return 'deferred-future' if candidate > now + future_skew else 'admissible'
