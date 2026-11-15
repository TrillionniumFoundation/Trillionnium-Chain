"""Finite classical-help reduction for MU1's existing conditional query bound.

The alphabet is fixed before the oracle/experiment, across ALL executions.
An observed message count, signed log, or oracle-dependent singleton support
does not certify this assumption.  No quantum side channel or uncounted initial
oracle correlation is allowed.  This module proves no actual SHA-256 model.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from mandatory_units_query import QueryBudget, quantum_weight_bound


HELP_SCHEMA = "pon-work-lifecycle-fixed-classical-help-v1"
MAX_SLOTS = 64
MAX_TOTAL_PAYLOAD_BYTES = 1_048_576


def need(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def integer(value: Any, minimum: int, maximum: int, code: str) -> int:
    need(type(value) is int and minimum <= value <= maximum, code)
    return value


@dataclass(frozen=True)
class HelpSlot:
    """A predetermined slot; absence, errors, source and time are information.

    Data lengths 0..max_payload_bytes are all allowed.  A data payload is an
    arbitrary byte string; a digest is derived metadata, not a substitute for
    the bytes.  Error codes range 0..error_codes-1.  Source labels and delivery
    bins are part of the alphabet.  There is one canonical absence outcome.
    """
    sources: tuple[str, ...]
    delivery_bins: int
    max_payload_bytes: int
    error_codes: int

    def check(self) -> None:
        need(type(self.sources) is tuple and 1 <= len(self.sources) <= 16,
             "HELP_SOURCES")
        need(all(type(s) is str and 0 < len(s) <= 64 and s.isascii()
                 for s in self.sources) and len(set(self.sources)) == len(self.sources),
             "HELP_SOURCES")
        integer(self.delivery_bins, 1, 4096, "HELP_DELIVERY_BINS")
        integer(self.max_payload_bytes, 0, MAX_TOTAL_PAYLOAD_BYTES, "HELP_PAYLOAD_CAP")
        integer(self.error_codes, 0, 256, "HELP_ERROR_ALPHABET")

    def wire(self) -> dict[str, object]:
        self.check()
        return {"sources": list(self.sources), "delivery_bins": self.delivery_bins,
                "max_payload_bytes": self.max_payload_bytes,
                "error_codes": self.error_codes}

    def support_capped(self, cap: int) -> int:
        """min(cap, 1 + S*T*(E + sum_{n=0}^B 256**n)), without huge powers."""
        self.check()
        need(type(cap) is int and cap >= 1, "SUPPORT_CAP")
        size = self.max_payload_bytes
        if 8 * size >= cap.bit_length():
            payloads = cap
        else:
            payloads = min(cap, ((1 << (8 * (size + 1))) - 1) // 255)
        return min(cap, 1 + len(self.sources) * self.delivery_bins
                   * (self.error_codes + payloads))

    def description_bits_upper(self) -> int:
        self.check()
        coefficient = 1 + len(self.sources) * self.delivery_bins * (
            self.error_codes + self.max_payload_bytes + 1)
        return 8 * self.max_payload_bytes + (coefficient - 1).bit_length()


@dataclass(frozen=True)
class HelpPolicy:
    slots: tuple[HelpSlot, ...]

    def check(self) -> None:
        need(type(self.slots) is tuple and len(self.slots) <= MAX_SLOTS, "HELP_SLOTS")
        for slot in self.slots:
            need(type(slot) is HelpSlot, "HELP_SLOT_TYPE")
            slot.check()
        need(sum(s.max_payload_bytes for s in self.slots) <= MAX_TOTAL_PAYLOAD_BYTES,
             "HELP_TOTAL_PAYLOAD_CAP")

    def wire(self) -> dict[str, object]:
        self.check()
        return {"schema": HELP_SCHEMA, "slots": [s.wire() for s in self.slots]}

    @classmethod
    def from_wire(cls, value: Any) -> "HelpPolicy":
        need(type(value) is dict and set(value) == {"schema", "slots"}, "HELP_POLICY_FIELDS")
        need(value["schema"] == HELP_SCHEMA and type(value["slots"]) is list,
             "HELP_POLICY_SCHEMA")
        slots = []
        for row in value["slots"]:
            need(type(row) is dict and set(row) == {
                "sources", "delivery_bins", "max_payload_bytes", "error_codes"},
                 "HELP_SLOT_FIELDS")
            need(type(row["sources"]) is list, "HELP_SOURCES")
            slots.append(HelpSlot(tuple(row["sources"]), row["delivery_bins"],
                                  row["max_payload_bytes"], row["error_codes"]))
        out = cls(tuple(slots))
        out.check()
        return out

    def support_capped(self, cap: int) -> int:
        self.check()
        need(type(cap) is int and cap >= 1, "SUPPORT_CAP")
        result = 1
        for slot in self.slots:
            result = min(cap, result * slot.support_capped(cap))
            if result == cap:
                break
        return result

    def description_bits_upper(self) -> int:
        self.check()
        return sum(s.description_bits_upper() for s in self.slots)

    def validate_delivery(self, value: Any, payload: bytes) -> int:
        """Checks an observed delivery fits policy; does NOT prove mediation."""
        need(type(value) is dict and set(value) == {
            "slot", "status", "source", "delivery_bin", "payload_bytes", "error_code"},
             "HELP_DELIVERY_FIELDS")
        index = integer(value["slot"], 0, len(self.slots) - 1, "HELP_SLOT_INDEX")
        slot = self.slots[index]
        need(type(payload) is bytes, "HELP_PAYLOAD_TYPE")
        need(type(value["payload_bytes"]) is int and value["payload_bytes"] == len(payload),
             "HELP_PAYLOAD_LENGTH")
        status = value["status"]
        need(status in ("absent", "data", "error"), "HELP_DELIVERY_STATUS")
        if status == "absent":
            need(value["source"] is None and value["delivery_bin"] is None
                 and value["error_code"] is None and payload == b"", "HELP_ABSENCE_ENCODING")
            return index
        need(value["source"] in slot.sources, "HELP_SOURCE")
        integer(value["delivery_bin"], 0, slot.delivery_bins - 1, "HELP_DELIVERY_BIN")
        if status == "data":
            need(len(payload) <= slot.max_payload_bytes and value["error_code"] is None,
                 "HELP_DATA_ENCODING")
        else:
            integer(value["error_code"], 0, slot.error_codes - 1, "HELP_ERROR_CODE")
            need(payload == b"", "HELP_ERROR_ENCODING")
        return index


def multiply_fixed_support(fresh_bound: Fraction, support: int) -> Fraction:
    """Conditional union bound for a globally fixed finite help alphabet.

    For every transcript t, force t to obtain a valid fresh-oracle strategy
    with the SAME uniform bound B and hard Q,M caps on every path.  Classical
    helper response probabilities on an actual path are at most one, so
    P(success AND T=t) <= P(forced-t success) <= B.  Sum over at most D t's.
    """
    need(type(fresh_bound) is Fraction and 0 <= fresh_bound <= 1, "FRESH_BOUND")
    need(type(support) is int and support >= 1, "GLOBAL_HELP_SUPPORT")
    return min(Fraction(1), support * fresh_bound)


def finite_help_weight_bound(full_value_queries: int, complete_outputs: int,
                             credit: int, policy: HelpPolicy) -> dict[str, object]:
    """Conditional theorem arithmetic, deliberately not an observation adapter.

    Q is the full lifecycle bound of EACH forced-transcript strategy.  Helper
    oracle queries may be unlimited only because *all* their influence is
    restricted to the globally fixed finite classical alphabet.  A helper
    cannot lend unrecorded state, a quantum system, timing, or another channel.
    Passing this policy does not establish any of those real-world premises.
    """
    need(type(policy) is HelpPolicy, "HELP_POLICY_TYPE")
    policy.check()
    base = quantum_weight_bound(QueryBudget(full_value_queries, complete_outputs,
                                            True, True), credit)
    b = base["bound"]
    if b == 0:
        value, capped_support, cap = Fraction(0), None, None
    else:
        cap = (b.denominator + b.numerator - 1) // b.numerator
        capped_support = policy.support_capped(cap)
        value = min(Fraction(1), capped_support * b)
    return {
        "model": "mu1-fixed-classical-help-query-reduction-v1",
        "Q_for_every_forced_transcript_strategy": full_value_queries,
        "M_for_every_forced_transcript_strategy": complete_outputs,
        "credit_threshold": credit,
        "fresh_uniform_bound": b,
        "help_policy": policy.wire(),
        "global_support_description_bits_upper": policy.description_bits_upper(),
        "support_saturation_threshold": cap,
        "global_support_capped_at_threshold": capped_support,
        "bound": value,
        "fixed_global_support_verified_by_this_function": False,
        "complete_help_mediation_proved": False,
        "initial_oracle_independence_proved": False,
        "actual_sha_idealization_proved": False,
        "physical_resource_bound": False,
        "native_confirmation_risk": False,
    }
