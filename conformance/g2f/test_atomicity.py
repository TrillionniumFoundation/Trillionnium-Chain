"""Focused candidate tests for the G2F authenticated-cut seam.

These tests are intentionally independent of the light-client and state-sync
fixtures.  They exercise the smallest cross-plane contract and retain the
known limitations: an unsequenced double read cannot prove atomicity, while an
owner-issued mutation generation closes the same-token A→B→A ambiguity.
Nothing here creates node, signer, voting, activation, or release authority.
"""

from __future__ import annotations

import unittest

try:  # package invocation and direct unittest discovery are both supported
    from .atomicity import (
        REQUIRED_PLANES,
        AtomicityReject,
        PlaneObservation,
        authenticate_snapshot,
        double_sample,
        double_sample_strict,
        snapshot_to_dict,
    )
except ImportError:  # pragma: no cover - direct `unittest discover -s`
    from conformance.g2f.atomicity import (
        REQUIRED_PLANES,
        AtomicityReject,
        PlaneObservation,
        authenticate_snapshot,
        double_sample,
        double_sample_strict,
        snapshot_to_dict,
    )


def _observations(
    transaction_id: bytes = b"t" * 32,
    version: int = 7,
    generation: int | None = 11,
    suffix: bytes = b"",
) -> list[PlaneObservation]:
    return [
        PlaneObservation(name, transaction_id, version, name.encode("ascii") + suffix, generation)
        for name in REQUIRED_PLANES
    ]


class AtomicityCandidateTests(unittest.TestCase):
    def test_authenticated_snapshot_binds_all_planes_and_generation(self) -> None:
        observations = _observations()
        snapshot = authenticate_snapshot(observations)
        self.assertEqual(snapshot.transaction_id, b"t" * 32)
        self.assertEqual(snapshot.version, 7)
        self.assertEqual(snapshot.source_generation, 11)
        self.assertEqual(snapshot_to_dict(snapshot)["source_generation"], 11)
        self.assertEqual(
            tuple(item.plane for item in snapshot.observations), REQUIRED_PLANES
        )

    def test_mixed_plane_token_or_generation_fails_closed(self) -> None:
        observations = _observations()
        observations[-1] = PlaneObservation("Order", b"u" * 32, 7, b"Order", 11)
        with self.assertRaises(AtomicityReject) as token_error:
            authenticate_snapshot(observations)
        self.assertEqual(token_error.exception.code, "mixed_transaction")

        observations = _observations()
        observations[-1] = PlaneObservation("Order", b"t" * 32, 7, b"Order", 12)
        with self.assertRaises(AtomicityReject) as generation_error:
            authenticate_snapshot(observations)
        self.assertEqual(generation_error.exception.code, "mixed_generation")

    def test_exact_bytes_mutation_fails_even_when_token_is_reused(self) -> None:
        first = _observations()
        second = _observations(suffix=b"-changed")
        samples = iter((first, second))
        with self.assertRaises(AtomicityReject) as error:
            double_sample(lambda: next(samples))
        self.assertEqual(error.exception.code, "source_changed")

    def test_strict_generation_rejects_same_token_aba(self) -> None:
        # The bytes and transaction token have returned to A.  The owner
        # generation is different, proving that B existed between reads.
        first = _observations(generation=20)
        second = _observations(generation=21)
        samples = iter((first, second))
        with self.assertRaises(AtomicityReject) as error:
            double_sample_strict(lambda: next(samples))
        self.assertEqual(error.exception.code, "source_changed")

    def test_strict_generation_accepts_stable_cut(self) -> None:
        first = _observations(generation=20)
        second = _observations(generation=20)
        samples = iter((first, second))
        result = double_sample_strict(lambda: next(samples))
        self.assertEqual(result.source_generation, 20)

    def test_strict_generation_rejects_legacy_unsequenced_sample(self) -> None:
        samples = iter((_observations(generation=None), _observations(generation=None)))
        with self.assertRaises(AtomicityReject) as error:
            double_sample_strict(lambda: next(samples))
        self.assertEqual(error.exception.code, "generation_missing")

    def test_duplicate_or_missing_plane_fails_closed(self) -> None:
        observations = _observations()
        observations[-1] = PlaneObservation("DA", b"t" * 32, 7, b"DA", 11)
        with self.assertRaises(AtomicityReject) as duplicate_error:
            authenticate_snapshot(observations)
        self.assertEqual(duplicate_error.exception.code, "plane_set")

    def test_mutable_input_is_frozen_at_boundary(self) -> None:
        transaction_id = bytearray(b"t" * 32)
        exact = bytearray(b"DA")
        item = PlaneObservation("DA", transaction_id, 7, exact, 11)
        transaction_id[0] = ord("u")
        exact[0] = ord("X")
        self.assertEqual(item.transaction_id, b"t" * 32)
        self.assertEqual(item.exact_bytes, b"DA")


if __name__ == "__main__":
    unittest.main()
