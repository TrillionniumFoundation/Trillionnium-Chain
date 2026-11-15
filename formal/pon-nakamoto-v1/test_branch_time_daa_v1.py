"""External arithmetic vectors and adversarial temporal-reference controls.

All clocks, body IDs and temporal records here are experiment inputs. Passing
these controls never means native admission, W1 verification or WAN execution.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import branch_time_daa_v1 as component
from branch_time_daa_v1 import (
    ASERT_ALGORITHM, BranchAnchor, BranchTimeDaa, DaaError, LegacyParameters,
    Schedule, TemporalHeader, TimeDeferred, U64_MAX, U256_MAX, Upgrade,
    asert_target, qualification, snapshot_id, trunc_div,
)
from reference import retarget as retained_periodic_retarget


HERE = Path(__file__).resolve().parent
LIMIT = (1 << 255) - 1


def identity(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def schedule(upgrades=None, **changes):
    if upgrades is None:
        upgrades = (Upgrade(16, 10, 160, 120),)
    return replace(Schedule(identity("temporal-reference-network"), 1000, LIMIT,
                            LIMIT, LegacyParameters(16, 10, 120), upgrades), **changes)


def append(view, parent_id, timestamp=None, label="ordinary", observed_now=100000):
    parent = view.header(parent_id)
    if timestamp is None:
        timestamp = parent.timestamp + 10
    header = view.candidate(parent_id, timestamp, identity(f"{label}:{parent_id}:{timestamp}"))
    view.append(header, observed_now)
    return header.record_id


def advance(view, parent_id, count, step=10, label="ordinary"):
    for _ in range(count):
        parent_id = append(view, parent_id, view.header(parent_id).timestamp + step, label)
    return parent_id


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n").encode("ascii")


def restore_untrusted_envelope(value, rules):
    """Give a mutant its own seal to exercise checks *inside* that envelope.

    This is explicitly not the independent recovery-anchor production contract.
    Other controls preserve the original external identity to check rollback.
    """
    data = encode(value)
    return BranchTimeDaa.restore(data, rules, snapshot_id(data))


def rebind_row_id(row):
    row["record_id"] = TemporalHeader(
        row["schedule_id"], row["rule_id"], row["parent_id"],
        int(row["height"]), int(row["timestamp"]), int(row["target_hex"], 16),
        row["body_id"]).record_id


def compact(target):
    """Independent test-only nBits representation; candidate keeps raw u256."""
    byte_count = (target.bit_length() + 7) // 8
    if byte_count <= 3:
        coefficient = target * 256 ** (3 - byte_count)
    else:
        coefficient = target // 256 ** (byte_count - 3)
    if coefficient & 0x800000:
        coefficient //= 256
        byte_count += 1
    return (byte_count << 24) | coefficient


class AsertArithmeticTests(unittest.TestCase):
    def test_eighteen_pinned_bchn_vectors_and_independent_compact_encoding(self):
        fixture = json.loads((HERE / "vectors/quantum-daa-asert-bchn-v1.json").read_text())
        self.assertEqual(fixture["source_commit"], "07576013c91ff4a3a74acd85f189c69121cdad1b")
        self.assertEqual(fixture["algorithm_blob"], "52b37822da2d4c132b31113a1fc1e3d7b670e3a7")
        self.assertEqual(fixture["source_blob"], "fd3ea96b9a663b28a7020393e5a71a413b2ed355")
        self.assertEqual(len(fixture["vectors"]), 18)
        for row in fixture["vectors"]:
            with self.subTest(upstream_line=row["source_line"]):
                actual = asert_target(int(row["anchor_target_hex"], 16), row["time_delta"],
                                      row["intervals"], fixture["spacing"], fixture["half_life"],
                                      int(fixture["pow_limit_hex"], 16))
                self.assertEqual(f"{actual:064x}", row["expected_target_hex"])
                self.assertEqual(f"{compact(actual):08x}", row["upstream_expected_nbits_hex"])

    def test_signed_truncation_and_raw_fractional_target_are_explicit(self):
        self.assertEqual(trunc_div(-65536, 3), -21845)
        self.assertNotEqual(trunc_div(-65536, 3), -65536 // 3)
        self.assertEqual(trunc_div(65536, 3), 21845)
        # Exactly one half-life early / late has an exact power-of-two result.
        self.assertEqual(asert_target(1 << 220, 10, 17, 10, 160, LIMIT), 1 << 219)
        self.assertEqual(asert_target(1 << 220, 170, 1, 10, 160, LIMIT), 1 << 221)
        # The raw profile preserves low limbs; it does not round to nBits.
        source = (1 << 220) + 57
        self.assertEqual(asert_target(source, 10, 1, 10, 160, LIMIT), source)

    def test_extreme_shift_clamps_do_not_allocate_unbounded_integers(self):
        self.assertEqual(asert_target(1, U64_MAX, 1, 1, 1, U256_MAX), U256_MAX)
        self.assertEqual(asert_target(U256_MAX, -U64_MAX, 1, 1, 1, U256_MAX), 1)
        with self.assertRaisesRegex(DaaError, "ASERT_I128_RANGE"):
            asert_target(1, 0, U64_MAX, U64_MAX, 1, LIMIT)

    def test_numeric_aliases_zero_and_ranges_refuse(self):
        valid = [1 << 200, 10, 1, 10, 160, LIMIT]
        for index in range(len(valid)):
            for value in (True, False, "1", 1.0, None):
                bad = list(valid)
                bad[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(DaaError):
                    asert_target(*bad)
        for index in (0, 2, 3, 4, 5):
            bad = list(valid)
            bad[index] = 0
            with self.subTest(index=index), self.assertRaises(DaaError):
                asert_target(*bad)
        with self.assertRaises(DaaError):
            asert_target(1, U64_MAX + 1, 1, 1, 1, LIMIT)


class VersionAndAnchorTests(unittest.TestCase):
    def test_schedule_commits_all_rules_before_header_construction(self):
        original = schedule()
        altered = replace(original, upgrades=(Upgrade(16, 10, 80, 120),))
        self.assertNotEqual(original.commitment, altered.commitment)
        left, right = BranchTimeDaa(original), BranchTimeDaa(altered)
        self.assertNotEqual(left.genesis_id, right.genesis_id)
        candidate = left.candidate(left.genesis_id, 1010, identity("body"))
        with self.assertRaisesRegex(DaaError, "SCHEDULE_IDENTITY"):
            right.append(candidate, 100000)

    def test_unknown_algorithm_duplicate_and_unsorted_upgrades_refuse(self):
        for bad in ("unknown", "periodic", "", 1, True):
            with self.subTest(bad=bad), self.assertRaisesRegex(DaaError, "UNSUPPORTED_DAA_ALGORITHM"):
                Upgrade(16, 10, 160, 120, algorithm=bad)
        for upgrades in ((Upgrade(16, 10, 160, 120),) * 2,
                         (Upgrade(32, 10, 160, 120), Upgrade(16, 10, 160, 120)),
                         ("upgrade",)):
            with self.subTest(upgrades=upgrades), self.assertRaises(DaaError):
                schedule(upgrades)
        with self.assertRaisesRegex(DaaError, "ANCHOR_PARENT_REQUIRED"):
            Upgrade(1, 10, 160, 120)
        with self.assertRaisesRegex(DaaError, "UPGRADE_SCHEDULE_BOUNDS"):
            schedule([Upgrade(16, 10, 160, 120)])

    def test_anchor_uses_real_parent_timestamp_without_synthetic_spacing(self):
        view = BranchTimeDaa(schedule())
        tip = advance(view, view.genesis_id, 14)
        anchor_id = append(view, tip, 1153)
        required = view.requirement(anchor_id)
        anchor = required.anchor
        self.assertEqual(anchor.anchor_id, anchor_id)
        self.assertEqual(anchor.anchor_height, 15)
        self.assertEqual(anchor.anchor_parent_id, tip)
        self.assertEqual(anchor.anchor_parent_timestamp, 1140)
        self.assertEqual(required.target, asert_target(LIMIT, 13, 1, 10, 160, LIMIT))
        # Use a non-limit target to expose the 3-second first-step discrepancy.
        other = BranchTimeDaa(schedule(genesis_target=1 << 220))
        tip = advance(other, other.genesis_id, 14)
        anchor_id = append(other, tip, 1153)
        required = other.requirement(anchor_id)
        self.assertGreater(required.target, 1 << 220)
        self.assertNotEqual(required.target, asert_target(1 << 220, 10, 1, 10, 160, LIMIT))

    def test_identical_numeric_fork_anchors_cannot_share_cached_identity(self):
        view = BranchTimeDaa(schedule())
        common = advance(view, view.genesis_id, 14)
        left = append(view, common, 1150, "left")
        right = append(view, common, 1150, "right")
        left_requirement, right_requirement = view.requirement(left), view.requirement(right)
        self.assertEqual(left_requirement.target, right_requirement.target)
        self.assertEqual(left_requirement.anchor.anchor_parent_timestamp,
                         right_requirement.anchor.anchor_parent_timestamp)
        self.assertNotEqual(left_requirement.anchor.anchor_id, right_requirement.anchor.anchor_id)
        with self.assertRaisesRegex(DaaError, "ANCHOR_CACHE_MISMATCH"):
            view.requirement(right, left_requirement.anchor)
        with self.assertRaisesRegex(DaaError, "ANCHOR_CACHE_MISMATCH"):
            view.append(view.candidate(right, 1160, identity("right child")), 100000,
                        left_requirement.anchor)

    def test_descendant_forks_with_same_anchor_can_reuse_correct_cache(self):
        view = BranchTimeDaa(schedule())
        anchor = advance(view, view.genesis_id, 15)
        cache = view.requirement(anchor).anchor
        left = append(view, anchor, 1160, "left")
        right = append(view, anchor, 1160, "right")
        self.assertEqual(view.requirement(left, cache), view.requirement(left))
        self.assertEqual(view.requirement(right, cache), view.requirement(right))

    def test_cache_field_mutations_and_wrong_types_cannot_authorize_target(self):
        view = BranchTimeDaa(schedule())
        tip = advance(view, view.genesis_id, 15)
        anchor = view.requirement(tip).anchor
        for changed in (replace(anchor, anchor_parent_timestamp=anchor.anchor_parent_timestamp + 1),
                        replace(anchor, anchor_timestamp=anchor.anchor_timestamp + 1),
                        replace(anchor, anchor_target=anchor.anchor_target - 1),
                        replace(anchor, rule_id=identity("other rule")),
                        {"anchor": anchor}, True):
            with self.subTest(changed=changed), self.assertRaisesRegex(DaaError, "ANCHOR_CACHE_MISMATCH"):
                view.requirement(tip, changed)
        with self.assertRaises(DaaError):
            replace(anchor, anchor_parent_timestamp=True)

    def test_new_epoch_reanchors_and_old_epoch_cache_refuses(self):
        rules = schedule((Upgrade(16, 10, 160, 120), Upgrade(32, 20, 80, 60)))
        view = BranchTimeDaa(rules)
        first_anchor = advance(view, view.genesis_id, 15)
        first_cache = view.requirement(first_anchor).anchor
        tip = advance(view, first_anchor, 16)
        second = view.requirement(tip)
        self.assertEqual(second.next_height, 32)
        self.assertEqual(second.anchor.anchor_id, tip)
        self.assertEqual(second.anchor.anchor_height, 31)
        self.assertEqual(second.future_skew, 60)
        self.assertNotEqual(second.anchor.rule_id, first_cache.rule_id)
        self.assertEqual(second.target, asert_target(view.header(tip).target, 10, 1, 20, 80, LIMIT))
        with self.assertRaisesRegex(DaaError, "ANCHOR_CACHE_MISMATCH"):
            view.requirement(tip, first_cache)
        wrong_version = replace(view.candidate(tip, 1320, identity("seam")),
                                rule_id=rules.rule_id(31))
        with self.assertRaisesRegex(DaaError, "RULE_IDENTITY"):
            view.append(wrong_version, 100000)

    def test_reorganization_parent_selection_does_not_use_global_tip_epoch(self):
        rules = schedule((Upgrade(16, 10, 160, 120), Upgrade(32, 20, 80, 60)))
        view = BranchTimeDaa(rules)
        old_parent = advance(view, view.genesis_id, 14)
        long_tip = advance(view, old_parent, 25)
        self.assertEqual(view.requirement(long_tip).anchor.activation_height, 32)
        legacy = view.requirement(old_parent)
        self.assertIsNone(legacy.anchor)
        self.assertEqual(legacy.rule_id, rules.rule_id(15))
        with self.assertRaisesRegex(DaaError, "LEGACY_HAS_NO_ASERT_ANCHOR"):
            view.requirement(old_parent, view.requirement(long_tip).anchor)
        alternate_anchor = append(view, old_parent, 1157, "alternate old branch")
        self.assertEqual(view.requirement(alternate_anchor).anchor.activation_height, 16)


class TemporalRuleTests(unittest.TestCase):
    def test_retained_negative_span_and_new_nondecreasing_refusal(self):
        legacy = BranchTimeDaa(schedule(()))
        tip = advance(legacy, legacy.genesis_id, 15)
        first = append(legacy, tip, 1160)
        tip = first
        timestamps = [1160]
        for _ in range(15):
            timestamp = legacy.requirement(tip).minimum_timestamp
            timestamps.append(timestamp)
            tip = append(legacy, tip, timestamp)
        self.assertEqual(timestamps[-1] - timestamps[0], -42)
        required = legacy.requirement(tip)
        self.assertEqual(required.target,
                         retained_periodic_retarget(LIMIT, 1160, 1118, 16, 10, LIMIT))
        self.assertEqual(required.required_work, 7)

        upgraded = BranchTimeDaa(schedule())
        tip = advance(upgraded, upgraded.genesis_id, 15)
        first = append(upgraded, tip, 1160)
        bad = upgraded.candidate(first, timestamps[1], identity("negative endpoint"))
        before = upgraded.snapshot()
        with self.assertRaisesRegex(DaaError, "TIME_NONDECREASING"):
            upgraded.append(bad, 100000)
        self.assertEqual(upgraded.snapshot(), before)

    def test_nondecreasing_equality_still_requires_strict_upper_mtp(self):
        view = BranchTimeDaa(schedule())
        tip = advance(view, view.genesis_id, 15)
        tip = append(view, tip, 1160)
        tip = append(view, tip, 1160, "first equal timestamp")
        self.assertEqual(view.header(tip).timestamp, 1160)
        # Equality is not an exemption from MTP: after enough equal parents,
        # the upper median itself is 1160 and the next timestamp must be 1161.
        while view.requirement(tip).minimum_timestamp == 1160:
            tip = append(view, tip, 1160, "further equal timestamp")
        bad = view.candidate(tip, 1160, identity("equal to mtp"))
        with self.assertRaisesRegex(DaaError, "TIME_MTP"):
            view.append(bad, 100000)

    def test_monotone_compressed_schedule_remains_possible_not_security_proof(self):
        view = BranchTimeDaa(schedule())
        anchor = advance(view, view.genesis_id, 15)
        tip = advance(view, anchor, 64, step=1, label="compressed but monotone")
        branch = view.ancestry(tip)
        self.assertTrue(all(child.timestamp >= parent.timestamp
                            for child, parent in zip(branch, branch[1:])))
        self.assertEqual(view.header(tip).timestamp - view.header(anchor).timestamp, 64)
        self.assertLess(view.requirement(tip).target, LIMIT // 4)
        self.assertGreater(view.requirement(tip).required_work, 2)
        self.assertIs(qualification()["mixed_consensus_security_proved"], False)

    def test_future_clock_deferral_is_nonmutating_and_same_header_can_later_pass(self):
        view = BranchTimeDaa(schedule())
        tip = advance(view, view.genesis_id, 15)
        header = view.candidate(tip, 1271, identity("future"))
        before = view.snapshot()
        with self.assertRaisesRegex(TimeDeferred, "TIME_DEFERRED"):
            view.append(header, 1150)
        self.assertEqual(view.snapshot(), before)
        receipt = view.append(header, 1151)
        self.assertEqual(receipt.record_id, header.record_id)

    def test_target_rule_height_parent_and_body_commitments_are_not_interchangeable(self):
        view = BranchTimeDaa(schedule())
        tip = advance(view, view.genesis_id, 15)
        candidate = view.candidate(tip, 1160, identity("body"))
        for changed, reason in (
            (replace(candidate, target=candidate.target - 1), "REQUIRED_TARGET"),
            (replace(candidate, rule_id=identity("other rule")), "RULE_IDENTITY"),
            (replace(candidate, height=candidate.height + 1), "HEIGHT_BINDING"),
            (replace(candidate, parent_id=identity("unknown parent")), "UNKNOWN_PARENT"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(DaaError, reason):
                view.append(changed, 100000)
        self.assertNotEqual(candidate.record_id,
                            replace(candidate, body_id=identity("different body")).record_id)

    def test_duplicate_record_cannot_increase_snapshot_or_bypass_current_clock(self):
        view = BranchTimeDaa(schedule())
        header = view.candidate(view.genesis_id, 1010, identity("one record"))
        original = view.append(header, 1010)
        snapshot = view.snapshot()
        self.assertEqual(view.append(header, 1020), original)
        self.assertEqual(view.snapshot(), snapshot)
        with self.assertRaises(TimeDeferred):
            view.append(header, 0)
        self.assertEqual(view.snapshot(), snapshot)

    def test_even_short_history_uses_native_upper_median(self):
        view = BranchTimeDaa(schedule())
        tip = append(view, view.genesis_id, 1010)
        required = view.requirement(tip)
        self.assertEqual(required.minimum_timestamp, 1011)
        with self.assertRaisesRegex(DaaError, "TIME_MTP"):
            view.append(view.candidate(tip, 1005, identity("lower median attempt")), 100000)

    def test_u64_clock_sum_is_not_wrapped_and_time_domain_exhaustion_refuses(self):
        view = BranchTimeDaa(schedule(genesis_timestamp=U64_MAX - 10))
        header = view.candidate(view.genesis_id, U64_MAX, identity("last representable time"))
        view.append(header, U64_MAX - 120)
        view.check_activation_clock(header.record_id, U64_MAX)
        with self.assertRaisesRegex(DaaError, "TIME_RANGE_EXHAUSTED"):
            view.requirement(header.record_id)


class PeriodicCompressionRegressionTests(unittest.TestCase):
    """Exact legacy arithmetic contrast; no native packets or mining clocks."""

    def branching_view(self):
        rules = schedule(())
        view = BranchTimeDaa(rules)
        receipts = {}

        def record(parent_id, height, timestamp, label):
            header = view.candidate(parent_id, timestamp,
                                    identity(f"{label}:{height}:{parent_id}"))
            self.assertEqual(header.height, height)
            # These are explicit logical observations, not measured completion
            # times or an assumption that the proof can be mined by this time.
            receipts[header.record_id] = view.append(
                header, rules.genesis_timestamp + height * rules.legacy.spacing)
            return header.record_id

        common = view.genesis_id
        for height in range(1, 16):
            common = record(common, height, rules.genesis_timestamp + height * 10, "common")
        ordinary = common
        for height in range(16, 66):
            ordinary = record(ordinary, height, rules.genesis_timestamp + height * 10, "ordinary")
        compressed = common
        for height in range(16, 65):
            compressed = record(compressed, height, view.header(compressed).timestamp + 1,
                                "strictly-increasing-compressed")
        return rules, view, common, ordinary, compressed, receipts

    @staticmethod
    def required_credit(view, tip):
        # Recompute from the selected ancestry, excluding the genesis record.
        return sum((1 << 256) // (header.target + 1)
                   for header in view.ancestry(tip) if header.height)

    def test_strictly_increasing_legacy_branch_reaches_793_with_positive_spans(self):
        rules, view, common, ordinary, compressed, receipts = self.branching_view()
        self.assertEqual(rules.upgrades, ())
        self.assertEqual(view.header(common).height, 15)
        ordinary_branch = view.ancestry(ordinary)
        compressed_branch = view.ancestry(compressed)
        ordinary_ids = {header.record_id for header in ordinary_branch if header.height}
        compressed_ids = {header.record_id for header in compressed_branch if header.height}
        common_ids = {header.record_id for header in view.ancestry(common) if header.height}
        self.assertEqual(ordinary_ids & compressed_ids, common_ids)
        self.assertEqual(len(ordinary_ids | compressed_ids), 114)
        self.assertEqual(set(receipts), ordinary_ids | compressed_ids)
        self.assertEqual(len(json.loads(view.snapshot())["records"]), 114)
        self.assertEqual((view.header(ordinary).height, self.required_credit(view, ordinary)),
                         (65, 130))
        self.assertEqual((view.header(compressed).height, self.required_credit(view, compressed)),
                         (64, 793))
        for branch in (ordinary_branch, compressed_branch):
            self.assertTrue(all(child.timestamp > parent.timestamp
                                for child, parent in zip(branch, branch[1:])))
            self.assertEqual(sum(receipts[header.record_id].required_work
                                 for header in branch if header.height),
                             self.required_credit(view, branch[0].record_id))

        by_height = {header.height: header for header in compressed_branch}
        for height in range(16, 65):
            self.assertEqual(by_height[height].timestamp - by_height[height - 1].timestamp, 1)
        self.assertEqual([receipts[by_height[h].record_id].required_work
                          for h in (16, 32, 48, 64)], [2, 7, 31, 123])
        signed_spans, clamped_spans = [], []
        for height in (32, 48, 64):
            first, last = by_height[height - 16], by_height[height - 1]
            signed_span = last.timestamp - first.timestamp
            desired = (rules.legacy.interval - 1) * rules.legacy.spacing
            clamped = min(4 * desired, max((desired + 3) // 4, max(1, signed_span)))
            signed_spans.append(signed_span)
            clamped_spans.append(clamped)
            self.assertEqual(by_height[height].target,
                             retained_periodic_retarget(last.target, first.timestamp,
                                                        last.timestamp, 16, 10, LIMIT))
        self.assertEqual(signed_spans, [15, 15, 15])
        self.assertEqual(clamped_spans, [38, 38, 38])
        self.assertIs(qualification()["mixed_consensus_security_proved"], False)
        self.assertIs(qualification()["complete_work_relation_verified"], False)

    def test_compressed_legacy_replay_preserves_credit_and_current_clock_refusal(self):
        rules, warm, _, ordinary, compressed, receipts = self.branching_view()
        snapshot = warm.snapshot()
        cold = BranchTimeDaa.restore(snapshot, rules, snapshot_id(snapshot))
        self.assertEqual(cold.snapshot(), snapshot)
        for tip, expected_credit in ((ordinary, 130), (compressed, 793)):
            self.assertEqual(cold.ancestry(tip), warm.ancestry(tip))
            self.assertEqual(cold.requirement(tip), warm.requirement(tip))
            for state in (warm, cold):
                header = state.header(tip)
                earliest_clock = header.timestamp - rules.legacy.future_skew
                self.assertEqual(self.required_credit(state, tip), expected_credit)
                with self.assertRaisesRegex(TimeDeferred, "ACTIVATION_TIME_DEFERRED"):
                    state.check_activation_clock(tip, earliest_clock - 1)
                with self.assertRaisesRegex(TimeDeferred, "TIME_DEFERRED"):
                    state.append(header, earliest_clock - 1)
                self.assertEqual(state.snapshot(), snapshot)
                state.check_activation_clock(tip, earliest_clock)
                # A later duplicate supplies the original arithmetic receipt;
                # it cannot create another record or increase branch credit.
                self.assertEqual(state.append(header, earliest_clock), receipts[tip])
                self.assertEqual(state.snapshot(), snapshot)
                self.assertEqual(self.required_credit(state, tip), expected_credit)
        for name, value in qualification().items():
            if name not in ("schema", "scope"):
                with self.subTest(qualification=name):
                    self.assertIs(value, False)


class ColdReplayTests(unittest.TestCase):
    def branching_view(self):
        rules = schedule((Upgrade(16, 10, 160, 120), Upgrade(32, 20, 80, 60)))
        view = BranchTimeDaa(rules)
        common = advance(view, view.genesis_id, 14)
        left = advance(view, append(view, common, 1150, "left"), 24, label="left")
        right = advance(view, append(view, common, 1153, "right"), 21, label="right")
        return rules, view, (common, left, right)

    def test_hot_cold_branch_anchor_target_and_version_results_agree(self):
        rules, view, tips = self.branching_view()
        snapshot = view.snapshot()
        cold = BranchTimeDaa.restore(snapshot, rules, snapshot_id(snapshot))
        self.assertEqual(cold.snapshot(), snapshot)
        for tip in tips:
            with self.subTest(tip=tip):
                self.assertEqual(cold.ancestry(tip), view.ancestry(tip))
                self.assertEqual(cold.requirement(tip), view.requirement(tip))
                warm_cache = view.requirement(tip).anchor
                self.assertEqual(cold.requirement(tip, warm_cache), view.requirement(tip))
                cold.check_activation_clock(tip, 100000)
                view.check_activation_clock(tip, 100000)

    def test_current_activation_clock_is_required_after_replay_and_matches_warm(self):
        rules, view, tips = self.branching_view()
        snapshot = view.snapshot()
        cold = BranchTimeDaa.restore(snapshot, rules, snapshot_id(snapshot))
        for state in (view, cold):
            with self.assertRaisesRegex(TimeDeferred, "ACTIVATION_TIME_DEFERRED"):
                state.check_activation_clock(tips[1], 0)
            state.check_activation_clock(tips[1], 100000)

    def test_independently_expected_recovery_identity_rejects_valid_prefix_rollback(self):
        rules, view, _ = self.branching_view()
        original = view.snapshot()
        original_identity = snapshot_id(original)
        mutated = json.loads(original)
        mutated["records"] = mutated["records"][:14]
        truncated = encode(mutated)
        with self.assertRaisesRegex(DaaError, "RECOVERY_IDENTITY_MISMATCH"):
            BranchTimeDaa.restore(truncated, rules, original_identity)
        # Demonstrate the exact remaining custody assumption: replacing BOTH
        # bytes and the caller's external identity can restore this valid prefix.
        prefix = BranchTimeDaa.restore(truncated, rules, snapshot_id(truncated))
        self.assertEqual(prefix.snapshot(), truncated)
        self.assertIs(qualification()["independent_recovery_anchor_established"], False)

    def test_restore_never_accepts_snapshot_schedule_as_its_own_authority(self):
        rules, view, _ = self.branching_view()
        original = view.snapshot()
        with self.assertRaisesRegex(DaaError, "SNAPSHOT_SCHEDULE_BINDING"):
            BranchTimeDaa.restore(original, replace(rules, genesis_timestamp=999), snapshot_id(original))
        with self.assertRaisesRegex(DaaError, "EXPECTED_SNAPSHOT_ID_ENCODING"):
            BranchTimeDaa.restore(original, rules, True)

    def test_persisted_anchor_mutations_refuse_even_inside_matching_envelope(self):
        rules, view, _ = self.branching_view()
        original = json.loads(view.snapshot())
        for forged in (identity("foreign anchor"), None):
            mutated = json.loads(json.dumps(original))
            mutated["records"][-1]["anchor_commitment"] = forged
            with self.subTest(forged=forged), self.assertRaisesRegex(DaaError, "PERSISTED_ANCHOR_MISMATCH"):
                restore_untrusted_envelope(mutated, rules)

    def test_mutant_target_cannot_be_laundered_by_rehashing_record(self):
        rules, view, _ = self.branching_view()
        mutated = json.loads(view.snapshot())
        last = mutated["records"][-1]
        last["target_hex"] = f"{int(last['target_hex'], 16) - 1:064x}"
        rebind_row_id(last)
        with self.assertRaisesRegex(DaaError, "REQUIRED_TARGET"):
            restore_untrusted_envelope(mutated, rules)

    def test_cold_time_version_and_parent_mutations_are_recomputed(self):
        rules, view, _ = self.branching_view()
        original = json.loads(view.snapshot())
        for change, reason in (
            ({"timestamp": "0"}, "TIME_NONDECREASING"),
            ({"rule_id": identity("retired version")}, "RULE_IDENTITY"),
            ({"parent_id": identity("missing parent")}, "UNKNOWN_PARENT"),
            ({"observed_now": "0"}, "TIME_DEFERRED"),
        ):
            mutated = json.loads(json.dumps(original))
            mutated["records"][-1].update(change)
            rebind_row_id(mutated["records"][-1])
            with self.subTest(reason=reason), self.assertRaisesRegex(DaaError, reason):
                restore_untrusted_envelope(mutated, rules)

    def test_duplicate_reordered_and_uncommitted_records_refuse(self):
        rules, view, _ = self.branching_view()
        original = json.loads(view.snapshot())
        for mode, reason in (("duplicate", "DUPLICATE_RECORD"),
                             ("reverse", "UNKNOWN_PARENT"), ("body", "RECORD_COMMITMENT")):
            mutated = json.loads(json.dumps(original))
            if mode == "duplicate":
                mutated["records"].append(mutated["records"][-1])
            elif mode == "reverse":
                mutated["records"].reverse()
            else:
                mutated["records"][-1]["body_id"] = identity("changed after persistence")
            with self.subTest(mode=mode), self.assertRaisesRegex(DaaError, reason):
                restore_untrusted_envelope(mutated, rules)

    def test_noncanonical_numeric_unknown_fields_and_json_duplicates_refuse(self):
        rules, view, _ = self.branching_view()
        original = json.loads(view.snapshot())
        for value in (True, 1, "01", "+1", "-1", "1.0", str(1 << 64)):
            mutated = json.loads(json.dumps(original))
            mutated["records"][-1]["height"] = value
            with self.subTest(value=value), self.assertRaises(DaaError):
                restore_untrusted_envelope(mutated, rules)
        mutated = json.loads(json.dumps(original))
        mutated["records"][-1]["production_activation"] = True
        with self.assertRaisesRegex(DaaError, "RECORD_FIELDS"):
            restore_untrusted_envelope(mutated, rules)
        data = view.snapshot().replace(b'"schema":', b'"schema":"shadow","schema":', 1)
        with self.assertRaisesRegex(DaaError, "DUPLICATE_JSON_KEY"):
            BranchTimeDaa.restore(data, rules, snapshot_id(data))
        data = json.dumps(original, indent=2).encode("ascii")
        with self.assertRaisesRegex(DaaError, "SNAPSHOT_NONCANONICAL"):
            BranchTimeDaa.restore(data, rules, snapshot_id(data))

    def test_explicit_resource_bounds_never_drop_records_or_reset_anchor(self):
        rules = schedule()
        view = BranchTimeDaa(rules)
        first = append(view, view.genesis_id)
        original = view.snapshot()
        with patch.object(component, "MAX_RECORDS", 2):
            with self.assertRaisesRegex(DaaError, "RECORD_BUDGET"):
                append(view, first)
        self.assertEqual(view.snapshot(), original)
        with patch.object(component, "MAX_SNAPSHOT_BYTES", len(original) - 1):
            with self.assertRaisesRegex(DaaError, "SNAPSHOT_BYTE_BUDGET"):
                view.snapshot()

    def test_qualification_does_not_promote_reference_execution(self):
        result = qualification()
        self.assertEqual(result["schema"], component.SCHEMA)
        self.assertEqual(ASERT_ALGORITHM, "aserti3-raw-u256-monotone-v1")
        for key, value in result.items():
            if key not in ("schema", "scope"):
                with self.subTest(flag=key):
                    self.assertIs(value, False)


if __name__ == "__main__":
    unittest.main()
