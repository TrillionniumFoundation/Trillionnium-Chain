#!/usr/bin/env python3
"""Read 6f account_node_decode_arithmetic; no SQL-read or time inference.
Producer: native_node_decode.rs blob 2c86a7c89297df32b75526b0d1e3fe751d8c5d26.
Counter retained is cumulative writes; the retained object contains snapshot gauges.
"""
DECODE_SCHEMA = "pon-native-account-node-decode-arithmetic-v1"
DECODE_U64_MAX = (1 << 64) - 1
DECODE_COUNTERS = ("calls", "exact_hits", "original_decodes", "retained",
                   "bounded_probe_refusals", "borrow_conflicts")
DECODE_META = ("slot_limit", "probe_limit", "record_byte_limit", "slot_size_bytes",
               "retained_software_charge_limit_bytes", "hard_software_charge_ceiling_bytes")
DECODE_GAUGES = ("allocated_slots", "occupied_slots", "retained_record_bytes",
                 "allocated_slot_bytes", "retained_software_charge_bytes")


def _decode_uint(value):
    return type(value) is int and 0 <= value <= DECODE_U64_MAX


def _decode_meta(value):
    if not isinstance(value, dict) or value.get("schema") != DECODE_SCHEMA:
        return None
    meta = {key: value.get(key) for key in DECODE_META}
    if not all(_decode_uint(item) for item in meta.values()):
        return None
    if ([meta[key] for key in ("slot_limit", "probe_limit", "record_byte_limit",
                              "hard_software_charge_ceiling_bytes")] != [8192, 8, 163, 4194304]
            or value.get("has_consensus_authority") is not False
            or value.get("charge_is_process_rss_bound") is not False):
        return None
    allocation = 8192 * meta["slot_size_bytes"]
    return meta if 0 < allocation < meta["retained_software_charge_limit_bytes"] <= 4194304 else None


def _decode_gauge(value, meta):
    unknown = {"status": "unknown", "values": None}
    if meta is None or not isinstance(value, dict) or value.get("retained") is None:
        return {**unknown, "reason": "not_observed_or_metadata_unknown"}
    raw = value["retained"]
    if not isinstance(raw, dict):
        return {**unknown, "reason": "invalid_gauge"}
    gauge = {key: raw.get(key) for key in DECODE_GAUGES}
    if not all(_decode_uint(item) for item in gauge.values()):
        return {**unknown, "reason": "invalid_gauge"}
    slots, occupied, payload, allocated, charge = (gauge[key] for key in DECODE_GAUGES)
    overhead = meta["retained_software_charge_limit_bytes"] - 8192 * meta["slot_size_bytes"]
    if (slots not in (0, 8192) or occupied > slots or payload > occupied * 163
            or allocated != slots * meta["slot_size_bytes"] or charge != allocated + overhead):
        return {**unknown, "reason": "gauge_bound_mismatch"}
    return {"status": "observed", "values": gauge}


def _decode_counts(value):
    raw = value.get("counters") if isinstance(value, dict) else None
    if not isinstance(raw, dict) or not all(_decode_uint(raw.get(key)) for key in DECODE_COUNTERS):
        return None
    return {key: raw[key] for key in DECODE_COUNTERS}


def decode_delta(before, after):
    bm, am = _decode_meta(before), _decode_meta(after)
    bc, ac = _decode_counts(before), _decode_counts(after)
    result = {"schema": "trnm-native-account-node-decode-delta-v1", "status": "unknown",
              "reason": None, "delta": None, "bounds_before": bm, "bounds_after": am,
              "counters_before": bc, "counters_after": ac,
              "retained_before": _decode_gauge(before, bm), "retained_after": _decode_gauge(after, am),
              "retained_gauges_are_deltas": False, "sql_reads_inferred": False,
              "timing_attributed": False, "has_consensus_authority": False}
    if bm is None or am is None or bm != am:
        result["reason"] = "missing_invalid_or_changed_schema_bounds"
    elif bc is None or ac is None:
        result["reason"] = "missing_or_invalid_counters"
    elif DECODE_U64_MAX in (*bc.values(), *ac.values()):
        result["reason"] = "counter_saturated_or_exactly_at_limit"
    elif any(ac[key] < bc[key] for key in DECODE_COUNTERS):
        result["reason"] = "counter_rewind_or_owner_reset"
    elif any(c["calls"] != c["exact_hits"] + c["original_decodes"]
             or c["retained"] + c["bounded_probe_refusals"] > c["original_decodes"]
             or c["borrow_conflicts"] > 2 * c["original_decodes"] for c in (bc, ac)):
        result["reason"] = "inconsistent_completed_counters"
    else:
        delta = {key: ac[key] - bc[key] for key in DECODE_COUNTERS}
        if (delta["calls"] != delta["exact_hits"] + delta["original_decodes"]
                or delta["retained"] + delta["bounded_probe_refusals"] > delta["original_decodes"]
                or delta["borrow_conflicts"] > 2 * delta["original_decodes"]):
            result["reason"] = "inconsistent_completed_counter_delta"
        else:
            result.update(status="observed", delta=delta)
    return result


def _self_test():
    from copy import deepcopy
    import unittest

    class DecodeDeltaTests(unittest.TestCase):
        def fixture(self, counts=(10, 4, 6, 3, 1, 2)):
            # Synthetic ABI sizes exercise bounds; these are not native measurements.
            return {"schema": DECODE_SCHEMA, "slot_limit": 8192, "probe_limit": 8,
                    "record_byte_limit": 163, "slot_size_bytes": 400,
                    "retained_software_charge_limit_bytes": 3276872,
                    "hard_software_charge_ceiling_bytes": 4194304,
                    "has_consensus_authority": False, "charge_is_process_rss_bound": False,
                    "counters": dict(zip(DECODE_COUNTERS, counts)),
                    "retained": {"allocated_slots": 8192, "occupied_slots": 3,
                                 "retained_record_bytes": 147, "allocated_slot_bytes": 3276800,
                                 "retained_software_charge_bytes": 3276872}}

        def test_errors_and_two_borrow_conflicts_still_count_as_original_decode(self):
            a, b = self.fixture(), self.fixture((13, 5, 8, 4, 1, 4))
            self.assertEqual(decode_delta(a, b)["delta"], dict(zip(DECODE_COUNTERS, (3, 1, 2, 1, 0, 2))))

        def test_missing_gauge_does_not_invent_zero_or_destroy_counts(self):
            a, b = self.fixture(), self.fixture()
            b["retained"] = None
            out = decode_delta(a, b)
            self.assertEqual(out["status"], "observed")
            self.assertIsNone(out["retained_after"]["values"])

        def test_gauges_can_shrink_without_counter_subtraction(self):
            a, b = self.fixture(), self.fixture()
            b["retained"].update(occupied_slots=1, retained_record_bytes=49)
            self.assertEqual(decode_delta(a, b)["status"], "observed")

        def test_invalid_or_missing_inputs_are_unknown(self):
            for change in (None, {}, {"schema": "other"}, self.fixture((True, 4, 6, 3, 1, 2)),
                           self.fixture((10, 5, 6, 3, 1, 2)), self.fixture((9, 4, 5, 3, 1, 2)),
                           self.fixture((DECODE_U64_MAX, DECODE_U64_MAX - 6, 6, 3, 1, 2))):
                with self.subTest(change=change):
                    self.assertIsNone(decode_delta(self.fixture(), change)["delta"])

        def test_bounds_initial_unallocated_and_malformed_gauge(self):
            a, b = self.fixture(), self.fixture()
            b["probe_limit"] = 9
            self.assertIsNone(decode_delta(a, b)["delta"])
            b = deepcopy(a)
            b["retained"]["retained_record_bytes"] = 1000
            self.assertEqual(decode_delta(a, b)["retained_after"]["status"], "unknown")
            zero = self.fixture((0, 0, 0, 0, 0, 0))
            zero["retained"].update(allocated_slots=0, occupied_slots=0, retained_record_bytes=0,
                                    allocated_slot_bytes=0, retained_software_charge_bytes=72)
            self.assertEqual(decode_delta(zero, zero)["status"], "observed")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DecodeDeltaTests)
    return unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()


if __name__ == "__main__":
    raise SystemExit(0 if _self_test() else 1)
