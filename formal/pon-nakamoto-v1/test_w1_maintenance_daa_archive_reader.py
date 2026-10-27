"""Actual W1 transcript replay, cold bytes and explicit failure boundaries."""
from __future__ import annotations

import copy
import tempfile
from pathlib import Path
import unittest

from w1_maintenance_daa_proof_research import run
from w1_maintenance_daa_archive_reader import replay, _strict_read, _unique


class ArchivedRealProofReadbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = {}
        cls.report = run(cls.artifacts)
        cls.reads = staticmethod(lambda key: cls.artifacts[key])

    def test_recomputes_actual_31_w1_transcripts_and_signed_free_work(self):
        result = replay(self.report, self.reads)
        self.assertEqual(result["complete_w1_valid"], 31)
        self.assertEqual(result["invalid_transcript_rejected"], 1)
        self.assertEqual(result["inventory_sha256"],
                         "ecf015e262b03043b8a0395ee78a7cf04889a514dcf74f15c17106203ebfefbc")
        self.assertFalse(result["native_Node_acceptance"])
        self.assertFalse(result["independent_operators_accepted"])

    def test_a_real_proof_byte_mutation_is_never_work(self):
        first = self.report["proof_inventory"][0]["block_id"]
        def wrong(key):
            header, proof = self.reads(key)
            if key == first:
                broken = bytearray(proof)
                broken[-1] ^= 1
                proof = bytes(broken)
            return header, proof
        with self.assertRaises(ValueError):
            replay(self.report, wrong)

    def test_missing_original_packet_cannot_be_substituted_by_another(self):
        first = self.report["proof_inventory"][0]["block_id"]
        def missing(key):
            if key == first:
                raise ValueError("MISSING_ORIGINAL_PACKET")
            return self.reads(key)
        with self.assertRaisesRegex(ValueError, "MISSING_ORIGINAL_PACKET"):
            replay(self.report, missing)

    def test_claimed_chainwork_and_nonce_attempts_are_rederived(self):
        for field, value in (("work_cumulative","100000000000"),
                             ("attempts_including_misses", 9000)):
            fake = copy.deepcopy(self.report)
            fake["proof_inventory"][2][field] = value
            with self.assertRaises(ValueError):
                replay(fake, self.reads)

    def test_report_cannot_escalate_into_consensus_authority(self):
        for field in ("native_Node_execution","new_daa_activated","work_hardness_qualified"):
            fake = copy.deepcopy(self.report)
            fake["qualification"][field] = True
            with self.assertRaisesRegex(ValueError, "false authority"):
                replay(fake, self.reads)

    def test_false_trace_replaced_with_real_valid_proof_must_fail(self):
        honest = self.report["honest_tip"]["block_id"]
        def invalid_replaced(key):
            if key == "invalid-claimed-transcript":
                return self.reads(honest)
            return self.reads(key)
        with self.assertRaises(ValueError):
            replay(self.report, invalid_replaced)

    def test_invalid_resource_observation_type_not_promoted(self):
        for value in (-1, float("nan"), True):
            fake = copy.deepcopy(self.report)
            fake["proof_inventory"][0]["producer_cpu_ns"] = value
            with self.assertRaisesRegex(ValueError, "untrusted resource metric"):
                replay(fake, self.reads)

    def test_duplicate_metadata_and_hostile_paths_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate report key"):
            _unique([("target",1),("target",1)])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/"payload"
            p.write_bytes(bytes(20))
            with self.assertRaisesRegex(ValueError,"artifact size/type"):
                _strict_read(p, 19)
            sym=Path(d)/"slink"
            sym.symlink_to(p)
            with self.assertRaisesRegex(ValueError,"symlink"):
                _strict_read(sym,20)


if __name__=="__main__":
    unittest.main()
