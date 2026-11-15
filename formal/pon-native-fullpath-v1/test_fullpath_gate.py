"""Adversarial reader controls. Generated envelopes are NOT valid work fixtures.

No test result qualifies native work or the collector. These fixtures exercise
byte/accounting consistency and refusal paths without expensive mining.
"""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

import fullpath_gate as gate


def envelope(parent="03" * 32, height=1, nonce=0, target="ff" * 32):
    witness = bytes(44)
    header = (b"PGH2PNH1\x01\0" + bytes([1]) * 32 + bytes([2]) * 32 + bytes.fromhex(parent)
              + struct.pack("<QQ", height, 11) + bytes.fromhex(target) + bytes([5]) * 32
              + gate.sequence_root([]) + bytes([7]) * 32 + bytes([8]) * 32 + bytes([9]) * 32
              + struct.pack("<Q", nonce) + gate.domain_hash("native-growth-account-witness-v2", witness))
    proof = b"PNW1" + bytes(gate.PROOF_BYTES - 36) + bytes([11]) * 32
    return b"PNP2" + header + b"\0\0" + struct.pack("<I", len(witness)) + witness + proof


def progress(counts=(1, 512, 1, 1)):
    value = {"scope": "admission_call_only; cold-open and observer replay excluded",
             "clock": "nanoseconds since this process admission call", "expected_transcript_tiles": 512}
    for index, (field, count) in enumerate(zip(("BeforeReplay", "TranscriptTile", "BeforeProduct", "BeforeVerifiedWork"), counts)):
        value[field] = dict(count=count, first_ns=index + 1 if count else None,
                            last_ns=index + 1 if count else None)
    return value


class Campaign:
    def __init__(self, root):
        self.root = Path(root)
        self.raw = envelope()
        self.packet = gate.parse_packet(self.raw)
        self.packet_ref = self.put("packet.pnp2", self.raw)
        self.context = dict(schema="trnm-pon-fullpath-context-v1", scope="same-host-component-observation",
            clock_id="parent-clock", source_sha256="10" * 32, binary_sha256="11" * 32,
            resource_contract_sha256="12" * 32, workload_sha256="13" * 32,
            network_hex="01" * 32, parameters_hex="02" * 32, genesis_hex="03" * 32,
            stage_semantics={phase: phase + " bounded native collector stage" for phase in gate.PHASES})
        self.context_ref = self.put_json("context.json", self.context)
        self.manifest = dict(schema=gate.MANIFEST_SCHEMA, context=self.context_ref, observation_end_ns=1000,
            required_depth=0, minimum_reorg_window_ns=0, maximum_total_cpu_ns=1000,
            maximum_peak_rss_bytes=1000, maximum_total_wire_bytes=1000000,
            minimum_timely_ppm=1000000, minimum_samples_per_group=1,
            schedule=[dict(id="valid", cohort="honest", mode="native", scheduled_ns=0, deadline_ns=900,
                           reorg_observe_until_ns=1000, parent_hex=self.packet["parent_hex"], task_hex=self.packet["task_hex"])])
        self.receipts = {}
        stages = []
        for index, phase in enumerate(gate.PHASES):
            event = self.native_event(gate.EVENTS[phase])
            if phase == "search":
                event["nonce_attempts"] = 1
            if phase == "verification":
                event.update(work_progress=progress(), admission_call_ns=10,
                             admission_reused_existing=False, admitted_block_hex=self.packet["block_hex"])
            if phase == "acceptance":
                event["native_observation"] = self.observation()
            self.receipts[phase] = event
            ref = self.put_json(phase + ".json", event)
            stages.append(dict(phase=phase, started_ns=100 + 100 * index, ended_ns=200 + 100 * index,
                               status="complete", claim_sha256=self.packet["claim_sha256"], receipt=ref))
        check_ref = self.put_json("final-observation.json", self.observation())
        self.row = dict(id="valid", context_sha256=self.context_ref["sha256"], status="accepted",
            packet=self.packet_ref, claim=self.packet["claim"], stages=stages, cpu_ns=100,
            peak_rss_bytes=200, wire_bytes=len(self.raw), canonical_checks=[
                dict(at_ns=600, receipt=stages[-1]["receipt"], canonical_path=[self.packet_ref]),
                dict(at_ns=1000, receipt=check_ref, canonical_path=[self.packet_ref])])
        self.report = dict(schema=gate.REPORT_SCHEMA, manifest_sha256="", context_sha256=self.context_ref["sha256"],
            clock_id=self.context["clock_id"], observed_through_ns=1000,
            resources=dict(cpu_ns=100, peak_rss_bytes=200, wire_bytes=len(self.raw)), attempts=[self.row])

    def put(self, path, raw):
        (self.root / path).write_bytes(raw)
        return dict(path=path, sha256=gate.sha256(raw))

    def put_json(self, path, value):
        return self.put(path, gate.canonical(value) + b"\n")

    def native_event(self, name):
        value = {field: self.packet[field] for field in ("claim", "block_hex", "parent_hex", "task_hex", "challenge_hex", "packet_bytes")}
        value.update(schema=gate.PROCESS_SCHEMA, event=name, development=True,
                     compressed_proof_generation_ns=None,
                     compression_status="not_applicable_native_full_verification")
        return value

    def observation(self, *, depth=0, tip=None, member=True, stored=True):
        tip = tip or self.packet
        return dict(schema=gate.OBSERVATION_SCHEMA, packet_profile="PNP2", network="01" * 32,
            parameters="02" * 32, genesis="03" * 32, block=self.packet["block_hex"], stored_exact=stored,
            block_height=self.packet["height"] if stored else None,
            block_chainwork_hex=f"{1:0128x}" if stored else None,
            active_tip=tip["block_hex"], active_tip_height=tip["height"], active_tip_chainwork_hex=f"{1 + depth:0128x}",
            active_chain_member=member, active_depth=depth if member else None,
            active_work_depth_hex=f"{depth:0128x}" if member else None, generation=1,
            global_absence_authority=False, confirmation_authority=False,
            finality_authority=False, execution_authority=False, production_activation=False)

    def refresh_phase(self, phase):
        index = gate.PHASES.index(phase)
        self.row["stages"][index]["receipt"] = self.put_json(phase + ".json", self.receipts[phase])

    def evaluate(self):
        manifest_ref = self.put_json("manifest.json", self.manifest)
        self.report["manifest_sha256"] = manifest_ref["sha256"]
        self.put_json("observations.json", self.report)
        return gate.read_campaign(self.root, manifest_ref["sha256"])

    def add_hostile(self, error="WORK:Product"):
        plan = copy.deepcopy(self.manifest["schedule"][0])
        plan.update(id="hostile", cohort="hostile")
        self.manifest["schedule"].append(plan)
        value = self.native_event("error")
        value.update(stage="verification", error=error, cancelled=False,
                     work_progress=progress((1, 512, 1, 0)), admission_call_ns=10)
        ref = self.put_json("hostile-error.json", value)
        row = copy.deepcopy(self.row)
        row.update(id="hostile", status="rejected", canonical_checks=[], stages=[dict(
            phase="verification", started_ns=100, ended_ns=500, status="rejected",
            claim_sha256=self.packet["claim_sha256"], receipt=ref)])
        self.report["attempts"].append(row)
        self.report["resources"]["cpu_ns"] += row["cpu_ns"]
        self.report["resources"]["wire_bytes"] += row["wire_bytes"]
        return row


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.c = Campaign(self.tmp.name)

    def test_component_never_upgrades_even_if_all_recorded_arithmetic_matches(self):
        self.c.add_hostile()
        result = self.c.evaluate()
        self.assertTrue(result["recorded_arithmetic_thresholds_met"])
        self.assertEqual(result["timely_accepted_progress"], 1)
        self.assertEqual(result["performance_gate"], "COMPONENT_OBSERVATION_ONLY")
        for field in ("security_gate", "overall_gate"):
            self.assertEqual(result[field], "HOLD")
        self.assertFalse(result["security_qualification_verified"])
        self.assertFalse(result["production_activation"])
        self.assertFalse(result["quantum_lower_bound_proved"])

    def test_relabeling_scope_cannot_qualify_development_collector(self):
        self.c.context["scope"] = "campaign"
        ref = self.c.put_json("context.json", self.c.context)
        self.c.manifest["context"] = ref
        self.c.report["context_sha256"] = self.c.row["context_sha256"] = ref["sha256"]
        self.assertEqual(self.c.evaluate()["performance_gate"], "COMPONENT_OBSERVATION_ONLY")

    def test_actual_pgh2_fixed_vectors(self):
        header = (b"PGH2PNH1\x01\0" + bytes([1]) * 32 + bytes([2]) * 32 + bytes([3]) * 32
                  + struct.pack("<QQ", 7, 11) + b"".join(bytes([i]) * 32 for i in range(4, 10))
                  + struct.pack("<Q", 13) + bytes([10]) * 32)
        self.assertEqual(gate.domain_hash("permanent-account-growth-challenge-v2", header).hex(),
                         "8f051f34d44a6385e3c386325c2d82091d2563b40ce4443f1056ef5abf633208")
        self.assertEqual(gate.domain_hash("permanent-account-growth-block-v2", header, bytes([11]) * 32).hex(),
                         "4b87b9fca8d5a0eeec486d9eef108b445d28998fe5db3cc0f4f6dea6db9a22eb")

    def test_exact_body_and_witness_digest_scopes(self):
        self.assertEqual(self.c.packet["claim"]["body_sha256"], gate.sha256(b"\0\0"))
        self.assertEqual(self.c.packet["claim"]["witness_sha256"], gate.sha256(bytes(44)))

    def test_late_product_invalid_preserves_block_but_changes_packet_claim(self):
        changed = bytearray(self.c.raw)
        changed[-36] ^= 1
        bad = gate.parse_packet(bytes(changed))
        self.assertEqual(bad["block_hex"], self.c.packet["block_hex"])
        self.assertNotEqual(bad["claim_sha256"], self.c.packet["claim_sha256"])

    def test_packet_encoding_and_binding_failures(self):
        for offset in (0, 4, 8, 14, 190, 330):
            changed = bytearray(self.c.raw)
            changed[offset] ^= 1
            # Network bytes change identity, not the packet commitment grammar.
            if offset == 14:
                self.assertNotEqual(gate.parse_packet(bytes(changed))["network_hex"], self.c.packet["network_hex"])
            else:
                with self.subTest(offset=offset), self.assertRaises(ValueError):
                    gate.parse_packet(bytes(changed))
        for raw in (self.c.raw[:-1], self.c.raw + b"\0", self.c.raw[:100]):
            with self.assertRaises(ValueError):
                gate.parse_packet(raw)

    def test_missing_rows_remain_denominator_even_at_low_ratio(self):
        extra = copy.deepcopy(self.c.manifest["schedule"][0])
        extra["id"] = "missing"
        self.c.manifest["schedule"].append(extra)
        self.c.manifest["minimum_timely_ppm"] = 1
        result = self.c.evaluate()
        self.assertEqual(result["scheduled"], 2)
        self.assertEqual(result["missing"], ["missing"])
        self.assertFalse(result["recorded_arithmetic_thresholds_met"])

    def test_duplicate_block_never_adds_progress(self):
        plan = copy.deepcopy(self.c.manifest["schedule"][0]); plan["id"] = "again"
        row = copy.deepcopy(self.c.row); row["id"] = "again"
        self.c.manifest["schedule"].append(plan)
        self.c.report["attempts"].append(row)
        self.c.report["resources"]["cpu_ns"] *= 2
        self.c.report["resources"]["wire_bytes"] *= 2
        result = self.c.evaluate()
        self.assertEqual(result["recorded_unique_new_native_blocks"], 1)
        self.assertEqual(result["timely_accepted_progress"], 1)
        self.assertTrue(result["attempts"][1]["duplicate_progress"])
        self.assertFalse(result["recorded_arithmetic_thresholds_met"])

    def test_duplicate_observation_ids_and_unscheduled_ids_rejected(self):
        self.c.report["attempts"].append(copy.deepcopy(self.c.row))
        with self.assertRaisesRegex(ValueError, "UNSCHEDULED_OR_DUPLICATE"):
            self.c.evaluate()
        self.c.report["attempts"].pop()
        self.c.row["id"] = "unknown"
        with self.assertRaisesRegex(ValueError, "UNSCHEDULED_OR_DUPLICATE"):
            self.c.evaluate()

    def test_parent_task_context_and_clock_cannot_be_spliced(self):
        changes = ((self.c.manifest["schedule"][0], "parent_hex", "ff" * 32),
                   (self.c.manifest["schedule"][0], "task_hex", "ff" * 32),
                   (self.c.row, "context_sha256", "ff" * 32),
                   (self.c.report, "clock_id", "other-clock"))
        for container, key, value in changes:
            old = container[key]; container[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.c.evaluate()
            container[key] = old

    def test_phase_claim_changed_or_receipt_spliced(self):
        self.c.row["stages"][3]["claim_sha256"] = "ff" * 32
        with self.assertRaisesRegex(ValueError, "PHASE_CLAIM"):
            self.c.evaluate()
        self.c.row["stages"][3]["claim_sha256"] = self.c.packet["claim_sha256"]
        self.c.receipts["verification"]["claim"]["body_sha256"] = "ff" * 32
        self.c.refresh_phase("verification")
        with self.assertRaises(ValueError):
            self.c.evaluate()

    def test_full_path_requires_every_phase_and_complete_native_return(self):
        original = copy.deepcopy(self.c.row["stages"])
        for index in range(5):
            self.c.row["stages"] = original[:index] + original[index + 1:]
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, "ACCEPTED_WITHOUT_FULL_PATH"):
                self.c.evaluate()
        self.c.row["stages"] = original
        self.c.receipts["verification"]["event"] = "error"
        self.c.refresh_phase("verification")
        with self.assertRaisesRegex(ValueError, "ERROR_IN_COMPLETE_STAGE_RECEIPT"):
            self.c.evaluate()

    def test_terminal_cancel_callback_cannot_be_promoted_to_completed_work(self):
        value = self.c.native_event("error")
        value.update(stage="verification", error="PUBLIC_REQUEST_CANCELLED", cancelled=True,
                     work_progress=progress(), admission_call_ns=10)
        receipt = self.c.put_json("cancel.json", value)
        self.c.row.update(status="cancelled", canonical_checks=[])
        self.c.row["stages"] = self.c.row["stages"][:4]
        self.c.row["stages"][-1].update(status="cancelled", receipt=receipt)
        result = self.c.evaluate()
        self.assertEqual(result["timely_accepted_progress"], 0)
        self.assertFalse(result["attempts"][0]["full_native_replay_observed"])
        self.c.row["status"] = "accepted"
        with self.assertRaisesRegex(ValueError, "ACCEPTED_WITHOUT_FULL_PATH"):
            self.c.evaluate()

    def test_phase_after_cancel_and_overlapping_or_backward_clocks_rejected(self):
        self.c.row["stages"][3]["started_ns"] = 399
        with self.assertRaisesRegex(ValueError, "PHASE_START"):
            self.c.evaluate()
        self.c.row["stages"][3]["started_ns"] = 400
        self.c.row["stages"][2]["status"] = "partial"
        self.c.row["stages"][2]["receipt"] = None
        with self.assertRaisesRegex(ValueError, "PHASE_ORDER_OR_POST_FAILURE"):
            self.c.evaluate()

    def test_partial_native_tiles_not_full_replay(self):
        self.c.receipts["verification"]["work_progress"]["TranscriptTile"]["count"] = 511
        self.c.refresh_phase("verification")
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_FULL_NATIVE_REPLAY"):
            self.c.evaluate()

    def test_native_duplicate_callback_zeros_not_new_verification(self):
        self.c.receipts["verification"].update(work_progress=progress((0, 0, 0, 0)), admission_reused_existing=True)
        self.c.refresh_phase("verification")
        with self.assertRaisesRegex(ValueError, "REUSED_WORK_IS_NOT_NEW"):
            self.c.evaluate()

    def test_required_depth_does_not_shrink_to_recorded_depth(self):
        self.c.manifest["required_depth"] = 6
        result = self.c.evaluate()
        self.assertEqual(result["attempts"][0]["last_canonical_depth"], 0)
        self.assertEqual(result["timely_accepted_progress"], 0)
        self.assertFalse(result["recorded_arithmetic_thresholds_met"])

    def test_deadline_includes_search_queue_and_all_later_work(self):
        self.c.manifest["schedule"][0]["deadline_ns"] = 599
        result = self.c.evaluate()
        self.assertEqual(result["attempts"][0]["latency_from_scheduled_ns"], 600)
        self.assertEqual(result["timely_accepted_progress"], 0)

    def test_terminal_observation_and_window_end_must_be_covered(self):
        self.c.row["canonical_checks"].pop()
        result = self.c.evaluate()
        self.assertFalse(result["attempts"][0]["reorg_window_covered"])
        self.assertFalse(result["recorded_arithmetic_thresholds_met"])
        self.c.report["observed_through_ns"] = 999
        self.assertFalse(self.c.evaluate()["observation_window_covered"])

    def test_reorg_then_recovery_does_not_erase_observed_loss(self):
        ref = self.c.put_json("reorg.json", self.c.observation(member=False))
        self.c.row["canonical_checks"].insert(1, dict(at_ns=800, receipt=ref, canonical_path=[]))
        result = self.c.evaluate()
        self.assertTrue(result["attempts"][0]["reorg_or_absence_observed"])
        self.assertEqual(result["timely_accepted_progress"], 0)

    def test_membership_boolean_alone_and_forged_depth_cannot_pass(self):
        self.c.row["canonical_checks"][0]["canonical_path"] = []
        with self.assertRaisesRegex(ValueError, "MISSING_CANONICAL_PATH"):
            self.c.evaluate()
        self.c.row["canonical_checks"][0]["canonical_path"] = [self.c.packet_ref]
        changed = self.c.observation(); changed["active_depth"] = 6
        self.c.row["canonical_checks"][1]["receipt"] = self.c.put_json("forged-depth.json", changed)
        with self.assertRaisesRegex(ValueError, "CANONICAL_DEPTH"):
            self.c.evaluate()

    def test_parent_link_and_work_delta_are_recomputed(self):
        child_raw = envelope(parent=self.c.packet["block_hex"], height=2, nonce=1)
        child = gate.parse_packet(child_raw)
        child_ref = self.c.put("child.pnp2", child_raw)
        ref = self.c.put_json("depth-one.json", self.c.observation(depth=1, tip=child))
        check = dict(at_ns=1000, receipt=ref, canonical_path=[self.c.packet_ref, child_ref])
        self.assertEqual(gate.check_canonical(check, self.c.packet, gate.Evidence(self.c.root), self.c.context)["depth"], 1)
        bad = self.c.observation(depth=1, tip=child); bad["active_work_depth_hex"] = f"{2:0128x}"
        check["receipt"] = self.c.put_json("bad-work.json", bad)
        with self.assertRaisesRegex(ValueError, "CANONICAL_CHAINWORK"):
            gate.check_canonical(check, self.c.packet, gate.Evidence(self.c.root), self.c.context)
        wrong_ref = self.c.put("wrong-child.pnp2", envelope(height=2, nonce=1))
        check["canonical_path"] = [self.c.packet_ref, wrong_ref]
        with self.assertRaisesRegex(ValueError, "CANONICAL_PARENT_CHAIN"):
            gate.check_canonical(check, self.c.packet, gate.Evidence(self.c.root), self.c.context)

    def test_failed_resource_counters_are_not_optional(self):
        self.c.row["cpu_ns"] = None
        self.assertFalse(self.c.evaluate()["recorded_resource_thresholds_met"])
        self.c.row["cpu_ns"] = 101
        with self.assertRaisesRegex(ValueError, "CAMPAIGN_RESOURCE_UNDERCOUNT"):
            self.c.evaluate()

    def test_integer_types_and_overflow_are_strict(self):
        for value in (True, 1.0, -1, 1 << 64):
            self.c.row["cpu_ns"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.c.evaluate()

    def test_json_duplicate_keys_nonfinite_and_oversize_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}'):
            with self.assertRaises(ValueError):
                gate.decode(raw)
        self.c.put("large", b"1234")
        with self.assertRaises(ValueError):
            gate.Evidence(self.c.root).read("large", 3)

    def test_artifact_hash_missing_and_path_boundaries(self):
        evidence = gate.Evidence(self.c.root)
        with self.assertRaisesRegex(ValueError, "ARTIFACT_HASH_MISMATCH"):
            evidence.artifact(dict(path="packet.pnp2", sha256="ff" * 32))
        for path in ("../packet.pnp2", "/etc/passwd", "a/../packet.pnp2", "a//b", "a\\b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                evidence.read(path)
        (self.c.root / "link").symlink_to(self.c.root / "packet.pnp2")
        with self.assertRaises(OSError):
            evidence.read("link")
        (self.c.root / "directory-link").symlink_to(self.c.root, target_is_directory=True)
        with self.assertRaises(OSError):
            evidence.read("directory-link/packet.pnp2")

    def test_frozen_manifest_digest_is_external(self):
        self.c.evaluate()
        with self.assertRaisesRegex(ValueError, "FROZEN_MANIFEST_HASH"):
            gate.read_campaign(self.c.root, "ff" * 32)

    def test_native_receipts_cannot_be_relabelled_compressed_qualification(self):
        self.c.manifest["schedule"][0]["mode"] = "compressed"
        result = self.c.evaluate()
        self.assertEqual(result["timely_accepted_progress"], 0)
        self.assertFalse(result["compressed_path_qualified"])

    def test_no_hostile_cohort_is_never_complete_arithmetic(self):
        result = self.c.evaluate()
        self.assertEqual(result["missing_cohort_groups"], [dict(cohort="hostile", mode="native")])
        self.assertFalse(result["recorded_arithmetic_thresholds_met"])

    def test_local_failure_after_product_is_not_a_mathematical_rejection(self):
        self.c.add_hostile("PUBLIC_CPU_BUDGET")
        result = self.c.evaluate()
        self.assertFalse(result["attempts"][1]["late_product_rejection_observed"])
        self.assertFalse(result["recorded_arithmetic_thresholds_met"])
        value = self.c.native_event("error")
        value.update(stage="verification", error="LOCAL_IO_ERROR", cancelled=False,
                     work_progress=progress((1, 512, 1, 0)), admission_call_ns=10)
        row = self.c.report["attempts"][1]
        row["stages"][0]["receipt"] = self.c.put_json("local-error.json", value)
        self.assertFalse(self.c.evaluate()["attempts"][1]["late_product_rejection_observed"])

    def test_mixed_success_and_error_receipt_cannot_complete_phase(self):
        error = self.c.native_event("error")
        error.update(stage="verification", error="LOCAL_IO_ERROR", cancelled=False)
        raw = gate.canonical(self.c.receipts["verification"]) + b"\n" + gate.canonical(error) + b"\n"
        self.c.row["stages"][3]["receipt"] = self.c.put("mixed.ndjson", raw)
        with self.assertRaisesRegex(ValueError, "ERROR_IN_COMPLETE_STAGE_RECEIPT"):
            self.c.evaluate()

    def test_accepted_needs_actual_canonical_snapshot_bound_to_acceptance(self):
        self.c.row["canonical_checks"] = []
        with self.assertRaisesRegex(ValueError, "ACCEPTED_WITHOUT_CANONICAL_READBACK"):
            self.c.evaluate()
        absent = self.c.observation(member=False, stored=False)
        ref = self.c.put_json("absent.json", absent)
        self.c.row["canonical_checks"] = [dict(at_ns=600, receipt=ref, canonical_path=[])]
        with self.assertRaisesRegex(ValueError, "ACCEPTED_WITHOUT_CANONICAL_READBACK"):
            self.c.evaluate()
        ref = self.c.put_json("unbound.json", self.c.observation())
        self.c.row["canonical_checks"] = [dict(at_ns=600, receipt=ref, canonical_path=[self.c.packet_ref])]
        with self.assertRaisesRegex(ValueError, "ACCEPTANCE_SNAPSHOT_BINDING"):
            self.c.evaluate()


if __name__ == "__main__":
    unittest.main()
