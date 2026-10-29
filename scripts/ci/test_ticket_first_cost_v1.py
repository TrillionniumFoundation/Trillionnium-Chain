#!/usr/bin/env python3
"""Explicit synthetic trace controls with real wire/material reconstruction.

These records do not execute a producer, admission or W1 transcript. Synthetic
traces deliberately supply every eighth-attempt exhaustion and missed-then-hit
case; only codec/hash/accounting and reader rejection behavior are tested.
"""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_ticket_first_cost_v1 import (
    ARMS, COHORTS, H, HORIZONS, JOURNAL_LIMIT, JOURNAL_LINE_LIMIT, JOURNAL_SCHEMA,
    PHASES, PROOF_BYTES, RECURRING, SCHEMA,
    STREAM_DOMAIN, bound_capture, header_decode, header_encode, material,
    sequence_root, summed, validate, validate_journal,
)
from contract_wire import SCHEMA as WIRE_SCHEMA


def refresh_stream(row):
    template = header_decode(bytes.fromhex(row["native_template_header"]))
    stream = hashlib.sha256(STREAM_DOMAIN)
    for search in row["searches"]:
        for trial in search["trials"]:
            stream.update(header_encode(dict(template, nonce=trial["nonce"])))
            for field in ("trace", "ticket", "canonical_proof_sha256"):
                stream.update(bytes.fromhex(trial[field]))
    row["stream_sha256"] = stream.hexdigest()


def refresh_costs(row):
    row["all_exclusive_phases"] = summed(row["phases"].values())
    row["recurring_producer_encode_admission"] = summed(row["phases"][name] for name in RECURRING)


def fixture():
    _, _, task, prefix = material("continuity-maintenance-v1")
    template = {field["name"]: (H("synthetic-reader-field", field["name"].encode())
                               if field["type"] == "hash32" else 0)
                for field in WIRE_SCHEMA["header"]}
    template.update(height=1, timestamp=1_800_010_011, work_task=task,
                    target=bytes.fromhex("7f" + "ff" * 31), transactions=sequence_root("transactions", []))
    step = {"wall_ns": 1, "process_cpu_ns": 1}
    rows = [dict(schema=SCHEMA, kind="begin", horizons=list(HORIZONS), arms=list(ARMS),
        attempts=8, rounds=2, seed=2, budget_seconds=600, native_workers=1,
        settings_setup=dict(step), compiled_driver_sha256="ab" * 32, compiled_cargo_lock_sha256="bc" * 32,
        old_v3_v4_v5_experiments_unchanged=True, failed_proof_materialization_is_not_required_work=True,
        winning_only_still_computes_all_transcript_tiles=True, gpu_measured=False, energy_measured=False,
        hardware_authenticated=False, exclusive_host=False, global_minimum_proved=False,
        production_qualified=False, debug_assertions=False)]
    for round_id in (0, 1):
        for horizon_index, horizon in enumerate(HORIZONS):
            searches, retained = [], []
            for search in range(horizon):
                exhausted = search % 17 == 0
                trials = []
                for trial_id in range(8 if exhausted else 2):
                    nonce = (2 << 32) + round_id * (1 << 24) + horizon * 4096 + search * 8 + trial_id
                    header = header_encode(dict(template, nonce=nonce))
                    challenge = H("challenge", header)
                    hit = not exhausted and trial_id == 1
                    counter = 0
                    while True:
                        # A deliberately artificial trace, not a W1 replay.
                        trace = hashlib.sha256(b"synthetic-reader-control\0" + nonce.to_bytes(8, "little") +
                                               counter.to_bytes(8, "little")).digest()
                        ticket = H("ticket", challenge, trace)
                        if (ticket <= template["target"]) == hit:
                            break
                        counter += 1
                    attempted = dict(trial=trial_id, nonce=nonce, challenge=challenge.hex(), trace=trace.hex(),
                                     ticket=ticket.hex(), canonical_proof_sha256=hashlib.sha256(prefix + trace).hexdigest(),
                                     target_hit=hit, generation=dict(step))
                    if hit:
                        packet = header + b"\0\0" + prefix + trace
                        packet_id = H("block", header, trace).hex()
                        attempted.update(packet_id=packet_id, packet_bytes=len(packet), native_admission=dict(step))
                        retained.append(dict(id=packet_id, sha256=hashlib.sha256(packet).hexdigest(), bytes=len(packet)))
                    trials.append(attempted)
                searches.append(dict(search=search, won=not exhausted, trials=trials))
            attempts, winners = sum(len(search["trials"]) for search in searches), len(retained)
            for reuse in (False, True):
                arms = list(ARMS if round_id == 0 else ARMS[::-1])
                rotation = (horizon_index + int(reuse)) % len(arms)
                arms = arms[rotation:] + arms[:rotation]
                for order, arm in enumerate(arms):
                    calls = 1 if reuse else horizon
                    phases = {name: dict(step) for name in PHASES}
                    for name, value in (("producer_setup", calls), ("all_attempt_generation", attempts),
                                        ("packet_encoding", winners), ("first_native_admission", winners),
                                        ("cold_packet_readback", winners)):
                        phases[name] = dict(wall_ns=value, process_cpu_ns=value)
                    own_searches = copy.deepcopy(searches)
                    materialized = 0
                    for search in own_searches:
                        for attempted in search["trials"]:
                            attempted["proof_materialized"] = not arm.endswith("-ticket-first") or attempted["target_hit"]
                            materialized += int(attempted["proof_materialized"])
                    row = dict(schema=SCHEMA, kind="cohort", status="complete", round=round_id, search_horizon=horizon,
                        reuse=reuse, order=order, arm=arm, arm_index=ARMS.index(arm), parent=template["parent"].hex(),
                        target=template["target"].hex(), task=task.hex(), native_template_header=header_encode(template).hex(),
                        proof_prefix_sha256=hashlib.sha256(prefix).hexdigest(), fresh_store=True, template_seed_admitted=False,
                        attempt_budget=8, attempts=attempts, winners=winners, exhausted=horizon-winners,
                        producer_setup_calls=calls, proof_materializations=materialized,
                        proof_bytes_materialized=materialized*PROOF_BYTES, first_native_admissions=winners,
                        cold_packet_readbacks=winners, explicit_activation_calls=0,
                        hot_active_before_close=dict(id=template["parent"].hex(), generation=1),
                        cold_recovery_active=dict(id=min(p["id"] for p in retained) if retained else template["parent"].hex(), generation=2),
                        phases=phases, observed_outer=dict(wall_ns=100000, process_cpu_ns=100000),
                        searches=own_searches, retained_packets=copy.deepcopy(retained))
                    refresh_costs(row)
                    refresh_stream(row)
                    rows.append(row)
    rows.append(dict(schema=SCHEMA, kind="terminal", status="complete", cohorts=COHORTS, wall_ns=10_000_000,
                     global_minimum_proved=False, public_fairness_qualified=False,
                     active_chain_rewards_measured=False, production_qualified=False))
    return rows


def select(rows, arm="generic-legacy", horizon=1, round_id=0, reuse=False):
    return next(row for row in rows[1:-1] if
                (row["arm"], row["search_horizon"], row["round"], row["reuse"]) == (arm, horizon, round_id, reuse))


def journal_events(rows):
    def split(total, index, count):
        return {clock: None if value is None else value // count + int(index < value % count)
                for clock, value in total.items()}

    for row in rows[1:-1]:
        identity = dict(round=row["round"], horizon=row["search_horizon"], reuse=row["reuse"], arm=row["arm"])

        def event(kind, **fields):
            return dict(schema=JOURNAL_SCHEMA, kind=kind, cohort=identity, **fields)

        yield event("cohort-start")
        encoded = 0
        for search in row["searches"]:
            for trial in search["trials"]:
                yield event("trial-start", search=search["search"], trial=trial["trial"], nonce=trial["nonce"])
                yield event("trial-generated", search=search["search"], observation={
                    key: value for key, value in trial.items() if key not in ("native_admission", "packet_id", "packet_bytes")})
                if trial["target_hit"]:
                    yield event("admission-start", search=search["search"], trial=trial["trial"], packet_id=trial["packet_id"],
                                packet_encoding=split(row["phases"]["packet_encoding"], encoded, row["winners"]))
                    encoded += 1
                    yield event("admission-result", search=search["search"], trial=trial["trial"], packet_id=trial["packet_id"],
                                timing=trial["native_admission"], accepted_id=trial["packet_id"], error=None)
        yield event("generation-complete", attempts=row["attempts"], winners=row["winners"],
                    all_attempt_generation=row["phases"]["all_attempt_generation"],
                    first_native_admission=row["phases"]["first_native_admission"])
        for index, packet in enumerate(row["retained_packets"]):
            yield event("cold-read-start", packet_id=packet["id"])
            yield event("cold-read-result", packet_id=packet["id"], sha256=packet["sha256"], bytes=packet["bytes"],
                        timing=split(row["phases"]["cold_packet_readback"], index, row["winners"]))
        yield event("cohort-complete", stream_sha256=row["stream_sha256"])


def write_journal(path, rows):
    hasher = hashlib.sha256()
    with path.open("wb") as stream:
        for event in journal_events(rows):
            raw = json.dumps(event, separators=(",", ":")).encode() + b"\n"
            hasher.update(raw)
            stream.write(raw)
    return hasher.hexdigest()


def write_capture(directory, rows):
    raw = b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)
    compressed = gzip.compress(raw, mtime=0)
    (directory / "stdout.jsonl.gz").write_bytes(compressed)
    source = dict(kind="head", tested_commit="1" * 40, tested_tree="2" * 40, tracked_worktree_verified=True)
    for name in ("before.json", "after.json"):
        (directory / name).write_text(json.dumps(source))
    capture = dict(schema="pon-ticket-first-release-capture-v1", exit_code=0, timed_out=False, stable_binary=True,
        stdout_within_bound=True, timeout_seconds=610, elapsed_ns=10_000_001,
        build_profile="cargo --release; original repository release defaults",
        package_opt_levels={"trnm-pon-node": 3, "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 3},
        debug_info=0, incremental=False, build_jobs=2, build_environment_overrides={},
        exclusive_host=False, host_contention_controlled=False,
        production_qualified=False, hardness_proved=False,
        binary_sha256_before="cd" * 32, binary_sha256_after="cd" * 32,
        stdout_bytes=len(raw), stdout_uncompressed_sha256=hashlib.sha256(raw).hexdigest(),
        stdout_gzip_sha256=hashlib.sha256(compressed).hexdigest(), argv=["/synthetic/pon_ticket_first_cost_v1"],
        stderr_sha256=write_journal(directory / "stderr.log", rows),
        source=dict(commit=source["tested_commit"], tree=source["tested_tree"],
                    example_sha256=rows[0]["compiled_driver_sha256"], lock_sha256=rows[0]["compiled_cargo_lock_sha256"]))
    (directory / "capture.json").write_text(json.dumps(capture))
    return capture


class Reader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = fixture()

    def reject(self, change, message=None):
        rows = copy.deepcopy(self.original)
        change(rows)
        if message:
            with self.assertRaisesRegex(ValueError, message):
                validate(rows)
        else:
            with self.assertRaises((ValueError, KeyError, TypeError)):
                validate(rows)

    def test_complete_grid_real_codec_and_all_three_cost_partitions(self):
        result = validate(copy.deepcopy(self.original))
        self.assertEqual(result["cohorts"], 96)
        self.assertEqual(len(result["fixed_paired_comparisons"]), 32)
        self.assertEqual(result["first_admission_calls"], 12 * result["distinct_fixture_packet_ids_across_paired_cohorts"])
        row = next(row for row in result["groups"] if row["horizon"] == 8 and row["arm"] == "generic-ticket-first")
        self.assertEqual({name: entry["attempts"] for name, entry in row["generation_partition"].items()},
                         dict(winning_trials=7, misses_before_winner=7, exhausted_search_trials=8))
        self.assertEqual(row["proof_materializations"], 7)
        self.assertEqual(row["attempts"], 22)
        self.assertFalse(result["boundaries"]["every_w1_transcript_independently_replayed"])
        self.assertFalse(result["boundaries"]["global_minimum_proved"])
        self.assertEqual(result["groups"][0]["outer_residual"], dict(wall_ns=99983, process_cpu_ns=99983))
        self.assertFalse(result["boundaries"]["source_capture_is_physical_attestation"])

    def test_grid_order_seed_and_boolean_counter_mutations_fail(self):
        self.reject(lambda rows: rows.pop(2))
        self.reject(lambda rows: rows[0].update(seed=1))
        self.reject(lambda rows: rows[0].update(native_workers=True))
        self.reject(lambda rows: rows[0].update(debug_assertions=True))
        self.reject(lambda rows: rows[1].update(order=True))
        self.reject(lambda rows: rows[1].update(producer_setup_calls=True))

    def test_nonce_challenge_trace_ticket_and_canonical_proof_are_recomputed(self):
        for field, value in (("nonce", 1), ("challenge", "11" * 32), ("trace", "12" * 32),
                             ("ticket", "13" * 32), ("canonical_proof_sha256", "14" * 32)):
            with self.subTest(field=field):
                self.reject(lambda rows: select(rows)["searches"][0]["trials"][0].update({field: value}))
        self.reject(lambda rows: select(rows).update(proof_prefix_sha256="15" * 32))

    def test_recomputed_individual_stream_still_cannot_disagree_with_other_arms(self):
        def change(rows):
            row = select(rows)
            trial = row["searches"][0]["trials"][0]
            challenge = bytes.fromhex(trial["challenge"])
            counter = 0
            while True:
                trace = hashlib.sha256(b"different-synthetic-control" + counter.to_bytes(8, "little")).digest()
                ticket = H("ticket", challenge, trace)
                if ticket > bytes.fromhex(row["target"]):
                    break
                counter += 1
            trial.update(trace=trace.hex(), ticket=ticket.hex(), canonical_proof_sha256=hashlib.sha256(
                material("continuity-maintenance-v1")[3] + trace).hexdigest())
            refresh_stream(row)
        self.reject(change, "all six arms/reuse")

    def test_declared_stream_digest_cannot_replace_recomputation(self):
        self.reject(lambda rows: select(rows).update(stream_sha256="16" * 32), "recomputed complete native stream")

    def test_only_ticket_first_omits_failed_assembly_and_winners_always_materialize(self):
        self.reject(lambda rows: select(rows, "generic-ticket-first")["searches"][0]["trials"][0].update(proof_materialized=True))
        self.reject(lambda rows: select(rows, "limb-candidate-all")["searches"][0]["trials"][0].update(proof_materialized=False))
        self.reject(lambda rows: select(rows, "limb-ticket-first", 8)["searches"][1]["trials"][1].update(proof_materialized=False))
        self.reject(lambda rows: select(rows, "generic-ticket-first").update(proof_bytes_materialized=PROOF_BYTES))

    def test_exhaustion_failed_costs_and_first_hit_cannot_be_dropped(self):
        self.reject(lambda rows: select(rows)["searches"][0]["trials"].pop(), "complete bounded search")
        self.reject(lambda rows: select(rows).update(attempts=7))
        self.reject(lambda rows: select(rows, horizon=8)["searches"][1].update(won=False))
        self.reject(lambda rows: select(rows, horizon=8)["searches"][1]["trials"].append(
            copy.deepcopy(select(rows, horizon=8)["searches"][1]["trials"][-1])))

    def test_winning_packet_identity_exact_bytes_and_cold_readback_are_checked(self):
        self.reject(lambda rows: select(rows, horizon=8)["searches"][1]["trials"][1].update(packet_id="17" * 32))
        self.reject(lambda rows: select(rows, horizon=8)["retained_packets"][0].update(sha256="18" * 32))
        self.reject(lambda rows: select(rows, horizon=8)["retained_packets"].pop())
        self.reject(lambda rows: select(rows, horizon=8)["cold_recovery_active"].update(id=select(rows)["parent"]))

    def test_phases_are_exclusive_outer_is_inclusive_and_terminal_includes_all(self):
        self.reject(lambda rows: select(rows)["phases"]["producer_setup"].update(wall_ns=0))
        self.reject(lambda rows: select(rows)["observed_outer"].update(wall_ns=0))
        self.reject(lambda rows: rows[-1].update(wall_ns=1), "sequential outer cohorts")
        self.reject(lambda rows: rows[-1].update(wall_ns=600_000_000_001))

    def test_all_exhausted_horizon_has_cost_but_no_winner_ratio(self):
        result = validate(copy.deepcopy(self.original))
        comparison = result["fixed_paired_comparisons"][0]
        self.assertEqual(comparison["winning_first_admissions"], 0)
        self.assertEqual(comparison["attempts"], 16)
        self.assertEqual(comparison["exhausted"], 2)
        cost = comparison["aggregate"]["outer"]["process_cpu_ns"]
        self.assertEqual(cost["reference_total_ns"], 200000)
        self.assertIsNone(cost["reference_ns_per_first_admission"])
        self.assertIsNone(cost["reference_over_alternative_complete_cost"])

    def test_two_comparisons_keep_allocation_change_separate_from_skipping_misses(self):
        rows = copy.deepcopy(self.original)
        for row in rows[1:-1]:
            row["observed_outer"]["process_cpu_ns"] = 20000 if row["arm"].endswith("candidate-all") else 10000
        result = validate(rows)
        comparisons = [row for row in result["fixed_paired_comparisons"] if
                       row["horizon"] == 8 and row["producer"] == "generic" and row["reuse"]]
        self.assertEqual([row["comparison"] for row in comparisons],
                         ["candidate-allocation-path", "omit-failed-proof-assembly"])
        self.assertEqual([row["aggregate"]["outer"]["process_cpu_ns"]
                          ["reference_over_alternative_complete_cost"]["value"] for row in comparisons], [0.5, 2])

    def test_paired_sign_reversal_and_unknown_cpu_are_retained(self):
        rows = copy.deepcopy(self.original)
        for row in rows[1:-1]:
            row["observed_outer"]["process_cpu_ns"] = 10000
            if row["arm"] == "generic-ticket-first":
                row["observed_outer"]["process_cpu_ns"] = 5000 if row["round"] == 0 else 15000
        result = validate(rows)
        pair = next(row for row in result["fixed_paired_comparisons"] if row["horizon"] == 8 and
                    row["producer"] == "generic" and not row["reuse"] and row["comparison"] == "omit-failed-proof-assembly")
        observed = pair["aggregate"]["outer"]["process_cpu_ns"]
        self.assertEqual(observed["paired_alternative_minus_reference_ns"], [-5000, 5000])
        self.assertTrue(observed["observed_sign_reversal"])
        self.assertEqual(observed["reference_over_alternative_complete_cost"]["value"], 1)
        select(rows, "generic-ticket-first", 8)["observed_outer"]["process_cpu_ns"] = None
        result = validate(rows)
        pair = next(row for row in result["fixed_paired_comparisons"] if row["horizon"] == 8 and
                    row["producer"] == "generic" and not row["reuse"] and row["comparison"] == "omit-failed-proof-assembly")
        observed = pair["aggregate"]["outer"]["process_cpu_ns"]
        self.assertIsNone(observed["alternative_total_ns"])
        self.assertIsNone(observed["reference_over_alternative_complete_cost"])
        self.assertIsNone(observed["observed_sign_reversal"])

    def test_source_capture_and_lossless_raw_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = write_capture(root, self.original)
            args = (root / "capture.json", "1" * 40, root / "before.json", root / "after.json")
            self.assertEqual(bound_capture(*args)["cohorts"], 96)
            for change in (dict(exit_code=1), dict(timed_out=True), dict(stable_binary=False),
                           dict(stdout_bytes=1), dict(stdout_gzip_sha256="00" * 32),
                           dict(binary_sha256_after="00" * 32), dict(argv=["/synthetic/pon_ticket_first_cost_v1", "--override"]),
                           dict(stderr_sha256="00" * 32), dict(schema="pon-pure-native-capture-v1"),
                           dict(build_profile="cargo --profile test; repository package overrides"),
                           dict(package_opt_levels={"trnm-pon-node": 3, "trnm-crypto-primitives": 3, "trnm-mvcc-fee": 1}),
                           dict(build_environment_overrides={"RUSTFLAGS": "-C opt-level=1"}),
                           dict(build_jobs=0), dict(hardness_proved=True)):
                with self.subTest(change=change):
                    (root / "capture.json").write_text(json.dumps(dict(original, **change)))
                    with self.assertRaises(ValueError):
                        bound_capture(*args)
            (root / "capture.json").write_text(json.dumps(original))
            (root / "after.json").write_text(json.dumps(dict(kind="head", tested_commit="3" * 40,
                                                          tested_tree="2" * 40, tracked_worktree_verified=True)))
            with self.assertRaisesRegex(ValueError, "full source identity"):
                bound_capture(*args)

    def test_complete_journal_has_exact_events_and_no_second_cost_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr.log"
            digest = write_journal(path, self.original)
            result = validate_journal(self.original, path)
            attempts = sum(row["attempts"] for row in self.original[1:-1])
            winners = sum(row["winners"] for row in self.original[1:-1])
            self.assertEqual(result["events"], 3 * COHORTS + 2 * attempts + 4 * winners)
            self.assertEqual(result["event_counts"]["trial-start"], attempts)
            self.assertEqual(result["event_counts"]["cold-read-result"], winners)
            self.assertEqual(result["sha256"], digest)
            self.assertFalse(result["journal_timings_added_to_existing_cost_totals"])
            self.assertFalse(result["physical_execution_attested"])

    def test_missing_duplicate_reordered_or_non_json_journal_records_fail(self):
        prefix = list(event for _, event in zip(range(4), journal_events(self.original)))
        encoded = [json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in prefix]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr.log"
            cases = {
                "missing": (encoded[:1] + encoded[2:], "journal trial-start"),
                "duplicate": (encoded[:2] + encoded[1:], "journal trial-generated"),
                "reordered": (encoded[:1] + [encoded[2], encoded[1]] + encoded[3:], "journal trial-start"),
                "non-json": ([b"native unexpected text\n"], "Expecting value"),
                "truncated": ([encoded[0][:-1]], "journal missing/truncated/oversized"),
                "oversized": ([b" " * JOURNAL_LINE_LIMIT + b"{}\n"], "journal missing/truncated/oversized"),
            }
            for name, (lines, reason) in cases.items():
                with self.subTest(case=name):
                    path.write_bytes(b"".join(lines))
                    with self.assertRaisesRegex(ValueError, reason):
                        validate_journal(self.original, path)
            with path.open("wb") as stream:
                stream.truncate(JOURNAL_LIMIT + 1)
            with self.assertRaisesRegex(ValueError, "journal total bound"):
                validate_journal(self.original, path)

    def test_journal_clock_and_boolean_alias_tampering_is_rejected(self):
        events = []
        for event in journal_events(self.original):
            events.append(event)
            if event["kind"] == "cohort-complete" and event["cohort"]["horizon"] == 8:
                break
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stderr.log"
            for kind, field, reason in (("admission-start", "packet_encoding", "journal packet encoding phase total"),
                                        ("cold-read-result", "timing", "journal cold readback phase total"),
                                        ("admission-result", "timing", "journal admission-result fields"),
                                        ("trial-generated", "observation", "journal trial-generated fields")):
                changed = copy.deepcopy(events)
                target = next(event for event in changed if event["kind"] == kind)
                if kind == "trial-generated":
                    target[field]["generation"]["wall_ns"] += 1
                else:
                    target[field]["wall_ns"] += 1
                with self.subTest(kind=kind):
                    path.write_bytes(b"".join(json.dumps(event).encode() + b"\n" for event in changed))
                    with self.assertRaisesRegex(ValueError, reason):
                        validate_journal(self.original, path)
            changed = copy.deepcopy(events)
            changed[1]["trial"] = False
            path.write_bytes(b"".join(json.dumps(event).encode() + b"\n" for event in changed))
            with self.assertRaisesRegex(ValueError, "journal trial-start"):
                validate_journal(self.original, path)

    def test_rehashed_stderr_cannot_disagree_with_stdout_and_failure_keeps_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = write_capture(root, self.original)
            # The attacker updates the capture's stderr digest after changing a
            # value in an otherwise valid journal row. Cross-stream agreement
            # must still reject it; a matching self-reported hash is not enough.
            lines = (root / "stderr.log").read_bytes().splitlines(keepends=True)
            changed = json.loads(lines[2])
            changed["observation"]["canonical_proof_sha256"] = "a5" * 32
            lines[2] = json.dumps(changed).encode() + b"\n"
            raw = b"".join(lines)
            (root / "stderr.log").write_bytes(raw)
            capture["stderr_sha256"] = hashlib.sha256(raw).hexdigest()
            (root / "capture.json").write_text(json.dumps(capture))
            with self.assertRaisesRegex(ValueError, "journal trial-generated"):
                bound_capture(root / "capture.json", "1" * 40, root / "before.json", root / "after.json")
            failed_bytes = lines[0] + b"ACTUAL_PARTIAL_NATIVE_FAILURE\n"
            (root / "stderr.log").write_bytes(failed_bytes)
            capture.update(exit_code=1, stderr_sha256=hashlib.sha256(failed_bytes).hexdigest())
            (root / "capture.json").write_text(json.dumps(capture))
            output = root / "must-not-exist.json"
            command = [sys.executable, str(Path(__file__).with_name("check_ticket_first_cost_v1.py")),
                       "--capture", str(root / "capture.json"), "--expected-head", "1" * 40,
                       "--source-before", str(root / "before.json"), "--source-after", str(root / "after.json"),
                       "--output", str(output)]
            observed = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(observed.returncode, 0)
            self.assertFalse(output.exists())
            self.assertEqual((root / "stderr.log").read_bytes(), failed_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
