"""Fixed campaign inventory, source claims and no-clobber evidence controls.

One actual reduced observation and one actual replay exercise the entire runner.
The mutation-only controls reuse a deep copy of that observation as the mocked
rebuild: they validate structural guards, not another circuit or native run.
No test result is quantum hardware execution, native admission or a security proof.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import w1_bounded_search_campaign as campaign


def rehash_nested(record):
    """A changed checksum must not turn changed evidence into a valid replay."""
    for group in record["groups"]:
        for run in group["runs"]:
            result = run["result"]
            binding, observation = result["binding"], result["observation"]
            binding["binding_sha256"] = hashlib.sha256(campaign.canonical({
                key: value for key, value in binding.items() if key != "binding_sha256"
            })).hexdigest()
            observation["plan_sha256"] = hashlib.sha256(campaign.canonical(observation["plan"])).hexdigest()


class FixedCampaignControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reduced W1 shapes only. This does execute census, circuit accounting
        # and the bounded simulator; no imported result substitutes for them.
        cls.observation = campaign.observe("reduced")
        cls.actual_replay = campaign.verify(cls.observation)

    def reject_structural_mutation(self, mutate, error="CAMPAIGN_REPLAY_MISMATCH", *, rehash=False):
        changed = deepcopy(self.observation)
        mutate(changed)
        if rehash:
            rehash_nested(changed)
        # Only the expensive recomputation is mocked. The actual campaign
        # guard, canonical comparison and Git source-claim checks still run.
        with patch.object(campaign, "observe", side_effect=lambda scope: deepcopy(self.observation)):
            with self.assertRaisesRegex(ValueError, error):
                campaign.verify(changed)

    def test_real_reduced_observation_and_replay_keep_complete_fixed_inventory(self):
        record = self.observation
        self.assertEqual(self.actual_replay["replay"], "PASS")
        self.assertEqual((self.actual_replay["groups"], self.actual_replay["runs"]), (1, 8))
        self.assertEqual(record["scope"], "reduced")
        self.assertEqual([group["name"] for group in record["groups"]], ["reduced"])
        group = record["groups"][0]
        self.assertEqual(len(group["domains"]), 5)
        self.assertEqual([row["profile"] for row in group["domains"]],
                         ["PNH1", "PNH1", "PGH2", "PNH1", "PGH2"])
        self.assertTrue(all(not row["native_shape"] and row["domain_size"] == 16
                            for row in group["domains"]))
        self.assertEqual([run["name"] for run in group["runs"]], [
            "reduced-full-p1-mixed", "reduced-full-p4-mixed", "reduced-full-p1-iteration-one",
            "reduced-full-p4-empty-reuse",
            "reduced-prefix-restricted-p1-mixed", "reduced-prefix-restricted-p4-mixed",
            "reduced-prefix-restricted-p1-iteration-one", "reduced-prefix-restricted-p4-empty-reuse",
        ])
        self.assertEqual([row["result"]["binding"]["processors"] for row in group["runs"]],
                         [1, 4, 1, 4, 1, 4, 1, 4])
        self.assertEqual([row["result"]["binding"]["predicate"] for row in group["runs"]],
                         ["full"] * 4 + ["prefix-restricted"] * 4)
        self.assertTrue(all(row["result"]["observation"]["plan"]["horizon_seconds"] == "4"
                            for row in group["runs"]))
        self.assertTrue(any(row["result"]["observation"]["termination"] == "horizon"
                            for row in group["runs"]))
        for key in ("finite_horizon_is_native_acceptance_profile", "all_clocks_are_measurements",
                    "fixed_contexts_are_native_eligible", "quantum_hardware_executed",
                    "profitable_consensus_attack_demonstrated", "quantum_mining_qualified",
                    "production_activation"):
            self.assertIs(record[key], False)
        self.assertEqual(record["native_blocks_admitted"], 0)

    def test_native_and_reduced_declared_inventory_keeps_the_original_shapes(self):
        # Inventory construction only: no native census, circuit or proof runs.
        groups = list(campaign.cases("all"))
        self.assertEqual([name for name, _ in groups], ["native", "reduced"])
        for group, templates in groups:
            with self.subTest(group=group):
                self.assertEqual(len(templates), 5)
                self.assertTrue(all(template.shape.native == (group == "native") for template in templates))
                self.assertTrue(all(template.nonce_bits == (2 if group == "native" else 4)
                                    for template in templates))
                self.assertEqual([template.target for template in templates[3:]], [1, 1])
                self.assertEqual([template.profile for template in templates[3:]], ["PNH1", "PGH2"])
                self.assertEqual(len(list(campaign.scenarios(group))), 8)

    def test_empty_domains_execute_all_paid_retries_evictions_and_revisits(self):
        def value(number):
            return Fraction(number["numerator"], number["denominator"])

        group = self.observation["groups"][0]
        for domain in group["domains"][3:]:
            self.assertEqual(domain["marked_count"], 0)
            self.assertTrue(all(row["winner"] is False for row in domain["outcomes"]))
        runs = [row for row in group["runs"] if row["name"].endswith("-empty-reuse")]
        self.assertEqual(len(runs), 2)
        for run in runs:
            result = run["result"]["observation"]
            with self.subTest(run=run["name"]):
                self.assertEqual(result["termination"], "schedule-exhausted")
                self.assertFalse(result["success"])
                self.assertEqual(result["plan"]["schedule"], [[3, 0], [3, 0], [4, 0], [3, 0]])
                self.assertEqual(result["plan"]["processors"], 4)
                self.assertEqual(result["trials_started"], 4)
                self.assertEqual(result["unstarted_predeclared_trials"], 0)
                self.assertEqual(result["completed_measurement_batches"], 4)
                self.assertEqual(result["candidate_checks_completed"], 16)
                self.assertEqual(result["domain_setup_charges"], 3)
                self.assertEqual(result["grover_iterations_completed_all_processors"], 0)
                self.assertEqual([row["domain_setup_charged"] for row in result["trials"]],
                                 [True, False, True, True])
                expected = Fraction(0)
                for trial in result["trials"]:
                    clock = result["plan"]["costs"][trial["domain_index"]]
                    expected += (int(trial["domain_setup_charged"]) * Fraction(clock["domain_setup_seconds"])
                                 + Fraction(clock["prepare_seconds"]) + Fraction(clock["measurement_seconds"])
                                 + 4 * Fraction(clock["candidate_check_seconds"]))
                    self.assertIsNone(trial["censored_phase"])
                    self.assertEqual(trial["candidate_checks_completed"], 4)
                    self.assertFalse(trial["verified_winner_observed"])
                    self.assertFalse(trial["proof_complete"])
                    self.assertTrue(all(row["winner"] is False and row["candidate_check_completed"]
                                        for row in trial["measurements"]))
                    self.assertTrue(all(phase["complete"]
                                        and phase["paid_seconds_exact"] == phase["planned_seconds_exact"]
                                        for phase in trial["phases"]))
                self.assertEqual(value(result["elapsed_seconds_exact"]), expected)
                self.assertEqual(sum(value(number) for number in result["phase_paid_seconds_exact"].values()),
                                 expected)
                self.assertGreater(expected, 0)
                self.assertLess(expected, 4)
                self.assertEqual(value(result["phase_paid_seconds_exact"]["proof"]), 0)
                self.assertEqual(value(result["phase_paid_seconds_exact"]["propagation"]), 0)
                self.assertEqual(result["online_proofs_generated"], 0)
                self.assertEqual(result["native_blocks_admitted"], 0)

    def test_group_domain_and_run_deletion_rename_reorder_or_duplication_is_rejected(self):
        mutations = (
            lambda r: r["groups"].clear(),
            lambda r: r["groups"][0].update(name="native"),
            lambda r: r["groups"][0]["domains"].pop(),
            lambda r: r["groups"][0]["domains"].reverse(),
            lambda r: r["groups"][0]["runs"].pop(),
            lambda r: r["groups"][0]["runs"].pop(2),
            lambda r: r["groups"][0]["runs"][0].update(name="replacement"),
            lambda r: r["groups"][0]["runs"].reverse(),
            lambda r: r["groups"][0]["runs"].append(deepcopy(r["groups"][0]["runs"][0])),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject_structural_mutation(mutate)

    def test_rehashed_seed_horizon_clock_and_resource_mutations_are_rejected(self):
        def observation(record):
            return record["groups"][0]["runs"][0]["result"]["observation"]

        def binding(record):
            return record["groups"][0]["runs"][0]["result"]["binding"]

        mutations = (
            lambda r: observation(r)["plan"].update(seed=10),
            lambda r: observation(r)["plan"].update(horizon_seconds="400"),
            lambda r: observation(r)["plan"]["costs"][0].update(iteration_seconds=1e-9),
            lambda r: binding(r)["physical_model"].update(cycle_ns="1"),
            lambda r: binding(r)["domain_resources"][0]["classical_costs_ns"].update(per_winner_proof_ns=0),
            lambda r: binding(r)["domain_resources"][0]["clock_seconds_float_upper"].update(iteration_seconds=1e-9),
            lambda r: binding(r)["envelope"].update(planned_trials_per_processor=1),
            lambda r: r["illustrative_physical_model"].update(magic_state_error="0"),
            lambda r: r["illustrative_classical_costs_ns"].update(task_preprocessing_ns=0),
            lambda r: r.update(physical_qubit_cap=10**30),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject_structural_mutation(mutate, rehash=True)

    def test_census_winner_and_selected_result_tampering_cannot_pass_replay(self):
        mutations = (
            lambda r: r["groups"][0]["domains"][0].update(marked_count=0),
            lambda r: r["groups"][0]["domains"][0]["outcomes"][0].update(winner=False),
            lambda r: r["groups"][0]["runs"][-1]["result"]["observation"].update(success=True),
            lambda r: r["groups"][0]["runs"][-1]["result"]["observation"]["trials"].clear(),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject_structural_mutation(mutate, rehash=True)

    def test_rehashed_qualification_escalation_is_rejected_at_every_layer(self):
        mutations = (
            lambda r: r.update(quantum_mining_qualified=True),
            lambda r: r.update(finite_horizon_is_native_acceptance_profile=True),
            lambda r: r.update(native_blocks_admitted=1),
            lambda r: r["groups"][0]["runs"][0]["result"].update(production_activation=True),
            lambda r: r["groups"][0]["runs"][0]["result"]["binding"].update(attacker_minimum_cost_proved=True),
            lambda r: r["groups"][0]["runs"][0]["result"]["binding"].update(native_node_admission_checked=True),
            lambda r: r["groups"][0]["runs"][0]["result"]["observation"].update(consensus_security_theorem=True),
            lambda r: r["groups"][0]["runs"][0]["result"]["observation"].update(online_proofs_generated=1),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self.reject_structural_mutation(mutate, rehash=True)

    def test_source_schema_and_exact_inventory_hashes_are_checked(self):
        first = next(iter(self.observation["source"]["source_sha256"]))
        for mutate, error in (
            (lambda r: r["source"].pop("git_head"), "CAMPAIGN_SOURCE_SCHEMA"),
            (lambda r: r["source"].update(extra=True), "CAMPAIGN_SOURCE_SCHEMA"),
            (lambda r: r["source"]["source_sha256"].pop(first), "CAMPAIGN_SOURCE_HASH"),
            (lambda r: r["source"]["source_sha256"].update({first: "0" * 64}), "CAMPAIGN_SOURCE_HASH"),
            (lambda r: r["source"]["source_sha256"].update({"invented.py": "0" * 64}), "CAMPAIGN_SOURCE_HASH"),
        ):
            with self.subTest(error=error):
                self.reject_structural_mutation(mutate, error)

    def test_committed_source_claims_are_rederived_from_real_git_objects(self):
        source = self.observation["source"]
        alternate = [] if source["uncommitted_source_files"] else ["invented.py"]
        for mutate in (
            lambda r: r["source"].update(all_sources_committed_at_head=not source["all_sources_committed_at_head"]),
            lambda r: r["source"].update(uncommitted_source_files=alternate),
            lambda r: r["source"].update(all_sources_committed_at_head=int(source["all_sources_committed_at_head"])),
        ):
            self.reject_structural_mutation(mutate, "CAMPAIGN_SOURCE_COMMITMENT")

    def test_source_head_must_name_a_real_commit_not_a_blob(self):
        blob = subprocess.check_output(["git", "rev-parse", "HEAD:AGENTS.md"],
                                       cwd=campaign.ROOT, text=True).strip()
        for head in ("0" * 40, "not-a-commit", "A" * 40, blob):
            with self.subTest(head=head):
                self.reject_structural_mutation(lambda r: r["source"].update(git_head=head),
                                                "CAMPAIGN_SOURCE_HEAD")

    def test_source_change_during_observation_refuses_the_record(self):
        before = deepcopy(self.observation["source"])
        after = deepcopy(before)
        first = next(iter(after["source_sha256"]))
        after["source_sha256"][first] = "0" * 64
        group = self.observation["groups"][0]
        # This is specifically a source-fence control, not another simulation.
        with patch.object(campaign, "source_record", side_effect=(before, after)), \
                patch.object(campaign, "enumerate_domain", side_effect=deepcopy(group["domains"])), \
                patch.object(campaign, "run_constructed_search",
                             side_effect=[deepcopy(run["result"]) for run in group["runs"]]):
            with self.assertRaisesRegex(ValueError, "CAMPAIGN_SOURCE_CHANGED"):
                campaign.observe("reduced")

    def test_unknown_scope_refuses_before_any_census_or_circuit(self):
        with patch.object(campaign, "enumerate_domain", side_effect=AssertionError("unexpected census")), \
                patch.object(campaign, "run_constructed_search", side_effect=AssertionError("unexpected circuit")):
            for scope in (None, "fast", "", True):
                with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "CAMPAIGN_SCOPE"):
                    campaign.observe(scope)


class EvidenceIoControls(unittest.TestCase):
    def test_output_type_and_size_refuse_before_any_file_is_created(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with patch.object(campaign.literal, "MAX_REPORT_BYTES", 8):
                for raw in ("text is not serialized bytes", b" " * 9):
                    with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "OUTPUT_BOUND"):
                        campaign.literal.write_report(output, raw)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_strict_json_rejects_duplicate_keys_nonfinite_values_and_excess_size(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"a":-Infinity}', b'{"a":1e400}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                campaign.literal.strict_load(raw)
        with patch.object(campaign.literal, "MAX_REPORT_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "JSON_BOUND"):
                campaign.literal.strict_load(b" " * 9)
        sample = {"large_integer": 1 << 256, "qualification": False}
        self.assertEqual(campaign.literal.strict_load(campaign.canonical(sample)), sample)

    def test_reader_rejects_symlinks_and_declared_size_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(b'{"a":1}')
            alias = Path(directory) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "INPUT_FILE_BOUND"):
                campaign.literal.read_report(alias)
            with patch.object(campaign.literal, "MAX_REPORT_BYTES", 6):
                with self.assertRaisesRegex(ValueError, "INPUT_FILE_BOUND"):
                    campaign.literal.read_report(path)
            self.assertEqual(campaign.literal.read_report(path), b'{"a":1}')

    def test_existing_file_dangling_symlink_and_partial_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "report.json"
            campaign.literal.write_report(output, b'{"old":true}')
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                campaign.literal.write_report(output, b'{"new":true}')
            self.assertEqual(output.read_bytes(), b'{"old":true}')
            dangling = root / "dangling.json"
            dangling.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                campaign.literal.write_report(dangling, b"new")
            blocked = root / "blocked.json"
            partial = blocked.with_suffix(blocked.suffix + ".partial")
            partial.write_bytes(b"retained failed attempt")
            with self.assertRaises(FileExistsError):
                campaign.literal.write_report(blocked, b"new")
            self.assertFalse(blocked.exists())
            self.assertEqual(partial.read_bytes(), b"retained failed attempt")

    def test_atomic_publication_preserves_a_competing_writers_result_and_own_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            original_link = os.link

            def competing_write(source, target):
                Path(target).write_bytes(b"other completed writer")
                return original_link(source, target)

            with patch.object(campaign.literal.os, "link", side_effect=competing_write):
                with self.assertRaises(FileExistsError):
                    campaign.literal.write_report(output, b"own complete staged bytes")
            self.assertEqual(output.read_bytes(), b"other completed writer")
            self.assertEqual(output.with_suffix(output.suffix + ".partial").read_bytes(),
                             b"own complete staged bytes")

    def test_cli_rejects_malformed_saved_json_before_campaign_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            saved = Path(directory) / "report.json"
            saved.write_bytes(b'{"schema":"first","schema":"second"}')
            with patch.object(sys, "argv", ["w1_bounded_search_campaign", "--verify", str(saved)]), \
                    patch.object(campaign, "verify", side_effect=AssertionError("unexpected replay")):
                with self.assertRaisesRegex(ValueError, "DUPLICATE_JSON_KEY"):
                    campaign.main()

    def test_cli_observe_writes_once_and_prints_only_a_limited_receipt(self):
        # CLI publication wiring only; the real reduced runner is tested above.
        record = {"groups": [], "schema": campaign.SCHEMA, "quantum_mining_qualified": False}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            stdout = io.StringIO()
            with patch.object(sys, "argv", ["w1_bounded_search_campaign", "--observe", str(output),
                                            "--scope", "reduced"]), \
                    patch.object(campaign, "observe", return_value=record) as observe, \
                    patch.object(sys, "stdout", stdout):
                campaign.main()
                with self.assertRaisesRegex(ValueError, "OUTPUT_ALREADY_EXISTS"):
                    campaign.main()
            self.assertEqual(observe.call_args.args, ("reduced",))
            self.assertEqual(campaign.literal.strict_load(output.read_bytes()), record)
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt, {"output": str(output), "groups": 0, "quantum_mining_qualified": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
