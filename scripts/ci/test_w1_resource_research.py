#!/usr/bin/env python3
"""Evidence parser and collection controls; no synthetic execution qualification.

The tiny subprocesses below test retained failure/output behavior. Synthetic Cargo
and observer receipts test their grammar only and never stand for native work.
The miner raw-reader suite replays complete actual or explicitly constructed W1
proofs separately. No timing or hardware result is produced by these unit tests.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import run_w1_resource_research as runner
import read_w1_resource_research as reader


def plan():
    return {
        "schema": runner.PLAN_SCHEMA, "production_activation": False,
        "hardness_accepted": False, "hardware_attested": False,
        "proof_retention": "all-completed-research-proofs-including-misses",
        "independent_replay": "all-retained-full-proofs-posthoc-no-selection-feedback",
        "collection_output_limit_bytes": 1024 * 1024,
        "generation_then_receiver_then_audit": True, "miner_feedback_from_receiver": False,
        "waited_cpu_endpoint_allowance_ns": runner.WAITED_CPU_ALLOWANCE_NS,
        "gnu_time_print_allowance_ns": runner.GNU_TIME_PRINT_ALLOWANCE_NS,
        "jobs": [{"name": "miner", "binary": runner.BINARIES[0],
                  "args": ["--setup-budget-ns", "1000000000", "--miner-budget-ns", "128000000",
                           "--parents", "1", "--max-attempts", "4096", "--acquisition", "selective",
                           "--policy", "maintenance-only", "--parent-policy", "newest", "--screen-width", "4",
                           "--arm", "structure-paired", "--cache", "hot", "--seed", "4101"], "timeout_seconds": 10}],
    }


class CollectionControls(unittest.TestCase):
    def test_registered_plan_and_exact_argument_decoding(self):
        frozen = runner.decode((ROOT / "formal/pon-nakamoto-v1/experiments/w1_miner_resource_campaign_v1.json").read_bytes())
        jobs = runner.validate_plan(frozen)
        self.assertEqual(len(jobs), 58)
        self.assertTrue(all(j["binary"] == runner.BINARIES[0] for j in jobs))
        runner.validate_plan(plan())
        for mutation in (
            {"name": "build"}, {"name": "../escape"}, {"binary": "foreign-executable"},
            {"args": ["--parents", "1", "--parents", "2"]},
            {"args": ["--foreign", "1"]}, {"args": ["--parents", "5"]},
            {"timeout_seconds": True}, {"timeout_seconds": 1801},
        ):
            changed = plan()
            changed["jobs"][0].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                runner.validate_plan(changed)

    def test_registered_orders_are_balanced_inside_each_fixed_cell(self):
        frozen = runner.decode((ROOT / "formal/pon-nakamoto-v1/experiments/w1_miner_resource_campaign_v1.json").read_bytes())
        groups = {}
        for j in frozen["jobs"]:
            if not j["name"].startswith("miner.fixed."):
                continue
            options = dict(zip(j["args"][::2], j["args"][1::2]))
            key = (options["--policy"], options["--cache"])
            groups.setdefault(key, {}).setdefault(options["--seed"], []).append(options["--arm"])
        self.assertEqual(len(groups), 4)
        for group in groups.values():
            self.assertEqual(group["4101"], list(reversed(group["4102"])))
            self.assertEqual(len(set(group["4101"])), 4)

    def test_observer_allowances_are_rejected_before_expensive_collection(self):
        self.assertEqual(runner.WAITED_CPU_ALLOWANCE_NS, reader.WAITED_CPU_ALLOWANCE_NS)
        self.assertEqual(runner.GNU_TIME_PRINT_ALLOWANCE_NS, reader.GNU_TIME_PRINT_ALLOWANCE_NS)
        for field in ("waited_cpu_endpoint_allowance_ns", "gnu_time_print_allowance_ns"):
            for value in (None, 0, True, float(plan()[field]), plan()[field]+1):
                changed=plan()
                if value is None:
                    changed.pop(field)
                else:
                    changed[field]=value
                with self.subTest(field=field,value=value), self.assertRaisesRegex(ValueError,"REGISTERED_OBSERVER_ALLOWANCES"):
                    runner.validate_plan(changed)
        changed=plan()
        changed["waited_endpoint_allowance_ns"]=changed.pop("waited_cpu_endpoint_allowance_ns")
        with self.assertRaisesRegex(ValueError,"REGISTERED_OBSERVER_ALLOWANCES"):
            runner.validate_plan(changed)

    def test_plan_cannot_promote_authority_or_drop_failed_proofs(self):
        for field, value in (
            ("production_activation", True), ("hardness_accepted", True), ("hardware_attested", True),
            ("generation_then_receiver_then_audit", False), ("miner_feedback_from_receiver", True),
            ("proof_retention", "winners-only"), ("independent_replay", "first-winner"),
            ("collection_output_limit_bytes", True), ("collection_output_limit_bytes", 512 * 1024 * 1024),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.validate_plan({**plan(), field: value})
        changed = plan()
        changed["jobs"] *= 2
        with self.assertRaises(ValueError):
            runner.validate_plan(changed)

    def test_duplicate_json_keys_and_nonfinite_values_are_refused(self):
        for value in ('{"x":1,"x":2}', '{"nested":{"x":1,"x":2}}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.decode(value)

    def test_gnu_time_snapshot_never_turns_missing_or_bad_usage_into_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "command.usage"
            with self.assertRaises(OSError):
                runner.usage_snapshot(path)
            for raw in (b"", b"NaN 0.1 32 0.1\n", b"0.1 0.0 -1 0.2\n", b"0.1 0.2 32\n",
                        b"0.1 0.0 32 0.2\n0.1 0.0 999 0.2\n"):
                path.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    runner.usage_snapshot(path)
            path.write_bytes(b"0.10 0.02 1234 0.15\n")
            result = runner.usage_snapshot(path)
            self.assertEqual(result["maximum_resident_set_kib"], 1234)
            self.assertEqual(result["user_seconds_decimal"], "0.10")
            self.assertEqual(result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_build_receipt_requires_the_fresh_exact_miner_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, log = Path(tmp) / "target", Path(tmp) / "build.stdout"
            location = target / "release/examples"
            location.mkdir(parents=True)
            rows = []
            for name in runner.BINARIES:
                path = location / name
                path.write_bytes(b"synthetic receipt parser fixture, not an executable")
                rows.append({"reason": "compiler-artifact", "target": {"name": name},
                             "executable": str(path), "fresh": False})
            def write(items):
                log.write_text("".join(json.dumps(row) + "\n" for row in items))
            write(rows)
            self.assertEqual(set(runner.build_artifacts(log, target)), set(runner.BINARIES))
            for changed in ([], rows + [rows[0]],
                            [{**rows[0], "fresh": True}],
                            [{**rows[0], "executable": str(location / "foreign-binary")} ]):
                write(changed)
                with self.assertRaises(ValueError):
                    runner.build_artifacts(log, target)

    def test_failed_native_command_is_retained_and_not_zero_yield_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            row = runner.run_step(out, "unsupported", [sys.executable, "-c",
                "import sys;print('UNSUPPORTED_AVX2_NO_FALLBACK');sys.exit(9)"], dict(os.environ), 10, 1024)
            self.assertEqual(row["returncode"], 9)
            self.assertFalse(row["complete_success"])
            self.assertIn("UNSUPPORTED", (out / "unsupported.stdout").read_text())
            self.assertEqual(runner.decode((out / "unsupported.step.json").read_bytes()), row)


class BindingControls(unittest.TestCase):
    def test_json_receipt_equality_preserves_recursive_types(self):
        original = {"count": 0, "flags": [True, {"cpu": 1}], "fraction": 1.0}
        self.assertTrue(reader.same_json(original, copy.deepcopy(original)))
        for changed in ({**original, "count": False},
                        {**original, "flags": [1, {"cpu": 1}]},
                        {**original, "flags": [True, {"cpu": True}]},
                        {**original, "fraction": 1}):
            with self.subTest(changed=changed):
                self.assertEqual(original, changed)  # The old Python comparison aliases these.
                self.assertFalse(reader.same_json(original, changed))

    def test_cross_observer_cpu_units_and_signed_residual_cannot_be_hidden(self):
        result = {"binary": runner.BINARIES[0], "total_process_cpu_ns": 100_000_000}
        step = {"whole_waited_child_resources": {"user_cpu_ns": 100_000_000, "system_cpu_ns": 5_000_000},
                "command_usage": {"user_seconds_decimal": "0.10", "system_seconds_decimal": "0.00"}}
        observed = reader.cpu_observer_reconciliation(result, step)
        self.assertEqual(observed["signed_residual_cpu_ns"], 5_000_000)
        result["total_process_cpu_ns"] = 105_001_000
        self.assertEqual(reader.cpu_observer_reconciliation(result, step)["signed_residual_cpu_ns"], -1000)
        result["total_process_cpu_ns"] = 105_003_000
        with self.assertRaisesRegex(ValueError, "NATIVE_CPU_EXCEEDS"):
            reader.cpu_observer_reconciliation(result, step)
        result = {"binary": runner.BINARIES[0], "total_process_cpu_ns": 100_000_000,
                  "phase_cpu_ns": {"setup": 15_000_000, "miner": 5_000_000, "receiver": 40_000_000, "audit": 30_000_000}}
        self.assertEqual(reader.cpu_observer_reconciliation(result, step)["nested_native_cpu_ns"], 100_000_000)
        step["command_usage"]["user_seconds_decimal"] = "100.00"
        with self.assertRaisesRegex(ValueError, "GNU_TIME_CPU_UNIT"):
            reader.cpu_observer_reconciliation(result, step)

    def test_transitive_helper_config_and_ignored_module_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args, stdin=None):
                return subprocess.check_output(["git", "-C", str(root), *args], input=stdin).decode().strip()
            git("init", "-q")
            for name, content in (("scripts/helper.py", "value = 1\n"),
                                  ("formal/oracle.py", "value = 2\n"),
                                  ("config/context.json", '{"version":1}\n')):
                path = root / name
                path.parent.mkdir(exist_ok=True)
                path.write_text(content)
            git("add", "scripts", "formal", "config")
            tree = git("write-tree")
            head = git("-c", "user.name=Evidence test", "-c", "user.email=test@example.invalid",
                       "commit-tree", tree, stdin=b"Synthetic source closure test\n")
            with patch.object(reader, "ROOT", root):
                result = reader.reader_tree_snapshot(head)
                self.assertEqual(result["files"], 3)
                for name in ("scripts/helper.py", "config/context.json"):
                    path = root / name
                    original = path.read_bytes()
                    path.write_bytes(original + b" ")
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, "READER_SOURCE_BYTES"):
                        reader.reader_tree_snapshot(head)
                    path.write_bytes(original)
                (root / ".git/info/exclude").write_text("scripts/ignored_extra.py\n")
                (root / "scripts/ignored_extra.py").write_text("altered = True\n")
                with self.assertRaisesRegex(ValueError, "READER_SOURCE_FILE_SET"):
                    reader.reader_tree_snapshot(head)

    def test_git_tree_and_blob_identity_cannot_be_swapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def git(*args, stdin=None):
                return subprocess.check_output(["git", "-C", str(root), *args], input=stdin).decode().strip()
            git("init", "-q")
            blob = git("hash-object", "-w", "--stdin", stdin=b"registered bytes\n")
            tree = git("mktree", stdin=f"100644 blob {blob}\tplan.json\n".encode())
            head = git("-c", "user.name=Evidence test", "-c", "user.email=test@example.invalid",
                       "commit-tree", tree, stdin=b"Synthetic Git identity test\n")
            digest = hashlib.sha256(b"registered bytes\n").hexdigest()
            with patch.object(reader, "ROOT", root):
                reader.source_objects(head, tree, {"plan.json": digest})
                with self.assertRaisesRegex(ValueError, "SOURCE_COMMIT_TREE_BINDING"):
                    reader.source_objects(head, "f" * 40, {"plan.json": digest})
                with self.assertRaisesRegex(ValueError, "SOURCE_BLOB_BINDING"):
                    reader.source_objects(head, tree, {"plan.json": "f" * 64})

    def test_external_manifest_pin_is_required_before_reading_native_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "campaign.json").write_text('{"synthetic":true}\n')
            with self.assertRaisesRegex(ValueError, "BUNDLE_MANIFEST_PIN"):
                reader.read_bundle(directory, expected_head="a" * 40, expected_tree="b" * 40,
                    expected_plan_sha256="c" * 64, expected_miner_binary_sha256="d" * 64, expected_manifest_sha256="f" * 64)

    def test_step_manifest_and_immutable_receipt_must_agree(self):
        # These actual tiny Python children exercise collection; they are NOT
        # claimed to be the protocol binaries or a real GNU time observation.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            jobs = plan()["jobs"]
            steps = []
            for name in (*reader.SETUP_NAMES, "miner"):
                steps.append(runner.run_step(directory, name, [sys.executable, "-c", "print('fixture')"],
                                             dict(os.environ), 10, 1024 * 1024))
            usage = directory / "miner.usage"
            usage.write_bytes(b"0.00 0.00 0 0.00\n")
            observer = {"sha256": "a" * 64}
            steps[-1]["command_usage"] = runner.usage_snapshot(usage)
            receipt_path = directory / "miner.observer.json"
            receipt = {"usage": steps[-1]["command_usage"], "usage_error": None,
                       "original_step_receipt_sha256": runner.sha(directory / "miner.step.json"),
                       "observer_sha256": observer["sha256"]}
            receipt_path.write_text(json.dumps(receipt))
            reader.check_steps(directory, steps, jobs, 1024 * 1024, observer)
            original_step = runner.decode((directory / "miner.step.json").read_bytes())
            for key, value in (("returncode", False), ("complete_success", 1)):
                changed_step = {**original_step, key: value}
                (directory / "miner.step.json").write_text(json.dumps(changed_step))
                changed_observer = {**receipt, "original_step_receipt_sha256":
                                    runner.sha(directory / "miner.step.json")}
                receipt_path.write_text(json.dumps(changed_observer))
                with self.subTest(alias=key), self.assertRaisesRegex(ValueError, "DIVERGENT_STEP_RECEIPT"):
                    reader.check_steps(directory, steps, jobs, 1024 * 1024, observer)
            (directory / "miner.step.json").write_text(json.dumps(original_step))
            receipt["original_step_receipt_sha256"] = runner.sha(directory / "miner.step.json")
            receipt_path.write_text(json.dumps(receipt))
            changed_observer = copy.deepcopy(receipt)
            changed_observer["usage"]["maximum_resident_set_kib"] = False
            receipt_path.write_text(json.dumps(changed_observer))
            with self.assertRaisesRegex(ValueError, "DIVERGENT_OBSERVER_RECEIPT"):
                reader.check_steps(directory, steps, jobs, 1024 * 1024, observer)
            receipt_path.write_text(json.dumps(receipt))
            for key, value in (("returncode", 1), ("stdout_truncated", True), ("stdout_sha256", "f" * 64),
                               ("wall_ns", steps[-1]["wall_ns"] + 1)):
                changed = copy.deepcopy(steps)
                changed[-1][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    reader.check_steps(directory, changed, jobs, 1024 * 1024, observer)
            usage.write_bytes(b"0.01 0.00 1 0.01\n")
            with self.assertRaisesRegex(ValueError, "DIVERGENT_USAGE_RECEIPT"):
                reader.check_steps(directory, steps, jobs, 1024 * 1024, observer)
            usage.write_bytes(b"0.00 0.00 0 0.00\n")
            receipt["observer_sha256"] = "b" * 64
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "DIVERGENT_OBSERVER_RECEIPT"):
                reader.check_steps(directory, steps, jobs, 1024 * 1024, observer)


if __name__ == "__main__":
    unittest.main()
