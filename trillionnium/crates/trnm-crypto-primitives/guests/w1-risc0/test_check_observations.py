"""Research-reader boundaries; these controls do not generate or qualify a proof."""
from copy import deepcopy
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_observations as check


HERE = Path(__file__).resolve().parent

# Exact original B records: ZIP SHA256 ab2ba1d482da96f629e1266ca03c283ddfb7f11387627c245e1417481e56f34e.
# The original prove timeout is intentionally not a successful proof fixture.
ORIGINAL_B_PROCESS_RAW = {'native-execute': ('{\n  "schema": "pon-w1-actual-process-v1",\n  "command": [\n    "/home/runner/work/_temp/complete-w1-build-40825729537-1/host-target/release/examples/pon_w1_complete_relation",\n    "execute",\n    "/home/runner/work/_temp/complete-w1-proof-40825729537-1/input.bin"\n  ],\n  "started_utc": "2026-10-29T05:52:19.958384+00:00",\n  "timeout_seconds": 60,\n  "source_sha": "504ccfe6bc4aa504f4a67f73c16040fca5b8e10e",\n  "timed_out": false,\n  "consensus_authority": false,\n  "returncode": 0,\n  "wall_seconds": 0.003659799000004682,\n  "user_cpu_seconds": 0.001841,\n  "system_cpu_seconds": 0.0,\n  "max_waited_descendant_rss_kib": 13708,\n  "rss_scope": "maximum reported for the waited child family; not total cgroup peak",\n  "finished_utc": "2026-10-29T05:52:19.962064+00:00"\n}\n', 'e021809dd027121651d2a374b6b1524e5eddd2a5f8e7b361385f1529611017df'), 'prove': ('{\n  "schema": "pon-w1-actual-process-v1",\n  "command": [\n    "/home/runner/work/_temp/complete-w1-build-40825729537-1/host-target/release/trnm-w1-risc0-host",\n    "prove",\n    "/home/runner/work/_temp/complete-w1-build-40825729537-1/backend/tools/r0vm",\n    "/home/runner/work/_temp/complete-w1-proof-40825729537-1/guest.bin",\n    "/home/runner/work/_temp/complete-w1-proof-40825729537-1/input.bin",\n    "18",\n    "/home/runner/work/_temp/complete-w1-proof-40825729537-1/receipt.bin"\n  ],\n  "started_utc": "2026-10-29T05:56:32.919557+00:00",\n  "timeout_seconds": 5400,\n  "source_sha": "504ccfe6bc4aa504f4a67f73c16040fca5b8e10e",\n  "timed_out": true,\n  "consensus_authority": false,\n  "returncode": 124,\n  "wall_seconds": 5400.001817587,\n  "user_cpu_seconds": 0.022664,\n  "system_cpu_seconds": 0.004817999999999999,\n  "max_waited_descendant_rss_kib": 15092,\n  "rss_scope": "maximum reported for the waited child family; not total cgroup peak",\n  "finished_utc": "2026-10-29T07:26:32.921400+00:00"\n}\n', '99123646baa16971166a85c5b7047b97adb1bc2fce675b54c98cf8da4b51ff90')}


class ManifestBoundaries(unittest.TestCase):
    def setUp(self):
        self.pinned = check.load(HERE / "backend-manifest.json")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)

    def write(self, value):
        path = self.out / "backend-manifest.json"
        path.write_text(json.dumps(value))
        return path

    def test_actual_source_manifest_is_the_only_profile_authority(self):
        check.validate_manifest(self.pinned)
        reordered = dict(reversed(list(self.pinned.items())))
        path = self.write(reordered)
        path.write_text(json.dumps(reordered, indent=4) + "\n")
        check.validate_manifest(check.load(path))

    def test_each_source_field_is_bound_including_schema_algorithm_image_and_security(self):
        for field, original in self.pinned.items():
            changed = deepcopy(self.pinned)
            if type(original) is bool:
                changed[field] = not original
            elif type(original) is int:
                changed[field] = original + 1
            elif isinstance(original, str):
                changed[field] = original + "-changed"
            elif isinstance(original, dict):
                changed[field]["unreviewed-source"] = "0" * 64
            else:
                changed[field] = "unreviewed"
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.validate_manifest(changed)

    def test_source_map_cannot_drop_replace_or_add_a_guest_pin(self):
        field = "guest_source_sha256"
        name = next(iter(self.pinned[field]))
        for action in ("drop", "replace", "add"):
            changed = deepcopy(self.pinned)
            if action == "drop":
                del changed[field][name]
            elif action == "replace":
                changed[field][name] = "0" * 64
            else:
                changed[field]["new-source.rs"] = "0" * 64
            with self.subTest(action=action), self.assertRaises(ValueError):
                check.validate_manifest(changed)

    def test_missing_extra_and_numerically_equal_json_types_are_refused(self):
        changed = deepcopy(self.pinned)
        del changed["proof_commitment_hash"]
        extra = dict(self.pinned, new_authority=False)
        zero = dict(self.pinned, pq_128_security_qualified=0)
        real = dict(self.pinned, proof_fri_queries=float(self.pinned["proof_fri_queries"]))
        for value in (changed, extra, zero, real, [], None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                check.validate_manifest(value)

    def test_manifest_is_checked_before_assets_in_build_and_full_paths(self):
        # No ELF or receipt exists. Even coordinated image/algorithm changes
        # must fail at the profile boundary, rather than reaching asset reads.
        for build_only in (False, True):
            for field, value in (("guest_image_id", "0" * 64),
                                 ("proof_receipt_kind", "Groth16"),
                                 ("proof_commitment_hash", "sha-256"),
                                 ("proof_fri_queries", 1)):
                self.write(dict(self.pinned, **{field: value}))
                args = ["check_observations.py", "--out", str(self.out)]
                if build_only:
                    args.append("--build-only")
                with self.subTest(build_only=build_only, field=field), \
                     patch.object(sys, "argv", args), \
                     self.assertRaisesRegex(ValueError, "manifest differs from checker source"):
                    check.main()

    def test_nested_unsupported_authority_requires_literal_false(self):
        for flag in check.UNSUPPORTED_AUTHORITY_FLAGS:
            path = self.write({"nested": [{flag: False}]})
            check.load(path)
            for invalid in (True, 0, 1, None, "false", [], {}):
                path = self.write({"nested": [{flag: invalid}]})
                with self.subTest(flag=flag, invalid=invalid), self.assertRaisesRegex(
                        ValueError, "unsupported research authority"):
                    check.load(path)

    def test_duplicate_json_and_nonfinite_numbers_do_not_hide_a_claim(self):
        path = self.out / "record.json"
        for raw in ('{"pq128_qualified":true,"pq128_qualified":false}',
                    '{"schema":"changed","schema":"original"}',
                    '{"nested":{"seconds":NaN}}', '{"seconds":Infinity}',
                    '{"seconds":-Infinity}', '{"seconds":1e999}', '{"seconds":-1e999}'):
            path.write_text(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                check.load(path)
        path.write_text('{"seconds":0.25}')
        self.assertEqual(check.load(path), {"seconds": 0.25})


class ProcessSchemaBoundaries(unittest.TestCase):
    """Metadata association controls; synthetic v2 data never qualifies a proof."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)

    def fixture(self):
        import proof_observer_v1 as observer
        command = ["/original/trnm-w1-risc0-host", "prove", "/original/r0vm",
                   "/original/out/guest.bin", "/original/out/input.bin", "18", "/original/out/receipt.bin"]
        process = {"schema": "pon-w1-observed-process-v2", "command": command,
                   "started_utc": "2026-10-29T00:00:00+00:00", "finished_utc": "2026-10-29T00:00:01+00:00",
                   "timeout_seconds": 5400, "source_sha": "a" * 40, "returncode": 0, "timed_out": False,
                   "wall_seconds": 1.0, "user_cpu_seconds": 0.1, "system_cpu_seconds": 0.01,
                   "max_waited_descendant_rss_kib": 42,
                   "rss_scope": "direct host wait4, potentially including descendants it waited; not whole-family peak",
                   "cpu_scope": "direct host wait4 only; adopted rows separate; total family unknown",
                   "supplement": "prove.observer.json", "supplement_sha256": "",
                   "family_capture_complete": False, "complete_family_cpu_seconds": None,
                   "consensus_authority": False}
        report = {key: deepcopy(process[key]) for key in ("command", "source_sha", "started_utc", "finished_utc",
                                                         "timeout_seconds", "returncode", "timed_out", "wall_seconds")}
        source = (HERE / "proof_observer_v1.py").read_bytes()
        source_identity = {"sha256": hashlib.sha256(source).hexdigest(), "bytes": len(source)}
        held_identity = {"sha256": "0" * 64, "bytes": 4}
        report.update(schema="pon-w1-proof-process-observer-v1", family_capture_complete=False,
                      complete_family_cpu_seconds=None, proof_qualification=False, consensus_authority=False,
                      finite_cleanup_observed=True, failure=None, secondary_failures=[],
                      adoption_probe="ECHILD-observed-not-full-family-certification",
                      direct_wait4={"pid": 123, "returncode": 0, "user_cpu_seconds": 0.1,
                                    "system_cpu_seconds": 0.01, "max_rss_kib": 42},
                      leader_pid=123, observer_source=source_identity,
                      host_before=deepcopy(held_identity), host_after=deepcopy(held_identity),
                      backend_before=deepcopy(held_identity), backend_after=deepcopy(held_identity),
                      stream_limits=observer.STREAM_CAPS, streams={}, shim_source=deepcopy(source_identity),
                      effective_command=[*command[:2], "/original/out/prove.backend-shim.py", *command[3:]])
        (self.out / "prove.backend-shim.py").write_bytes(source)
        for name in observer.STREAM_CAPS:
            raw = b"{}\n" if name == "stdout" else b""
            (self.out / ("prove." + name + ".log")).write_bytes(raw)
            report["streams"][name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "truncated": False}
        sample = json.dumps({"schema": "pon-w1-process-sample-v1", "historical_family_complete": False}).encode() + b"\n"
        (self.out / "prove.process-samples.jsonl").write_bytes(sample)
        report["samples"] = {"bytes": len(sample), "count": 1, "sha256": hashlib.sha256(sample).hexdigest()}
        phases = [{"schema": "pon-w1-host-phase-v1", "sequence": n, "pid": 123, "elapsed_ns": n * 100,
                   "event": event, "consensus_authority": False} for n, event in enumerate(observer.PHASES)]
        (self.out / "prove.host-phases.jsonl").write_text("".join(json.dumps(row) + "\n" for row in phases))
        report["host_phases"] = observer.phase_readback(self.out / "prove.host-phases.jsonl", 123)
        self.bind(process, report)
        return process, report

    def bind(self, process, report):
        raw = (json.dumps(report, indent=2) + "\n").encode()
        (self.out / "prove.observer.json").write_bytes(raw)
        process["supplement_sha256"] = hashlib.sha256(raw).hexdigest()

    def test_actual_original_b_records_keep_schema_scope_and_timeout(self):
        for name, (raw, expected) in ORIGINAL_B_PROCESS_RAW.items():
            self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), expected)
            process = check.decode_json(raw)
            check.validate_process_schema(name, process, self.out)
            if name == "prove":
                self.assertEqual(process["returncode"], 124)
                self.assertIs(process["timed_out"], True)
                with self.assertRaisesRegex(ValueError, "explicit workflow requires"):
                    check.validate_process_schema(name, process, self.out, True)

    def test_bound_synthetic_v2_metadata_has_no_resource_or_proof_authority(self):
        process, _ = self.fixture()
        check.validate_process_schema("prove", process, self.out, True)
        self.assertFalse(process["family_capture_complete"])
        self.assertIsNone(process["complete_family_cpu_seconds"])

    def test_unknown_schema_mixed_legacy_and_wrong_phase_cannot_skip_observer(self):
        process, _ = self.fixture()
        for namespace in ("unknown", "pon-w1-actual-process-v1"):
            changed = deepcopy(process)
            changed["schema"] = namespace
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                check.validate_process_schema("prove", changed, self.out)
        with self.assertRaises(ValueError):
            check.validate_process_schema("verify", process, self.out)

    def test_forged_types_and_cost_scope_refused_even_after_digest_rebinding(self):
        for field, value in (("user_cpu_seconds", False), ("system_cpu_seconds", "0.01"),
                             ("max_waited_descendant_rss_kib", 42.0), ("wall_seconds", False),
                             ("timeout_seconds", 5400.0), ("cpu_scope", "complete family CPU"),
                             ("family_capture_complete", 0), ("complete_family_cpu_seconds", 0)):
            process, report = self.fixture()
            process[field] = value
            if field in report:
                report[field] = value
            self.bind(process, report)
            with self.subTest(field=field), self.assertRaises(ValueError):
                check.validate_process_schema("prove", process, self.out)

    def test_rebound_supplement_cannot_hide_changed_source_executable_or_failed_cleanup(self):
        for change in ("source", "host", "backend", "shim", "command", "cleanup", "failure"):
            process, report = self.fixture()
            if change == "source":
                report["observer_source"]["sha256"] = "1" * 64
            elif change in ("host", "backend"):
                report[change + "_after"]["sha256"] = "1" * 64
            elif change == "shim":
                report["shim_source"]["sha256"] = "1" * 64
            elif change == "command":
                report["effective_command"][2] = "/other/shim"
            elif change == "cleanup":
                report["finite_cleanup_observed"] = False
            else:
                report["failure"] = "host-phases-incomplete"
            self.bind(process, report)
            with self.subTest(change=change), self.assertRaises(ValueError):
                check.validate_process_schema("prove", process, self.out)

    def test_changed_raw_stream_sample_phase_or_shim_is_not_bound_by_report_alone(self):
        for filename in ("prove.stdout.log", "prove.process-samples.jsonl", "prove.host-phases.jsonl", "prove.backend-shim.py"):
            process, _ = self.fixture()
            with (self.out / filename).open("ab") as stream:
                stream.write(b"changed\n")
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                check.validate_process_schema("prove", process, self.out)


if __name__ == "__main__":
    unittest.main()
