"""Cost-profile authority and short real owner controls, never a W1 proof."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_observations as check
import proof_observer_v1 as observer
import test_check_observations as baseline_controls

HERE = Path(__file__).resolve().parent
PYTHON = str(Path(sys.executable).resolve())
ORIGINAL = observer.ORIGINAL_PROFILE
COST = observer.COST_PROFILE


@unittest.skipUnless(sys.platform == "linux", "Linux owner controls")
class CostProfileAuthority(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out = self.root / "out"

    def command(self, out=None):
        out = self.out if out is None else out
        return [str(self.root / "trnm-w1-risc0-host"), "prove", "/usr/bin/true",
                str(out / "guest.bin"), str(out / "input.bin"), "18", str(out / "receipt.bin")]

    def cli(self, flags, *, command=None):
        return subprocess.run(
            [PYTHON, "-B", str(HERE / "measure_step.py"), "--out", str(self.out),
             "--name", "prove", *flags, "--", *(self.command() if command is None else command)],
            cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            # The copied interpreter keeps its actual standard-library root;
            # this is a synthetic test fixture, never a production prover env.
            env=dict(os.environ, TRNM_EXPECTED_SOURCE_SHA="a" * 40, PYTHONHOME=sys.base_prefix))

    def test_default_and_explicit_original_refuse_four_hours_before_spawn(self):
        for extra in ([], ["--proof-profile", ORIGINAL]):
            with self.subTest(extra=extra):
                result = self.cli(["--timeout", "14400", "--observe-proof", *extra])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"between 1 and 5400", result.stderr)
                self.assertFalse(self.out.exists())

    def test_cost_requires_observer_and_exact_integer_budget(self):
        variants = [["--timeout", "14400"],
                    *[["--timeout", value, "--observe-proof"]
                      for value in ("0", "1", "5400", "14399", "14401", "14400.0")]]
        for flags in variants:
            with self.subTest(flags=flags):
                result = self.cli([*flags, "--proof-profile", COST])
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.out.exists())

    def test_unknown_profile_is_refused_by_actual_cli(self):
        result = self.cli(["--timeout", "14400", "--observe-proof", "--proof-profile", "unreviewed"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"invalid choice", result.stderr)
        self.assertFalse(self.out.exists())

    def test_wrong_cost_command_or_po2_is_refused_before_owner(self):
        original = self.command()
        variants = [original[:-1], ["/usr/bin/true", *original[1:]],
                    [original[0], "execute", *original[2:]],
                    [*original[:5], "19", original[6]],
                    [*original[:3], str(self.root / "other.bin"), *original[4:]]]
        for command in variants:
            with self.subTest(command=command), patch.object(observer, "run_observed") as owner:
                with self.assertRaises(observer.ObservationError):
                    observer.observed_prove(command, self.out, "prove", 14400, proof_profile=COST)
                owner.assert_not_called()
                self.assertFalse(self.out.exists())

    def test_internal_owner_preserves_default_limit_and_rejects_unknown_profile(self):
        for profile, timeout in ((ORIGINAL, 14400), ("unreviewed", 14400),
                                 (COST, 5400), (COST, 14400.0)):
            with self.subTest(profile=profile, timeout=timeout), patch.object(observer.subprocess, "Popen") as spawn:
                with self.assertRaises(observer.ObservationError):
                    observer.run_observed(self.command(), self.out, timeout, proof_profile=profile,
                                          backend_index=2, require_phases=True)
                spawn.assert_not_called()
                self.assertFalse(self.out.exists())

    def test_cost_cannot_override_sampling_or_stream_limits(self):
        for changed in ({"sample_interval": 0.05}, {"stream_caps": dict(observer.STREAM_CAPS)},
                        {"backend_index": None}, {"require_phases": False}):
            options = dict(backend_index=2, require_phases=True, proof_profile=COST)
            options.update(changed)
            with self.subTest(changed=changed), patch.object(observer.subprocess, "Popen") as spawn:
                with self.assertRaises(observer.ObservationError):
                    observer.run_observed(self.command(), self.out, 14400, **options)
                spawn.assert_not_called()
                self.assertFalse(self.out.exists())

    def synthetic_host(self, returncode=0):
        # A copied real Python ELF executes the local script named "prove".
        # This emits synthetic host phase metadata only: no SDK, guest, seal,
        # receipt or proof is generated, and the full proof checker cannot pass.
        shutil.copy2(PYTHON, self.root / "trnm-w1-risc0-host")
        program = ("import json,os,time\n"
                   f"phases={list(observer.PHASES)!r}\n"
                   "with open(os.environ['TRNM_W1_PHASE_JOURNAL'],'x') as output:\n"
                   " for sequence,event in enumerate(phases):\n"
                   "  output.write(json.dumps({'schema':'pon-w1-host-phase-v1','sequence':sequence,"
                   "'pid':os.getpid(),'elapsed_ns':sequence*100,'event':event,'consensus_authority':False})+'\\n')\n"
                   "print(json.dumps({'synthetic_owner_control_only':True}),flush=True)\n"
                   f"raise SystemExit({returncode})\n")
        (self.root / "prove").write_text(program)

    def test_actual_short_cost_cli_retains_scoped_success_and_original_reader_refuses_it(self):
        self.synthetic_host()
        result = self.cli(["--timeout", "14400", "--observe-proof", "--proof-profile", COST])
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        process = json.loads((self.out / "prove.process.json").read_text())
        report = json.loads((self.out / "prove.observer.json").read_text())
        self.assertEqual(process["schema"], "pon-w1-cost-observed-process-v1")
        self.assertEqual(report["schema"], "pon-w1-cost-proof-process-observer-v1")
        self.assertEqual(process["timeout_seconds"], 14400)
        self.assertIs(process["original_5400s_budget_passed"], False)
        self.assertIs(report["proof_qualification"], False)
        self.assertTrue(report["finite_cleanup_observed"])
        self.assertEqual(report["direct_wait4"]["returncode"], 0)
        self.assertEqual(report["stream_limits"], observer.STREAM_CAPS)
        self.assertEqual(report["sample_limit"], 16 * 1024 * 1024)
        self.assertEqual(report["cleanup_allowance_seconds"], 5)
        self.assertFalse((self.out / "receipt.bin").exists())
        check.validate_process_schema("prove", process, self.out, True, COST)
        with self.assertRaises(ValueError):
            check.validate_process_schema("prove", process, self.out, True)

    def test_actual_short_cost_cli_preserves_nonzero_failure(self):
        self.synthetic_host(returncode=7)
        result = self.cli(["--timeout", "14400", "--observe-proof", "--proof-profile", COST])
        self.assertEqual(result.returncode, 7, result.stderr.decode(errors="replace"))
        process = json.loads((self.out / "prove.process.json").read_text())
        report = json.loads((self.out / "prove.observer.json").read_text())
        self.assertEqual(process["returncode"], 7)
        self.assertEqual(report["direct_wait4"]["returncode"], 7)
        self.assertIs(process["original_5400s_budget_passed"], False)
        self.assertTrue(report["finite_cleanup_observed"])


class CostProfileReader(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)
        self.fixture_owner = baseline_controls.ProcessSchemaBoundaries(methodName="runTest")
        self.fixture_owner.out = self.out

    def fixture(self, profile=COST, samples=1):
        process, report = self.fixture_owner.fixture()
        if profile == COST:
            process.update(schema="pon-w1-cost-observed-process-v1", timeout_seconds=14400,
                           proof_profile=COST, original_5400s_budget_passed=False)
            report.update(schema="pon-w1-cost-proof-process-observer-v1", timeout_seconds=14400,
                          proof_profile=COST, original_5400s_budget_passed=False)
        raw = (json.dumps({"schema": "pon-w1-process-sample-v1", "historical_family_complete": False}) + "\n").encode() * samples
        (self.out / "prove.process-samples.jsonl").write_bytes(raw)
        report["samples"] = {"bytes": len(raw), "count": samples, "sha256": hashlib.sha256(raw).hexdigest()}
        self.fixture_owner.bind(process, report)
        return process, report

    def test_profile_and_schema_must_agree_in_both_directions(self):
        for actual in (ORIGINAL, COST):
            process, _ = self.fixture(actual)
            check.validate_process_schema("prove", process, self.out, True, actual)
            for selected in ({ORIGINAL, COST, "unreviewed"} - {actual}):
                with self.subTest(actual=actual, selected=selected), self.assertRaises(ValueError):
                    check.validate_process_schema("prove", process, self.out, True, selected)

    def test_cost_reader_requires_explicit_observer_check(self):
        process, _ = self.fixture()
        with self.assertRaisesRegex(ValueError, "requires explicit proof observer"):
            check.validate_process_schema("prove", process, self.out, False, COST)

    def test_original_supplement_refuses_each_cost_only_metadata_field(self):
        for changed in ({"proof_profile": COST}, {"original_5400s_budget_passed": False},
                        {"proof_profile": COST, "original_5400s_budget_passed": False}):
            process, report = self.fixture(ORIGINAL)
            report.update(changed)
            self.fixture_owner.bind(process, report)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "cost-only profile metadata"):
                check.validate_process_schema("prove", process, self.out, True)

    def test_new_profile_has_separate_sample_count_but_same_byte_and_line_bounds(self):
        for profile, maximum in ((ORIGINAL, 1082), (COST, 2882)):
            process, _ = self.fixture(profile, maximum)
            check.validate_process_schema("prove", process, self.out, True, profile)
            process, _ = self.fixture(profile, maximum + 1)
            with self.subTest(profile=profile), self.assertRaisesRegex(ValueError, "sample bound"):
                check.validate_process_schema("prove", process, self.out, True, profile)
        for raw, message in ((b"x" * 65536 + b"\n", "sample line bound"),
                             (b"x" * (observer.SAMPLE_CAP + 1), "sample bound")):
            process, report = self.fixture()
            (self.out / "prove.process-samples.jsonl").write_bytes(raw)
            report["samples"] = {"bytes": len(raw), "count": 1, "sha256": hashlib.sha256(raw).hexdigest()}
            self.fixture_owner.bind(process, report)
            with self.assertRaisesRegex(ValueError, message):
                check.validate_process_schema("prove", process, self.out, True, COST)

    def test_forged_original_budget_claim_and_mixed_supplement_are_refused(self):
        for target, key, value in (("process", "original_5400s_budget_passed", True),
                                   ("report", "original_5400s_budget_passed", True),
                                   ("process", "proof_profile", ORIGINAL),
                                   ("report", "proof_profile", ORIGINAL),
                                   ("report", "schema", "pon-w1-proof-process-observer-v1"),
                                   ("report", "timeout_seconds", 5400),
                                   ("process", "timeout_seconds", 14401),
                                   ("report", "finite_cleanup_observed", False)):
            process, report = self.fixture()
            (process if target == "process" else report)[key] = value
            self.fixture_owner.bind(process, report)
            with self.subTest(target=target, key=key, value=value), self.assertRaises(ValueError):
                check.validate_process_schema("prove", process, self.out, True, COST)

    def test_cost_only_cli_cannot_skip_full_observer_checks(self):
        for flags in ([], ["--build-only"], ["--build-only", "--require-proof-observer"]):
            args = ["check_observations.py", "--out", str(self.out), "--proof-profile", COST, *flags]
            with self.subTest(flags=flags), patch.object(sys, "argv", args), \
                 self.assertRaisesRegex(ValueError, "full explicit proof observer"):
                check.main()


if __name__ == "__main__":
    unittest.main()
