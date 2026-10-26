#!/usr/bin/env python3
"""Evidence parser and collection controls; no synthetic execution qualification.

The tiny subprocesses below test retained failure/output behavior. Synthetic Cargo
and observer receipts test their grammar only and never stand for native work.
The miner raw-reader suite replays complete actual or explicitly constructed W1
proofs separately. No timing or hardware result is produced by these unit tests.
"""
from __future__ import annotations

import copy
import base64
import gzip
import io
import lzma
import tarfile
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
import run_w1_fork_resource_research as runner
import read_w1_fork_resource_research as reader
import w1_fork_resource_reader as native
import analyze_w1_fork_resource as analysis


def plan():
    return {
        "schema": runner.PLAN_SCHEMA, "production_activation": False,
        "hardness_accepted": False, "hardware_attested": False,
        "proof_retention": "all-completed-research-proofs-including-misses",
        "independent_replay": "all-retained-full-proofs-posthoc-no-selection-feedback",
        "collection_output_limit_bytes": 1024 * 1024,
        "generation_then_receiver_then_audit": True, "miner_feedback_from_receiver": False,
        "finite_common_root_sibling_branches": True, "epoch_budget_reset": False, "arbitrary_strategy_bound": False,
        "waited_cpu_endpoint_allowance_ns": runner.WAITED_CPU_ALLOWANCE_NS,
        "gnu_time_print_allowance_ns": runner.GNU_TIME_PRINT_ALLOWANCE_NS,
        "jobs": [{"name": "miner", "binary": runner.BINARIES[0],
                  "args": ["--setup-budget-ns", "1000000000", "--miner-budget-ns", "128000000",
                           "--branches", "1", "--depth", "2", "--max-attempts", "4096", "--acquisition", "shared",
                           "--tasks", "both", "--policy", "adaptive-cost", "--screen-width", "2",
                           "--arm", "structure-paired", "--reuse", "lifetime", "--seed", "5101"], "timeout_seconds": 10}],
    }


class CollectionControls(unittest.TestCase):
    def test_registered_plan_and_exact_argument_decoding(self):
        frozen = runner.decode((ROOT / "formal/pon-nakamoto-v1/experiments/w1_fork_resource_campaign_v1.json").read_bytes())
        jobs = runner.validate_plan(frozen)
        self.assertEqual(len(jobs), 42)
        self.assertTrue(all(j["binary"] == runner.BINARIES[0] for j in jobs))
        runner.validate_plan(plan())
        for mutation in (
            {"name": "build"}, {"name": "../escape"}, {"binary": "foreign-executable"},
            {"args": ["--branches", "1", "--branches", "2"]},
            {"args": ["--foreign", "1"]}, {"args": ["--branches", "5"]},
            {"timeout_seconds": True}, {"timeout_seconds": 1801},
        ):
            changed = plan()
            changed["jobs"][0].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                runner.validate_plan(changed)

    def test_registered_orders_are_balanced_inside_each_fixed_cell(self):
        frozen = runner.decode((ROOT / "formal/pon-nakamoto-v1/experiments/w1_fork_resource_campaign_v1.json").read_bytes())
        groups = {}
        for job in frozen["jobs"]:
            if frozen["cohorts"][job["name"]] != "main":
                continue
            options = dict(zip(job["args"][::2], job["args"][1::2]))
            key = (options["--branches"], options["--depth"], options["--policy"])
            groups.setdefault(key, {}).setdefault(options["--seed"], []).append(options["--arm"])
        self.assertEqual(len(groups), 6)
        for group in groups.values():
            self.assertEqual(group["5101"], list(reversed(group["5102"])))
            self.assertEqual(len(set(group["5101"])), 2)

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
            ("proof_retention", "winners-only"), ("finite_common_root_sibling_branches", False),
            ("epoch_budget_reset", True), ("arbitrary_strategy_bound", True), ("independent_replay", "first-winner"),
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
            compression = {"miner": runner.compress_completed_stdout(directory, steps[-1])}
            (directory / "miner.compression.json").write_text(json.dumps(compression["miner"]))
            reader.check_steps(directory, steps, jobs, 1024 * 1024, observer, compression)
            original_step = runner.decode((directory / "miner.step.json").read_bytes())
            for key, value in (("returncode", False), ("complete_success", 1)):
                changed_step = {**original_step, key: value}
                (directory / "miner.step.json").write_text(json.dumps(changed_step))
                changed_observer = {**receipt, "original_step_receipt_sha256":
                                    runner.sha(directory / "miner.step.json")}
                receipt_path.write_text(json.dumps(changed_observer))
                with self.subTest(alias=key), self.assertRaisesRegex(ValueError, "DIVERGENT_STEP_RECEIPT"):
                    reader.check_steps(directory, steps, jobs, 1024 * 1024, observer, compression)
            (directory / "miner.step.json").write_text(json.dumps(original_step))
            receipt["original_step_receipt_sha256"] = runner.sha(directory / "miner.step.json")
            receipt_path.write_text(json.dumps(receipt))
            changed_observer = copy.deepcopy(receipt)
            changed_observer["usage"]["maximum_resident_set_kib"] = False
            receipt_path.write_text(json.dumps(changed_observer))
            with self.assertRaisesRegex(ValueError, "DIVERGENT_OBSERVER_RECEIPT"):
                reader.check_steps(directory, steps, jobs, 1024 * 1024, observer, compression)
            receipt_path.write_text(json.dumps(receipt))
            for key, value in (("returncode", 1), ("stdout_truncated", True), ("stdout_sha256", "f" * 64),
                               ("wall_ns", steps[-1]["wall_ns"] + 1)):
                changed = copy.deepcopy(steps)
                changed[-1][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    reader.check_steps(directory, changed, jobs, 1024 * 1024, observer, compression)
            usage.write_bytes(b"0.01 0.00 1 0.01\n")
            with self.assertRaisesRegex(ValueError, "DIVERGENT_USAGE_RECEIPT"):
                reader.check_steps(directory, steps, jobs, 1024 * 1024, observer, compression)
            usage.write_bytes(b"0.00 0.00 0 0.00\n")
            receipt["observer_sha256"] = "b" * 64
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "DIVERGENT_OBSERVER_RECEIPT"):
                reader.check_steps(directory, steps, jobs, 1024 * 1024, observer, compression)


# Exact native small-cap outputs, not performance or qualification evidence.
FIXTURE_PROVENANCE = {'git_head': '635734087e505e065243f6464342e41c48f20f21', 'source_files': {'trillionnium/crates/trnm-pon-node/examples/pon_w1_fork_resource_research.rs': 'b07608ac18c07b5e1ba355859792bd7ac66f1f3875e5d2c3f0f5f9d90daf5a3d', 'trillionnium/crates/trnm-pon-node/examples/support/w1_fork_resource.rs': '4228fb45b2534570549551a8aa381fa5cdd2e0b6253d73275bf5902d18d3a1fc', 'trillionnium/crates/trnm-pon-node/examples/support/w1_zero_strassen.rs': 'bbf861856e63e1d3d9a85792b32a33d821073fb89d149a54ec366984c7f6e8cb', 'trillionnium/crates/trnm-pon-node/examples/support/w1_cost_game_producers.rs': 'e0fb6efca800442be52c0fe9868e4b29f07fbbf47c5b633c08960b0147df8588'}, 'binary_sha256': 'd2caaa1e29645b4873409876916c540644ff265ed468b105a61157439d10c2df', 'performance_measurement': False}
FIXTURE_MEMBERS = {'four-rr-lifetime': {'raw_bytes': 6154295, 'raw_sha256': '370e8c3fcfba1cdbf23f49304e2b2e3cddc13e994351f2bae32a644f01ac78bf'}, 'four-adaptive-lifetime': {'raw_bytes': 4849038, 'raw_sha256': '4234a3957ed93b21bb715eb59ce6da7f8d8607bb78b879b1c8f20f3fede1e02b'}, 'two-window': {'raw_bytes': 4030832, 'raw_sha256': '2e7eff26a9b3b9eb3cd7a7a6f5344c162ab8b406dc4d2f83958725d62ac35545'}, 'two-screen': {'raw_bytes': 2703873, 'raw_sha256': 'f6687b0defdc753c04ee517a2edd89af67aca3fb22581d85b2dd64b313cf1de0'}, 'zero-cold': {'raw_bytes': 1073285, 'raw_sha256': '613fec6c3f533bc29c411f991a8ea7bc41d960c1c6b82c8bda90164fe7cc7ad6'}, 'setup-zero': {'raw_bytes': 5888, 'raw_sha256': 'a551efacbb7f19e19604454a0ba3952858ba2e53554a15f7d25dfc59c2ad075a'}, 'setup-tight': {'raw_bytes': 145451, 'raw_sha256': 'd6c6b2a6baa77013e6736c47d78bc99bb31e4410c002b264f9c3a3b589d3d995'}, 'miner-zero': {'raw_bytes': 1366645, 'raw_sha256': 'a139ab755f9b65664b4d4c330915a60d1d0b73275e8bec09051908b76d454a28'}, 'miner-tight': {'raw_bytes': 1472190, 'raw_sha256': 'd0770666bd83d48a4080b6a35257d8fbbad1b5fb5e3fa4b0d69d62057cafea0c'}, 'maintenance-selective': {'raw_bytes': 1907006, 'raw_sha256': '4f19147249489a52be2185c2f2e5d038659da34126d18509f1d0b50736987ef9'}, 'strassen-zero': {'raw_bytes': 1575641, 'raw_sha256': '31a27532b520f7f47b4998e501f31c59c06ec184b3b66808802718121a9ec4cb'}, 'maximum-depth': {'raw_bytes': 3896432, 'raw_sha256': 'd8f92bfeb0b2417d8ab3b7e7d8ff651dfd4d7d96251f58a6ccfa22ca522d0267'}}
FIXTURE_ARCHIVE_SHA256 = '91ab8705d07a137c357b6562e4db43bb6f67eb706c90a9176381ec084aeec4f1'
FIXTURE_ARCHIVE_B85 = (
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5|NkUl;9USS8_N;xl_y^rJJK<L3TBZnm{L=HImz{(rxe3pwQdy7Y25c~aC8aJ^6Ur9@K%!8'
    'd~BB8Sb1#+an9T?8hCh1n|Fu2=ni!NGW+JVeC{$>MOSKy-|BhG8oxwD%6QEKW(DR8aqJW`G^7CB^;!>C6h}VM$gET$b>Q-'
    '!r#kVKPK)L<X`CB=lN>@8a>oRe7B74zGvX4gj;G}|oJ~LI9(C!>W`lM2FKR8~{afmj1*LELf|(|RcrYG=nx#y7>vrwRPDK6z>@LN'
    'sp!B;$LPVPxk;mJ7G!e2(D!NnR3{V8Wuy-'
    '%XHdUVDcIg1574nbl+nEImTsQZq{0Bxz1+>(k4C@5kJ*8>~N`h;yFCDbV5I2owB~igj-'
    'v8Z`%F0CETm*?*3hemGp}0H*Euf0UMlZ4IuiZD`;$z+sE1i{Y`Z6Df?j+5o)h>|gBImiq;2<ze$GI%ut)>QWNIbp{%E)nEB>D}RE'
    'M&+9D*48JRYQof3!mtBlaK%p*M8(`v;N-QUtR#%x{+KS*p*RhyaqEb(E}U^BP7-;e9`dEdYGW~QANtsQ@5?-'
    '%=CeKQF3?1*EE4M0qc8|!H=YLQ{0jp1s9;uIOS{h9|iYH$>`PW&}1b$>V4@zRtQx2-'
    'U~b5f>J}e_jn9d4H%HV^qQFeh}#b!Yyjt}{zWa^2O?c+j%V?r>Fa}e>w2Q9!&u$|3SG=l<lZ<!)|%S#6kJ(XfaJ|bFVCpNLAe2vw'
    '26}lC6Ta2Z=5LRPT04WXQd|qqpS49`3HSrP|z}{4<_=SZxi>xK{MWilmzf4%07<wZBrLD3lJSCbkiN-'
    'R+^07nIZq33=&J6qSj;?U4wv{LCmRkwwiJFA(3JN$rCU=dCv3WsIxfKw*Pur?trX)9Ar7C>Tny`GqCC+$Xa(|7YBtsv=mG3rP0Ry'
    '<5U?F!7cwQJ>owQUv+A@YVb(+vVeWz)zSIgv0=%;(^%07y29756pQ_f>M{^6tofjooGJZi%JYiEvrstuS$?#qt;<$2y6=vMjNDUe'
    'WXvwMZ1kS`<L7r5grpp*_0!X?a$F)$w8Gj>ksM|}U2sM&!snU``k0O>rermh=?<3b3^_c2V+V%=2xeJu5J|(*Vz_@MpYZovS7sLx'
    'fv-'
    ';(YQbmg1xMa#QzXGVX)t~xNk9H3*)wJTo?$LUiP2h~ONn?qv4&*s?Y8d`Daw_kV5i*SUqRYUj(CPE9m*=gbs1AufitA#@FumK;2t'
    'j!A^l$w3mI6i3iTkD_cYZh!QCi#ziJC7^S5lswa$=_UnB-XcxcOWI2UX_LhWcj@E2&9>s|zXTn-'
    '8+v1bO;tcET;jj_8wWa4EHEh>?gvV+DwPFm3|?!8(}R}AEDphsc09YRav)7}lWw}aiiDyq|t*Z`g9KE?UDs(>!iB<6x-aGru{-'
    'jrz_f(boG&_>?QD&(jpSqMLL*CnUBZsV}FooDA6=ll4`oK&as2n2=f6mm0c=Cg^Mb6Z5jAS>4o5<r6D+G=--u8-'
    'Ig#7Cul*&q&|`mES@u*nF~Eo$D!tWL+UEoiN@J9OopPCC3+xTYKU<|dr^zZBrg?(H`2U7B#}gK?KB{sIOf8vJLGqO<d2YTz4YrV)'
    '3z2xZpxPD7q`>8pjkk`@rn)Q=1AXIdA9G#B`>EL$TFGU4`)-'
    'xqZ6m5YKkm{eX8Y7Wz6aG%t5$xkcC<U5hFbToU9OIP+ou0;wZ=?)zr$Re9T^1olvealSG;ZbgZ)IGx!YD-'
    '73?t04E*}NlXK0PLfqg~OWujC_}SZy2sVo3r8Rm#5@Ot))8>9&ptfod44ainT&a;!xRZS!v{lPiL<0L8&aP%6B!WVbTNDKMegd=T'
    'W$5$)bonmK%|Bl0^oi*8MYk}^X}u8r+;by?<IB5njY!;rkC(rHjn==D7|C4kyW%FsYfXCSq13&`4LZD0GW1yQt&W7((apG6L9-'
    'XO=VsHeS&pFfXUf<soi0N;kyre=XBkV}T2%dX4x2f?ETI@%z0y}vOdc8A;|QdW%eA?s|bhZMxy%mZPrUR7NAYZHU#&gJYz3?cJY='
    'g4QaN;klRvml$-KAFs4q9W5LI-HKwdHFVnas9}gvSwBv6WO*9K2wi$YEh&T3=1LS?O|26Y?(P@*C!W$Rs`JRFL+kKGS}G$wr5Ce&'
    ';(BNgos(@%YHiVX_ih^wyGmK9F!MfzQbY}Y3zB%)*_70&Y{enz^S?ef7irW_s1lGwgd9oBL1_vR!O5OoR~KHV!^j*eHZqU;egPSZ'
    'Sm$Qp0-'
    'XbXYTBCv`<4IC*r`8a9u~{`o5gash~Npd8c_|G>GuXI>Am5&7bYxs>r0^M&;JEWz%m{=8@Uykr8tqHTaTM69;w!^I$A)GNhK|`bj'
    'gq3tEr|eL@FWgYbrNL$7f2*Iss?z6_*JB-EK+s;*pYXu}B1s8%Uh;iD$QE3U-r=duQ85Cln**LBN4Ij0?G1iTl1W-'
    'QI%`0CTnzbV_d;R(QG3d|7o{_U)p#8LXB#uD!I#}h-'
    '@ib_!rUt@%cxrm?Q_I#Y`Yom8zYRWR@8Tc;pzP%xcyg9emBby{(qx9I@TS6jh(jDRnpa^lnr5;XO7}W`%f-'
    '~o)o(Xy^@}^~xB$JNT4;!kbI-e|sPF_+}gfUpC(WT?h^+*-M&BIXC+TwkAB=Gs>XBzW|c&Toxk5Ju*=t)*lDm)Uy6o~#lz4IT3-'
    '}GGaq0<+6+$1O5B@xEPD)&QtUF-pw-'
    '$DX&g}!)g&%fUJpm7fOEkBXEz;#rr@)nuQT?69xbX#%AMGHQ$#n8LC_mwtDU~Xy9{!D*PreVmgv4wZ|`eqF2a;DiV&Zo7Y!%x3_6'
    'Q}k^x2AFpC_gNe1ktVsYPEVlrs>=wPdOH9f{Wt6c)g;dDlI=0?jf<F6h#@Gtqr2HRBphD8PU<l>*zEwNDm*5bfeUajZq101Y4EaW'
    '~X|avRLj!1>W&MVTFieJ`w#8?qGYAbEi7K*Ulc;D4fT_T9D+=JlAP-'
    '#*D;ov|2lxX*F+plWCT!*LyJzA=&x!+HKMQi#JuNAf_n1^n*__mjOvB8~{Hxhr<%n$=PfZs`0D6A4n{<_q+{b?Dr*zmvPO8yxFOf'
    '9QP6LOTs0?()F{RY7j$6cdQ=sb{tbR%iv8()lAs&S??-'
    'rYQ?df_hHBC+VOX*33*h`?!xFzweL5j*oL6U5f{IQQWhO%ap2w2p^2lMMf)W#)ZA!dJ*v0H*zV;oXot`ehgD>HB6MI)H(j&txYBt'
    '|CyPm9W5bzt41QpPa1FFg!V5q!e59gBKKX*}I+dKgdiz#U5fGj~SC76^uqq`-l0NwFq$Ae=vANkGtUxG-93-'
    'Sagql5uK1Ai;(|1rvvS30cIB7K?>7j(^AxO$wcIOz4yTEx~qAsHN)08dppqCa^MWDEiWQE5-'
    '=GJC3!Le4B2Hh{JGSmBVHl4h}j6eS)QU<G>ewPL|xR9x3ug@vRh?B<+colYCFw=uoRWJ~BHwDRhE}Y+M+)Wg$jB{dOrC{_21DBp`'
    '=HuR)NTm*`OR6ZwKv7Lh5XYv*%I>+)X3~g%%Hct-gcm*b$<S`RJ+31nybrEIq8@~Ec5*RFByw>jlR2B;PLb9z<q$3SmYVZ!{?F@x'
    'waliJmHwNnuqwE3K<hWM<fA<aX3?D3jQY|Xe!hvO{^hGLTeY}7K#(=ehJ~LI3eV&ig7z?~Y15Ke?Cww~y_vKPh%m?%jfxQ#tW<_L'
    'JD8+NHVinBKwZVKMDYkVy}<z<b-bL;+}8zy!?X1{J;vp3p~wenEkzS(UjA4H9M^%u^@15hWq}xh<zHhD30;e=(guX#-'
    '`fT%pQgpq<1a)zldHbXDhUk9lkke>o00{jdn!#A%OB(u7A?il#^mJ37Yc}hN0E>23#w}eJ2Dozsx4?%CSP(Vb#xnnnG8M7T8q@&X'
    'Vn{tiNMfZM1w)*81Dn1R)DGX`1C9R2hTLcYL{bhdr`C)nN24jdCrb`<>@PT-G*5T$euf1bF*H7OGp$EVwU}Ir!(l8|Ji^A#aq@M-'
    '_Tgau#MGNl#(5j@M<R{wJ-zUlQz<O)wQeBAGhs^8Hq`915v0(oKkYEFAIuhSymK3Qkf0Ry@$ead}JKTS66{Gei8No%@;5e^VQV8D'
    '}?@BB%NxFI^l_H0A36?vXB*~qs(~~zXVgI2|9;F4`gE4rQhXxc0}c2niEK1DiQ%-'
    'k68jE{`IN^!y1LZE{x?ml$K63beii}egF`+D~w6}(jxQTSK*!)(Eo2jHbB42;1f9IN*&BWahYmC6nifP?vX%sha>FTR)M^<-'
    'Fp=V^1+P&Y?{%C<9FhCzgnLGh5ce$#DT2Z2P!3toO&0#!m6pK`#-'
    'j{mBKA+J14OUI3f|N>eK%}yG%A!+$dzMhRMJ$?HMPU@@^)PnL~j;7dk;S$%<wa^RY4BhFy%0eha-'
    'f!olE2!UnKF1s^Pl3R(#>*aug{uyiaZ%ax?y4+C}6=Y2bh=ULRVTT}r|Y?}IUyOc415M#fjx0FvQp?oq5$%ZwyrJB>y`38p%D_12'
    'V*u)^B&O<=_*!+@XvV=M&REb}Bp+3-'
    'UvT3MQGL5aAF5*T&3^F$*?U&fylRfxrXpEp4{oq$k+6q4#fw`>_zjp4BaI|GGX?>5+c+nVx+^7QwK=$`%HV(g811m7YD^gz*h6!*'
    '=4I6;S(uGp1Y2r(a34}*!2$7utX>%)!FllHj;;;f(_Xj&sAyvpk9oYVD^@Etc5rFi)_wIpOi?ZXeoS~R8nbVlFJ@;@XyyUn9B@Cn'
    '3P^@bVxQdAgSPW{TGPIkz(h%TTE&>cpoz%hm3k<N|3fo*|#BZR6Z`K`<Wf?&%Sr`K6sAf+OLu#y&t*NSz*?q=f<ozXzp2)@ve4pO'
    '3^W`?N^BFQljc=OTBudSUzDzDKS4Q3f$HK+5Mz-'
    'zrz+Ye5Vr?Z@-8<^iTF>vEs#v@-nMzW#T;WJr)<8EoG4KN%^CzZMn|2r*acLP2`)_UM-'
    'ZMDmaP(32s@qUZImEtn^WoHa=Hl@UO}4vuLo-RmHUmf2tCmrD>cs^wiGxAAz#0fe#P9axTP%`uwBYtZR>(bJ+vPk9cWr0ljY<(TS'
    '~!4H9ew9?2;j4VsOU^7O4lwNv>d^_Rx9lSy}+{P$KkWNHF(x;>%9HX&JjAF-'
    'hZ9gIM0pDput$w`V^BZR#*l(P~%y=&Mg3^rl5&`_6@m#(<()4N^y{xQ_d5{qf#m&_Vq{E3csontS@5nIR2VEwV=PWOY4jOMZ-XnD'
    'l@_CqTb3>5<4MlR%%TfMQp3t7cLCYKNDLY%?txnBCXxs(5eL3M!RV?;wPh67ms2p?=^cGRP*dsoGb*3aa3?p9v*Q5gb~5fzK|T=e'
    'tlXcz~mEYaQ&gdmHhfumLg6O?muq72MIuRXg1taF9kQJwaUzE2WX1)<e&D3^%HtXD1~t*@_<|QikosYtVT{iZ2XM>f*;4l^!aZ@D'
    'IAH}%uN0^GU~)6XyZ|CqgOx9*P%&&sx?Ml1!ZFKWjS2wR?mS~`4)Sfj1u)x4X}{Ozg=$uOls=!=HPxoy{)+8LRwsi>>|w@mcJZ<W'
    'p?*6Ydl8hj{LD2;EGMKeLzb!Dd?0R^hrEXxGXoqPNKRNVVbfqj4!&c%@V1|CV+nkaPCH_tMQKkV>7%d{I>XoSv&41+rEhm%<nTD>'
    'PQdI{u+v#U833OZ_}|eqXKQ@dy$bsv(~++PohD2nZKkO?9hITP0n%HZ_v4s`&l*u1Zb$bWl8YS@D_&iepKMITgEvt&5c^pi=Hf`*'
    '6Qe_Al`~UKGd~qZ#`KSg?D+uy!fgFjnvZ8d7SNyeS=TSdPB+kVl&5e`?S7%tESRvLV*ZS^**0rbWfbsaE5(b0GY1NIz2Sw4jd4Y@'
    'pq091Uxn$+RvZ$ur`&glM#?EiAjheAl|lqgp&~|So7+t_goa|JTR_xzKNGUwNa^uE)N9uq$DZS7G7M5KV!`r{i)DGkiTRll*~G@6'
    'Ti|sBb=0Y_kG?{*^ybL;5Zg7DB{<n#>`$fj7$jHp#6pqB!4CNAC^4)^0UhQ3|nN3V{pNfB#{a}a;&?jqA+Y7c9b$@`@kfXiL|1Ek'
    '2C1IrC{u^BxZOuEQq+8R133GVosE-'
    'D+A$(?MI*7A|G?~0iej)$kdw*kMf%>Pa|O;e5Ob|&7d2eO5~|t{Pc*Sr2)yFt4nGzrm4tTXv5Git`N$7fl$mAIV`XNMIEOLk-UU-'
    'fvTgT*iz(FBUN>{O{@q=!;>El^EW_O#f?Qd8jQxl+a*5<1`yNX=LzMWtXT<XKmW_bpPtS)BA@ns<~4dbW}!Spzw$rpes%~@gxtPm'
    '8Wh|4n6XqyPUM>HF1JPQgW&u8kL|Z8N1NIQ*4S9xVpvZAUWnug%J)7XPDrVlf2}?$*)~9kvE-kv9n)iWwy`x*fA{a&Q4YbKW~`~E'
    'mNX6m^U@8oA&p7$m>pZ4@V?H;zogadII(;Bjl>p#%Ypf530Ak=byr@-'
    'z+vI1Bvl*Ld{24JID`Hy$71b@sa7c5nJ0eCUI&1nB?j<DWSh>p()({$AhMSnqnBJIS$@F9uv%o_`{BG7ff#CvmeBO`fo7tV3EDvo'
    '`bO{kaNC-)0yJaNOi~}~imuy^lUjZxvBA-higF910be;6IYERQ`V_flkAkZ-'
    'Y|eG6lXAB|cfS;AoR7Yx@~aHt;CE(i{FV6*)<hfNi;iy?NfJ~?oU73_C=sjaw%rAAAwwOzpvY^+{nJdG&I|T#mICFcINS)dZR*jz'
    '6#g#!P@pQ1l#0dc@pLbDUPxcjQ6DUt0QN)7bBFReUu7g`-es}i!t?98e&P-G0)rvgHfY<xKCWDSR0SfGcuD6Jwkad-'
    '^XK8aQ0DE#{vBa<2emyR2l8E{E!zAJp+ml5n!E*5I>|1IE@9z`2fPe$_1M5mjE7Y-'
    'fM5%E70ZK$vy<4=twJcM0`53d>u;iBE8i!c!tQX=qhDHUK_qT$cv0ns8*)gH4ea+eUrnfLu?|wx)$cHV#30A&&!Gb*-'
    '<XtS=|kmSRa}KWn#&s>w=sW0kwUK-k05`!BxKdzSrxP(P*LWwa|q?6EX{mfv}6%i4`Z@BdGQN;=S^d)b#zW+4s-'
    'CT)G0LXKa!Vy{WH`FPqAt5pAZmqJ(#CHje#$*p+EvkCtFs~%jf&@o;-n3pvN4XmZ*%F&d23xjV3?N{xn-x0@AMg$(t5(j{_-'
    '1ug5di4w!$A7+7(8x79qw-c_B-{l&93mtoIOnuGNIBL?O~?mLUb2L`Q}W#m(RViv}XM)>W4a|Y>}LquwZr71T-'
    'P%oQEby8Uy4nlC0%tchFjvAJFK(Id196EIrw`Zxrk+pgWiegcO>?)tk(E(pBn^TsCkd;OdAWd@g#Gg}A&(y`9>`or!n!?wvgu2g8'
    'BGybn7?eaL{bXbIUDm=xxrlDhwZ$W3@9&CbREb4C-7gaL3VuLW7X5}h#ofTRppfWcZ8bFycrm?23ZDGEy#nJx=C27x=5gkzxB3m-'
    'i`VC<HvN1A%oKpq?4!+{0LqhjHbs+#Wguwa$D*eH$ilwLE9dsSJ@;ih8V`_p4QKdAlJ$@SlX%&*mH3_I2LRQt0Nwyqxxj7j<YK8D'
    'wBSFw#R^4<ud`vTy9tJZ8Jj4<1I=e~AelEk)+gNOnGBKl!W}LjpyPpU8qrRS!`&%<W6ztH(WIO`F0!-'
    '{(_g8!Gy4P~Y)v6EEQ2tg8>CF_SH>8nme5OQu|D(oi5^pq!4izm=oh$G<;)Ug{(wxWAohIGg&w%4@bwg{z{NaKvW=DR9-'
    '2ulj5;EdcR91U>E_&(Fh^XOVmO!Xo&+u8C)GR81Zsg_sM!98|KUfyt@|-'
    'P8TetA(U>wdB{XAt5ZG(k##H~6@eK8wcA%BJSdfn)qR(@6qiXJ?JV>l@p4bTN(@ex>Ng$dxq*Ga1G~FH`LQWh`h#^lhJlW4-w^1-'
    '^OFRt755!-Xs(G08L-'
    '|c|Bmv9+C<Hh2Xdh`uO4iprMPkTfENXMosxcyqE9M7j>Uvsc{mVzW(RPyTT(?Ln#z$vzlZ9bXWis=?DgoIJa_!Q^S-'
    '~6d9LRM=8kFWl1l3)wF{w-'
    'v#FgoQ&>@HSUP|Km>^V~P<j)RhxAtiAzhCcby0zysYti2)PuMC~5d&}$C$TWPsY3~TPl7G$ePXZx3;@H$v%vVWajWjC$T);<AY!l'
    'n?Z#`HtgnG|=ElnPy86kH$n{S_9`e=coFW+8Z#CHnb^5!7+?L?8!)niulI*7|<vf(`Ru$R)HnrYl@ye*%O<+RYG!;eJ$e|j!JPeR'
    '^gGxi+`IUko*<x+=MPb97GmpDHw|RKPNlVsfdmJ(}eo!ixB2|1Q*D!IaddFfl-{tB^pxL0R;ea89y-'
    '%IkrO>hq2dtW1oYTOe^j#JLhU2^>rMR!$i=jV@;LGoC{H}9t*K6es=ApwkxZ)l%D}!GxaLlCk>4q>Rg;EgVxGq9ZSyL(R^Q22dC8'
    'p>={zX|aP|e1j4iVM6!OC&0ManmG(XlNB7KN7a;M2$ld&8*kY0r|tt63|QT)E_iL5&os-'
    'eo||+@#dhik7b?;3lR<D;g|nlc#-YG>q)`CE@v}XS%cemlgNz-lg5^66A;ou6wxy_lgT4wiFZv59)>R?DC;|`Drl;t3znFKn@ucD'
    'zYMY>;Kd9Y~w6MXQK%WXTp#^sE*1fVR+q*5TeSQ3FR7kaq}QENxo%@&?&Q4fQXAx^()S8HNE`wHx!{{MKvA=4j8QMh1*pGI{ynLp'
    'dS|8jZYE`MZokj%Y1{V;y$z>1Y!#QVsB+O&ShhKif`k^3uy=x%69hr3-'
    '2~Di?UoiAPwgrFKqSG@8S*u#9Q90ziGcGbN=ooc*REa#W5EReez}+9EoM@(O5xH>XN=qb$gAt#qC#hBG)9|09tmi-'
    '(>M~ajqv@MoE&p?>(^_Ly#3NJwuEfX8^U$HQx{;>RMUo+>~emkKXoT(HqdnD=<h*9ZT|x`{ky??87r~yMSHnaM@SUVS%j!zCQIU5'
    'GV^Zh<rleeuQ)G8VrWqUnAd^U|Pf`iR$3Y#7dcX{{2DgZ5F<@ED1*`yA{uSJqwhh3`^&zd03;MEU-_hS$w@Uu~nnd5GA_GKE6HOE'
    'lxFl2#w^PyTDHIXDcGs8@0p4<~Yt)lXCMAWM^GCST9?#XXE4nJT%)GT^*uG_f_z!!=f{2%z}1Z&ojd?ae_0;Iz6l{Y))c;RFfFSR'
    'O(a5>Ry}}d={d7MYkinOHzJ1!&u)wW6}SbNV^uBNELlV$AK?xIkv&=bd|^gu3h(^TU9mr%TphNovPEdHlGc(gF?vYgsdab(<KWu*'
    'Vkssos~A2>({S=e+(~Vyrx92+Ceyh*qfuml+}*IN{nRiUANtsx{F(x@AdpYv#kRae~cvV-'
    'D^tSdleMQ7*Ja=;JnhU|E@7Fn$AbV_BX9hU6R=##`JI(grl3DMJRTB?kdd;;16bBJ5XD|X79%+DoUD%%<2M#UQxBWfJ7^)2k9>DR'
    'lOi)XlozO`M68%EtSO(U&x<tF%Z)_4SCxDY2+{w;{~_xpAU)%kcH$HC}HNwPvW)(Dir=jILg`4d}oxdOzE5p2It!53ZZ3LYFdrBU'
    'Kw_#g_(?e$I{ooZ=*b22SZ_AuTdW@Q#W?~w2UFw?UkR*LHQ)6KOf8>4T9Zca7D7*aC71sN=C|mAD<$12HvTL8#J90uzfz+EN1qHX'
    'M9wcsO*GFT!dRB+5t=Hsn^nuV-#kp3qYf#=q_xezz7v{z(9<|JUZ-mJAwn$Q&Uiv=A|+xc3so5_BxlrgIj<yi*!!zCAGAtZU2IRL'
    'bk>z6*MC%b93qMuc!DGosSUdfpn`WrtiyF=JU`V1{Ej&qEFQW@@?|C*1N-'
    '<=DWF6`U7##&X?+rw==yuJpX+6k<r&I^<L;VCDEw8XIkyJR1^Sab4{S3dv+aKUd1iV>Hp_krn^0-M!le#Z4%W{azew7QW>#T=^-'
    'gZou&uFm85XK1%JS8CsolhlXQd7cX5RKr9X>UKfbNu<pbkPkO-~+%iIE`Jf-ukasUz*vXBs`ZsA+}9rTu4IgNM#{YL~1fh;;JCr|'
    '?T+Tj;=X{yZD3Bad_T@K!~Bk$t4t?<`mFDCh_s>y%?J)=(WNKLf*ID)xCWGUKvk3-}q&G5$1-'
    '?xRik|VK;CMp?QKbt}KoIxBZO@mu)PDs<+scMlKedu_6A8?C46Y#FIQAV#JZEe9>qtJvXJH}#4jHSj~OC~Xg(rE!_%o{Tadc`*I5'
    '>6TrFia#~khoHpTx)^LQb-nFPw?xOZVY#0%}xP#P!I8<*Ae&Tgq5^}sOv~wsA)yBH2nl|{!%B0#+gM1sQw&?UU$|FuGm{#pZGbmJ'
    'J&_(TKnjAYUi^#g}qhVvSqmC$RnZwW0$zu)4P&}v?BNEvhK|cEaiNWgyoK^v+W!qOBwd&Z6P|DD<bn7hcseDB!foUqlS*U;LT9$4'
    'cDNlY~<q1j&2b-EsYoAc5`#U%<dVSbD&;w=2KsSb2Rj&4aJ3-'
    '_~Uo&M5r#g7<~kx%{tsf5DGm8Hoi(@hf|hUi6i$y4IdOy?5&Wn?l*5&^K*49rbF^UR4@>;=hT7XF8AuA?q_{eq<7MYn(X|>N>OVA'
    'nFY*KfSDD-<#&2K+?s>AK<3JX0P*-h(et(cijX*LDJ*;yEhhgoO7KCQe>ZKsGXs-1dRQWiNHhE!$@%vyPztOsj=TLruP3eB%H-'
    'U4&+Gb&{AeT~`8cyH@`IFu!nk->b_b5K@s{5$Q;=4-qvq%8Mh*myB<B;N&%fbPAfvQ|I8ei->vyu(S$zRtiN2ED-Fs?)o6AtzLy8'
    'A@Aj9+kgJ6&V<z`lzT<nj%cMr10Mx;~piq10X+aYifHH`x{*>tsOWYT*Z9GeUu!wFm)6!n6eeMUKq`3LR+`#zn{Vi0;V9cBxvpMb'
    'i!7bEp<;2O+4f3@jTCYPikzhT5Z9Z3weRR+<asp;CK?8C3^JlsS<K>VxL@8b~^&Ew*G9%UEzIZD`fAjW)u1j@y=w_BIfr;*cjIus'
    ';636sNxI<RiER9Iw9LJp2CrKMcV#rXWGzr2o4pg_-YT4z>)X-&2V0QWLBaFr-xr=rLonc4?nS8{h~v8PdN*xjFJLfB5~oBYESq}p'
    'AQwOi<Sq#_~4_~L&;96;o6-DJWwY|m-'
    'VIryxw`+!r9261zE<&Qz}@G)e2Zx!i^Py6zAYP(|;>KOh|<ol@WZiZ|~e$@`>X#vsKv>}MTEzT5uk2aQ}*Eq$!UN%gy23r>ek(!J'
    'U_~1O4X-'
    'tHjGZ|)FkaqG=1$1fPrg1JNf~W<b0A25jEm~KCTq`vW09g_yG1eF|IKQ!zwjfr1o?EN&q+NfsP7cb2F%|4{a^#C3vn*P+_EknKtp'
    'Vmr=C>vA2sIqnLoaL?6rgUKGAxrL0Y8e}i@Brp0X9v}Y%g#ZNlQ``CLND~Ytd2SE_DntpOSjTJ>(GLfM+@@%}*x8lrj=cUu+wzJk'
    'giM0)2dSt`DpN3&}pS#fmcjBrBD_4_ZEF>L=ed-cn9l<*fR>s$Fwt=G&zX6>z=DGzEfK&z?9%$Q97ZW!`%Epn0MOE+Y*Zn>lFFPW'
    ')oD=eD{{AH_jG>x*CnXGOqKJYk^#g2r80%CigEr#mMW;xQtOjSN}~+&#eSkj4~ky(ExXR~^4LjLEk;Q6UJ2w8&wjPg{F8kvSNWiR'
    'ZzZ2411$iLz$!LFdydEen%=(oyT>$msE()ZD^w^CDNbVKxydob2wV^R4@OVXcsaywP@D>>;VfwIfprZFrtY^<<8Zh@`%-'
    'e^D;)InG2_9RK+Rke{>L8&Ipe>`l9&;zg%&R%#arT=va@7Oz>kBjUahOv}3!=608m3oew=C+aOPyxy2%$Iw+y<9}U&cD7w}uqfgx'
    'YMIkjvZh4gy`TVG(kq#xk8Sju^I;uRqef^UGkCQHc4#F0lQ-FKNdtV8t@emJD4Z9#BAccwKs6gn1xb-H$bZq9zap-'
    '}!B1|A%(R&hvdESuR6elB+)@fgD(Y>Xyr$x^sB#A-'
    'kGC34x&2?r%A}j5E7go8?lOT>!i#Kn@f(4jWjw?ak1&dMDK)#zNl%vFpwQd#<~P)mbH-'
    'Ohu#zZ&=8tRk1R~@XL~czs79rwU&b4mrF>ym(hN;RbPoVF-Kj$!c^Bgz4)bc(8nhM+=!2_;{db#rPHf9#SR$VoQ!JvDdEcNl?ey#'
    'J)H~q<a0!A0>+5$D>R(1e)SU$H+J=&`iYb7vA7eSrS(n#&nSTXmV1az?*FUE+hqw0QZRJO5^s8k(q<}IIF6o9mzcdh980_5p;Box'
    'bvMk&4cAWAw={X-@RLgA*~TI145Z5Iamm00q>o|2_G-j@L<xP?49tAZ&Jg8KS2m>X49;sX!f79-'
    '1AE=F*UD3i*2tqbiMz+uTu#b&fJPRi9h`OQ|FvZ@$3#xgs9>iM%h;8)}SrS3|n-'
    'jPB+=HpA|=bVDba?7xe;2=iJwEE3i<U}5oxWD+UrRaQ|YpL*~fca*fgy!XMRLvb$eC`i4e3HW8{R$^G6-'
    'D?2DkG|Z*D;0jB^U+#%=%3f;ti<>f0ZkPoq4T-'
    'MEWxu$%3k#%MpkQvT27DuiS%yi&VW31RC6^eYdfRypJX?KHh~SW6ygjiTAW8YHb$e>jF5RZXK-TU!pYn{6MZ^*8Y1fDL&EHs1@Q#'
    'S1YYWY+^o(KWm^YK5(pkv4F-%yHHQFeG=57d%W4Fdi}YTYX`VSrPXmY*QFVI_9i~Jll!5sq1k1>W%V@C-'
    'xu+URnjm30d!m3+3rGnCQIG)0?n>+h*z>EsOU`k4ULo?O0DUsxLeWSYjFJCcAwSf^q1*(q>lpGc$z*h9hEt07xYOyB*x0;nQRDLS'
    'B0`;LAf`V3bQn3zdA<1TSIm&iqa;oCxRLn(S$aFsx-'
    '`n7*(#jQy|f0f;$*KZ}@7T^|@IV2@v=IICr5>je<tV^>m%3YcwG>(&w#V*0#0*<%AAmn>P?VtvnpN!=nR%DVkNpeM&EiBM{_u8pJ'
    '%i%Qgp`0PUj;Q1cofv`Z!}T<&0@QJ^!)6Dn|Ago%UR9Rw<}JS~;kux!z2oml9TbhL=s<=-VydGW(3dV^-'
    '*ox7cy<Uk~uvqz>kCW{Ed`KP%F&TWuTg~zjv8CpbO_#aH4VhV(?gy{$!>M<@d$({PEV#5kK`yeCRXbVFctpwqzZI=td>k<Fff%9E'
    'nJygu*C<*P;*GylUALktFisM<##BnmQwnSa}_-G-e?l_6`$U6z`Ql8-f*pczKknKLnMJq@-'
    '((g`~)p>y&SvPy8b+hAl%6c`Du)Ab^li!&rL&TZe$*8_fD!j(d@RaWT)8vAT!ORcX;bG^<>+$L7r0@C5Hfzk_Ho5x{1D?1X`Ewi-'
    'xyD3+;nU5Cg5o+=GwT0<yF@x|#wUO%09r7ovhK|Jxvy3i?o<d6N@DF%ToAN9LFE1r^?ciiIzDPZ)Tu3BbhMIHNL1F^d*nQH(Y}TO'
    'IYkAw1CX&wnvxSxZi3OeBX96exbA$!ZXL<Y>XlKwRtPfezC$lj4Si<34j6zMF^^0{2%RfLL-'
    '=|zJ~V!38@U3DWd^!qYvcSDBSRwSj$Br%9V#>^3&P)MqTIKYtP*-'
    'Q5}3xG{GX}1RDoTPm3c8Lk0+jWqsYtRVaY!f`&nj?$6BE_jp`@wL$Y>O7Ed)~^UEV7e(ZPe0?s#(a+cvrf>u9P(00g~Y%<Z^*Vs&'
    'v{eTYh<IMv0l6I(YXd5voA!2y14(=e;MoEk<LV9XAW+!dZ%Bs)1Ou_x-p9O`wb-'
    'o{eBQ5+v)r0`YQz?fDKQ=ZNE~MNJ0JrO~PqotaC{^5)K8fIys6oNWZlW8k%1_k00DC5E3a+RP(Aq5T%~}39xL1Sk2340Na?F_28m'
    'pq2<?R>1#c#mo(r~H|!WwFNCfdVN&+c%9R58988%ww`k?jMtA%3K=2K9h_JI*zWOMKQ_Bz;Wj-FNCqXDg6;U0(QY-'
    'V|*~@LwViSXG5M+|7QiHA3vjW5`^CYweH)_=xTcGVt4%LK3oH6x^XB!Kn*|RuIIUW>D}*2e2g?#esMo54npbC0ffmhz_H;B|UB5$'
    'KLAIOG%^QQKY>|N`gwD)CUdpB6T}=UEZ>WAK&E*<gKmHe3}Bb7CK3tN<;>>eygXOMP%IW6VOZTKs-'
    '*{oHtLp9dJkc&@)UPBUU*b&$PCXr3wNx-'
    '<665rzK6pF|xUWN(~L&@(FA6h=b1t!q`q8qtNyp&j8BZ`n*W35ruP*i_XpF%b2O`GKVt7OwZsLcl(7Nd8aH%-'
    'dCf1jq)lE$5AI(jwhb%(Jf15Hlb$b;O2|o$u)`K$q~)>+t<->+R~i*3wc2Sh^z2{<J9n6O|-'
    'utW&$mfC2o+azxj#?Y1e&9JUz_LUBVEp4!?Kl&YKkOv9w`_$A2@hQ~<P!_<eI$d&R1=4&vvFno8~AkSgorGO+ymn!GUoF&isb<2A'
    'EM9$9wkuwot$SSL$fvghgX=<u=U5qQLAHQB2i#q(zfTs!=$)W|av(})B|U<|OsCU|}iuYRK!20GBmMvZRLkEYl(QIC?|*tf0&8>7'
    'a=pLcN@ueu<L(`P-tohRjgyf>JrgWM4-oy^z82+!2U9Ov=)TeEr|Oiq}=-d#L+DjA9^3iX!cCb;ff)zp7y5-'
    'J>*=y^5b_<5a)<K{c;j*4n0{kyZ%?6CF=$NHtr^%jtdn;0g4Bs%UAAV}7b9GjI<u=$Sq=1IJfiZ@=dT7OMG+QJ&_t8LD|6n^Q5eC'
    'mL6<kPWm^MM^el~}W$h878l@;jNUTj0Ze4bG6*3>Vk8RHy9V9F^E4+JsxUNP~6?jf#cb(|}J|0(d7igEPNPbiFqt+_GoU3gKTDBR'
    'N*{t0gEtrx&{;G`g0nfJj}ECdD5XIa}}elUc7SL3>G2G&m8uUH=ZH3ew(NHpCPYE_cVglY2eiF=zKn4UbqC4t2ibYpuZdg;5$EQd'
    'ch(Bunh?Q)8*0uK>}rAw??rnZrxrFC{3s@O-2tnf})+3S7-PyZgj$PZssMOCpbQ-fy2vWEucJ3quz(UO|_q)1{Bc6{z@6#@d4gx`'
    'XPt+%nh*Igw@rL=|8fqnDRVa0Vz|cWx|&QV?s`z9y7v6AL1J_1jw_9*oK&u4>V_+==T~H)B3<wOB7Q$)9wspSAmNf^%z3GcFhq$<'
    '{Bn{$b5+=ENFU(<eg3kc)cM^0CneJZXj>sT!wP`xSpc)~JbG9Nlg3x&59FAtD-k5nZ5BA$|^Y-y+pkj1!u_7_r-y-'
    '9|>a*Wsokv}<ZnV#II^3EerTW^<p|D7W#cnz*#*C;Mg#(hj{amRtuEm;*8eCit$mT(dK0&l3;)2?{-'
    '!Lmx<uK)6lVKfcDtLBPLD=87V{Sz-KXW}CN#B7w%LP#x|T&ADr;+dN6%Fo>ACKQaL9j%Oguh9&%KjiV4f97z%gPu(a|eENl&=k#~'
    '(uvy^Fhfj5%I+V*K^@3)3nYcg1;SA)|sXv8iB;_F(q673wbg9~$SKFzCU#t~!Y6DKaFam2+Yv%TCzxixE9MbqzXEz<OZAIzWV!%D'
    'pJLN8a-|;0cV6|x<TrFT1u?x33$-!h~eB~ghqHuu78+KfXvIA_Mw-pANSq4xh96}=PE!7bzf-'
    'w5JgNQhN7&lObr`58!oj>N)T<!jPwRii98UB(jJqCq7bYN$;mqmr*y!J06bKTT{6MY1)$U;iDHpD9j(`Vh~I5un*n(|uPe)^BHrz'
    'U3}XTaa9Bl5kJ*HbUEs^Kqnx$x#{0;1+`xkafG;438`Es-QIYqmkh@J+8e<xlmnmA<G-wFI2M9J0pqzBl3amTUm-wxyXQLe7t7f-'
    'Y-!C5;`^(6%piI@fp<#Qc=ah`)Pi_!l*T=-'
    '2)SR4&meqhrH@X!YS0vgK@2Daak}m}DinZ|WcRQn`!4sjjQX>t9f;cyBVbwkAtGBu8R?{bG2G%v(8L&tQY<Yp`^t^P*+UJJH_r22'
    '7`m;fxW#fA0~3NU20Oo)B%L_v<fPQRwkBK)(Q;hC@<N?^*2hh*xczQ5!f1l!y&rIbfJ;)vNQPRV8E@`U_5)vxqBH`(_3Fp9^gSJ}'
    'aWtIFYAXNv?NzL9Zw|XQKRJ^8?~*HOYtxL$;Qm*HvS*=VfxXUQKIV9gLkn9pB-R*WnW)WKlPe<v|JaxymrFz;v&3#%#-'
    'FkTG42MaWC(8kJjb|8Of&{6$~m`_g4XAvZJ-'
    'E;2k|uP=h{9eyT9n}l%r(86&rAP(=YfC_eDaERq_#B){)Sy&RJ;W8~csglNLPioR%QYy%Nl9+cCOt#dw5^`d)0a(&2Arryr#U}BH'
    '$QPiHjIenYCDGWz$_O8?<aIc4@Gh=eY@<|2hM?%5Mvfa49OUTu#CPCK!hB7qMI*b)m*uDyXk}59JSOOiIGeGL3u*T5aN2>B#Two+'
    '&o{fNs4F@Rm3hq^Sua#xX$KdWI5qkP1^#M=y9bl4j@W&&#U}LepcN|2Ku+NElmB%?^`)hlqpsb#p;`PneCXv4w&%fGjKd9nHS*^d'
    'd}eeF5LN);C{D;Xf?zU@VX%!#3;T(DPWgG|8jwtM`bCws#)jVyyQ(SI4%gMYljoY=Mfwjda$0VL)If977eSY~>hJHX>qs~9<T_gU'
    'MH9{3A9K8}kX@N(`GaILSIrEawu>;Tm{)bd9o)g-'
    'waNZjL3w1pdo&7%^(LchKI+1ewjR_uan8}J$~ZpR$N}?k1#Pk3{OUA17Ro5}U;%QZYXCoO!e^v_2_Rx4QzJl5@p__qE%y;DCbTUN'
    'BiFK8`?+M_FgwcrzhEg&KVeDfujJ-NXOM?=rUTRQodY&DLD{(>Lic|SZRX~&DFqCD(1Uvwi<x$Oxaw0iUe9Fx;f1|~lL=I~tt#gQ'
    '2ozYfsU~1*r8{{xdZ9=$zf{s}VxbwAVP0-@N?{-?8H1&rD}Y^B5bhc(gxDkHM}?SvOD6v2W4*-'
    '2j1~r*LLeK3R+O+VKo6;rw89w2^Wi=#g6?OD_u62CcRo@v=@ipd+H2Oz>yH_MzA3|ZmadBS(FE&YMXARa$sS;mOB+^THugpsfmJ3'
    'lE`Z)wLXHM%capJaH9Mz`3z<6uSJ-WUGUfTySkgJX`9zR%y86T9BUOPL>=zA2++P7X<?XW+<i#6@+jY|H7KL}DA`QDn*%*tM)`46'
    'H^i?@=7S9wmpO1gF%U0<n8-'
    'uUS=hx*_ZKtkQbmvf67{oB?_64|^bUW=(S$_5)O)fF7cT;mBaWOWM)6l|UClEAz5*;V|#)K#0`8G=>`E5V$x;jd;n|yjY&;>XDLf'
    'JkaG6MnBUn6?A37GmqyfSsoOArp=JPFdZnKdBLWrs6pPH4gr3K{RTLSxmE3!r41D{^3_N?RfK8x;_Rz6M{mKu2fvPeUKO8&Z*VP;'
    '}Zo_kP;YFk$Km<)cdSWf%geCvp;c9T2Gw1<eeNTHw{W><odsEnw09J3-'
    '9knbygCF~Yq5ZBMUqbtE{2EzOg5*y5*%fCs8GXiQUauEd|O%yo>DUr__+DDX2MFKH*uxy~+kvGt_zeKi4y7?wtYL4I4H6bC_8Jfa'
    'NTsfn2YokFqRQbzP+E{CUZJItj#)Ns;sCuC8T#Cm!bVjqb4PoKGUL`ElW|HQQ)j&G2{OBw02uFtpnUF7wJE7q0@T}Om@D(w!9hxY'
    'Ofjz(Wcf+fb3%a86|(>}D-'
    '{8vlP846AIY6Fhlap;+|%52@aW2sfg_3SZ?AzB;EH0Uj0VzQx(mK)`bPcLU;#?vS<3?T<4<A;NNk5#+na+osuuS?ZmtJZ|CuxIg$'
    'Txet2&Lsk|gM>YNV|_288s~~+kSD&0h^t&yx7k}UST@0RpP^}Q(4gt`0fG5SE%$CzA#cO8RpCuM?g5v8<>Bl}tBv+Y&@q5ix94sT'
    'yzCv(P7UOj5(|@1PR&Qiv{q8)xC>^=d2}}~QXHBT<4yL6=8*;rRxbTFBmtp?{9O}iFc8d1LZI%(s@jcmrjlRnX~J3NwF@6UG)*}Q'
    'YT;v$VnZGau2zg-SY`T%Nur|HizE8LDZAj!Rxy9X*FXyUy+9s)QOkR);;7i`A&fS%ZVGINm!hfbKnX42<6??#RF$f^(EMaWs=2OB'
    'Fu5b$eO*p#3)~aJVf6=@*{oJWYuFgg_<6$g6@t9GKgclYpW=ZE^`@7Y)qU$)=(wx=WvOxON><eS1rR~-'
    '>N_#lU0G4P$q+r~zc&@QkpH(R`wVa%(cI#VO=vh877RTswmKIWx>dfQ9DEz<I?#N6<CT~k^MUjjfc+_YNPn+qEWYmQ{<fN7)u{S#'
    '(C1DTRubfvYDk3nlz9$lO_A?@3UD4IJ-zU)w(Z0upUW6K(ba3f=BD9eK(HDa-'
    '@dOm7;?&HfU^fJR**VSvU#(r(Jv0`PztVf{W!9;s!6|1PpZ9E<-'
    'JxYJKf)X@_JR#smY(go($=Hr6d>YpOYSmlOw$c=yM0SCBS97gvJRZ>vFV5c>0~C#cerK=r&B`{Nm4a|CTPQ9KzF$Psj5(j$(4u_o'
    'a;MchypPc>jn~*>U>e-4f<oBKFlsC$`9zIOx=e1@0R<BNY|zs1jZPb7Ji9xf32ATgEVV8OALxbLi%3ko6&-'
    'Xd=W6nsOAx6LGMZE#PL8$%-'
    'e44u<^TBZO=8YxkEr!Y?Lsqr`Tqelc^cD@wy!aPF03Pq^pIpiC)+6b94*nHHAt>l;aafQrEW#c^VAA0r?Kgw>SpeuU;;!Ho>8R)>'
    '<sNH+XFGhqAs;e-'
    'w8(S4kqKoBPUS6Ef9(N&Aad5e~pYmb8BA^<2iC%BqXAHKh8!o4GZkvEB&K|JyQiX@!YHuw~40A&|e?%F#;9alCoE?;o>CQKfDb8&'
    '!iko7F!jV-|-KG?f@p+B3e(^fmixFGbBZ2)^Y?>wyS5a3X3L1PH-'
    '!8ppXy=2(ov_PTV5tEYI!Aa1b?+(%!NR{?ff{}ayK^DgicGKvNCatAY$H%9zL=HHB1WXAZuw7SQUWPVxI&~_kHc#tEYM9duc48)g'
    '1BCW}o*0wPS$ax6WigDeSL_VRO^uM!0_RJj(p8=ZM}oRO*FmH7<j++ZM7vYL$|2)G$y~!4TN38JoVakEt=N^u#moSDMdDn%Bt9Y&'
    'acukrJv92aJRr;N7UJV?-'
    'WDA}rKI!LBv$@$UQGrXz<PRKb?+>C@hJ<8d&mcU95d12e*e?Jz6wc^J=Su3y0dbJS_A=w5Wog8<I`dO-'
    'a(K%!HhQrY=G3Wd6}ckN;aDT^v8Y#pNF%C?C4mF9zN9F>ZRD(fJG}7a7gH+nUr<0=F7>BapqSUpg-40L8o$I?M-'
    'Fd6H4n#&RyXwJs*m$6wn2p+8^NcWHPRI1NV-'
    '3R}j`CJ70`7&?_4osrlpb;GMRI^LEVZZf^^2_HOZLy1F87+Fn#6C)>&H(@3C>NpvC42RVBm)3T;FCJPdNak05&3?vHb(F~dYSJCk'
    'rE3!ziYbp%&)^3%DaA+`spz6^iAnG;GNU5p$6|z_yWCB|8*5Srx^Dij!YWic&qd$53^Hbobpinicy!d7?2elbF_#z5wx>q8~guf^'
    '30(^Sm6B?8<WKTBz2dZ&8R0{;yU2qVlL+T!Dc!0l(D0~gjHhN^)U?*)_q!5_XLl{U7O3kc3eB(AQQ~`BHw?-'
    'ZB92rzLJPxMLRHc8K<A>NrkiBxr^$aA&QTTL_39o)Vi$V4KvTrqhi0JocCxk|6q%SNT42@BznJd8US_&mCKHJJp2})K3zGtG8fd$'
    '+p_FDt2jC~DYv~SJdtXUhGWTdC^znLr|_4%_%4_#*qxe;OUmXj^jNloyq@msXli_3y{`Vmr7vj2tDAKX@MYNBvgONVF1;a#__%o1'
    'ki6EU#jBtf@}UQ}A#)_TF6Qbf%;s&PaSjlRDb>!!0{U}^zYh`-'
    '%{3FEz7CW4<^>si@SoX8>u0dssK8kx{!jGr{*r<uPyW=IqL+@txV;DnWz4&;dnl+i1}?mgxwn{UNGRP;Mv$t3SbbVs84{31}anlh'
    'bRW2uPQhzCU?wOM0D&wVTt`$s@QzZ256I$$3qB<NO|Uhf+bO5J!^9((^RZe7>FP#bPxal9M88|3f6H~?7q0@wdJ6mZ?a`gkELQ*u'
    '}GPIN<_Zl0^AQPm?1J+gi-n5C;~%XM+IFo4ftqGdAm(oGp=rc-&#n!KkXQV4d2HYOw8D*RgW$;R+?-h`@xnb^=SjCqz{71dF+h-'
    'rT?c6LyG=Ud?s5IO@*>rYB}yZmS{T6IbQQSA_-AcNiL{8xt3X*2A(x!2ZC3Hyc!4+nmv3k?tgEaHP4t_~1t>e$Rd3jj>7w;2)RuK'
    '&8h?Kh5y)HyGgYAQB^p`8I=h!}Y#1%?ulaz07`RZPZm1ZcIAzVBumyA6R{q+APehH{^}wc}y@%Axej?q3}m1oy7MAnEHE!NkxPfr'
    'tKE!YnE;XPbZc{gIpmB)nK$a?l545t=L47V8}au!=u5YZ@6_i`}uGTH(BTp*Gx;fseD`lauCjW0Ykeh%)j86P%q#MYV6Arc#C8Z+'
    '<bj1RI9drL9H;<J`gj;Q`W7_#g+Uy9g%$LY^<(#DWB8d!hGiXB5mSM;192Ve9zdVn58Cc+9~l*HLVBVg2JcwKo=DHq-UO-'
    'D*tWWz8amx9}5yPm<=wiGKv7Oa=<8vLIIrT;}$i3RTWP4<2&7B}7KMDc9NMfS{$2l&TVj(%83*2JeBY;Mz6pC7^c+j$!K&lbD0Aw'
    'A?dhSeJ-ujR{K(1u(s4jdvbo-w}-3d(`GM=5;2RdS|WNd-'
    'I*~`2V#ZXe5+>;FX3OMCS%yft^Mk9bXlo?c74vx6v(blIcgzFnMpEG?C597yml$OfmKpVW4Z0RWX%e1@0RcGi?ZrRwx)UFf}130@'
    'yy5@JhQr3feH6+(k_F7jc1G&5m}xF$-9LPHx-'
    '7aDEv=bK=z)Q5r7Kjw7fePS)ek(sFl41tfPifyGT)peJer4<;%X&`s0Ex+6~k0|)=rO}1SsL(?E!qwKfV#wNYV8;>x?dC2)VVLl7'
    'k8u~5?Gl8K`*t;2SOTRNAp6==jglz2KEyj4DY@;aYmVA8FquCH5aRuHQOHG38cQMs=dWmRW;#cW>O_e{I_l2&@ZExuyV30n>YXD!'
    'Ho|@H82HoCBDl!_s+%=d0!lU>0Yt0KD^t<43@w{_@`#HjGD3?Pb(R@Dqh4j8>k<7deHYfb5h*nJ5ww}l28*E=T6~}*V?r(z=V_2?'
    'i#J_4p*u8EGgWaP?DLB|Lt01Sp7B<@NAW(KzlIn(ghR8F67uq+t^+4r0Lic)n9L{nbGh&e76$yu+6rgb_qedCle4&iqh|>AimiY)'
    '3qgL4cf=pQl%_<dvjYr;A84y?^PVm0iCd64%eHC3-g6|`8Pd&A`u--5c!S_68-'
    '%wUEzx$SN<gV*xOOk@av5t;hx=668Xv_%rKIb<$za+fE6UCo`f9><(D4NKNxkN23La&Y91!|gVIXVf?myXetsk7=e7V@-'
    '{mcm;f>v2u&O1exq=pn-@gDs^$zmi>ToHGR9@<o9la-ue?w&ivJ61{7H?QO_fMOl>H8&N*hnD%WbPpA(!{|owc+!v`;xB@ZRD=b9'
    '<6`&&2QzvEAt?oOJRnd+q1v2$m<=hldSvn)0SKnOP^z=4`>bz-rfxraJs~sV3Ff@Z?=?%ozl_4o&E;+h?exowOju_K*VKjec86K3'
    '3fujE?ZfSY%A$xkllDc4t&!mRiNPH<NPI4^l2?Y7_aI(jmyYK5teF<va0dGWCy;W3^nn%t3$43Wvb_#)(k5p2ps6f>oBLH?Kxd0t'
    '>Mp)9M4?w9W1{Dx43Bq~@k;K?IakJG)XRw5K(Pv%_-)Bw)%=L$g+gW0-'
    'YIG+;xr*EFFnpm3LTK~zB;WXSbm1Ufq)A7j`6ioiWRE>jcp9I1-'
    'EVZTNnWDX^4jZkglF^>e(FjNgQDCN5!9n)3j5!EPyIQBjW!(6edp_$zmuoGury9if7g=LgWMVPLkU_hrI4c*V6u`0TAc}G<+Pr#f'
    'iR%drf3!oJH3IVuLzI$LM^;@R}>oE%U?7Xf*g=IObjAN8XaA<cM^<Ix2|C;UIW2lRh7JvaX+cvJv7zs#EQw2bJ38QZOi2{yb<+IY'
    'c(|GCjPd~R>1Z-'
    'bYit7;S{7!v<OhrSRO8mkH9sUkTC)N79H$<gOgriaUxn*j~8MlskMZTS2Ty;Z2x8OQ`WawuqTfut)h2ogqvlnJyKo$#JEGP0`!>+'
    'c(xOxo7hgD!g1u-=L7u}E4}+;eQPmnB(cb}R(ja$Lj_W;t{^Ifh5KOS#9dhR?;6-'
    'zIzXNWNew2O!7i^Pjq%oNdspkZrMKRGkNaHvWyQIkPN=h=IoG{~Lxuu_LW&=P_HuA+5nDB3hxN5TUJO<Ju;@&NOUY5cF6YuDK*xZ'
    'DbrpD<OV1fR_Z3Ob#r5_g&GJ@yhYvIZLO@t~o7=<CNaZI_57oPZENrF)ir}1XwUI3PVwa*LMBaKqQWvNOL68-'
    'xsENk%FELcq*M5dT7ydCN<5aDT_v$;wXe(zuD`0S`(h|klxB9T)|DWetxW=l0Ezx^p>ODy$a|%M~ZSC-VHFT+_0#Wj8w9AX?z*S5'
    '}H1e@R{PG8u>X>D-'
    'uxN5o8>n;u#QNB{CZUJat14h$S5%{G6yjrV4#WSrcl1tb$=JfrO90hSt}2xbn+g<7>mVBb>85J{w%3kyc`7a>7e&X+*u+S=qTf7o'
    'Ii_AF^WP7i;67M%qu$6lJ-5z(bI%Knpiyu{-U{O#KOn7r9291W-'
    'W1Hn^GVwfsU}72*IrjGFygO5Ze?(q*WBV7IhN;IxNYfnpex1M&m1G}t!P*c`eerz^==Jd#k=bQFCGYWpP|!WQUKN7QsdYB`{OrL2'
    '~*5Y;eN!_$~`93t%pI>RiS;pwMbE6%IFGBhUHeRcCK_=-'
    '1jyUV=KQC1!o9%PN6yky+zO<G&;a7gZ6njV+qj&eOVmk%Rv&CXOre68B#}tdMFpDhZsn*QHZzvrSp$ztnx~SskZI3?AneQ8++xLz'
    'e$iTdr^SnTRD@*fA@#KA#6qhCLEmCeN^;?Gje^C;8z@=%t+azc01&;N<hNd;LWhvDj_PLOXVE+GNL%LQMy#20Llh;*Wzem@MsN3M'
    '1P^tZ<~vk9!p~ps+KG|i9HeD&%gQY0i}yY=pXOmswQJ?Dd5rDj#{K*lw$ZU$w&arXxZkt!LSL8+cPt%#8B?JujXotWqn8|BYv*Lc'
    'l0fA4KETxY2|b1p(^)?8Ht0>LTsd>czi?ph$6HEekv_fDT}75cGr<5W?dqltYK@qxCWysnsS-'
    '~+nksfI+^x@X8mwagOOWScZUcWrlSA2ruoJ<@#q%hXq=Vw?97jD2>X5Rr041sec(wC-EFgBF*2bP)g(GR^poCSK}qv>u)?pa{8V>'
    'Z5h;mI4bQG$kEZZ7QAY7PMUUvXRiNmC77%Z}GJb;4$yThJ-'
    'l0FRLFY@>>7PRUzgqxw_=2C#sKAO@I_Dj!LFdRqE^swTO`KK190QJmQBwKIJ5-6sHXI2s>`n$g-'
    'pvvdPh#88&LGrI?8G3_j4N>p#-'
    'Aj^_TFQ@A`$SinD>u_ZII~^^Q;P^p00VF8Ysu>1e(>$QSgO%+UrDIgG0{E!xVh0PL?J^nvIJnO#4jOBT`GtZMlOexQ!g4l?i?-'
    'mjk+|O91U~C`$cqpxUie)yhfrhSnym9dRZ%3XAAy?^Hq>0c2v(_pt-'
    'j$l@%i*Q@=~=#F!;Rl(Z|nv_jhT44v%dL0AB{LbvY?tLt*9SJ2ok|!^yLfbI;6_c&g7QLUVsN5Q|cRbm))Lk@1nudsR2IK^?f^}z'
    'lXADBGwKxiL)Gg734yOY4$<r?Bfiw23$hw!O^nAzn#}sTcl;U|&E64UhJDfPkVsJ*{IF|iFWa~>u1*ohIH^hb?>u_CnVDNb{@K>8'
    'f+N%Ypx}8Xzg++Lk02=ny%-yZQ8Mq)6I@9Q9stYDat}IQ#F}DG<vZke7sq0IWiBstivWihDPz$}muIP)-'
    '9lr76X1E3?honRtqT*`gcO2IPOmX6V9$hS*LPqPEfia1YaZr*_iqJ)7V3LB2%UX)c8&v7RZNfyY^&&Y3vKas2$?@iwq$2ap4OZ0n'
    '*j`Pm!S_V|969#t%V2JR?XESEnLQG|MoEwhD7)#kx{8tbqG`MpKg!-'
    '$pzPk%2MObB|F27DIEvRUavOPRdx4A!Do$Hm(ay;0p;e*cZ5!bN;YwvxOYs?Pn{bm;+B0_)fd6tey6}UdFEMrY9xud68n)oZz54U'
    '$0GGUjJ9z73`rle+crs^3Z(s9EQmtYx`Lbj4A>8d6X$9o7ku26#(m-'
    ')w=oLALkMEN0ybaUT;sla1T1F5oi9`et;?RWA+O#N~KI$g=EqbTSNdzSz%~4O2=5r;(rhdL4F`_48<6rxF9sK*4v-'
    'Tt)N7s)EexTYTu1_NY#L&1W1%b?#7BGg7y2^?m%BODgdo`b%!Di)V0krde_^ieWWq6^zLu3Q_bid1QIYnVJE+_+urumobl634Jp+'
    'yJz0FBzugJc)gRXb0GHZ1$kF=;f9hb>IDxB$#G9s}W($6xl*t}~?`2ONc`)8yQ!TeuAFhKH>xy6@2pHy)hb@skpl{1gua!<)!V{P'
    'my3Jq@w&9aWXovR=${awNY0^*5*X6=~X3#y!A`kr6G;QONOsLwD^r0^U515hUWk2S*hwuUC72GO7c{OHQvC{?2DgP(r?{`stc4>$'
    'IU0cVn56fiXz0ak_T#Pj;~WnlcF&cRBln&q3+%HO~x(A#49;?HT<^p?Wf;Q0V;`hn4X)5NwtR$hh92t}@+R=xFp7kupt3p}4J6b('
    '{0;0`_`uQO3G032e)hkjK0uv<*tK@p3KQeW@|LUS&@3D_Q{zE=`HcIl(c@sRoqeMc36X_TYZmoPr2c{)chbTIman_3^WK;QW877m'
    '(eFcZ%a&G$~gZF{WUo23dG-H6$VY6ri;-L&Ux9Sjv|N=#od{xLwj98_u3%-~CH~$nbRVT6g&<99XI2N`g;Qr}J~8`myg4mV$I-'
    '&jZR-Ul#dz6TA=pt3u{r)!$z13HLFIAGF%iA*yq8sLX{|!k#C+481B>dp5@6c{H1S4`;mdaIK$)?KW-'
    'k#e0+>{}sjxU=xxfW$<z(Cgy{~QO1qaafxOv&B>iMrjyMJhAe)GkrlgtO`LF=!BhnxGLA5m>&u=dQghVP&_m?}DC|x2#?aM&wq`!'
    '7vxZOjQ@3)ASOHpz5J2Brg89Il7k#1E>hG`9(wv6YpH$xN@C}pH?hR%IrnBo#Vlj_k`8>63>^Ow;E+R!ZNnj)@YSI;Rhk>7T)P*z'
    'kYyrfAv|Oe!Z_zK`N;(C(lmPZM0vemvWjN}A*o#}pStVA=S~;ktNe@Pa?>k}!{<dwSI7Tc@=Dh-'
    '|<tpGacY0`p2T+SLERAyki&~V~-|zh9Xs(5Ad!r@k>?SiSHaEeP58d@OVwahvn{J>_u8pf}L0B-pGc10-BMP?CT4-'
    '!zdJ<P61%1N7&YQ}B1EsII)lPC<xo)K(@cXtdF>hwSLT@?TO-u~jZM^`AGT|^QRy{5msws_Zq@l`PG-'
    '*G<$sF$9DP%BgOnYu6Wu*>c&3`DosK)>SiMbYJoFwJ;zO*9APh@iFc@_f~1zR>TDi2+PwShc1RkCX<u~Nw$O|M~xg7IwbrBT4qAr'
    '?y)3P5gj$p<E6vcUU3$b~i^ziHZlM0!#`;(6Bc1OIbtKINelkD<kg%mxzz<!4p}Awsoj(Ks9o+)sV(Ple<KX0p%9jJ`fem!&wG*r'
    'Y#9)efP2=#7|WKX=XCToKqmICl-'
    '$n*6n)5Y9rp{LM>2W1l$Q1=FnMbS28T4+oeLY}+~V0{j|Kk?l>G#md?HO@j5Sd4(jMu)hK?cg-+Y(K$;JYdLzRdMST-'
    '2PYo)^i6T0In+QiBiu$1{lFOT8wedIeDscgX!Gzs$lmDSbAtgY0?}Rkw@Fge+A)R9-'
    '|lpPqtM)T!KGcJ?Ja~By{PHl*AG>SjFtq<7w}!|08{T?+topgnClab8(XIRtwVSn&}jWA!gd4HTNh_12%EE+P=P7g-'
    '1xRxYq$j<e0#g($3Jf!)+#Ev2U$fp>pF`up;J5~#?z2&V_cX&oRMiUiuSyRB1q2`U^fvowO3stJ)L@<^`y&EhTxsUsE$pKS0OpZ^'
    'lGKtxv1f|talb61+UlwEs$52DX)@t#1^B>h8U+M^|)&ANIvFNFhoR1evasWE_l*n+#96(8vY>I7N~{97@)WCx?}I0&Kx?mNoc##9'
    'U%f(1}&pRSK{evhGUEqoZG02H<X3SXw^*Rx!K-'
    'wJoO=T=Ca%w1X!0qScci$vvwI=RYupgV+KcQTswM>fx{&7GNt`IFKy)dqU(g`>xY0eODN*W!gS02^iDu&j}8`4(*!(~=GAdjad#w'
    ';O!I4W6(r!OFy23n8)0ykFLeoktPv1@YDkw?3qfd$lL+TT(%sRronwJ3<F``VvFeEK_b=1oV4tg8M{Vwv+ppZ1o97s~1|&XOqgq{'
    '0G`!&|y>8*?1mPY>SiOx0gDX??olK5KjMK27FmWWGhdd}sNe;NcK#Af4Zi5~Loj0UD#%KC7-H%2`8AU#`bl-|oMV&2-'
    'fUx0AfaMCKk}K=Orrzmk$2LQkhtL!JYu)vbDz2Sni5>g6LSRuK1&ZJ}r#8KXaKWZEuJYLNWnh-xK-IZrs}pc#P9KW|Z80=wRbV~='
    'C?Va&#7Crw6qOr?titc<QIUq{oBXN$UO4_%-F9BLr^|;MS4TD^63vol%_)SS{(t4;cc1i*A+i=LXJqnX>(cD=zTMw5w-'
    '0+(eM1Eca<f(5uRn&4k}5aF9WCHMIk1q+f++b$=h&TR-F_R6=$`TBU2Hzm#W~x<8Z0(W-'
    'eO`VcbRCF;iVI0bnoD34_Zp#2iAQ)TQ1nvp8dFMYVj#O9s0Jo;X<l<@qhp|+TRkyis3NvH&LNnYLh(l5u-'
    '~qto_1<KucnI<HaH+i8vBQozz8o<e`v!w;;xl2GQ$y<6n*+#rQ(c^X~@EL57UFjC{lfoNpHW$rzHIsc_9i15XjOhHs8#OVQ7h&AC'
    'pjWzK1bJw#GvJbJpY6NekUM|=cQjyu^%_ykCxOThaH7}udmy7S2a7`OGvULpc`X;8lR+G6HsZu`@a`<ohl9Fs$Qx0BW^W?HvvI_E'
    '`|E~`J^*MxAlzNiF%?vs)_P;Sh=h8?C=8#r6WB3DPK7sKHm@c|zg@teDQTtub8bb0wCZB`fIejhom=72#>c4{fzO#_^*1u%WXWp3'
    'OTNcIW8qC88i3PhEoE^6;sIf8^h-=OC_QjX<MCZa4G6e-r!owMTH+F7D(X_f?+;}J9HJM-Ar@*g68VZiCfL#Y`>X>NMy-gRVbR0;'
    'i3G~jF^!F0K1+Q51I^K&NWpU56!Bl^_g+AR7c#f-'
    '|zhLy`g#EqnSXdk`_L=_H48qdmDnTSScY32|VB%baETyjqurmNMn?v67|7tpV2u{HsaLu#cDe@)U%OP;leN!D3j(3Y$=f<IhkXS{'
    'uep<q3&(1r=IK~}w{_v3#3@U&WP1C`EEwJ&ApC7rlRdmPN(u#lRl25{lg94VqOh*n#sErSnTuciPkr5VrYD||bl+=zQnxO-s_m2;'
    '$0h(=593aTL&HnRDFe`9V88-#4Gv-819DlPcDD$QmV8tpstD+5o?JE&6lko}k}uo1IR*Zt=1NOVMadx_w5gFToTk66177>&-'
    '*AEfp=qy4=gnY{8K@pJpLkCQ$IzvO83v=Fr&JK{odMHT)0G}~#XalOyvI|~@46qwaN;<FJKRS_K8xDmQ6ub+>}0E*|+@ph*D>0&#'
    '}>WtHR9}p!y8l}@29Fwa~U^|97+B^q)U%VSu49LlX@c(*LE1T;O=CN<3o@WN9oP^1&CrmpLNG5hiE+kVwbxlH?yOAZ6xeNQ+Iz1L'
    ';s(Nx)E#WDx+qg<RR+v;#LOIp8q@bHNRYg^0hh}pGt>pI+$EbuNpi`0<UPu2k^J4dyg!f*YK=t@Qb9`=Tep`1TdW)&#%F~0eZt$n'
    '@3`iwdg6sT&Fu84{$_`W-_s_Cuj~e#Z#)WE=Z>aTQ6<bZo<2x@)@P{sDM63)$f`tosUA@=`I-'
    'WnpDJ3ZwbgvspR5{TMH=9n78`u<d^bn;1RGdI>3x~lNC{E1AkhaFaYvN=J_aa{A?;Q<g<#(A9pmAE3S{4D_9EeZ}(?{uvZaFHeIU'
    'jyN&uAmU$cpaUFZ0xHt~WVYyxN)QO_UgmRdsSAW8T0tuZP0!xxm>n8obykL-'
    '7KoE=Zu{uw#IQi+V7OrV!9OH)E48Dk!mAU~TzISW3IU5lcbqx;*~f!F{l;4N?l21n94-+%z#=%*UuCTzw7{$Q8nd+k-'
    'WP6@cUgbO+O&S)Q*Xq>gwxbRTn!$V@5t0isOBUD-kg6IW5{81K7aQNiR6O=qD0H~TVq8b)A}E3AukBVzrOYaJizcUX(~@lu7efiN'
    'IWy{j%UH>7fN*rrRH_6Ovs&wIEq&z5q>J$Tyg>^qN3q{wl>!f~TBpiHfRjv9#)dziiX0FgrbXIaKsa91RC=QwB;V$)H)-'
    '@dPJjP33DruQlzKCn%&;mjggmy3)fo}i8ym6TDQ6iGvfRd==y^koqnuw4@m#Z#*<s)L_QWC;wL_35VY27_Iqj=5F5*!&E7+2Ci-C'
    'p4Air-'
    'U)>N#^Lwz=r_J*i|WU*SWsJPY+^!xzFa)lCrN4PvA{Hh7`0hwEZb0*=u~`Yi8{Wf<Nz?ONIyKH!}rvPp;S?Tgi;>km4>uwD^f(nw'
    'vZKnGxKX4JM*U2xl_z4ibeKg1A5nvg%s0yaH63F1Sl*9!F_LM&#^=S4?-'
    'k@%MZ)(fs<oZJDxipX7#w&8+*fP&t}a!hy})PfM)vJd!N)ibO5|r;pu=o#x@-4c**>G^Vs}*I8zqulgtGQ=eF?1UCM76-'
    'Ps0a9|B;5Q_XJ9~m=tC?vBzwcOIGDPg6t7<dMkkL3!8>1q9NnTtx&&@Rwipq%*Vz9jVO(?Aui3XRMEf}T}MWy7f_K70Z1Cs_@0b0'
    '9Lsn~W9m*y|ktSkMI7Bm3)^&mqsn3co7uHZqe%xC%Bbre!C<LO=jf`}iE>`*!|2`5gP`GpAUlL;Sr<YGJavnrKFLVTc)j$FNu31{'
    'nsI{LzHNW@m-'
    'm9@z6NL7y`$bL<SY_MB`v2H^D)z1BdaL3z#2!cS{6i0)oy3PHT$leyOWq4e>PS9>=we^Bv040a<suiGN4urD{S*iQ=jma_eUr`y9'
    'A>qgDVi4)!f8j^hEK-'
    '54v|26Daq3F_QVmCQtUX`&x>ErV+f(#20OBVaTw=VRJb+Bgxan<hsNHg)STa~Y?;tlY!0H*@Y17!*Q8Aqcj-QRM+!Gm=OR<i3IOp'
    'AGXVi%19Z;@Bzndkt+3?sr({HI&)R?uhaN-M5&PsQY%;7o2=f62b1%?`CQOTAiJNH-'
    '~zy5i|$XhiE52vmr|9~SFV(6Sf;$;@V?6lOcX<5cL9=nH6K0JADRCyZ~m+XxDMyW!1jFQvTjfH)F8Ml}2Q5v`~4!7~re(vZ#V(l9'
    'Rqh4dm$4~D|vHYSfjU#2kid{4Nzw><SW+mlgV_?0a@@O_g`Tzsn2bJGV@+UlE_p8jl*sw>))VQQiU$ZyVm>EFk2vp}-'
    '*q;`6D+~%bK3MYoc#@-;s;5$$E^J&SYL=wZPRq}25_EVQcuc~V=(_O+>UOt|+vMt>C-'
    'I*m!@1zip{M~2p_ek3eUNfUeX5Tx2Dx63@|JGZ-gi;q`qF6-(%u_+-'
    'P*Oi{uWvU`6N_;v#>F&*5r^=de`129$in?%v%XAtBSY*)m=&b8|NAxsG&opKFQAAsG`>PZUfv-'
    '5h*qd^0<>QlQ|Oj_OjDLN=7*u73GjQi8$-!^zCa306pP6BL$M8C<hsV(GcR9oHRU*(-'
    '+6F*bwC|iQIV;G6u<8NQ#BhdOiGE1&4hRgjv_^E{g_k;OhmFe-2nY<bBLp!DUo-7qc`VgVO9)ciE53aDGu28ky>Am=q-'
    'e}bpnD4j*O$ry7WKSU)U=vEp>rHc%{zm%XW%)y&R#@?$^qnTcvVC+dYq*I2E$)4OR^P$@@W$wHF%x%uJ(i?j0;jHW2)g1MM?oA-F'
    'qv9oZ@mM!!O0=~+XA#)-'
    '8LTW}CNjDNEltSAs0)`Y8BkpSn|7l=@^G!yvo>Mn{D!lilOFT{@z6WmOHr;Oi3D@O>t2`Gjvd@KBBvJRd@?6mS4E&fGSF{YQP8+R'
    '|u;Sfi_RkM4Y56$G+7$Vzw(d`n5)ev{tz+Cuv!aRK9RG&BMz$Inm3Hm)dWGMTD4Efh2i`t)}izwDxrAKOZpTi3&*HBV<+_i6+86i'
    'jd&pENd#GNY;&#1_YOO~C5`;;ZkY%yrxP-f%Wlc+aW{}?+5(`G|mSGvy=o$zPUf*-'
    'dcr0&^6zrkOuDrw+uB^jI4m_A|%5f&IR%k~I&otmFIK*F3GEc+b)>2(D$I9tOZ7u#nbP&6v0!!yqC6gaK=$jN}F&V4amZRRa-'
    'znS1~Rq-PAH)0~mmRoDDG*kzX_Z-iOUY&%~PkZp>F~@5^nt5S#gci-wa5JC2L6)siNt_mMYc-'
    '+b*`!R#n#m0WZ)B)Qotq1Hh@biWwlb6G-m*U>5BAp^LBd$D(Y2P>`{xhL)lEAKaMNQCv8-'
    'mqEAyIWV|4r9Lc~foyZA}i`Xx<KjOZiNdCGS5+7Ii;w?7!@G$68D|Av4n0rKnwjSB!97P~tm7NlD#B>HGe+5Kg;EJ#qO4Y6np$7P'
    ')p<)dB^#=UQ9Ww<J1QJ%HB9E7YTk&RJ9F=n3&yVa6L-'
    'TKjP4CGN6*`;VP8rJFh4sJvzk)QACErsB~l2#LTWox2ybrE`#3Kef#To#@1nqRU3LLd&;&y&+_&+mnE^AWa2uY6aCgfStf0<9oa8'
    'ls=zH!SN_%^c*`Dt}L+eTq%j8Yo6$rV%X8xM-'
    '9PC9A_w+(SnS1Sj#=Q)(WAmDF(Mw`8jbt_Yz1G^fz!jiFlU?w=Y^<A^Ndp7mNK?{|seRVP9y{hk@Cl5X9~X990Ajn4P?CC0}Qa=J'
    'oH+IAvll3ek?gNctO=V4aI#1fQ=Gx!mHoSR<<@aM<0$(jl^dk2D+XX@?`AcDF%FCe^=9baIc?qFarpy{2xeW<C#?UmuDc2Y?phY@'
    'elmX+AVx?B{I)HG{qzp_(vq@#!4xwt{h%?PEz3(-'
    'FduH2G|y2Bf*r&GU<Z8^c<41FuCbv~Q%oho+JnM!>dMewWs>4UB*^ga$esqddC`IE9|wv+bSzL0|p+6NW%Y6f<#H8qW}Ec%x3Bg7'
    '590`5Li<Jao07@@Ce`5B@A2FvQp+gux2yYscF`?MeVKMO-'
    '?rb6JnasJhmye(~v?kW$91{WwJbXs(D!%si6X2T1)ViE88MjiDKZYAfx!Ycu!-'
    'lWHT)(EaY|7Jn>>72WiE>=gsg&6jwl#CX*EN|E2JsY_wIebpk1XgJDzV-2v^q;L-4n+#ggU#qgiWXd}K;nFX({v?*X-'
    '^{w+HWyjDtj^Nq`U}gxybu*p<+Ffl!u}9wR(kqjyYiD*<mqfwXjrls@?CN-'
    'O2myrecU*Bg=2eNNSGUpW3rWM;F!f5S2$F@Va;u_Z}B~=uo|Cp8^zVialgkdV{fi=OZJNKIkp}K!k`RdlJ0{7uM<4o*@6c^4O%9m'
    'p<@QQmJ~xJQ6`A_a0$<?1p~-Iga}N5d}Sm*f%R}y5Lz5a(PBtVZf#3tBn-kIcwuLiGim~U--'
    'C(YeVW***?){uh-M2B)V2^H103Dq<5c-k0aNeJ2ek6%SA9G_ff&`C0P3x#wmd_AP-7Gs-Gk%f&Sa69o84**R2K506WC!I<pJmKH9'
    'xCi+Rmw+K?J?f1&TaR%WMb46+<$gLDwIyC~W72#G4BF<x*J)IcZjzCDC)-'
    '#V;vw2UB@TXG<LYil{^n%@q0O|qE&n7FANq!2g3W6i}0a!alhLGWCw$J^qCgy<h`yV%F31MLf#JK{G~=}rwi8upgHqn0|)78i9ny'
    '!Ep|C5uY!&fltbzwgVA{!ih88gnS#Nopgel({O?YF7t(Mjk^vtQIoeT*gv^WgDImxNX4rh;NhSZq<j=Nm&!+68eaxN$0FZ=G2ETW'
    'l^gL2a?E|;@VwByY|bx$I`&aU*zHFpB}yqbpgoG-'
    '7rm`|7aoI0PS4do{8CcICkvJWO7@U0*Sn$wifknDug*ai|Krj+!g}_7;S~z81VRoVr38W^x*+k1ebF<@dmM=L=pUX3Dd*AxQ(EyF'
    'YU$3f0QkCq34?;i(l)B*)~F+zDx_l4>ox2sztCctWogl=&C_Feg&%9BOs=r@;$+XCH+T?mOX%c4O-'
    'nLhf=%DY$$hH)l>nQJN;BnZ-8n5(P~d051oOt^66Y}d9wX)Z-ae<X8Op27J|uAvVzYs>uZ5r-'
    '5H{Bd<&#=VZyDaV{Cn!WOMBgzqqarqoPO)O{#fr=r&yF2zLxPk;DSsn6UaGcrI!$=xBo<T=S{a@1d%y#4y~1xQVJ~2IgDkgvw#lP'
    'zby8!d>ju!9brTKLVp0Vw=#`$v~@@16D&$4H>3lIIspzUgjPjV8ps<)P32*MdmQ^T#SlAU`{)U;U!_0@Z<QaU*vx=-'
    'kMJZVPI!iiVUt8j@hA_ZrZEACJ`mfasKe}WBEhw%H+fdg1*T!b5_Ykz=?Q-hJ%COJ$4!XTzRu<uOJSfv8L-'
    'GlDAw9n0^?&_@+Ci7SM>9@MvhSAFWAPOdU&KI*awHpX8gmUp(N}YB6A3Bys09H)1esw5Mf3Z?Ia@3Ke*l&yB4Y)k^!Ojs@1X4fCr'
    'm6WfY;nQdGHO0>BB&nyJ}Qy?zn(5dbDC1Atx?tDs?k#Lf3S>-'
    '@&ta_bw2RDPi%$7$LnwIw@A;p+i1WCy}RvsDpaC>y9Mx9BTNtwDkI<32$gW$-'
    'N=DJlJAMLQ3j`Pq8yucYxD$9!95rN%Q4dQ}M>gQB>j9O%$VQA((g^a<ObQ1(vlLG~3oULoHVyYwatSxATJ(CMcg`(Se_2<l~!ly4'
    'b#)*n9jHWhOUQey5j?R$L{IN@xXEkhKW-OHw*uF|9aNw2}r&N*ajp<sZ-'
    'G#~LmmVr;#|ALB;<96ZYu?<mdj}9220`z#CSDa`VRui1;vxL=Ezsd5Z=At~<&@WIr|B#aEk!fKo?FkjdlJBbBud0=P7NINWDy$~d'
    '<QSr=!2lQ19}Z;Cceb*bc+QJ@C?Ki=jADqJ4P94gj;_rrPu*lHc7q@Pu}9-'
    'ktzA~oae?$Y=`~O6_>HJ7b?OoMRLV8C9%S_+0(RmU=M1={|9h~FTNvtnetYyKMt2jB%%s)B$I1bvWdR+G2HOtR|pPyqur>>5u~!&'
    '*1^_0NH3hntRJl>+ZFE0LsUkk-'
    'O>PJ&pu~@6Jfb4Y2i36#cF1PDRW%iUSa_QY~;Y`t@$S?{s$y)oo!L+X(I(m#+c7h?5mVzoC{Civ3lYm+Zm+<P!F@oQE2&Yv6ZbcU'
    '5WlB#?{8hv{W`n>?o=g?;bTTX5Hb>otn6F!)X|Al88z5UJYvJlOlAFqv^&o#;%UD@GXSi7b@C?5m&}6Pl{lwN41KzzstZUb=KXxE'
    '4u(3V^ttE315df&jQwq!Nl@vm<R07^Qr}^9}N<m8cz>&KFp!Ey-'
    'S$ltx2TMw*Z;r#Ii}m3|ne$Nx)*S%*yFwbNFeh?=kZu9Ojr)DQbjt+zSUQRROHlii^gBF=0+MCmyPnc7m0`=TRfQUX{MRh`B#0Tr'
    'a=gcS|D#LJxFzq&^u2c%M-!@<7$dFSM#|2V8}@caz9-'
    '$=3yy9D_~h@43<oRGE@n8ETBdRE@37&?KWq!Ax=Itl|)JoBk0!H}m7c=F|<<>J~8iV%h(+{?GyPuD#U4W-'
    'ij%nL7H$CoJSbZJrPOCoJb+{8-'
    'j?d}FOf99xGS*Wnp37H*y?(q2dI^gVVVcM{hzcD71pDjGG@ojo*QBcn8HKQFp91qJ?=nmvHL8JJqc!%V$)vSequa?zQvXQvKi#Ic'
    '?i!&V7|I%o{OM<QYm?`CSWDo*dJ-1q?Pq(ybMU}&61m*00kWD9v0w)-jeHNe+Te$cKXV~@mT{G2<~Y-'
    '*N}b2MVw0q{S+=_~yhhPFa;s}dxPE6*MR?vy58{Il#$vQ;K=)NRaNPY>d<YydMFquns^bByK9nvPr@?};6IQHAlpyW3pTxA@~=*@'
    'W5|UhD>U<G&_xrU&0*s(szUHr=8=bHi7lV7W?p*+Fe{nk@eY6vMP0Ih;R3J@4y0#-EWccr_#HFM-liG)5=~(d@>Rg-'
    '(Y(gEaxy<E89|$fN<w3uGgiOvyUecQxWq8iqZqzG0TgO;VC2&oJ9FqUr}cNO3w;tf;p~cJ8=xC)glfcyx%ft?V_I%0U+R7~>~_YL'
    '!TQ%6lc2l?c<ui}x%7tvWw(Zx)FR)ZvKf1XWyC@>F5c<dwdR*(8NDYpN%EfaPIpS6q`NX`jFN7i6o`ac%7N8uRy@`x^ew?lfM-qL'
    'il0z@j<P$u$R#*=4xlrh_2%tv+dEbTVheHJEe7KN1&l3S+_;VD0KF5^76<JlgCjy8xAe_ZJ@LOUpAeExk>nw1+0(F7EC2KWJVmb8'
    'p@psu{0d++;o9X=@g~1YiO*6pi#oRGe_-KldMAnH&YS0Urwol6l^4*P)C!`_Q5%@7?Cy!`7})sRTG+b|R5eh<bAeU7|lwRS&acc{'
    '+OkczdZZ9{X}}4e+1b%{TdbFy>~GHHJ7JT1yAXFti_mf_;JK-FTtiwQOd*ofABa=gQ{jXfn`VElIhd&H_}aKxm9TEu)3205UNlBE'
    '&<@t@>U+L*~@^_zBk?$n+*)gw@6-'
    'N~1K0a{#Z;bwPCm4pPaxR$#~x<QsZ>y318MyZTj#>3#{Z#*L}>8n&FD<v}>c$%iT2&t`8e{+br1x)saf4Ju)`11W#1T!EdrS1aaB'
    '^hMtwWx!Nq(U{dO!<)Lz@}0tOkK3{B0#6H+i<A-'
    '@o>4*W;h&R;!^y7;7+urKEBrTR0{j<by<mpHKvJ#ATJ9N6v%>%JoMvg!o{=IGjg8}iRVuk03h=6hb3c2vorWP)EP7rztV0y*RJp$'
    'u>Nq&EwkppGH~>7srQc`%l2A_6pg{$ee3_P-'
    'P$oCp{7FsNM$oEqZ4kUSkY?TqAd8ff!l>Y^P~k44kYjP{mev0Zm~3#@56|M7orwKhXJdp7k<K9&j)F#WkKnb0+!yjkeY+k=;Gq6w'
    '64UxW#dsl3@~Kwdae=7Wl`fha0hYhB6)PeQTEjE!H~Ch(hS!r2C%&H(&4#6<A|#&u)Ilp#j_^8@Ul_*O?a(%$zd8XYlUg7kUo)J!'
    's{%3%Q(KfVyu7Cl3&zs#D@vc7pxzK9+5^vS`i<J^c9AGG^3D<60!!0Uv!ZrA7S4dNVPdPJ0bGk%jABblBb`kc;ZQ~42$qcb0pJ3&'
    'rn0J^{-'
    'U{yrCID2ioJp+DE%EiNNyRHrU+W=c1T55pcn?|G*#x8PL<WhED`H_Uj|i!>OYAS*XrZ%43#eiJ(B$;NT`3Mld+;69f7|ak|w9ztp'
    'diYb5``(tae+v4zphJ@P}A)H^hs7AKO*GJ3K)0aa=zGO4X5VW&E&HfFEmL;6|%S$z+=yK5_Y2`SuS^J<p_vfZ`LD!1;+&48dbYK>'
    'q*O(;#!Rlyry;Ow;okGBNE2DjoF^y-Z~2dnEdz%;?SA|IC(_ptMd~-'
    'HS2v)>0&3Yo|#J2N2QZXh#P(E$BOkP`x%cH~b(c8adZsNu2Nr(;sLTsK@BBOL*(n?|;r<7^oT*0NHJmDr1%uhX)v{{7b0i{hH1L{'
    '?mBYch`&7FS`NRLdN-kK9lCKO5%Hn9x?4`Eb=fhA@f_$h@xn(;|7hVnkQ}f>#c9sws#sTx+6e0MQD<Xuo2#00v!)*sbF`Y#QAJ}W'
    '1xo4L8q*XbT!$>7f={~$VogLSNd6QdqX~eHc<k!t69B@#f+&uaSKM&vcz;6qI|}mZ=w*ry2FIZhk<&!024a?*SQaR6|(r<4=0Cug'
    'PcGyuvR^43Hana7r%GxyK=0}H8G-'
    'cQdqJ(XOHa(A+JT|GM*!I(5FQMHiXDoU{3WbkaClDw+8)aJn(qhImb6d*V2M=Pbcu!gAKwq9NY=JF$cPqLZw?}iF}Y_!_BIBkg(U'
    'yRB#!Rd9p_?)`=8V>w$S5zvON;yPn)^1oKJzw2?-??O^^zm-YxI(Q)iHvVjmpolnzv=|-'
    'YKD<D_4CXV9a&KgBBMUORMHnZjwd8&1x8{+~3PU)PoOW<C`0XqYd7MgsQmvblmku*3oZ!X(;`eK*v0K4&yd+?LQw`?IU?g>O|5Xk'
    'tQYNgn`v-'
    '=w`F4#B#RxbWJqLRVFuHLbl6upJp8>LnyZ6SxNHn2r1fHcnp%4tiYKvyYTzXrx^dK>%U@^@ZXz5dqAL+Rv6+tQSToe^#>KBXuijz'
    'u;s)}PiAx}!GIor=6Gw}$cOy-U9RG=`wlFe`H(%DP$KNyH-hh??^faC9C^@ZCV|q=;aQN$P)kpGSI9iM;^5u5LihXReW+4%}S9{('
    'D1RNZgC<$2v%Z{DZddgB1cTpZ^TeO9^FgnWx~XYSgf6@X|d~siXEH_w&t+60}rN4<@^ehQNK<7v8!YWadG52S@t*fC=v6(YZvJug'
    'h!){SRLzlbK_g$z)e`F8Rb$5#2D5U~{lqh78rDZm|KfIvrVF#)p59QUC3Wa4^=d)Z}WwyUjN5qi=QabLhOE0^21LFSMHQnL@CBh`'
    'U4w=U~+0`>mBNn6UPm!e!<a5$Ypya$KpEuJEKHMYboPTuD7`_m>eg3P>~W198+;gagd*zgS;g<Hbg`=$zWa4MVJS02(D<>LJz3s*'
    'p}HC#Lj&O2*f<%)dd8mBJZ?^c_Gq)vv_wld-'
    's^z}V+*z8%5_C_q{~aA2To#h;RFXYnDgFx4_(7Tx?h&b|()L^LX&9Bq^7c0QPP`<7ym%(1bir!_IRN;7NQf^Qzfcc4_VUpd`r(s>'
    'jIZp*oPN*)k+-'
    'RvBb=2~R*@ES_fIdLJV6~yMG<9KhDyFyII8fG}~BWSL`(#L`Rs)y8g#SdfkvoePRJe>)n4k15+mQ(9*n4M*E*f3Col8YeHkkd>&w'
    'jIY#O{Hkfc9;qBsV9=b<HQJNZcJ0jb2Zyd9KhB^r(k`^6a^qcn^X`7zN3;VHqfJe(T#p?N}ggH`aL^pnCuNc6X-'
    'gH=YxHa7@I(vNe_%vl@4{PL*#O^sKxPcgTQr_mBzSH(Qt}!@Ml=BYck0yBs%+8o#{}&YrKm}ZLY>656Ce0eyPZJUv5{`uFQ@I6y*'
    '!CR@XQ;FA1#6iCf4M&|%v2f$?;iFn0IO)&;s=8({J|0KrypX1(S<i~rc{=`lQ=XJb@=ST*2E(eP!@9>;QKBj&T8%tAV7<5olRq(y'
    'SA{!k*D44F^ZI&mBaIyP%2nIC@Y{<*o0SY_=ttNUIA`KkFm4>6p4E)K9c!Ag8{yoq>1i+v4e!7!Nd5E?||Q~0khJvHz)*a7EjlFW'
    '^bBn8HN4V48~$WB~<6p3f37*%AkBH=#dj&K)iIGRJV6j-AOmABgnj{@Axf0F!RBT9hV`HV-'
    ')lZulpEK#&%j#V3son9x5p{yu~Nr%5~gE5A^COahzF8x^7@2jj`2rAlr{=18}A4=Jf4&O=_`4{nt#riv#O_*9BOn-Zq55-'
    '#aXi;3Qv5&}HlMBXTV29|S!3#f=h?yQ2WItJ&m@}G-4t;G@hKoEd!0c=2z-kJN>RXNU@LC~GLDttgeay-'
    'D5PXzG6qq=jP|Br1D(^JBqXo*Y&wy4Rp7eNd#>c*UJ_E5}v372efHw;FG<ILv|HXk+6XeUfoh<8rC`!uKh#HR>qbTHZjy7wO*%`U'
    '~La0>hDsh!x+Zo`z1AKeczIh!|L?>G+m_L5Dvu^HcPflu92=1s}nvI**$4gJJWt(em5PgA5`WZ{JmU+<Sn9_oz0MZz~u*W%>7IxA'
    '^?v$oeu0Rn2-1k~2rmI{(Bd)*G)w!4*zRooOLVeIABb~vSRS-'
    '=B)=ahJpi4|q?7%=mRxzqqdZ$kCcn%J9JEIVkK%x*Q6hbJLe+dVtEGakq<1}T7mdjfkwj|9S8n<t8Jihdn{#x1JUN8Po)PYg`VV#'
    '*$ZimeLCQf+?JGtRry%t_^B+v+S$>{Wknvy+zKq1KvUkObr*oe6mu2zprPE-6&`sEL`T+2NBL(Y%i-'
    'xGVX(aD3unNq>g*4RX~?1L$-'
    'mU6*xhc`0WC1ZS4=)K&yaE`FATSai|#+kLeIiW<$Hk{C`i?&gtP6cf7CCo3=v%lr6SH<p17)02Q&c$x+@*bMsG%9BAF3~d-'
    'WIk1si0_<Ba&nPIr|thWK&ON~0!h=tiJH!zoNh7gS`uoAgrpVjRw0@F@%ktS&Y)2$g8Z+(3ofP~Dk9YENSz-RuzZjBrNdpCl!A%X'
    '%bGz}QAmMfbY@dGLfZ#N3j>-'
    'ukn!#In@@DY4wMgT2GVnmp*`@APglp2P#nMrIx~vvDjfz4ncswb_t<(ZN8yf08qIyICtnHP_6%2)_P@iNQd+q+e{b1uik8<qy5WA'
    'n^I%ntvvW{S=`KbQ1RzwGqwx>fnWfI>hwu^rcI`V4R-chNvLEHD(1kOt{6Lj!9NUY8F`j`-'
    'hi9HwI{n@9tRgLKd*0Y9Qg@$sscr<~P8#9Nx;U}YsE>a5lev=l1&6nvd#Pk|6~ZULWmCwtK$MoeduJVO9PauELx$n;qIGq#nhgc<'
    'Ig$}CpaL(o`f~VeH(p58t_~@1Hv+DXuk^c)s1)?Xaw_Vql<I}$z`C~?4m}*b$idwIhb6bQ-'
    ';V5P=%mLa2yu)|ZhTIzm3c9Pr_(70BA2r(NMl9L+<%b6F(bJ!1MTj@ek7y|gepcU1_6|G(h>t%Ze$Uz3D@6dM>QG>24^{pf9lcQj'
    'pRiFOagWH*K!<m#fHBcZ8(rjs>1Dp*1dmS`~sRH;@|eb;9BEaCwRGa6uHN#nzASDI-F{aLvIA2=X(tsCEBfq2(%}i3uG=-'
    '(r5f^z8ITAWcOsMoA_jIuG!#?&ZXE?t+0Gc#!xjMU*qHD-'
    '+jlOO?2G__6#{|!EoH7qi(y4ZRlfZKtsl^3vQ=qhA?`*GSUf)A#p%6lD)omPT(z@A!md=a546PsvlXii0R)Ge4T=PmRz!bTd~bHr'
    'a?ETJ-Hjx0=pz!>?BROYdCNP#v7m?f@B59f1Rh;!rRy0*9vuaEJTV%;O@xIHe+#p12HfhD!L#OXgi1PP}lIr>U7gZV9p}WVs0Mqq'
    't0wlIS?_^>V91`N|0n}P=Ms|ZJ?h#i{iCmq+a9H+}CMWHKrz(FN)DNaXsjt3W-'
    'Bl#NtIII3O<U_Cvfl#PSsya3!Q6_nF;ZjGYjFg9huYR-qGpezQU>`zY_Q2ez<ig1g#(r>D1t{Wh&istEISkd)P8kSTLN)Sf&4&rz'
    'UBAW1T86mQX{&|aM*f>trL|Hnf1xoDXj+dNGi`ZgU8n1m~0hm9`i6v|amspRO%=ac0@DOBxtz{fRlaqfS^kb@*5=o{sI{g1WT$(3'
    'JwH`N>SKZWw-l$Tq*+D5vq<n<jS#Tu$q+0=4U7zL3|L_$9W`bTWlYD5I@s-'
    '&1(8lJc{82zjWid=O(9;{A&y$&D8uYy;<WtylVkgziu``|M{@D+^VfD~W64E=ubKQ3F<JKV7*D^QYY51fn=BjW%;$b5KOU|O#HJ+'
    'LVJ0*lSXWg>s?*pB}&DZneS2A_o(lV>zfuG7;7nH6Boi$QP;_4@^1M|GCww=@*Lw*!1wMrz33fEFz5ZOn3xQ>lySY2#BtszBSdIC'
    '+5P$NCbf-__idfJ!t~GgYk-PQfK5Ld%=8vTZyK=vpsWFZ(dPVTaZR(J^h;+KG)Bzswc7J!0Mw^!{)m!s_C1e-'
    'U2t!5<u%&cjOaTRpzQeqIQKi&D+Y#ep2mue!}Geh0t2!j?<PsX(Bb^lcw9j0+rk4A!xH+Y^|pedLzWg#ha}TEEPze#Pf14+iT?!M'
    'k9|1iA{Q!)eQ}cj+GyMs(t;n%cC0OBj!XLbb-'
    'g;|nF+p8^E%l;s&HQ)zEtB9n(rw#8I|yhF%uPsCw)_R{!5JHj<)n{7*aL{r=fSD*(IAkmP13lnx@Q|toNn3FC3t58#IdPo>h3ppE'
    'VOxk5Tny98&=KIT?j@X`JxJ2%b$G6LgoD!#VgNjdxWuu4*ofo{hzGJ^qhDE$g)|FB5RNpTi-'
    '*x0=7C+jvn1aV=Sn^Q)l!IFK$Tv&KGXH2Y@j-EoRawGO^+EdC9E;pyIkqo;1_eLUh%cH|yLMa7kY|#w6HYmFvGTd}!s-'
    'x3x}vTTvi!bVQaK20mgU`X-'
    'goAWve^4yEX|nf^{TtW=X?798X~>omn>TE=AvisO*}+>4d8h?eZj;IOjl=nFQR}1jU%pYSs!CUHpEd8&47Ox-{+g@4d^-'
    'KQvLqtI;RMn6rmaT{h&uY@qaZ;7_=IbJWR=a4&MUox>S(YDlYY?3ttxaxIFp%|G=Z;Ng7~VOy--g?^fMk$#JHZ>r@Vn-gMzD9w8f'
    '=N2kwsuQXiLPAAjrvW{>c9uPVEh+hIDzzD5bn%hF~-'
    '5W5igFx7Ff5asEJ>^Fu%wA8Vj?Xj+3qeBlSnWwn=@IKf29hNi@b#I;=7K+tflKEYI%&ssJ{qHw1P`u4o>jP6c)ps}-'
    'P#TgT+jhp;0Rv#sp4+JDi|<=L6O)U+z~wHisAuXit@_b+h2awdh<RMQ(?l1o$}U6s<nVKJNKzsh`oR&CprSkd?T1hIJP@IeJH6HQ'
    'OmfWQk(5t6h#}tN@YeV*T=}8<TmvQ-jV=1#JVzN!o26)06+Je+(@PP0)dtbeGH~Xw*hBOZnz{MmSgGVn;lt`G8gnS`j(0Pd55%9A'
    'V<PrB;SHa0IKPJS-~<kax7-8cJleOLPTk2|4436<sER>#ma95TvYgBmfxB4+@-'
    'Y>xt4YLU;)}yrDgopufl_&e<!HZv;xM?NH|J;0Z%){GPCoG?v0#7tfpJNfdJ-'
    '398R%bu(t5`X|x8r@1HgWnMEvcA=)jGf%5uoI83Kr4X@i*7&I=K!Jni^pYXL*7Ww%1)S@1=$(XSdM4O3+4!oSYIIGOLYijRenMm<'
    'n7QfvQP=asOtm^Yn!Cn0jG|C@uL7)vemg=1Xh%bgFMgKDjbeH8y2@$1J5tcdsW1Pz~`fxP>J$qSD4wLp)RC!K!GwvK9D$Wl))M%V'
    'u<~FN@1ka5!dD7)!HSBPDZLjcbVhj$l0H7m9H&9kXS+)H=07cki;ow#NymAy53x2cPR|)Fq2K(X;XZJ2B)SS@KI=wFpWm}^ZXBiQ'
    'xPsOHKA<XnH*1(Z5*}FNHJik6+4~+CQm#dV`c9{2*_EMUZ;lplWBRO_(ehhI*wVG>)!mtzUHJbh<P6~AopeV0T{@eFg!}*`?%af}'
    'QI<)UhmrCmlCPl<GYiT}bYRgXu&v!vRe|a{(*>TY<f<pCda(3ODX!^h;>a0m=X3~hi?=U%s`|;z+QGXKzTds^<i|jO(55It}JyFw'
    'qGRe@hCS}*ygg9k{{WQs&41%4aE|L`vNhAk3^$L$Hc&=P(3dWHGrH}hjE(8dF(_NF2Y}dRqpU4}MC@>R8>?Ej$U>FO>(#3gl7t1{'
    'DT|PVkrYWp=hNR8&jzhsl`6Yccv&7)~JA_w>a%o}**$4HX-lLJH^zNVC#+|KQVH>%`&OtkqP7W9_%`XJ0wr(5%Qafrmk}72A-'
    '07$@<G?%y?wVJBrRM*M?cNm#QG5|?2$wuq7A;Hom%wUPjQ%abuh$FHOeoiUe@FjuRO(chY4$135<45$$2Z($jX7q#TBK`QK*y_)i'
    'v?wA-%vVgTUZb#Q!wK>$@qxN^04EOgV0KC80!)WZY6Kh&-'
    '>=zA9G*2P?f4SgQScrcvhxKZAK0OcO{8S4$jevgw)gd9{!AgQ+fU(MGrubsM8r7_OXH;@D-'
    'R=05ML@5A4)hU*~x9_7#XQmOdj_bj_dm^ZLe>Ty_Y~WSsa%(qT(B;Ma`HXLm1m)b?(&5Y-'
    'jgAn8E$W68{hec`v5jt0;x_<3S70^`H-'
    'vD7AUN)SdBk|`lF$YYa1py%YnTZgO@O|);S;uh=(cHL@}BJlZ*j;LV1vO!v@%!%!8uimr9Nvtp6F0(^3VlcLgkm~aB8)pIasI!c&'
    'avKJFgRbqpPDNfO9Uj>b07Kk)ct@l^raE+N1qv8AO06!~UZJn4Zs5=}NiSJL9-'
    'rQtK_ifPOt?@e4%Zk`X>NPlXI{~run?2@V!t;DguFVkt<8x|?Rcz%{8!^WCf}~MD}bg;lu$TXOVK|@v;?>|?*e@5txHsVkae+O0R'
    'UyDGWg%uP@3d!Vd#1JrQ^|UY1xZt3icoWFz>7u>O3ckCPABMHQK=RnLR&X|JH{byVjkUI2AWn`mHL0up(*U|IYFEgA36*GBn27Y6'
    '**N^XjcJfQ#RlmG)yqX=E;R1n-O&u^nk%Xy^*ZWQGsU@v5`JxRi_XEc9Wb-'
    '=`gefFc6Z+5MSQ8odrGfuva|ny?L7!&TAx{2RW_UtJiEpa9>mO#Si=vUgeQlwat(IagQnlq%Ij1Jm!W!7#NOonS4Zug7sHwLLPRW'
    'aB23%juY*oF9j@K6ct~0e5945#wDXK)SeH(WHvq7`TX{*D0HU;`dO)R!2+<TX;c%y@z<WjF#iXyGF~C9EGv{{ts2Vrt1VCBLwX`9'
    '|65AXI~wE!TWdf+jeEB(p!WRpNA@&TK%8Ctor{`1Y<1}cB<VRIdq>&Egop1tkQm|IG8Yk(5GLsk$0*Q+9|i5c190*I)4Ph+ELjwr'
    '@U-kc^PXCXdL_K^qk0nim8FdhHYUAsys<edUH5L26r~(lw!#1pB2=5zY5bGb=L`BZFCnUwLpC$NP~0y95w^|0F1-'
    'blPzW9KwjyfKn}vg%36oqrKbSUe@SvyWgU=on2gfvr+=--'
    'xFJ%mU3jbNbzjSH2v489;EZhNw+*xTFh89NKRR^t>F$H<!HuJ=g<w2MY3O8Ph$*-'
    '7?7gGfNLW}sMv<8LNDS74!q*m>D1Wq`V}{<Ub}`mWD!~}3uOt$eP}zOg$&pl^#PSI{e|bnHn(J6Pd4|=r1De`4t}+ivKI8QbV_U?'
    '-gn)L;Z<=mUl&7e3`ZPwIK7}zujDb1r+Yz39CV*_TnOkMhmz=C&DAyKUe={8K5s6lg6+;+NQTgnQ%m09Un~k2$FV9Ufw>siauh#`'
    'DD`v&9`wACK54v-j!ihJETC&iYdTqlf9ZBaYb7a7j>9%RtbhPEC^d{0|S#ZoZYV)-'
    '8H7geJr!I?Q*<$$Sf0=YRo8<IdP+HN0w31{yGe9EK-zWM=$xri_V@qanoZ>@3zB{??R1sUX(2O=_KyAy3_Oo2DhGEfAOJI&^4_8^'
    '#QjDWqBEW;E538BUSk|BatPHOJ?A~r_osXdiXSL{QSk7_r{HPv4au-)cxF?HR`c1<b2-'
    'i0TvWqkyrOuV+={M5Vj4lrg4pe=B?*~ESE95*u+u*JtYV9scA&_>i>i8wk9F|11X%K+fnp0CU-'
    '3hq(+kJ4E4(tlZMZjw|*@%>wF*5=PMY=A>)#o4^_c)-'
    'T9pls{3w2HJs`s8It3<#3ncLW<sUh_SR#%Dkc5<_PGbrAE?{Ch@=ap&~y5h<nRhN1Rhp@CWFhCS(D81S?s+`K~+H#cwWQO4-'
    'et3pdzHlys*>xHT?~!}>%6`C`%pBQ&H9Dj2)cZcuTg%LCg&(5|V3T~RBEe<@_^feCyWgu_0xg&a|B@>lfh8^8N5sIE(Q=jwY&rQ;'
    '@m(mkAhP^ijuAWHGB}HXp10G2nR3|2_kHuaT2WQ!$asjJBwPP<n1NxqJS3kbK~Zl9-$E;5+ndR>kY5+t&Gj;j^G6X-'
    'tz0B^d1LYMNbN0sXk0os6u&;h0t@w-$D@C0u)++<7UU^O-S>u));q(*&c-'
    'd5w3(1)CXeZhaEunZe0v@%Pmn>QNpZ^rZ%)8DEQodZnZFHmkgQi5WyUml$kFD7O;q$}LujH8)bDZux!6xvjhV-Nz_Q62Cc%61tKh'
    '_pj8!E#MX863JY0Yps6UM4FZH6sb^!);?sJNYGD!>X8Ew~`(tmKEw%y@AUVo=GjLCFi*5ELmBfIWGwJka%o5lrVxPs7vrzOeo&op'
    'BmuIflZrtn!VsIbwGB=<mAxvaL&jq5<N0`^)Ul5vhcejVw$tQx(TFeZr?&kC*kyBp@ON_?X#3AX>Ub@3i>=El*uanHV4i?AAGW-'
    '{-'
    'LJ)P%3;zC{gky;uFh#sN=C;wsDN3an*F|C`K5E~Wd+2}Rt8ag&*YxTREqK{nKVggZl$?%=z<s>*X{z=^5Loj0TowdclJEP?pfR}='
    '&FJemlJmT>{*hMA-qUia-2CHn^D$xh($0)HW(uVI3Fh7ya>Mky8>cI}&xpfY>Nyk6W%zMYu|K6q&urTWc;br~LV4!Pv+Xc0bH8w-'
    'VNUz4Mn5h-5m%JPVEHQ+CX!DJ)V-7=tef$5-rF7+-yLHK{`H`-'
    'aXA1d<GwpB<7LMEvk5Agzq`*<*{A3~fOv;I!lSy(`TJ2SAUTVIa3@+(R#C^HO7H9yk$qF)QZHIOS_{XkPIS14P`Zx<ZtDk!9xwO^'
    'E6*6B~>`CRkSMv#B&8s$h*c2NO@mx(C%(G$(laKp6PY??&i?vo9z@ru7i}D&)0L@f5r??CFSvP+7MY~`F#KKTiCZ_grxJTS+dA)$'
    'gn<)XSk!|%71lQ6`NyTvcU*y@C$pf~cx0`nJFV@!h3-^~9FqTg~o{%&vOMf~&C#n18exs|rZLSh-D_>sf&KiWx7k9wm#+4~S!0sy'
    'XhwxL__(Fls6=h%wy$V_e+m)<{N>#V+jSkZKhJpUPQUyq?(|OMsUk8OoQ?$zXKm}%o3v5}>XH>3X7%^A|DDH%&mY@u@_~UZfGEW|'
    'wMNswl#CQfOlV^;|PXA7Tm2(2bQdrxb)Q(D&C`@QFn@3r26LjSLCKB!efdycfU||*K>p@q)wR({dvE=F0SRL-OfT??A#Ezr37y+5'
    'WMCyn{qbi*>Naf5TULdVSVkAkw5l2fJm9VXl0(p*i_tD%Hpz>oFI}qgzF2cU#NY+nmsveXRV2vGxxsgtP(&qqRbzr+ZYYzO!B^s?'
    'Y+j;%m*um>67iiS4u!>AP#ObPmfUV&{!;(P)bV{4eG~(}Ih0!yR`#G2g8ZXQFIbImMdy><@?!A7RaYvcc5P#~@ktPvQTR*#2+%r!'
    'sLRI`v(BSB8i4aH^3D%h*1B_cTGL_ae`ak>dL|YYUy7N1bS5sJQ9udA=?nwz)R4_+x%C~+e?V)t5`*JL|#cAjd$R;N=Kp8pOX8cA'
    '!zU>Z@CJhm_f!o{z#DU>vRU{zooOLx2+?pMDP%v@DrCCkk9<{^eHxK(^i|!A_1zVbqjNbWe$n8z1x^_NU7>=qFMo<r6W9a{T@L#q'
    '*J<xu=$aE6aB5X0R{}l5kJOxHdVF);RRsjC8Aw5`>&<Jjg&OGo#=-'
    'f{oZi!OY6*zXg2+fA}@xkaPaP}k{DiELW{Uh|5!DU1}*THIdJfBMv-'
    '}5uFmk*P~JBCb&Hsem3J;i%SR2qTCr?H|#QGtL=UY8%S6Ub9&<8_Z<==HpdoqF5h!me*9gA4&rY5NFFt;@hC4k&NFUKVmhak7~f3'
    '0pV(8i-'
    'G67|Zf?E95p%56J5;ei8$X#Ql`Zgd1i<9&MHwXt%}A3vDp3dqww?m3=nW<lY&WM!}d@>1}~SMe705xK1(!qD)SR4v&ZpXQT-'
    '+xgS8Q#gvfBnJMedv9_6*CY7%8c{twCnA4P^k>p{>Q`>NDMmGpb*C~Jl{1{w9l2qM?OG8mRnrF{#bQ;Fo5sgj9yH%<ZN;WqXWs~)'
    'TwlELR66(9sA?kjwsk`t@`TMj_em?*?y5%vMy`-I3w+aMcUqdsEqunZ<5-'
    'Z5&hw@f;lr^1M<SodQ=37`I06^na#7^oj`5$hKgd^Y5dGo<kOuv(&)xp+Xf5Y4TjecyB2$$XyiQ}dLij%lrUDi#|;{OP$c`>K-'
    '7lMWQ2`9$_21pwsyJHNq!@tVWJA}!bLPwMeHJ^lw(~E2>p%z!D-'
    'a6<f+t+y4C|Uvh<}=o4Xeun$Tr@03(aa$Z*C}(9VlhLrsG8UmS`Fw1ytw7-{QDwcJ$86#d)U5uQNfKYGz)g}R?ZKI{ecbf24BbpQ'
    '--qb93eVGg{{iWxM7i`p=$fwGXT;_+Td7&V>Etxp^mmsD>58{(*l8A<}B^U=V$CB>XzX7920M%N0)W|a~fzX7B^&j)|jQnaQL=kg'
    'HE5sZAw~!%X3sS1lL$Dc4>FjlH!qh5uRmmUJMYx!GUqLwc%07L4PD9z@@}?3y(@ud>-lvIMd3EkjrX5*(f=Ri@f*1XeDaKU-'
    '8u}31eOTAi?s%BI~ox5~GTvkky3WR(g`BO3=AL=Y;=GkW1dPO4N%U&7wWTIcA~+F+OI4lVx;lnig%fltAU7O`65Oq#2xMT|ho^ka'
    'Q;`I(Zn_56>Sj5l1Lqq8?9w9y>BxI&S8M<fMD;(=E7H*&&2X7474<C%csvfd?^Z2cMDPg(nkc=`VNZQ5a~gt^V&s@+0^V-'
    '2j~s2LStXXi2M6;v#UGif4^?+%Z&1k!$%P7nNRU;v<>tmr;dFrYl><!O%S7hu|L_Wf#ul<sl#6Y_PxQoVfr_;!rZ<*x&k~>G*{a^'
    '}|x%;jY*|4sgRaOJqm0r=`3uQa&ZXI5Bp?vL`(54&Uk|WX=-(A*1Bu_-2Zx+URs&oZxHWNyzZGsPm*PFk?ly9-'
    '2bRG5cnbB}t1lN%$&qGU<>~tVpC>M56X^lM2PED3Xgv!%W-vPnl$N(TxgSI4S>!4fS!dd$F5&ZeErOk@1)3R0=4vT!aAx2=dt9-'
    'RICypKjsh08?g!6W>%eRG4!l<6F*zAD`b5@TUB`G5%B9y@HfQZF%99E5@PLyXAkVgvz(BIHoQ)KGB)?#z<V}=D`J)mhI_nTJhJb!'
    'i1k(m33A+jF&e@i?uQe(Nv_>jfmd~9dPANSS=7JGGyMHhZ3xVTR-'
    ';=LHB*$=G*0tmcRvd#)zw=$a7Bm%&S;6bxz(>7o1#$R|DiQlH-'
    '(2D8v_NU_(uvpsMI$wrm=_A4(*i`HGRo*F)vl3kMju+bfo2#2G#{dA?dN-'
    'i|(m@Ho2%a`n3}vg<nZ`Xnf}2dR;Uy$g6tOv(SsP)sSiAPASG8OZSW8p^jcbD%DX%tHRR>OjDd8$(GReZGStv8>V#_ivB-AJ`i@)'
    '493!zw}^>Bwu03a|scQoQs(gb;o>(JvpovscM}s5nkRRVwiJsUEGC916>W$C~SHl7>_nmD}GbWzq_7m4Z{*6q_=!(qC1ea5;XM$@'
    'I&#ybtB)pyAb))pcGy=$nelUaXCg?k%W_duMWTJTCNGNrvh7=WDu-'
    '5EAq!8vU<qz1Q6^t$x27eb)+jWF*Q8ua~TW_N&Y`9PryRQ%tkETW0YA^XSAtTzT(G=SQJJH4jMc7d+_CmplWb;r8;$O@_%~s=1Kc'
    'AN>Y6u#3JBw=X7(R2B$ubRs#uF4Sst&@rMr|-'
    'NX@}sj#IiF*5}(ya@e^arLH`kA~>>*nkue2E)ONYE)pUlnP!`a&x*G*r+b~b8Zu#|4}Jm0P1pi@lH@|%V6U`(*x3tvz68vcX?z*w'
    '{VHL=0jy^F`TQLs6&6fo#}7)qJI?`QiU@I$e&Y0!jf}s()Aqg_M$g`sN_u^z7(-'
    ';`+Xc<$=R%$b7M{yd;!}^JY$bq6xKlBClD!YR?|JXepEsHL$SA={<D`S(}xaRQU^T<9O6s1`j1ZND#l=`?4$n3lfhDrme1+v2gf;'
    'ywPHcXRP^k^*<_h6z<Mb3g~kU^kp&ETv{ut~&(nR|mohkRF*bNP{+=ztd@|n{X1mHFo=XKjSnE$zp&v6&tzmy1B@GT;YX#@+k&9E'
    'rj<*eOv@jsqXCS;5AJ=o;PRNHV#l_tv_V34V8Dkwx*l%y`f>7zNt!mSkH3&xhYtk+Ulf(v);?pSGVWayOInjSp*2M=KKp}klQKxB'
    'R3pg+YDV0fi)LQcZ>){RKzp97{`u+t!0^Exi#UO$Q!RB%k{g>zoPtgM)z@ZSP8q0XFe*!7}j>p(_1kl0n5B$p2;fF<dRI-'
    'zWEe7X7&at{YJ>q;`?X@`MB<r4_lyUBLz9p_KzIW}a0XO~dFk@-d8Lj=+P|#q?0(}#dZd>HTBx%U+ANV;uS}@9_xI_rxI)~|4lB-'
    'yA9R$&}J9V>^3IraTvGkj+*eSHA@5AoUB)1#wL|zKzD}lH9_VJ2(gT=p(o>R5fBT_PuFr7u^j`dcM5)8_jtxlv5`Lj4LmeEbqGkn'
    'Oa4%-T7^Qy_zs}8F&>F!N%XL+{nWx)MW$=h?@?rQk`-h`7YVWel1!i)xXfP!uz!@$q-'
    'Ae<ZZqn)<lfgOWCr<#*K7x}A6$%tzQqy!5=x20V;z0d2#iBE4e109=&0<FX>ajdbe9Lz&dY)I+FYV8*wxLIULKG?NDk5)Z^8zLP{'
    'cwUyxd@`P~j!N?M7eQE;*C!QBUh%vw!^8G77uaA)y|uY8N*Ka?6~RHjoPOzx3bh1Iu)!%!-gNeeAJ6+-'
    'O@!u4v0Rz002ssWEUwBl^Z;O6rkQejHP%DP0Q7$5r_kLig)Q#dVP;m0@WPv;K>v0{C+}WBrB-'
    'X=^jU=;oeWR=(O(p`X>oeo4_X?*sbZ#U&?sQ8JXjna`jt$0S{e{EFk|Op;-'
    'q;z{+6`sQ*?`5U<8uRzF;^7uz?0<UF<V|19EI<;c_=JyE2z^pgZp+`OolB*Ns5*ne=RH)!CAV_94M^EW?Ro*Sm4K9R=-'
    'ws!2_}V0=6Dw%eje_p#eF34$S)$F(Du!Jy24uBeMJ4V!tud(VBfwC*i}0tWIE_=>k*IN~5?mM7cpVARq*pgIyW$Uv5nFy1Sib+YS'
    'VB(lxqHDek2V`h-'
    'u35&2XQ=~5f7c?ST*{ge*BiSU6wgxl5aW^L0mu785uEh2((4B6O3K+0HT=Wr5(~3_E?Ju&??@qL{^H?x3ZF47{vhZgPfl>!(eWZ5'
    'x;jvC^^tV3ETK+6W^#JReEsvAMUOC=vS|u0CSt}G{Ec%5WiYXtSou;smFa)ivGq8dD(I{u{xMCf%l!?_{<?kw+TKx%=(%}GOyLi$'
    'L=bULA5(pM*xrI4mfX-;&-V;{Ok3ly)>{eC`nwEbEiS6qR-bEUKtAA2smzSPxNgw+alCx(4tg5LRW?EbQDTRmZ0L8bn%9Qu%d*RI'
    '?7cm84)7x1?{`4&x8<r=BEO>NunO4XxhuE+Ho5ffvX0wUjhTM_mCA)5hGjVh^b}FL-'
    'P56s&K=Ri$yakAtoQ|i8BWD}bJU$waBQz^1_WYaU95i_jQA>p$F5a>>A)t~>_zme$N#E>+SS6nWnAVgy=tV`JLc`y-'
    '1a~0j7qKAxyWg`zm{RrXP@RDVPd7o;K#A3;5b9!N{}LP{D4N`rV?))%BkldZ2%}F`m<{R!EeaY)B6WDCj05(XDfVRJ`^KXJ6GANf'
    'neuMKj}X@`vaOI1*(b9o&!GlHR?kDn$*Gfxz_c>>B9tj`F-M5BDXP^`j>eP9YxlFWMo-'
    'i8MWL&LD6e>fb==ZEzlNvrH*KHe{*<{;hVBpBHrd1IZ5pITN{77%SamQY*uEEY%H|;}zXG5mD_n0d;i9)lIv;o=b&QKAt=W)DYP@'
    '_btJJUChqFNE3|^>aoMGJ%O4Zf~cq&o7b4Ld9JUD+~X_aeST8|pd;jB*yPpEvvQ0Y<Wn&dg8hKNEjK498FToYqgYSgD`#Q<(lYd|'
    '=l5PpFI$cH~Ipqr90k+KAcvVJ1wy3+^{+E_zWjyOxxh8%{XlfIwSciSBE=j&9yKyak`ycs7eMmb#kF(=`pc(M-'
    '!v(7+d+M>H|ClG?N8_s+{Nz<+&pfOLfg`Yy?0gF8)m^UBW7-h}$K`(1(-tVYO50ro~YNnoUpr+M-'
    'mNDTOih@U=e3X6C%Xy);AnLhM*#?Z4TJNR{e~m>*&>7a$L^=G<6TQ@n{Pgf@d%Lpb+(>Y!958Ga5#;jdu3~LN*WLF=zS=$JW}YSW'
    '@7CJ&NKodne=BbbFI@u3XoD(6=!SbfEjsn;oeBNG@yVkeU4MU;OipBFB_3(77!^13TF+IXAm8m`fp4=g?c)D1CQe<{^N)fo0)ogi'
    'ElVjBsJNG=cG^ar$6M!#trv<svtGsNI}jh|SS3g|-'
    'B2O!^#@;!DdE9xLvcQn;~&2(ylK*^MwBb3FgU)EpTF%>ycE14+^M}OZ#Q#9hRAn^+xLk;!L3zq!U$adkEvUdqv2c>D_D`YbTV7A{'
    'xIO)cXC!TgOQIY`aQZx1l+@)4?N5YxRThMVC&F>(f77LT&+S-dkqzvyL1dK1WbCL<~k-F;DJ<aSqGZ99)faGXq$W-'
    ';4Kf<H1!HEy^t2jC*odS?e4j?iX+qUWQ+J$)B|hS8IN@<!a5kCcY*av>UOwO0OnAKyqk!BTGz(Ag`27&KaU$h4|H)68=Nht?Pk0n'
    '|Jcy@`D~Nv#Lg5C28p_ZQ=&M>ak1>?=Hy3~4CHxgC&m6efb`y!bRS8|YNG6k?SH(ck~Sjiw$Y;e;3dn_4;lp+Ot{cajLn^jA&KWY'
    'f@)9;@ettt0Y4#QW)5xXBV2aHr*^ii;?8Dpj9aUf2GH6Qs4Vtim8o4BQu{uWU?NIs9{#?ZkC%4&PfQ%eV;QyfQ?nRtOXod=@v?%h'
    'w`jDMd>xP6$XeRwjEcKq%`rn$5z>XsvlQcmTZlg=dJ|Y5I<`sr(4||7Bz?7>f*-'
    'S`0{?89TV8u<146IwGU^(9jn)?pQ6CyRzbll<E+n%1(W)0nt);P?_v`-s=@-+;_YlS#;taX{t*$kE_jcq(pzLxm_&#;A|2-'
    'CX*u>lj%?Xe)GU}rJ<U1wr!6%94v=Vk6@z%k=!kQmS8%Q$JJ<bXk{oFaJoJtR0TvkO~^D$d^UAR2b^=`>zj<}gbSRyYjuk8N*b%X'
    ')yNTyT>LRloR0W$E=+eHp3jxg69az&hrUIU5nSN&H<>P_0zlB-+!J49SyQ4I<;5<|YKgTw4QLg(jD=c20h(BM!-'
    'qL%D2$KueYD;wx=iewTgKe}9v@lLQ!vohduEkfLvQGw<I8$4nH<gZaLNy68kNs!AcZb8cbprkSU9nd1e$i4`@B-'
    'BXKQ%g+IOA3IgdY{o)@5&NZ^t`k$@x`=qxmZXQeLGYfQr3ACKPKa~dPnIw$52LAmHMNAkI4j~r8Zza!PFqA9HnrtDWX0{d5{;QE;'
    'h|Ae&8QI%iW{e?S#@gho8{=yfHYJkUXY_kTLI{EK-TTxWL4amn@j6KH+TOgN`DxtDd)zfS%5!DcbArj&D*&4sm`b*36?g@&sG1RK'
    'NK4uk7Z6bUerd9zGwVMl$`MDnUkoi>MVAtgBk@>Lr((@}C{X1$hA7e>=FxafPzL{`_&%OmKNb^>KOz#48~qqCr3|K!ra_=Le}c%~'
    'Bqfl;+%F5%AC8G{6%jyY^u_7S<+em8_YP2zo=ALN+K@UnfkeU?~o^e4Ul-'
    '=qVtZQVvWdwLb=r)ppPgZl9+22v`tCoGvmw!j7>g%z%6A?_C&@5XB2=3iS$q<U+zZ`pX~qTM)MfyJpI^aegl=r?LvtS-'
    'X}tt#m5byj@&HFwV-6L9iM^JoaSi=~e?+kzP<!)nrOoO{c`yx^e_FXI9B~?yl0&@CH=TSOW!oHq30G=ZT-tQ{~%I4*$LoodHeeno'
    'F4BPo@nhHGe3Q4ch|Vt}&URyX-'
    't5d^sUk+^F5jOG_v9H6QUCarEqd!qhPR3V@AvDksm?!z|GhJ!#A}FwxcMtcP&cPUNB>Wo#5jRX}lr1DJEQm*S=_YdI&4!MtQz(C)'
    '%;4mFsJc~^k}a}1@ksH+k6{5Xe0(%FFU`AfD^63{P}GE-'
    '+{BUh*Y=`v>ztxPLk!vP3legsNmLGyz;)kY&rEE8Q!E&(w#Vx;lJ+~YsGX&%hfvR+~dBg5yI^)V}0uTEkc_1!OyVtkRP0`E-'
    'ma*2!zM~LYaZlHW0)um{Zy%CT}Dok3pwM6MVnkA^>VpIBgUELup2Ma(zWI;VyXS--'
    '%zSO&3L=(Hy)nP&4YQ8Yv|8byfn3yJ90qq2<pb_bzS9!R#Vy}eP5`rqcy)h%7imhma_X?7`u-'
    '3~s*V)S)RSHFsy|W{CW<35E;i<Sx^FS2_%EK=3wCc7Pd(1kqh_bDNX`KrP54|RRjSb%RYt}@d;q@^4^br<zY5ZXWeO+;u{EX+&XR'
    'U^h4@>dvZQQ@eGw9iDWvUPJHCI#ywK%0Yps9(%DLy@nhAu^hUr2}TAjNp`V=U(vedf5S>n=c+DnBuE6gs!$bb)sO#2m6Q<=8LN-'
    '8wmQ3huu5jo5<;whyRl=Uj-azsIP_zqPE6Q?E2VB|HZV6r$$Yz&VRo{XrOH654KmW^8#3a*iRX!KoZ-'
    '+iXmkUg%b+0Zu7cCgOI9HG}@<>fCp4xWZh035)>W+m<(C-'
    '+f`x)2~JaTiDBd4@6{|a#KVEs#WKwP#nK4CXHD;hxF>CDK2Cwvl{Dfh)`#6=MWtYp7L>85a>#|bGd2RP%ArI{V(XTAS=v03la~){'
    'P9FJ9b;{U^FY%G4%7>(c2hQlUCf*iN?i44WP2C9!5K4RJ)HS>i+n)IN5qrS>1Gwbz)4MA`*UX7pmdgLq88fIOKY~Hq?#Rf=n>-'
    '(+aj46@)!ucJ`c5i?`h>bW_yQLBZrjx(Ts?Bhp-_rt}s~L1xFfQ&{vIJa(jr*5M}9+Q*Bj_Lr)Ka)NJ9q9gI2RvopLPzJ0W{MDWs'
    ';l9qFUnk1%2hzFqQ&!Gye4CpVEE5q53{6zkpliVLJB2!j_lC#L9Bq>9{EBiga4uCeJz|4+J;-'
    'PE*3C8}f0M4~*Do&+IWuz$a)kP3}Ppx&`Yw3<Dy(K>l+bEV~;Nx2U-OLVQEzm6;=Ze2Ue-'
    '9^2faqu<<0qYIyY&^8O}83#9Q5yFB!C|KUsrz%JV7-K0%NUEhV(&Ftu2g)k@)f*Hab?1uU=-'
    'D7GKQ^z;dRSMlSG2NRuE+%uo(M70o?pl3b`#t!5PTcJ6Qoxld`IkFeU1MA?!ZvBODnMznBR_~AOxVLp@>di6aG0Bo-fbY3*Gz>yK'
    'Y33j{|Y2voSS6$`?x#N??dPiMK$;kajLq8DUJ`UHkZ8BaLwCj<QxrB8$myv-'
    '@+rM)3eQ#Ugnt)<saYy2(6GPGt7cM?+Ra6h}0|k{JaL3#flVP!BR-'
    'h}IJ?y?oT%DB)GyR0=b9WZL97BCDaUI<ike={t_8#*QNo8;+P1GMU3ywM&QtlO+MJCTg$cisW2fV&QvMZ~JXcAAJ;V3uoB9;*<#x'
    '$Z|$qm&do6L^`uZ_XRqaJBF74kvQFIj33Y*7buna8W5hevU_RP1kWs7=eFaqRt5Hfwi&7qX;8;%WGKUhb!HYD;6z-'
    't{THEX=vmxn7wNjCHt-n9RTv_0JKXce;q0xmO3kDwcLmSOmyJrT!IJgQpmfhM_n&QS$rp+lih`)tB}6hQ6`WF2+QsQ~aF3p+-'
    's|2ZaAHDg!zVCBlB|p&mj;P?Q*dWjAD=FB5%LWTJu{59ag%>zJ=ZP6h`jaFlg$FWV^M5I=-'
    '?di9k$;z6*BBcznf&vji|t`sB$l?rMPBbOaem+n{t^%>LN)xAH2h0eeLpvgzd9X&&E3Od}(wMlrN@*pl*n9B{xUrIbdjbG^+Kc^P'
    'si~Wby;$EmeJf)k#T2j*`qZ1C*dSa`e2O@Cr(br|(1!OlK6a1<ZqZLeeCT%=%ig9H;n}K1lddP?Yf&e1nYIl^iH&CdJ^L#8)^eb3'
    'aq~`DWSS%YE(8FlNGAZpL7|vrQMbPHd(n;X?^fTiy7RI<2yRlHP3U)x&0k7DXhxWeKE??wGtnX1wS62mH<WP75hg8W&)g*OuYuO>'
    '#zkvoLg?1&@$qz2GTQDLxU?0Y$2(aB}VQVSC;?VYoeL;Yr(dcz>Vs^yciv%X=Z$St>zA!z8>32EH+9~5AJJE(?pJYGbw!t4pG}PQ'
    '<D@0DY08^@M-mJX4>WTsj5J%<v9L{DCjOLh@(_hu{0bf5BNmPFCo}Z@9l><0dJN}gqfbmxG5;8LK7($SC-IH_W7nk&B`u~%Z#Ht-'
    'luABkzL0zS(?;pc~>NP~AMe!g-OldiZt2@m18CCH`1JBaBHs#2gsqW<+v5Q)3=gR5E>!D3A*}T$9>9l*{5t}sE`-'
    '7S6u6+ZvX8>l;_L(E|>aMQe-MM9f!{ExRSfC_g^&$r!t?wgq`wgGIA<2a!57-'
    'o%4AHyXi$a=gz*awdfNE!&#1Eh&@uGsD(u)mo7=GFo-10cuAhC^P6iR8>O~n^W65XY*>h00Z7ODqZsT4Opns19}ty8#rs-'
    'r2jaD_7CIyHMQ4bQz@!K0YuyA2?ispJCoWv?V&(*FA7o~s~PGMcoz`pe@70-w2nF}G7<YFW2UXal1>m3P##bwE;-'
    'Yz=52KZe7h7g~WBC-*aDHWr21q6DRpnhADxFACT!Zrv{!&v|?S$1y&XdWK+W;d8~UHBK_2?B_iWM2S8cVc^ubw0-'
    'lGZT1pd=YK3Y_14{_ycE^x3*(q5S7d@dP#;a6W2JDX!><0_n2WvKQ$*xyaCwKw3bLfE|9!j<<$Rfk($2Q&F@Xx90Fg5|XON+<c=^'
    '@|SE`Qep)L1~_P~ox2ir6xm?lCJ#rPE^*<gFxQk>^_g%EFm(aTiTDIeKLXvdZnFnG<Nnx2%ks?&R*V+}~R0c*Y7xWfq0EC)gM1@?'
    'Zr!b8>hvKwi7ao?~2xTk7l80UEY)~&6EYDH>C*wTZ96>;fANiJlEW)Ws7Z4Qoi=52YQ?tHfkc=kIypA$Au;7V(6z3lB>8=nXDVW5'
    'iN6EHpx)R|DdldgEFK&nFw$w!9}4$IL|5P-3Dn41A2VxP^L&Lw1XrM~BE5B!V*AiL`6{}~Je*bk2!K4e-'
    '3=4^%OeC;vpm&R{EJM|tE9^YiQytWKUYRF*(@4;iBj4kKKY}Fvp5pne=vK^dxS2E{d|L7Ongv(%7Y8TrO?a1jkLN5QQSo;hW@gRa'
    'Ed3RT;nE-@(%hR%vd^&O~UX)a~!$1U7g$cxvK+->f5+2Qz|25N5z|dl4Zr1M72zmJ<k92TI8u%jpA06c;j36KEEgLOe#DF-'
    '#JfX#q%P-%@R<J=viGuTqz4&M~!=D3{yPA$oQBH~cQi`KS!O0iCXb@mIj2k<3fheQsX;Eofa6<X!m`n`<ACw-'
    'A#YAXm60%9DujIg7dTWe$b4LvD%%qY%Rw-Mi`p9pQJ2RWRAdOZ0k!@Ep9)-'
    'nBLKuB}paUp7kt00?@l?{rzC}Q4b{}3IwHRER>o%(?JUI~|Q*F^^GW~jZe_nUf8`D*sHznuGiBs>m+C_iyrZzs!1@E6ABWuJ_x6w'
    'QY%X&a8eA8}5O?E}I5DJ!#Cha8P;^(x-Dt0P2+GE)`2qmD)8XIlON9FSceMQ+W*cbVs;S(6<Hr(Dh*=o;e^YN`+H-'
    'Lc?HIWl)CdBy&X*8n+cfCkddUmHW1Is;tL{tbRj<!}G@#`@|Mf!z-'
    '1I9l|lq!EBIxP;;Swe*sa@;X!uv>`b>N43D7xpuZnFmA&UuZwTHZy;;5K0f(z)+?lV!M5HPR-'
    '!X+faW``$^lB7Gn9DuADr5^RAZQ<`lb?HKc=Bq|D3omeej!`F+xgpYwx8Ppwvdp5zfK(U^f8uz3%|2_ymH#dd`{q)Q~i&T@$?d2c'
    '^J9BAM@T7;!~?t94Q8zFeHe#`?#F4+;5Zw@YXE5<%Dj4CdKRnfk3!krQ<j-'
    ';!*1E>(N+>!5ct~DSt{A4hM@~+^gZX2kP;sMjBB?VSuA?{ZM@t3z85-'
    'sEwl7UMmGRb$6Cvx|iD2c1bM}pW@d6d}i@tS%w70;>bTLR*$6B`Lg@0mE3xI?9%6QCyrpA`4TPYSSQ>|PRtNH?Zswlnes-'
    'U5+HTst*~{?|K>{`nn;x;fVgO9!!m9g3e#a14)!eRo{Z1GRTuYXAAUC6V1o05Zu1*cNyKmXC~-'
    'fFcj^4#%TZrf=2zT_44=a4?MXLhFf^-'
    'P8T~4d<#BfvQ_+w;kyZ(H0y8InbaL9H;i@$+8nioCtma6~|NYpkL*UupOE!f|d%c)6$+>lL-KKhKkHFCt$B5x!0+Z0S1n1aZnf%Y'
    'lg}ych@_b=j4{fRBiP`u?Fuq6L{38orR;<wCfVlVnl!sm0u3(nY;`<QfZthgvf-'
    '7t@BA=#q@`6Ft53c1egXoyYmSpGD}h}O(Rxvd#5ZLd8aVsaR<O=Q>yrfPxw`oQWoZLEK!BqXv5mKD*kJgo;RE`T))lNg-'
    ')@9*mYOCo6>~Jnatv1|9d{RS)2ezK%AJuKQgN&7!qxn=tE(VoU%45Fl@;#48NFve9v=%90XH8b{ek{7DUnJisfPf!dd<oougBVUu'
    'PE4{{S>d<-M;aIP_?$e^%?5j)Q3#iNhX&Jiib~ol$FDyiOO0!_O+<w!*-'
    '8K0?ewQ@!r#>(<W@EJtKVqO+_d11ALK#G~e?&o;@iq=PH<Buxa)XPn)LHKfZ@7g}H9$dbv)<)SIARo6)|{%-Xt|D2T18Lu-Vn(-'
    '!9StvOk^O+raU0O>h+zsr{vN%G?_tmqoba2|D_y7SIT)XfSG(mhqiEO{L742w{CNqy1FsTgnPT)ei0mt|h{`2waY^Wc5hLVen@gx'
    '1FODWs;a#qB_`2*`wVCHtwXT!mp-)v|8w=JE#(A3cHi+RGbp;s9i#&ndW+B2SXgB=7Ig_%gL0-'
    '5_=@&r|(M*>wEuchl+7+gP(Rg<Tkmz+uBX!z4xw#VUxiTO}{b2T$twES<y`s?&9c~I3q&f&oy9j@X#1s8<W>N{(Ptr7Db>wB}}(9'
    'A!_^~v_u8sL^kxcu+>D3jC%>^KX}^?G>Uy2sd;1D1sQjuIro54ZY#(?Lj{+L?}0IU;$^tyZtdVt%utwV6HXSiEe=ztk;3grnnD!>'
    '#y`QOO!qsGWpfM);##bg|-TIkOblWx&NaE3#z=qN%&oeIcOq+A~Gi&djaFmf~+LvypUAfD-'
    '}au^~ZJ_A}!lf^vs4UXbVZ+6jtyPTD~pmoQzxn9x3jdhV-'
    'f*iLx0J5ogAI&sClZe{L9Oy1+?MBA9+^1QX0pdQ&&nKn5)e?|~hZhC^QMC6BKe~)?kc|c%7{Wqrad0D}#Fs6DaT<slfV$6~2QQ~P'
    'Yt0#|{*@f+=)2a`#I=k;WXyuqqu7RI_#a;N*ISw1_FO>W?`THlI=p#L{5*|7ZrVFnSJpHIi4yWoCkImqB_V4t?0pu<dP}+7g4>l$'
    '&c&pFkVlQB!RjzMd6K|iB$(XvQAA0(=W13&89V%)2B_07Kmv2AY;`GJJuD@l}-'
    'rQJ_VV><CS)qzeP$dX*w1s8uu}m1DWZbl=n)spm!I#M<TjuHBMl0dfYNDv=N}dp*luw$53Sg6QYwsizo%M<FX4~7Q&2iJ%{w%qq$'
    '=U@VZwk1HXhiIIr3lnAM#B4E`1!(JLMrQ8Ql$#jW=syOW<Ngr6j{gr;YaAbcGv|x`UP!M0MuP15q(K*Gd%D9yEj*?wu`6NiPOs&8'
    'lX9I(%gbR5la<BJZ2nrZ8F{_6-4Ao02>g=r;c5*@AA_CJm-}TZ+q~vFPma-'
    '5J3c<#OtF|AaokH>(}Gykeb0rvHW(Y8un`;IQ(XHK2t3BpGkYh!S8lI>>^|<3rB;t`OQ08!A@I@WW@jtpI6%CFt$2|Zl0B<SPGyU'
    'W0K4J@%@~!<kFo4^H4Y_);h{>(U`Vmn?tZwXe!hm+6C2UZ4#lc=>YNK#PcU;sYeyq%G8=mIOJBJJzwiKV%w~B<b{pOrmjZF0Ra&$'
    'OJ+rvKABnu4*T12O&(4>L2)Xna4|z?_`3i}4tgE`#5t?D-60hAP=ofK(_S~-'
    'Vs!3Knnkq_7hBzWdmUz4xRIHR*!ocVpMXBJI{keINlgt51<|Zl22rxH!?ZrVdBzv&qAWstnsmXkyS?rjO#fRC4{-'
    'hf)f@c>X^uqt?LX-w$|?W8$sRC@i*QN&a&tuHx6s*T8cX0J<eR!dYwPDk(OmTO<@yaeMNn`^`~Jb&a}k(MUw;6QnV*TDz}XDY;-'
    'nRy)r4gn8MQN`H$P3N3)PGe6Z+6bFfKkb)uh~)4gFj8JboNU^RqiwJ<+kbm&u)!pNa;&@lhfQ@;NDa;KKg0=MNHz3K=8)`0ggDCM'
    '5iWh#%KDB8w2T*OD`+Nqm^n9L8lmh97|CpM;#QsB=M)-'
    '!^i@RPO%4SI0N36sr$_ZGfRa9l>!I)`;{qeY<P$rBCV4<~Zp1Q~UGYvH!cd<JGYWpzAjlA~K9J<1zGIWkk#FNu2)VA*yRG$KO2Nr'
    '`A*7t=?h<DAVe%JaQu06mo`w&y;SzbHiRppsRoowc1B-<=?G-'
    'g+9>sm*XxdEUd=K!7VwRj%FH;yK6ifa)qepju_LvZ&+W6^nXpjN;!tu((wEFt??rM?QX=ED&lSsN-lrY@ip6V*erFM=({-'
    '96BBJ2Z=ycR7np=D)yhtcg}fWx4ieK@1_2<YK{10mp?{~b@v?np{aC`N%i<gdq*uIDPzL$(Ok!9?<}r8u-'
    'iU2x8_mK7N5V(B*Y}h<O}(y@1ni$`-&cWr?!x_c?UBmglQy6D(svxKgf3M8;C?NQMMop-'
    'y9C8Cy|0(OQ<^KNO3_<13690^+hbRE1?+=vG;-'
    'W7+z6K57f2o*c#pa(y~?juU{A9uPt<p=15{dm0ifLladN)vgPNcach(*1j|KVhleckAG~!$r)U<QHH{}-AxYO-'
    '+fO?bZR+XxM*ruh<q^(@1DMrstGnaLY=`nL>V<lo6-{2Whx|>YHR3-JWS51)TgpAw^R=@iX7UiWqv1f|(4Y0o35=5oTA_8-'
    '7q<V`FG4qC64}Ee5*K0&GoOT|lm!7T7*nACltqq~!NEN68B00d`rsF7Lz^n2md(<!0^x>(u?D{Ge2B((~N?#UnjYYsxlG}`no>16'
    '7`~ZUHt1kn+Uaj`!`SDrxHSSja-nWK+3E;u*aNiS$%n>UXGwsEwrCCyFm7xN`70enw5+dc(=+@<d4P5+zrW>nSvw!A|uh)%>heS4'
    'NwT|?p=b^@a5YVL8NS>((xbWP&oBR3qr=}w@md1w~R9I5mIn7|65+Te)o2a%MGdL6wK&#Jvn4W|~Swy^XQM?gY)>y7@ufyRb#stw'
    'IIZP4bBloQ0&lBqWScr>+9%t4xMScVkCCn~vxfOD{Gzn#gXmc2}Aar;T@J+4%G&Tt)GBKKlgDQRO)Iz%%(aa6`JlxenDxD-'
    '>?vMep4+Dec4AX|BD_;>3FEo%GM3jh1#-ZuGjVOAOJ)u#gMzKnrjtV0n-'
    '!*k<w^n{`p%{fR*!cwvO>)iI)mcR?exkLRfy38F<%l3xbL@VfYjPE*Wv!(bKpL(h@?ZI^d--s_nT69HFd?3bg+U(0?BeRe!Sl%=i'
    'Q{|%$EVr|=wr9;dPi(7yZm|VRa28szz&;T5I}tv_tpk+?+U@DrqRgn?GMiIZl)DBLgNI=>ACnBkzmX0-Fmbk)1---eJGE?PSd)W7'
    'F+g<FFx_BKKL#>abCI`&7-k1d_{8k1)QrCAP&yN=Zu~GQo_ejxX%L+y&r)or#TqGS+S{ZkOSjG=*rRMlSrjLK?$hcnt-'
    'b~Q2HZpo%kj@JcyN!R7<h>8GWd00pp?&-'
    'F1MW>iK;Oa=tk?dkwhmwMhyQFOhE{tTVZ*4>hU+yU^qHH2^oZ@bDk5vW{QppK~#TX>0r27@UJTC>G*7=y=d?Gizf04-'
    'J9ht2X|XiI>8YA~KkRr300Bf4E<w)4_wkRL=LQq=^pf8Ci<gfW_8X*)&giv^F%#Bx*kmN+R=oqAw8q&}tHM${<_DH~mrn)X_OERF'
    'ZT623YQON4@2A&q!a8f|h}Zg4Ns+B`d#$4L8ZtayLMAk;!Vj-mY`uAx@5!=iCmn$FzU$t+VxdpEWL(dJVqh`#fdm)@3T+lH4$gR0'
    'My;0gA;=-=Ncp|66ecBB>5m!y1`Rm7h~2k6iWfJ3mxHxGxgOYc-a?IU)55Mjy5Sy<ixh6Wge35a-{=xVvw+sWT|kjg4~TF&%-'
    '%w&8{%5#-'
    'R+XW~NdCaj&h&>3^K1_bR(O99c@gX1Tc#Sh%0P*jlZpC3ce07n7%A(;J710_DkJH&G98ZH;1{G+hxd@kH@#PDy37g41XvYMuEE3N'
    'a7=V!L)LxyN)Q&|R?DrnM+98p|bjK4vOy~c$vPrv5t20gf(hYNLECNO~%i%vgN>&{!Z>^0TLOm^HVT+~(FrsOPqKpvC&<IN!;Du2'
    'cNTw5#h#yX&zm!$7#j|yhQl%2#GgOMeB!*i?;-'
    'O@uq4J>fbc5;RZa?sYMocvc6qd@nWTzM5Y#6`s#cY@QQXG*zWEnVVxv#?G!>OJu*_+afF-'
    'B1gflzb|kmXG>hYlpMYyBi!#ZktW<VH!Z|eCqkRa{9^g;00bjVLn74cj-gT)Ai}<02LkNR<WWXnXsyxKU_neXfK6gxedK3sA`C4$'
    'MI<7fkrYog2?wl(ZPjXXjy0qz=>Qit;1Z4GRCQKC&G`n!BuEdq~W{v|2M}fcwI#!nmFPX(!J}24c;#IO({Cmq!okjPtnr4)mw`S8'
    'WnFgSCcEr#?@|9vuJV?i~W!JjiJ`<depaao(54%X8Nb?&62@qR3wH_$TlGIiU?oyzk4#do>Y33FLWU;^)|_y6jWyC=~#HpPoobVZ'
    '8spY?(^%$PZ6zK{P~t7xTIgX==c`r)NcY{#Mfu!YF;zloXAR~h$4Mabc5qLHk&;JGb6E{9n=H~m_svR7vQbjOO3nraMIu`b+&&C('
    'D>`_WBp23kdCC_QFCQ`DDm)-&*Pmj-'
    '2m*PWc4uUQ_;+@?xRmlHsc64f2Wn{Skv~6vm%u!`e4e%79!Bo4=zOi>cWTG`HL1R_up*{Xi+EAF`5~)U?!`n=uC=$SyUcen|uS7R'
    '~k^Y(bD<C!WB@=zl-X;gvHEL=)I|9f5$M@V-'
    'Gq2QyGR*#+4Sf(13Y?vB%BZT&VxTyGeCao;q3yRIjSeQc7TmQ8Db}a2STDLBP12Jgp`shf4%CG6b;Mxn_RtjtcsNHxZ19r8fJ*^d'
    '-c%zd3KuHoeHPj#HO+DJfLVnZ%8H+ayuHKed-g+rBV-4OY({OmE(?WtXwXAf|i-'
    '6cpN3ZK%)qH`%#QYCXm7f|JsbL|8|a&~TJOq9tR|I&k?rWBcUDJe<^Oq#*rLuS#(EuS2=|Pry*(>2Nvle|@g9!{|>dwEi<mW7y8@'
    '`bSy(yN2?8@K#;q#DG`3L66mlV6v^qQ)R=-'
    '8#7aUOA*Xf4=eDs&Y%CS72E*vP1@}c@F5)<u$NaK9)o<Dp*(Wiq6zrGUnRbtTkpSAKlL}r7<@ZG?jB5Aj?oC?f9yRo3y((CrruY4'
    'b#?qiNA*kfGWyKELvl*RQ1%h!eiWt}j&5m+JB4dq0n2pjpTC(nW?F;T+1t3()NV3KPaq}ma+Aw@agPO1KmSrnTQ*H^5X*n@u3(uK'
    'h0^4By0&Y~dENLUzBH&-K(>EF+mDnUheMVRy-'
    'Z6Af}{~`RE*BW3j((Vn0ukN2qp;)|K!K|c+*mNYi`^Cb!gm&<tB^Ffo{fzc_r7BDsnWB9W1vs0I_aDKBfv8|Bf@XS%rJd&D$1#xZ'
    'yGp&O86n%M(o|#uIvp^-AR{j~<O@o;K+I`XrifvIIGBnMJ|%&vJ;-Iy|gA6Y-'
    'c3$*F=qBr}=8^|CJdHn(EN4(&Z+k}S$`*5s(s7(Dc&Kp#Q|o3Pld_^-'
    '+{*}Dy~ozIVnine{1b*2&8kUD!7vcGWFK$6=ueoSvxKCLM~dbJ0MuLdpbWS)Z)BMEKJ_ykF-cl+MO8sr?My^Hu@J)^da!WS<5sr&'
    'QM9Z}#!xs5pUDknpzpFeBzFwW^+D{d!N$#^OAMDi!Z7<?Pg&di88e@N_AppOQ$JB-'
    '9BgY%Vplu)W6vtgMjI7FN*#6;v}!_Gq+Oe3>}{nnw8SdNxxneqw4uYNA<EeZ^%rXUz;9B9RJR5g5x3d#zFu`RHGbJcZbPw%Dq(D;'
    'df3Cx8C%ysD~UzUcBvwI|O5!2*HJK$1PP6sq+0xJOBk8KAgYX|a58jDWAs){&pGzo?mPYnfk;u#*)6W1<Qy=5SpMBZ!wR-'
    '@no*z>D?2r$TyZkb7Q9(&8{F#W7Sh{6JFe@jD-'
    'g=?@kj{%ONJlA%K82R9$Au%G(TMD5*1KO2ZlI>sDAUT6ktIa6p){>??kX(gXD|YNJOXYctYFhn<)v#1clFi7kp~k+`sh}F#Zt3U4'
    '#lWxg2A})F6%ly8)eS6I%yqRTmFi3b)Y(3*tbc14iPX^cPyp*nY1e0aWheNH*8hy^f#6&lll*AR8DFh>9;9RX0}eTnQ2bzsE?y_x'
    'OWG<eR4lYnxS575k{sq`g>7xl@KV7C0yZrXr{N(7e~C*!mKk*k`7-Q54pz3-'
    'on%9fU)&ix)|>yr<zL`d3F6nauu(&Rjf`?sO|c_dWFTCdg~95FBjxUw1mkv}^1stjqQeQylIl*I9{~iMzovJ6ubxX}u4KrMM(6K0'
    'y<Ab^IqITXMRk7oAACD6n9N{rj|>y~h-O6`Ei>w!IU*E*;^Mi#%^m-bPKEobp0M1u5IhowCr-'
    'L%?!0)^8<d>0qB#FJ+Qk>xz;nyXuP&H_;>S$YzPTEjO69Ir0zkf4>A>fXH6c%?SflG4%nQY2|KKPmO{Yr24;m(82HJ~<))k_FaUn'
    'Envr@ZklHu$@Gi@UYdc3y}S-(wDfazgHDUe>ssMbFTGZWqs9I-'
    '6GbhN1ov#=@ny~@~f36KKB_q}bTWF!@SQOK3WexX9$*hL%Ls%pDjDF44}ReDc}F|ZeTUHj`FsU)y0B3N-'
    'P)1x!sjkKT!+&MAS10@j=N-'
    '&XM0pDJ>hgZ$ZlOoaIL{in;^b*Pfn?$6o2Ms`SE|U*s21jC?eFGMesH$CEzNCq2T(vIxkfNo0uXp=D*%UX3nEbo;Kg^peC+ZI<4i'
    'ghr{NecxW2-viKi3m&Qt_%a%f4AuPv%V`x+S{Ai5`zAILYk=)r7-'
    '7%d*9h;`vW^@71kVI)DP9e~Cr8Pj(K2g#aRbsJlyHi1syA^D}S|$OIS3%m8Jgws*0a^z62w`%Eg#oyRzf*g*O)p)xZ0`qosE-'
    '$O&XAI@!g4-BlAONqXS@ILg)g_O#72K5W!_cB@oQu^$raOfjEcM3&}WGlLUy1!kL9!khlwM7;KNrb^zfDv9rds%3Z-'
    ';i+h>xD0z5=nYgIlWAw3F^Fe)Wyho2k)YH#zjmx=OU{1d?vxl?oD2Y^~yX72QiVcg;SOh4oA7f4r6gD)m1nEvUM6~YVX_Ksky91>'
    'm8SLa6(<e>a{R_gXLc7?s$*{c*3xh&^7Jit9Y9QtBPHs+9V4tvu?eQaT}VuXRDltvn`<KgMkWwm=^XJy!-'
    '}I#~FM!bS333dafZLRtT|}1lW1H_>8;Xe4dxYl-bMg8u`9}N5YkW6?SO2HKvaf_=3RmHaC?UeONbEQ+zd9pS7(nt!R(QHfT~oPq3'
    '-cMnI1n-B!I4UGNRE>oD=G(sTjN=9pA9_~A1aWw@*e`FC;wpQ*6{8K-'
    'y}IyV2;g!Pm6s<bOE7KsYgG6%A}Z8iqkWlz9u$Is_jWhLqy@ai{p!7-gmnooG0{g*-'
    '#RS_6vg&IhvF10gPi5={E#L8`hN0=N{=g$UYfEKw#3R&HyF%(&Cmbpy8voKU+3a5}!Faa!2=NB<32VKZ2@Kq5miD>M0^N!3lw8JW'
    '*h*__Oyu0>R$9(Nc5uFTA>WGKieZA@VMVl1{R;5jDV}7pgzkyU#<XX6>+8CtRS&aF_sEIXHc!Gvxa>Y~FdVUN~OGn2eACVxPWag!'
    '1<QmbBjOWW*;{7h)_RG_Wq|+XpEC0>su%a+AnT|`&r_q*srg2AaebKSyt)nqFW!I{;jaFord!~?&Ro!>RIrvke-'
    '1Xo^?%vH18xUxi`pO@sTV?%hq)SY-l_DMd6T!AA(p|<ERqL}}vTD;}cx~~U(9s;018m^sanM^C1!smn)~Z3ytOg`;1go=dMYbQ{>'
    '1wINRS_ZVHrfiyr$=WIBPwas_CB=cX-M~(JT<M^rBU@gL}2?xinj!!n^*P*We?mr|EqguDg;7L>uI%74xJnA>iut^i^MY^W-'
    '!Ni)FZHF?gaJWlr$mJLVj9NspiS;7(gfpXVrtd6&spt*o=}w<6gQ?`E_}JR7E1RQaNmO>%m_{4+Pxqq{2j)#J%|ZWo!!YHDqG5RI'
    '4)PKGy;7-=D?|%uzPt3Mh3+i?Qt$uhTv<_L?XDj%zXYvcQ+=hz*8(Dipv1KEMC-I_Yk_t^tpJTR7mr7U8O02)sZE$qF!@O;f6!1T'
    '2#wqKs6`kvbt0gXMv>f!#de2GUM?pfO~5)LFt^F%S2}BgBgNauE<WDU_bUoB!`q=_NCdj|$>~5nE)vbTUGR0T>CC0*7KOZCe3mn4'
    'cv6uBk<Q1U?;J7uy%A8-'
    'W#NPGgklk>GcE;L9)0=t#nUag0~gX%!Z$WOZh&r$&d?Lfmc4`FB+)L95((0g=k?|3arMp~=PAh3!55+V3l20Sw$_qnOOPPODYr3i'
    '!%)UdmjYPHD8GA9(TJiJ{TNeH^3v1*qGlb9H2c*C2(F4W?}>yEW0Y^DWYfeVlb_LJv*ab72utcOwy>kjc7OOI6khd@zfVGU~$8vB'
    '0aQ_WPwKgg?JM6pwq7qoE^P_)t{fGdaF=eJR3UpyOQ(YMkN{zo}pmynZB!)M3XGkpxN-'
    'x?TJ7n~^}MpZm9FMGGb(5YoWa{~(nK?|3|^0G|nq)i@oY+3!VId;Cw%!5&S-'
    '_kf$yYWpO_ZXl8vBHD&US<i+Wl48nSFMOa6#<Ls)b*JW8!t5?#8)`uufT2}&yKwdC)vA(H5G*wD#<E&qyTM3@LrRAjjA*U)22}GT'
    'TEiW&l0g}|pKB5Y<KVr!@zXssO;1JDTO*hP$4i{0-LZnZBP2!De;*Y>4CO-ni2hSplnQvk+{|b&FJgRuuNr%uxM5Pk#27w24!^pC'
    '7;6pDXiO4~rDSGzocaK`v%^y-jM?83n$pGEqUoW9KcIDytqP-K@;oDO-N+%EMzXKS(1~`xEEU1sa+*8}oY-'
    '<}#SBknOq_4+IF=myloGYKlL!193y_W51v1P`dZ{N{AV`G*Iq5gB&ktiBSXNc2uATBH)d|8?<TRS49rU^d=w~cG5tHW{Xo;bbJ90'
    'eoG|=(zo3#hjFFyFVl@CT<&rwONAOdeu#vz-F$y63a@tR;;?c1h-`iRdO6-'
    '6qsXOzo=r*${;xzt{1HhbuDCD>9}7}Xq^V_a_E$Wn8f;6-'
    'mxST2EmC*<{o$Q@J1E_szKP!4T&YayzLCD_t+OgTCAbbMP!!nI#SL`*v%gTrwxC~$y&Gt8U~#Ms+{U!qX{OQ-'
    ';KtgU`&rDCn)^`6RYzWmEYtaf<X|Blzsx2A1<mw#)c10^KwpB@&^X_UeVN$I%byldthU$3sSKC;APvy*L|D33%U&J|?Vb^C$XV<P'
    ';chtbz|`qhN4lfT~c7DsdSv@$VddVUx|B(6MTnVU^RbE(<P-;F*jb-'
    'l8;fy%2ef+|<FWUmy5t0o_*f`w`Vgo+)ZWp8jW=E~yV+#Xq>y%@!-'
    '?9Eas1pQVM0<|FOpU5+bH;J{+G2Kz6B*;b}cxUuR&vkKhvnpX)=wrpkYJ`0$yY*=joAMF35f)0-'
    '|FAp`fA4@FBV#*lP)7fW0PSJi3vRHalXw6!`Gput)U+iy`#m_k6_S{ZgfW84E%*}*(@}kZm`7sWI+yvEmVll0x7boS;Ceiap`at@'
    'XkWLp?Hm7B$sBGqSqa<oS0dwWYzsh%wgXDT{*dkmvz~}xwDEL0Kv+^EKX4y$wq`!(KR3<SlWz6>Mx6dMeS1nbbALi-YVxDoPay?#'
    'GN%E|JS03zU)z3eRXxqIdQp+L65=?bRpY|hd8n<78ZjFo0RIA~rOF@t)wHV6MasxWEdLh`4t%mi=5yiVooQLywVKY#+bHC-'
    '(#95&y+XnGm%hKjvFA&;w2P~#5@NhIqTtIPu#?OpwmRZri+#41Qe?xf$s#HCv@1xP&{!Mrnv8MH?0gR%gb>L-j^#<Y-'
    'SA)9GbfT_cf>|*tTy}V7kJvnE|w(R_8VTYOt9^|Si=-'
    '!LJd4~(|lmh?XpHy^FD3TfK5Wp3NvlThJOY5fqOxkjc9Z{3~D6?h4t9O&J|5`@a~KVJ&&)JyMd%8j|sw0;9MK4+BnNHf54}yp(a)'
    '4PpABi$KnJ6GR_P>V{xMj6~tNsKdnp3LW)Q;c*SHnZ`*q*{)3?xZG~^ukH0?duCqFtP7lOK<ELDkR>8-Uh@7(nFo8u%-'
    '0&cUWDwE$pc_cGTJY-fbulfMhg4mLPY-dWguCh1=p4MhOe*pMYV}zHC0^|*dJtA1LJ<HO*s?75?KTN2H&EWo&E$TrjmAr;FrqoKC'
    'UEej=>H+smS_B|zVJ$<QoDx3Ij>7Dio&m<&u-+YffbL$TOfVa*D#AN5uqkQH7T+p{q7mQ+WHi~b`YH}r9H7_O9E-'
    'XKU=f`EuFguPXJu-X&}36^FWtQxvZ$X7S_&D=yw0VFAY^&z-'
    'E4*M#DF!W+e_0EE!@Su)_vplqF=5<9Jvc2^WSIAr+Kb1~X)mH)SsE<~Gvwr=wi3f6(}GcBjfAuC#=pnS^)N$BxlEox>u=1SsVY5J'
    'jG1)~UF77>Y?!cpiq7)*pG6a|EFl@Bq&6;pBXu`$DbsJF;exh}iERF@iIYjbru^5Q<cnhZ8SQU5>>k>ccI>wn9Q1@1fy}`Tx9oq*'
    'SGZcLEvO^QrJssF%L?)|Rh;8Gj70w6Y2L`QxbQvp!)G=iHsi(xzTk*Rs47?M^6+Q&<jb?H08>KLj&W-<CKU9GPHgK-'
    '@L&dqoOLn%x**nXA37pukMb3vTotr<FDmE4#U@1M))WLYl!0a`5|rR^81}-Fz-nuc>eNJTsfQTH9sIK8fX}wl-'
    '4A9&l3_XPNetW@RA*gh^NGZJ4cL^B(X;VT!Sdd&p%j=fcrP^@)ji20WsNL<HYGBJ6k~jY~Z8pde@co)9Gwj-'
    '4S~I3@g}%8uZ#1P1qW9oe~ptLZq4AQ{mnApIx9V)2~OF5YP!R=l`aUW4#$I{vtIG#Nx6+^r}Pt<(%vL5?#WV#*y~DT|yIF3#)BZa'
    'zIVnSKkB_)zKX(d#Z7J3`UTvfp$o=AlQ-qt9M%RR7=kVYEu}*3geUrNAH*@TOI2w*y{Jtg#a|3A=|6O0^Pm2~?|=eMoMV_SNTgmR'
    'B_vq+TQv!_U$i)b4y@DAK?vQ!FfLpkFJFwl0OI0S+-'
    '47WnCBsT2^Dwc;AHA+*E6&09g{YBv{?as+NG{F0*GR@Vf2#{dTE2IrlspvrbU@0F+^L(iSvK|{&#_3YC)nNuqRxTD<DQ`CO-'
    '|0Gy<m9_ae;rt0|V=IbDZ}1~P1Aex}Dt%m%)NsM0%Xo!L0D;78n8g=+-'
    '*iN~<BCXjLx7ItcY_1uwuNE4Wy4UM{_lO;?yy1(4_V7B2L6nH8bGFr!b9YX0D5FfzqT5=4)(whe3Qsit>-'
    '@%cr$yMTAkRp%s`1Y=qMwW8h{m-'
    'G<8D;z^#6n!o^+kDew%n5EFcF@8FiZr?^Z%^nfNLkmF>>a~*r9_ZI%@XI2yWR67KNnrb56`K)^f7y^k!*DulLucGmM;sgl+Ms!_}'
    '^z3imW8MN|78pzK=$W`zSPq2ArbN4n?#aXO0YSrVd6Zt9LBVE#X@N!9NA?jlN!-P0MWmpRa4OZ^9-'
    '}ixRSj*XFyuz|L*}Xvh;Bc%rm#Y;*(@Hjz>xzmq=?@FOoC_4g9DK_IxVUA9uU$ct^Tu(fanhZS6=)NjVyvowDVIg{zuQII&mHLVV'
    ')0JYk1$6d#rsgO?O!Fk0MxFzGV$sDOwzuhemAefPKkj3qkAeGW=(RgMeGPL-kIDmtW&UVr4}HCptl=x^M*MsP)?L2XRj*p{El(5r'
    'VN6)J)maVfvRs;_>T+8Z((7s~4KBPPyxivHz#qcEJ{f5|&qJhSz319+U7@@CQbyqq`fRm0N_p6*zS2@h+(S>CxM)r}XvjK%Ip?E}'
    'MP=dyz_F4p%{H($j$)t!6{Vz^2#UHa;C12{3`hdFsn-'
    '!M(fBH<$K8PqXy+1`6;UpG!JdPYPaqrUZR{f&mEvUF<7|SeP3VV@feh<nJ3d`sp6xsknS86znj`Sqjc!B9v34juos%@sD@?9OZ|I'
    '5zw%0v#?IETamuQ?62yITolV2n-'
    '6;r;&GZv&Jm&1Zm<djisu%INz7kK)w||sc0YEw|ImO8VY}n>j0s}iik5IQT6j*%lZg*y*GD<0pZu(er=%MA6f1G^HC@J?jp8v|Jb'
    'fD@NF>#En{0*X#+WqdSfQA@RUG^W)4xE1_l}y$-E5mM=?gA9HlD{3C9V;JiQMh}-65oj-MhMeW`KIq_#=^&-'
    'aCsBXDD;47oY#XY@3(MZOJ2i(&V|5?wNOEL_M5r(01)yYbca)9cczuK&p&b-'
    'Z4)+S>CDFUHmG25`J!$NeBJ(i$IO>QTTwl`iD;tGe+W{|1J|_0PJ!R*6eO>=<%B-JF9gYYIdj{D$Zk1rs-CDrh}&F_@a1I2ego2C'
    '`{KPL1{bQw+AInGug@emZBN`%&Y!YH{1(ea5&o(OI5-cig6>iIF{GnnJJ+B`y&e>NyAu-'
    'm5u3VM<qK%pEQO@sgd+h96RHDGT8sg&^*`iQuD(?su<}|nM^&M`z#6q_vJ(I(Ltfiiqg&@r)%7w1m+NQQ1`7)Qsm>q*5BF_b4L=P'
    '-&E&|8oFa&+2m&=-mpiP+6IhI#RBqm44cbTH-'
    'W=HSanWCO#Aj;Q9`qbLd02*@7ruzMc*h2qKu2fA=(o~A^kv7G=xRVy&MW;#yDzOPAm@URhXHdNo7xDBlp22bl@1Hh~<3s|6v?}iu'
    '}cs4fCnJ@59oLL)zlS%%03BHY@E#KGhp9pmk_|Ue);7dqEyqS4auI*qVdp+FIc8jYd$+(37)G&g#mTDr^Jqao9^_Nf6x9iNZQSxu'
    '}L#jbeAW;NV<{n<c;$FcEP8g9`sBhhKWoehEtvHWJxdhtt%FafpT98*`DMF_5svDnOf5$jT3$j{AmizeUyad#HRwMo%C||NXHNHF'
    '1scd3}Xky5v!G>{Yix2(7`rp*dcDiW}6PZUVA4iJXlLn1wU}pUAmZ8i{G71FW{`{BOz(rrecu)tWp1U<L|T(2EG(ylh#pVLKH_hJ'
    '~d{I*pn_nv3oU7DzBy4KMGAVtP?R`EcUmQ<$vN!8HlkDWub%+Cc5IBD!LZW$Hovu3i=n(=H3MWBsP}Kad!S5vM2r*E?va)xisOhw'
    'bCxY6Da?ftf*g9v7ZySmZ!!c-TWeh7YQI_#Hk(@_7JIEH-'
    '(SA`w*GQx!m){q{CYl2f69v=O^9GG$W^CCp~02k}fvf$4z2j|l?=+J#IPj?m-1-'
    ';J)~oFJ)!zp@mbr%;;_Mvn!Q*c~E^J+<QO?_4$AG$9X`jWRQ*GVv`Lx1`ptJn=;s5Gym&J#p7(^s}`Y?$YW@hZ#o(dUIn`IdAwPh'
    'GouPTa?yP-YC`YrSR-ma~5rpp>k-f_pPj)z2o*v3lvUQ#*;&ml(0)8G6n#5a$r?{Zk0?*!5+2w>s-'
    '7A|8lqrFe>|_e}KZC#sf50q0H?w#F`H~M0yAe+B$9JkmIM~CI(L$_%F}pNDx)dt(#y27K~x~?H>d~aT?ciaOsMBw-'
    't!O*t@jdzxj~K224`-B<6Z0FqH1Oq*Yut6brB-'
    '+dGeD<ni8v&e3q@3xBmI8p$F*755|HGYuWJ+@rVGZ<uW?#gU)q9DhLc$af0pjk*Q{J<U<}(%BBydoXOzF3ZV*U%EkYh|vL76-'
    '?C42F|ay=9-'
    '1*jA7cvoDXN|#RZF;&MPOxY1oTid6Re0ZaSDN33iuql%=KMe+@3Kfk}$T0)ccN(0n!kiDX%wU57c;5;DJrmpaq}eub;88V99XkS$'
    'Pp3Sd9C$1Ltu1HChMS2!)$JTQmOKqIy^mjTGPD6i+EH(Hueb0Gqo|By%aJkM}+JCy{`um0)tkxZcqxf}C4_(f6)c9PTDR>*sUl<~'
    '4&&hA&<^@B`&tcJRR8m1gc>Xl*m>>Pa~O)`~tH`mpNtej(;ipk=r1Riys;U?sR&1@S+il1(k1(61i?YaEJ*3!389^QVTf7g?iMRF'
    '={{G!gOcZn*%^9Q8Q=}f7v_8c=cPjYuTB{Zw!T`Y-tDN(B=3i{VtK>2D*!Zqj8l$H@#szA~7mGRFJ2>yqxk5)R}I&{(rk$oREQ-'
    '#_<p4KbG^s0n86=@O~KvYubcs~Ss$FWN3L!AJTPYP-'
    'Sck#%GB+BIpDT?q88hkR8Dg(Ag3`;j*1}|hh9G&s?U3hB&)yBt?t(ss~a)ThxXx;7U^#Rtx@%p&9Ks`Gd@Uzdv-Tzsi{k^!LU*wl'
    'yNJ=r8z}EuJ+HVJ?ZRMZOHz6IQeSH6splU5q2?9or&Iz*`ZTaV+#3Q?{1KM0Qh0?k9JTAK{MyA$2N?P(T6$^MMDdT*}S3iju>wrN'
    'L87CSH7(i#a7Uw<4T-'
    '!;xPo4{?u*wC9tXfzl@rmDb_UJIe1Vz!>E)I)~eL(4VJYQhr0;8DV{uK)15ijIIQy!V1N1+O}<<*<(NTv@pU+V^66{0GX)Xi9!<}'
    'CJL0kzu2$r4m!+fl;R+=}yvrZ=@^Izdu}6~u+t`Z*4L5S1Ym4ZzHd`eU@}2B2UazsK)wN6eCBdD&ossQ&>WzE<$Ix<xHy%{-'
    'HU!@En$-*%bZ2*Ji%2c(TwD;ml$0@mEZC_Y4OsBvX^oIx#LOeDX+Q9QQBxOCt~9jZ0_9dVv2Kl-lH_Cq}F3glGx`_|6FoU`rLAMA'
    'V+<xXPg&UjUh6VU{xdYr;2D=hi7|9LvTC=!c7@7ebBo)^+?nQy<&EUHidy+Ve7EvJ0T6q0`THpYGZ(wxQQJ?LYb31+{2Aa>u|k-'
    'zmhB49|r$>q77GqYKaze5v%&Q9gjB#L$#XP#O4CrqMB#?s&RFL8H#hxQc43QYl5ic5BoVwRdnry8GBNNl|yO~fyIvG@G0mU#-'
    '%kB8O7Xn_=9M3W+kgy%2Gm4I;pzWnpA1ar9l;$|(!oMD~Pr1=S>m_vuj_VcOJFoRCFds8H?jrj2m;Ys&O#YfAhm`**SD-'
    '(S0G>>9Y@?B1K?NHvyW(`<=6Fut;h#FTF_?M__@K8kq)zzUbF!Ce77<TK`L)9dE85fL;TD}u}7G2@NM@&PF%6-4ok-'
    '+4NArly^34Qb$gD$lK0CQA;J36g?u2Tq3V~@m-'
    'Y(|XaMu)RLt_W7n+*Y6&mu@9&%>9=ZeLS)vATd<jC?R2RW%~J?r$&3`Z;=lY2q_BgF0pi_lwHUJw2uS8jrCC0kfRA?u#;d7eS7(c'
    '&LYT+sQ(64H(Ytto5A((h2F^TQT~gSpFgBfmaR0<`!Equ<`>?Ii%Xr{gy^DpnXWZ^X@Uhlkt7Kj0t(y;#Tgu7ICJ@_vvL~F;z%_F'
    'LIG<mz&Xw*hu*GQKBqb%Q%u`0N^I~n!+G9Lfd@}eP$3gJdeJ*<rTGumJkuhRk_s5PjzSU4vhe1ykbSZ!ac~Sf+i!GK8LeAddM7v#'
    '^~}Li!t9L~2^2dfR0E&c^AOV8%iv%df(TkB|KMvaLhc3bQc-6H26vdX9VNj5I~PZaH35=xViXY^P68vTgP<Vv+K|;K>3|-'
    'vfV^oI`G0PF3e{R`C4(ieS0aYB$1mCL*%NIRGq*JfM40S9x$2AiE>V{0Z<TiyAy<x!SVoQ>fz+Suol(Y*f^*}Qu`HEx{<qc}AqtI'
    '7`>Ez9q(s14#P4SA9JFKv+8ldPx+jP!7P?v@KBUFr7#)O9l}C@FR2~68gHF%OFCM_o>3n+HJ<EbpLS4)`BMvQ+;jbQ>Q4M74(*j4'
    'xhI(ozXZ?5BI5wppR%-'
    'dERq4(gtn)YEmF(TmV3ukCjAel?L{WK!i2!7nPE^{IeM$h)q1}*S!SX9@5$~al*R}tFZ)CE99BLGwQr!84%|Di>&DB($RwSg(acq'
    'iAg6be&D>z5PjlEM<AcDcDJOCwOEg_GHCG2B*)2a{{$Khj@|C?TO3n0ign7qA)N^*8#8m|@l6+;cHrgi)a5$}4nG8e-'
    'U3PUU0vKwbVW(dJ<iOQW)qO65DPcc$eb(snQ^IAqDVaQk#%Ef6q4rJ1_ZD=3cf|r|FPrB#Nf{~f-'
    '+q%%3jVe8R`JOPJ5J)tSBF98d=f6^XT}5laFYAZdwj!mq;(tE@eeQAAOfyKYq2D{JktTM36>^EzFTW|{>+f;9<hL~-'
    '6Wmp_f!+LLp8T&PKL!sAZF(H#?bm~6iNgWpAaU8-'
    'cn1|EJ3(uX+MuI}y`2#_&k@e+Yb^y&;=#M)X`Su;!x;>rzq{g59qmu5eD?8dpZPxN%QvkxTM<7N*{7tPiOM=|4i~(bd9{!y6>LM>'
    'oF9oU_DNq;@_eKKw?kH`^OD<rHdTBbGj^D+pML^1qQxcS*?$G2aeA%l9Lz~W@0MsZ?pHhO7N;Tc;+0S$uD!k0WN#swKR^-'
    'Oa*P~e*T#8<jyW4-'
    'q3q|6goLPtv83Nu^gKU3@Cr>ZO3FV9snCz3eP)lNP!)1c{WZJ@jMib7qwx6wY|7<nVvNA~8#vS_Mc+xcEz*NfF96g|gJ7ac@YHZB'
    '2mTe(S?wXwOBVC3bmMfW_-LB-'
    ')$4;qH7IUIqFvWO8Dl>`yKDHDaN(FjTLnhNvflH!I@vPEDGj%H$i<xPDVnie)G(dp#unG_xS_|#ynQ4iZD4>IuNVSMrI7q+dB`8g'
    '6@1eymn4#(yNjnHE*Xb#un?m%qbwwS;rHiK<<zT0vimq|L@;P&%2D~EFa&ejw(!xT+jho$XJlA%Kt}~H?sYod@muZ0%S4xJvhC5P'
    'm33g=jBXXWS&Dm~IO1DK;km@ClyQ`j@!m3}x`C?g$aB@^1Hs(H5EUXmH`yo(_ph*v(QC&ghe>ZR;@K_Z^=nOJCRqC&gsP=o`Yhkh'
    'ZSq9MrXvOAzs2F~CX{U{XNO?3FWN3`u(Ye0A>~oHP)kW0R)bB`pIs#okl=Q32@$;%Kqg0kaZoJ)!7s;JE@?2?NGT3`0ntDOvP^op'
    'v^K$^BzDV^`HK8wVlf%BbK}+VULS&&5vlQW2+g7{E>t%o$|4h|l1q2%-'
    'A5^?qE#Zbq5R)+m|6u{JRNctRwkbi!HVwx)goOwr*6^T>2nzu5$Kqce4Ha$RHD*j;&E_gbqWO{;4Te^vf-'
    '1X@rB)`HK2qUMdEhjBs>Y1|NjM3Hy;7l(BDn_p%C&MR~1yJ<ZK>dg0Zb0MhY!22LZOE8vE$#w?kro&ZkuqthUIl3nGG2R7t<7#N5'
    'pigG2vNLMCzB%DGV5UBQc-Wv<F5nE)2hXXcH1p=-'
    'lGp7Er=^BfL2$d#*6pWN3M*<Ko?Z=P(hdW2Ip#bDVG!2O1s^FSMX9QaWHz}K@b!F;Y~`)Z%0f(6H3CMfuii0oXDUVK=m6A(D)r0N'
    'L^#M7M(I+a=RgwuGOivMglR4-S76DhU+EeFf1F?2v>^dG3|Za$HsGe6P-qZZ*wqQ=+Lo}_6LnVMlEKU%LCPs_Cj((N-'
    'X*OS96kGG^6&(K%}J;r~aG?8+ow8VYpBP;Zy;E~a-'
    'n4p^Kity+x0qwwkux!&C>bGOeF2Z=>jX(HSFcdIbB~W}|c+%NGVm7>~J<(zl>lNxq^1Gf#{-'
    '$K4R!CcXPj8EmN)kkS3!h`aSkVBz(lTMgo|8+9l%Fb)E`!%(<HC)7ybIFa7>LlRG$OsXu-'
    '!(wD(W4L+6VNIA1bZ}%lJYlpY$q|S#5fmy~HvPup-Bp|4cKG+^KgZuL+hQ1T5`46X~vxPWSS@Vu*nY>1ll_!R@=D49J-y&(-'
    'Q@kwSSq)bx%VN%11U0|o=m4Dr<FMJ6ym`MTSa5sP@};-uPtAqRnXXl@89nz*HyBeYdt8l6vSUO!nQMm-'
    '8kT?sV@4sE*M;}V>(fmF>CiD<e=DNXawygV1LDOm4bNBE}R2o{V(o`Y1E^7gRxHOumylkYi2WSCIPmgK?y8!pjCy4^bw1#uE&pt9'
    '0vT})a9o|A>$VXvL2z2oW6$(#v4hShZ-'
    '&(K5aF;N*MOueZ{Zi3V>c^qxVef$fTP9}B7$yzsu<jcg_t^L@1OOa{wck3kEkswTTeAPJQ)}$O|W`v}IBJZwtq)?MkhB{15!5>l@'
    'jRP5L(h_&}=WXwLwT!lisS*{57ad+cVw-|}7hGw!(-gK+R#(Bti$tE2os+_%Y4VLcmYxo?dRw-'
    'r@GuN1R<~n50;L&aMv;N14x@czr`KQBF`qw-%r>s7f?pEHh)Hq%RHM3aKN!$T#b7-{a>saio??+z)r0OUyP-uK=l_Rs4Vg2Jz$sJ'
    'C<fZ*pfGjl@eCEkOKq?Gp)>%Q_*Eq6=U^7xZblgyz*rcBQStAK9&5af>Dp?3pHmurxpRT&Bgl+J069rMHz}##r4h|f2M6_=JW))e'
    '_E9OD#NU!h7z=TA*8&o8@f&>H0@pTehCb~agClb$#m*^<Z{<^cj3=9gsX5+<!e7n<lIeknsDNYP7-_ttoMLir9({^LbL-'
    ')c5XSJuq(3dUEyi%<|OUR-<Vd5UXZzQ*wb5i}3P**GtHRga692cyGcsXqLP}2-WMf;;D_SvgF>XCrSR(-'
    'V;;);sUBq*mq_d_F0>@c@@T?vps_YXBgyff#BIj|#t?%so%VgFI<RuQuF9wdN|t)e94vH+H-'
    'Kn%CRg|*~HPxkINhyVD7UcKLKzqJ8s;R7Z-R+-'
    'H{pGFywZAaa3==R5b%FSuE+Gnqe*xCkjq#J@E_zilY%T$6ksjFiM3&V>TCB|bF#a;oK%C3Kp*=v$yqeQ=b4FTP6Eds6SD?+<(hh4'
    'Hc<(Y&JahkJSsvc48t59(zwvR$pZ98b<kYCh1m5_X_k0M=d(`Ec6z?JOZ_Vd25t*+fdsDU#ERah(}H`DZ(TVftga1-'
    'UVpZ{4ClK|{wVAh<swo-'
    'z3D+2CpSE!1SUVlW8gimvH!u<Be&GoMiXzFPLL=H(+c11cggRSl~YI|6P%UF$Ik!u;ZT0bjj0=`efE8a*s&Pq6Z9Ch9JLkgCA?LW'
    'V18kU(j0AIu#PL5b6HYQJTt%h>zO7$Rez_4}_z61E+OhM}QSLtlown%4@Fyaw2???Y*Q|f@ZjM!Im+a70$!pBu_mdSfoj>dm{S1;'
    '{eOgm@2QeO`4F=$r&L~^CKNFCJEo~x}@kWoiUYb+e{$(<9eN5$a2dwndBfND)xtl6(&xRu`NXQ6p#Y^7x`kd6T15EF1W%{{fD#P|'
    'AdvqwalHD;%Nrmmh?H_4v3i>-1CI*9-'
    'k#X?yOP@*GO+i`ruj4i?ON>S>Cl4JJUR}F|OOgaFDJ*n@zWcXQ&mTh#5da_)@ADtGgvw{0XT1uFzm||xQ7(bPEQjOPVGw{cQq(Fm'
    'R39*$bZPqguyCC${w3s*EfTnRW?o_!fn&m_qH&x-<-'
    '_*Z5d9IKslIiE%`kn&I_Jcfxg%F}yI%e6cET`{|QG{v)XD$^1+)$G*r0D@a4n?)7vfyL<i*&1_*Wvn~wb8F}j$e4=S!~!!>|0n^)'
    '+K`&EUgKvF^*0}4Ty(sJw;}4%lQv7ED<kxvd$-@ltZ=Os9mB8M>>m2U)ly2cJ80oE8*S6aFQPJ@)PY-Lu6zS4b6BLty)|1KGPs7j'
    '$Fk=g$>|{-*TMZra&ZuAJ=kOH&pP^SPGz+7s2dA>`ft2E@eXLmx`m5W5(Z0-'
    '(=OK_aP<>;yQMFA&=L9>DcVnU^`bUw>DzT3d^TqMJuOm5(wCT-;MEHuJw}U0zKU~>2<c0cdAjr$-'
    '>$A<O&UBx`+=qAatmQMg{^MHE;Rura&@=QP5_&u}|=R1s`VZ?1;C%_&M%)4{GRw`=JF0n7vEf^@lxEP7>mMNyt<$x`nDx%Lz!ZLz'
    'a0Sczu3d*if=T&Umq(@)J^AWt#Am$o2%Acpgn|0LdRCo2w+5$y77*mZj17@fQRv#7GgD*F=k5^n$0!$XZp*lFmmKh~$YYDu{`uO4'
    '&hubvHu$Bnw*t<TA0rLx=NZo|E$gFiWDtDRB=ecr*vg(Y4pF4T%Yk!3n)&;L7oaX7g~x=ym<C_b@D$HnB9{U`-'
    '23gSXeQ@N8i76Z=k`a;kYMzuJ=adCq}>=iQC=g^#sC;{ube2oCw|Hy_1k|7_u;gV<TWu=U7tV9I;vz7w4o>NRcS`SP5zQSJR1Yys'
    '_idnDw-'
    'm}y`8k2v$o^+z0!I^oz)SC1+}5vRb!2Jo+Au<jFv1pn@Ilr)LB4LCkaIUPuD9(*;U(JEb}q^w$_B<LW^xMD;XhgA8Aydm#-'
    'lQ$)YY6#%iA-b;bv%*C-vv>?UVj3RbCO%(f<$RZ@%-'
    'wsRQLD!IA_h;|%N0z#;>6WgxRu1&a#B7*ZM%~3M!t^AijyyNPj^FsUOJZV!q_&9ZvCziCQ`RWGuGZiRTJ2?&nk~1)>Dq&0u<$T3@'
    'vG9G&4JX<0s-LhE7SMYW|2c5mDG(hZdIFzDnBz+t2D_GQi}dRp723j~jHo5wI>vUx0Z8-'
    '}p)Wvxo*F8G`};7B3E_&><DTj%Uvp?C!HH&wYnDonGq$Bb!8~M!b~|IZgA$sKnEY1bg$an>BG|G1|dW;n{rIL(Uv?4##@Ga!W6^@'
    'JCn?F_8{KF;e6ZjHj_aIzW1`-'
    '?;}3=Q5ov;xa0fVuEcCXRMbmT9?9cBkhoTu&_}Qh>}d3z(DF^x+v`$fFcnzw5<Aa2)v!Y_T(?Z<Ch4|Gve>;b~m3Tt%iku`V%D;q'
    'mpGYv<zWtE2ztn`H}jup5HjZqxC3W3pLaMwWE=DK~ceR=qr$<smL>*a#tM+=xOibD-'
    'D9VbZ`v}Z36+7yhx0Ir*DrNOu#je8%H*||BhK>bp5L_Gn8*a`vzoj^aCBEKLRD#VeC?-@!okn@T^@_pnSf|1H4tWwSGavD&@If-U'
    'e$skd5K$TD|nAdX59z_rO<wW$|5v(7_IN9heEV=Z$sc6djmJT$T8L9xWzZr1GO^jLUNxcvgpuc4UUj(-'
    '(Rlz(gUfdsX=V<`0_jVi}`(R0i37MjDI%Z!f07hDX9i@hF*Bh!P$8IgqL(<Sew;Jrvyk@%(S>9(Z9*j=R22=YlOiM_&ufT|Cyty-'
    'J`Ar@=!j1;wx-NeAqWPY)Nry-PTo)7aiCD$3?f8bAmlP3tb2%tTHNQHV9|rfb&T3&(aSv81#_x!2~c;inL8U91kuq$Kc6WkG{g-'
    'LU#d5>&}u$Bf5G(HhS#1I(wA{@EO5VfvjqvkAL{%lEZ(2`|B!Mq~Iu6!^#A(PliOswsSi-'
    '$D#%xg1rm!~_V1|BPUbg<y~$m^vcG_QI2j0g`qjv|m}&g!_u}jba9_xY_G>D^FZ9QHw!0T*zmP=s{U&L+L-'
    '9O|r>P$vnY`Er$N?47MucZEd;2Pm;*}#z{C24nDG!%ygx6$ts1q%>pBCV+kFW*vc7!WYEdm)((Af&m_=P*^~T>4@2kqORVMGM7u@'
    'xg};6S(ZTpxkfn3<j8s#=BMYN4{Ka-'
    'p6XcDBY5?MMZu^?uhlx9VAT<RyCh3{`vdAZz2M<}^g5|fndzAn5FJ)&N8|j88;}ZwoI^^5`>P2J)ea+tT%PEU;?zRWmz<O0EqKOM'
    'qC=CPK(9HeiSJD=_B|-'
    'C(`7Cj7m@6UMenS#EbRJsyS*i<@Rc}N42#qp~C0T8dRFY1{a(_nm0nU#`RZ!%o5ZD>NooVYxPD0FmLqfmjsaC0;ck)p(ca|Q3wEi'
    'z0mRZCBQj71tZ+@^M_V8%PX!_he2KE?f-'
    'F$G`Au2RmG5Q1GSU2fp{P=fPCwAEwOR*r6`|)lwT3l0v%50h__j<=YvJHU9R$t)Dkeb5W^`fLr;IlDssq%bNCVHct2G!liA7)A&C'
    'd=-Zp4k@8(9w{kZg@WRuMb9k^27Ks=CXh-2-'
    '#9#p;7T)E<uWyfvboF&HYv!8K&}sAP6=e(Vo#r0uZ0!z_OQth$Qs5<oE#wL8~e8`QrJw_q8OjzJ8i#`*v-'
    'AQzp0aM}R=F*zkgs2ROMnY#+dfEs`SA_yzbTF<L-'
    '8Fg5^|beektqZ5H3trxUiJyykbY_sP1KO?wj6PB8e6|DZO6RK=&qrzgLmW#Z_kyw1{QCdr?#Gx(|Q8)p5#%y2@1~qXjh9U`FeJW}'
    'EkxY(rh0*zFCzIRVTZ!{qQ&%nTJDlM!G04=U!m~OR`ARUvWu%Y&(^8e3q3Me|^EA{6EEdnDHmFzL5YRz#7@}P_BhN~)Cd}T09kh*'
    'zB->sFq;Jjnd|~+OI0(;KSw%fbsMR}gTEtd1Cz@I)*A2E1IaMh&lOH7m-(aHLcWf{IKFMXz>+cR_Wduv8!3fptPF--b#pW~K5s<X'
    '>_=JXF0?`)VYVpfvTTZat@jG^EV$6@vq(UiHsHKGl%7<V?pkI*dmC46ByXwE|@isMzUp6a-'
    'Wr9xuZg;UDpwR#lr~}*?YaiK3#x8A3+xdws)D-?F>bPeIA-RV8NSS*f+-'
    'FA`(#l<$i6s}${qN~5zDTVV5=ALeiJa(OdoOJ#zGw3JnQ}e?;r%^-'
    '%j%lRrf%h_o7q#mzp1I!W<3{Ctm)<pd^<O8T6~Nm(Rs1N@2XJ0e6~9-KDUG%#Fi`djfM3RmLwZ{^z4kgTM~17m3J~Gx2SFUY~-'
    'B<AJBN-'
    '51NsbM<qBqYw7%@qU5upAvRLnWa*G4B=c<24R@x4e>WIH;k)v};Isp460tbZDAC3f2;O6G=U`RU+F5P;+g)+N7)ObKI+P}lvrbsy'
    'z)WJL#odyVR*teUjv{arj$=ag1k%F@0$%FrtMl|1Lgn$sA6P57kDmmw5%6LKYu)<u&76IE9)+6ZFET!KeQQ3+0`c{SnLkUh#7nge'
    '7yk6rnoO(R*YNqePgvObrqK1V!AEWhB0NVnxT6QVIhr;Vc!5UNQLjxg0>=nD+y#bA*u+Ss5IT=xkm${Z*{J~j2NS?S<&H9$G)}DK'
    'yu))JFzScvq>zX`Y6oF_NO@zz_p^;cszRB?7E#5XMhUx;1IM!5%>fi#>twveWswDFt+f4ty>>c$vv1lI3RtpM5ho(<I5{oCc@P1Y'
    'FEN{_7RnoY@VBYzT;%yGxzXlXKM`ct#ld}lxFUL*NJRA^Ke*DEq)&Vq9<LO1Q!sk!+6%Dx1LtaPklU6lgtckfAI+!gGS|D+tpaM*'
    ')`G!xfOak2UpbX!_tyh?p^$kb{o1?u{g&iP8ZbcT(mZOQs=2^s-bWnKPLIAzv2y~ZNm$T+I-'
    '7h*hRiWNI6YG~D?jEDh_+UJRL9RmC#!S=vaNFJ5SA0OCh;GB>euEmQV<4)Ub0osW9{D)RXu=f?aw^>=dNzC+4n=qrP7=mNAAX<^%'
    '|Jb*vz??lDUL<V#&oF6w@ur5y#|fyZh~k5VlZ9JdkQ?4S`dW5+bnge?>(6;k)Kr*QqR-gP%za718-'
    'k&9;mFz6;_k@_FAhH4A3wE?Hd$*^?2j&;%U;sDE#t=$k~N#;~0X;a&2+5kmPV(@GpOp#4eTWyoL9WAv(CgnlwDnXq8-'
    'RIY82&>g<VNQ)hPCwc(z>|t>i${)byY8H8B>#F$S6x{}R3gS1mvp+=6+zc|Un6s$3v81EB)X#aES>y|I6{m0sErae4nxy99gp8Pl'
    'Y4|t!^UVDiM)#&#!^Gca;;Oz6zyB7sJ_5^&>u^=^3F*os%a17gF^`}(Q)6b|_@#m!{$Aih)#}oYb^z}P?CLz%K!?kD(IX>P861-'
    'agzG#CXAu4{agAhyL4FOjE%qnG&UUKDY+3nG8n<7E!#Oe{(lr68at%7c-'
    '8*U63iid`IeJRi4RgZT!|QS@$icMwx#Oi2vT<uJh{hpxxxSv{ogEV$c{e_T!P)J0b}XmQLxzT%EUXZ|MC@ViSH0^6i=MYj({qgj3'
    'r7sKIn5CoRvj)Dq9Y(JWQ~{!2DUDwGngoYwlZ*})x+=as(}iiwY7+d$XGl^TN<kA{TIOv1o%4sesbS8Zt+h-'
    'jCG2LT;nSRK!dIn*{kZTiiQRO;3F>VDD<E3qGg+&<TS%DK#oJvi~D-'
    'fP;+B4@^t7$&4!Jor02D_pSe)5J8CeihBdv$3kb4o(oJmQXUf%ZUP6Mn9eH7IiAfGmICJ$P!>L@{)u}2_9F<gQTkJHb<~xemSNTH'
    'NlB2^O<%7;3;6Nkn<vS^|vI$Y^^z*YtU|T6CXEuC7-XNlpj-'
    '%DJ>|k|kXAFu6yUuqnrqjUSmuCtxa|`AzpTD{_zBUGL&qe_jKxg+{*h?u%=#`xom1ZJM`Sm9kF>J4>#w=PAz9UeF?n7v`JX*MPK3'
    ';|59Lltu^zzg5yKRIy5f%V>52M_&Ff1f7`RHFQZE|$uH|o&gOAg;?`jrrkouB{C@IQ>^D934(L5k2GV$>XXS-'
    'F+y77+Yv_A3hw@I0@To9`Jui#4~T-?sAQpZ7b_X38d#IhjEaa2KIhD~JD!Tk)$G0$<nMjco50MmhgeF$TCiCeAW|y)|S}1c-x-'
    ')lObL=M>pkos7Ssp(9r34Pos4?xkXm@Y#NHitCG~H=IEnac&(D9N|3e4cm5KwqPEED(%Y2ziFCW5{&PFP6t#pkeG}^;CTK3@{4tM'
    'CNjtUtkgZqR=dZ;gk322j=5M&Up)aCX*^M5cBYs|JX1s_X5;b&<@%!-'
    'dwKN#dY}`A9vEH_6UU!QB4s49Uea=#z;_lmQ_;1S>H>Ov+!`XA-'
    'Z>JisAgXLi7Am3{%KDUjkh@}PN3_ioQC*L&40<vEe7I?h~tt8$a=MXcdz_rIV_KrkEm9uFo{6bO5fjs1lL@g;C{Tp_W4B8n$x)Ay'
    'QplZABt`Ck|h0DJp&kzTtT=BpzCw&A$+Cc@P7w$?D3F(kh<6_bnErGwtI0@Y{#^hMJ(uc!SX(~GEDC5L*zX*Dt2`QURk}3xSLtZZ'
    'fU#~sgMH2HAgCi+<E*sG~0TBU3dbp2i?hb5Y|qq4oGHg$1IQ;6M<v#v1O}wPM(pjYBO9=9XV5Q<S*6A1Jk>co41x#bQd=A=Ez@CJ'
    '}<^;I*B3-BI>s&+p~L<xiB8@Rg|m@vf+X2=(oms;d0gRHjj5|4sE|`B|&k4p&;x7MSRs>J(<=Jny5!I#KY)dA~|KTXKSGL4+X-'
    '`lU^jAXZ_qr>^=1NLG0UnS|bChRhvudvLvZblle?j`1O%;^8oWIBe7KzL9<^v>&jU1CsC;RwqsPyEfA8%B(rKVv2|9mJnAZUm^lT'
    's$Yd-21n2AW)VRFSfEw}fmMly9zv!kUZkmhw3GI(!+no@N8M`Pju4$(H{ybQ$NEUgE(cGQC=@*{-'
    '_>FM^Q($+GZfAz{C*5C!hv|MpInJ?-'
    'gtl~0_&1ohn`XLI=#FTDscJz8n_B5&)U`Thb76CdihZF)yRzu0b7F!aEU93<;z(&P|F`)foML;4an%xx|1;Rh%AZ3u;l{*hwamL7'
    '2hyIt6$;(x*!y)+@CSsx?w|ir5}5$(e#mXYP*iK|p|eKnB|Hhx?F@qQy+vw;G_aGpGqD?@G2WqBJsUr2pyYFZ@)fxY58+($22*E~'
    'fq*oqHhl{(5Xetx+4UJg(IqlNMFir#Ebw|g1i?qo)FP!%^<Np3kgXBetzX97o$L0*fkv87wG>jV?2gex+l<}Nw;9T}5{O1m3zzpp'
    '<)gh`&(hK2do9iX1#KAwuCudO{10-'
    '<dXDF4yOY0ot*4Tyk3hyl$!H|Z3F_KG+5iPASlLnDpiA1+PCh+i(8tA?2ONX)DmuVzKf0nEs#!8u0~z>gL&Mjyf**VtTPav{%9Rf'
    'f7a#P9x&X9bLE+2w89EDb)SYbHA-wfX&AD;Nq;VM8g5Lx3YVffgm}sQv{v#9hDmxtb&V-'
    'acnKm0;l3_IEmwXrXVxmipe{YYV$Kx2g!1pqy+aghv;Y=cHl{4Q~zW)i4PDmIYwB6EcR|>lffv=oDc>e#o((VbsQY^|ipRiRW5VQ'
    '4u*|+5s@Jp}4X@T&}+*(H?32t2=`JTL+@IdLWvxrS%kt-Z3r?uW9+QpB=WOwxL?;`e`DfVw2<FvYfYa-'
    'T00KcHA<xn>h7sVU(z&M>U8Tuop)kYn@4#n}|yS!>yWg<V@JP2kED$UQ>x318JcPck%3WcMz)6+<g(U^08>R>~^{pFZsQdzg9<7c'
    'hD?>|h@#?vYEO85^!OMf(#L8P%22);G;6{76}){TEB_e+1h5z-'
    'j;dmsQNifBqpH}A1l%)lYSG$4DYqi=6kKpwxmu^o946}QK@64eS_7p|D+*{+Eo_Q_xZKCqddk$~6<9}?}`*a$}A;pfZm(pPMB+0g'
    'Prhb^PJJe$jsJ)gDWBa#(R`0Wo=mFeh4xTT8jvvP^uZzlk2e<PB_*)7NyR+<FRpi-MncIpvJ18h~`Ya*^J^*HL$*Acxu=#}3*En+'
    '9wUI+xvCcdzmWb0~T+?>6{hU95J^(Jyh08a1Iz-<2DsUwn^#faQnNe*8YdhYD7-YNkM(cnAZK+9l4iH$-'
    'od5&=OoRi$Ip;kdPn}VD*uQnWb7}Y3Sq3km!lVcOaj*`SJd*a-'
    'yfC`cb!ssSN6?f+$^4={(8*<xYHQAmn;JiZzJyti(>|foon@c!U4Lz|+jDSRtoBO8g@Wf)AHRb_jQn}*(#(STnH7)DSuBB$CS>ED'
    'D*K3(?zgV@O4UzDRk;`$NDXm;7j{u1VvHV!B^V~FQWCl)eNL?@kr|8rhU)9k<B_Ed4<)~rUEwV6;7FR;MlR#xVBk>FuyDk~eoP7q'
    'egWt4WwV|E<>;;RL;JXGBwFP+BsmZY(evTe?68<tq&lGa*#5tBe|059%bd+YdmJu{Ncrg%GCgSsaInW01pn|}AI*gNVEYsm$5SLQ'
    'LKN5-5xNf2p9F^T-'
    'q!wumx%p_53V7%`st3FwhOohRX(IWW@TR%h%EWsHqp|j@LX%EN%h()IB)k@ofr&hXW3xbxClu^D!l0Ul#m?H-'
    '0=Kd|EO~U<{yD(wWu#E{;dT&8d9S;c_i$#z+3mf~1)LB4bfb0!-'
    'MVcnOs6VCL*MQ88o9@?1HT0Vf$?XfNFYz_|70!57}T}%=c(+sJdh!uJrY{ibC_*~Dj}(I?)N}Y>3x7wWoTK%;s-'
    'sj$g}3Wu5kH!CUa_ZCEBJjZ`O3NB3AHPcU&80V4Y)Ml?wI$3yg^cR!l6R(~mp@gU(N}``9>^be_ziZeU90yUhxhP`v$H_Ku@&@AM'
    ')6t8ae9&84F1>cK=cC`>|Zy0xihCAaYObe95IN^O6UUgk#dV_6VbqJl$SvCT8J_GClj#IfZFr@@F%29b9Iu*H~;C5=BOL6nY^BzP'
    '){7U8%2iH$(ZQG^RL^(3D_0{vF;rC&3h-'
    'bV=KC>5`jj1&W^+ErwXUgg8&#9&EDG^z|L4Y3+6AB_N|q<pK1Cc%g{@l8_h*!$=DYW%S`0k1!^?Lo!aL<^?0E0fT>iyZIHU}ubrd'
    ')T52cTo%}#X=sm$>}8j24fOoBW>B<zz^kUk)FgbHPmbu5Bc0{%17=||4RO;36m|16*RR86HPKQ&d24O1?xo2MrF?+8MFRr+Qu5Ql'
    'tHut#`!l-3B2c<5HzZZzA+|R&sOeCjs{Q-UFDODK2^CR7@-'
    'ht69*{HgB5{_LArRnET@&GYR(bgqO>|Fo~><6*^JYXj_uxjAyNHSrN6~9oYvM;HDBO=(IAYy?n&5P%l{b?^~Q~iVm=x)HITASgE#'
    ';~YqWRPo0zZ8QRk{9NxK2m>az@EtjU?i?Z0ez_@qtqo0GQd)CE1?ZVd)sKbH0S@ujke0iq>3AugeLYxH9euh~j7gV-<)A%q*HW-'
    's*s=gS)QCBpUot>}_abS#6<2>2CdDyx_1dR81s%&!D~oNgK+4XJy6uSCO8S31Lw0^HIr&q9)FnnfPwIYVza=GBN|!}J)gTT2hA3A'
    '>D~1|S~=)YfDlP0~#^Pkgk)<-IF)hqr-_pOGpEE_&v%@!y!(h+{W-'
    '4nbqb5e$2jtMz9hNaq5~7`9?eEb3OKwF|?rdbn?ew_UPdSfez!u`%>wzWkW!Y)o6?V&l7xl)Zf{*iBweWnG6kwXe1H#@5*JWrW87'
    'l=FgniAy?zHIvG@BYY$xyvF~gpW74yNagNC6+~)gN+i2y>1k*>+imy`c+HTg2%SISYMvQ@<5J_Ni7d<?JCIk@mEv#n3P3js>|;Qn'
    '>PIHKATv=TepLoAkexwWnz2x=(O}+6f8Gu$G>J%)860hE!E={}1ND35>z}gMPj}-'
    'z!qY@ghxdkECLp(<m2DxS9aGf|qvCY@UuIc=h=ub`4;g?~#gVwqBfT{P3R_s@b_Cl)jTp#3;SU<VsYw;<;HwfT`8?Y;;D}TG@X(d'
    'AM>_;1q1d)ITVy2-j^&`(pjx?A1vk&w-B!vWi3SE0S!Rn#L;tL3haqkp3>W|RQ&O|#gcZ&svPuNJ{bK@jZ=<`{l<mI-'
    '1rD<sLis2Tt^=UkwHsT745pr52*ZT^<WyW?+XvRQ!KlCqTkc$eG~5g!4q4`=y~f8qJsR{D<>6(eTp-eEA{(D7G7lsm;F|(%D8glz'
    'XHv`XBW8$G4uB#!1ZvD-m14<nC<rtmQ~;F2X7%C}#mQb(LBvx84pQyF7tnP`X27?qQ`J*fN??Cj$@FN|eYgwUfpJcUCUgYZso=M-'
    '-%N`}hLE|Mhk9jf(4`@!|9))L6+CqVnz+A+<K8l`b1*tFTp*}PT{xA~IP;{gFBUn>f&h;s|A&yKFRX}xX4R;l5?96Vj5y1<vKehG'
    'OAV`#VvS!n`{<d!PBqS@#hW$o&58@_skg9;S|gOZgt4Q;x44g~z{vh#cUxd7jbXV&W+Q>7L-'
    '>@Nr;NUZtl|zdzN4l$7X|T5=&coFF)3T1dI(ji_9X$lTnYQ3E5V*9xi3&}6*R)S{6{~OAYFV(pl^S_Kh6(XyO@iIjGlu0QlRyDtZ'
    'h+)jym905xBskBTL9d9mu%~K4@yENhyR@Y85|s_x%*ug$X!2$o$v1f;k6j0JouujOghk?$1D6vm0<BOD(!CMzH&uI#2&0SDy%IIj'
    'V0YX(h```8TZPY@Fv-1%(jEvE}4x9(;sFXf(-'
    '+hKH@4W~25PabBvXLQ&+8Ra)K+JSTq`#RfuC{Ho|fSz=&Qjfl;l<<JE(x2w>D9~Z33^T%Nc6qtZUG+U|mMOr#GEFG6D&1egADqPU'
    'Ivv8z6ZuzZ31YW04yf86k7APzqSP3}skP4+N)kiVd2r84Zm|`7ZZ8ioJQ%fM&lfDr*UMU7Oy8MVN&AM|1f!dJcnE#?<&?%zUhm*o'
    'mw2S#qbCqZmt^4Y8s|!OE*0Y^E7_x11lmI^lYU0>#&?E1PkAfg(j3U)D2O_<<0dQkR+Z-'
    'Ns1Ju9DU&!}cCr|liTxNE6G%N`zn$<a|RBfpMU2i2C`G9I%e7um3@&Wf32%|!V+gSbumc_jS<6KRuR6pcGZHz0s0|ywzDL&u28;_'
    'm$+T?A<V+5FSaRN)j_=1MlD#VIzQ52&i?d>j7eT&%t5$uzUi*dm_mSop{Ks?{gF6acQq2-'
    'n6_0+#xoN`^+?OIRVVSw<T{d|HFn3l~ttkBa4<`A;CK-EMV`KbD^8|pk+so3BTGMU7QOyEMO5j^!Uzo{bzBF=rTUj`5~cl~zV)<Y'
    's6)wX-y>b2w_MBolpod5Wx>i_B1&U5cKDq%JahVVgwUfKln0-'
    'fj!ARCW<!6e70^(0`%RHlu7yNe0?K2^jfC!aZxg}T{iKJA>l8^cFx)O-'
    'n8%NiGd{EJR9HEC*32JXB|8E!Q6;b}e&d^g+I?RCLMT&TvZiI;CpZk|!Q;)X1SP~Feq5;Ubzz?io-OQq+SyOLtyph`1i28SOY1$^'
    'H~{iw^OW19)D_WesU)y(}c@9M7IMr3@R!>R{4&ul42{F9HRnUrWVz1U4b9yr3OFc`1A2H=PNqBpYOI)Y!H2-'
    'DY1cTX>`n5xGLY`2xJwGUc{?;{tPF@6PL!pwOfhWNtx#m;$!%{r=8Hl^Fk2Rz%6v7x%^4xY6Ul|Dcb3Ms{ICYf}<VQ)@N<4aqXNj'
    'z7t2KZA-'
    'M;_xKajc?t>s31#FL14C+fXPSbU_yb0T%VnFRu>#F;<A@gmmZio7^Dek=fFeZT6Fe$uKra{X1JjH!J4+pN|V!cj*2PF_0#9@mRJ}'
    'ov8Nvx!<bNGf|TR{z;+F<z%*GR5?y%2iDoghVex<ylI)|s~O3V@Y85i%yf}{h@?Cbu{R%IBT0V@-'
    'Wg6^aML2ts@1g(LR*db_^OTMFntJd5vH(EV`A==kgFS#4?uhX?`F*;2FpZ}M%k;6b%T(^(od@8wDtbZGh}sj%a!HuGAcp+J7`KH%'
    '}JTR&S}t^#`G6?K8>e|^MGRTVj$~4uushxm!VByp#X>>&W;fiTR}>VW^*5$9uY65w%pyjbK62nVb2&rr)*B{Gk^FDaA2_xRW66jm'
    '10kYpKaS5Ii#27Qnwekfn*p&sCEnL<W#$YGc>($o1|4HtfeTjw=<SdOy{(N1a)efe}mg{xNNa|up_q_ScgvIRw+?!f4I?{md6mfB'
    'MdQk3eOQ|oJSZY{$)jEjiw$e=ur60^5sWYwgT&iG+`_(rnYT&7#5DXdNLL2Qo5jMB-'
    '=chZqJEABD^{UOBRib`&;C&a}L7#xRb8a3k3lKHR#vgh@kDqhV@-Z$D0$BV)!lPR$e#De9`r=gpEhi@6}MvA~=9UT{cW6s-'
    '9@wx@|9`Wq8FFzWDO<XV&XT12>U-5|CA$M6by@a-2Nz*`l*))%NJ@q<l=0Ke5&~{lA_5*5$RTZWPf*FomHtPJ~`Lz>eKmf5XJ-BO'
    'NK0ZsSV-g{m1|yiM;Tg_;pfRQW@`izNGb9wIdaGl$bX(K;OkW8upRcH_`MSuvK+2gSEDfpF=%ZS|wz#5AF7e)|b8UBU?ynAFw6-'
    'vqfru|3nEl@*)+op4q{?EE|O*|x9_0W8@Sos0k+>^@}AjhMwf0v|Wog;>Py#n{Zus=mSUBBjDD-iwXstYaX7s<JE*N|<W!DIRngZ'
    '|g&wPIC~v4)?$-'
    'uR{v`5N;*3LM&K3MH{!1JKW3#C|HsFFdO#>qe#%Htv}Znl=oW5=vE8ftNr%S$C$&Ih{5Iznic{I6Fz@vsjdkV4Nl8*o)3J7{GcKg'
    'Slspf293P3v@nvE*NEjd!{<~ThU8@s8pV&tIXFPccr7Yr;C&VCPpQPTaG1v`I+Y9>ghuTW2_y^QBDo|C(v%wu%X&`~8P&&-'
    'f&3Sx(3A(g;w+%7zfLu`HNpr;|J&m`{|MO<RN2lrpbIIzyAg}L^}^BfZBOsIY$#HC5B5>ZX0v#%k9p=IP}hub@96?tv(G?1FA$Nt'
    ')Wkxctx-Yfy*RjEaHPkM_I~aPz-Z$0KZBE4N3e?I33oFxF~RuEyp&}Q=zKLkOJ+V|4~3%EJMV7*XIqx223*vxGiMDa@Ab|I-'
    'M@YfG~N8>c$r1BN1c(ddHIRWBZ<Fgj=K01yB<$XkSj(hVrl`5WdmpCegD(~jU+}eFdwR09NXz#5VGn9L=U|^ocjid!dW5KS5a3z5'
    'b`ykXzr^cDNG-vfzG=^%ZK)IeYfd?yuyO(!*|c4{(S2A(!?0dnM)GAWl{v;u^bhhF62h_`R#I$%cf5y=LH=$*hZJ-'
    'w!v3Oln{yTD?Rem=T8IppZ}^4%K+??k@^&;zByRBZoT+8&WGx&ENT)n#uzVu%?3vdYYaEua^b2uX0_%Zm-'
    '*zU(!~PkaM8wFgvO3bV@`2}gYWH1S<l+y{jU!P?P68Kw`Ig7QBQ8?>bcHVDGSm8bT>)d$_jx`*&Z%euY9XGSdaCfcB(%&0nsBUnh'
    'I;OlcnQpgN^FTFdw26btk+KbiCDEWIYQu(rcX`hqp`l-'
    'BKcEkJH6Jfp7wxGA64h83>e+p$e@ZM@8?$pl7z7ij^DWhco>v+fixe%erhRJ#K#+Lw`u8Epa}7iB|%4;M1e4-'
    '~G8mC>MZfN*J1(;oB2Tvjt|9BgSe))=lpykQ@!EaG~Lwv&!A{PJfk4Ll;l0tmvqcl!14i!};l%q|IJ|N`z5mIir&$VLCvAZD<}GP'
    '&F#1ei964yU=I*0N-'
    'bLnOi0XW@#Ott%Y@*(%3k8D6)PG8yKilwv?rNEET!rGq#G!(4W3vHSPt%x8m4eq3pLT%Dp*5LmR!QH{*^OMEvx{iTOdWw6OJEc|?'
    'MOR0^f^OyddxtXOg{+*9NwobhcFM(xmzZ(xF9_pHX|OJS83$A@PsQL4&YrDROi_%z%`Eq==^re^XYls}8pBp}V7*rNkgrEOpT^`h'
    'Q~Ofr2jJsvc^$zbu>vI#LsWANg1vXF|<l+^f1UbXf9)M1d(r_p5(5UQAwIV7&>>k1N}Epo}!fB^6?#~scPSblsP14<U{TUdI>a^U'
    ')oov}bY8D{4?m~_LPa2?0rA>SeuCDce(JWp8iwl=3NdR}2r;_1}AWOS|v7LHT&Frv)rz;pFmh-'
    'e+$3C?aCd<;U*j7(aBMFEu7QBLH{Fv#~lLjCRHQYEHz?$?2CJ?#KRt408I^8StviN^xfjL^f;QqKwTp={guTjZE?G*tmz<9_o3+2'
    'Nh+O*;AEq$?efBFtaq|IA7D9U{mPl!!mHtE5G7ioz?<>mlWoU!(X|Yd3!cw3)GJx@c4vm)cGQGx?dIq8fjdX>&DxKQ^NwH_NDyWU'
    'jixgHb?@Pu*~Qjg*uwBKd4X?A#@aYsh%Kl-$q>^!LV7%p8W;+yN4GF_gDhjc#L(NE4U~_~9YkHgL|qNReP)JvejVn<EN~-'
    '<1}fHv0?JySxb<Vsh`#F7-'
    '8P$~M(@AKa7Jj*0_zfyTH#Vu^K5MAwSDsZ;rzmGqGI0Re@IWob<UMoejRp?w~cxMA^H$r724xq=a$p)X&AJ)cD1a>kyWf}#0M5oV'
    'Jr#9b}UpL<Zo0ssV-v#|-'
    'JX;FKUliMj;Wob)GDepB*R6!Jy$tKd4wY#ZVq>E!}xRh&ns$I&sZb1d0mSY*TTryMXm8fwT!M@tUg#eQx$GUqXPfpn*8{)}weUWV'
    '`5lT4j9+-'
    '&*zq%@+<=hpdu1d<^5$OeMb9otwawMwHV~Kd54m?{2^dNlLkx}@KleS4aOUs*e#7B%k!kTOY>=W^j@%o3rKm{NV$@5W9c*^ZB#>D'
    '7pBcIkpy?=TD*nlsRV3W3W&)Et%dll+Y)z=K*`2^cE!GXq!hYt0n&}bDGDV{G&<Gd~i&*lB&v9c9oAF5(8BwY30rCE&bX`>T*H*m'
    'UD`(4x$k6qfd;g1wq{eb_+jz{9+tFcWRE81f1nj4izRDL$JLkmekaMsJ`09A3*nHYC>c`;%CKAgw0rqegl9JhYF`ueT~NX?+#NED'
    '^SN%*OIma`nV$reHu%GH;^ZbuAGinn+if_X<oZ4otk1xZj2Yx!gK8Mhr0*4c&t>Gy2!@vvA9t(QA<ABu)e_?BxQQh=#nOi7z4g62'
    'h7>lReUaFx^EuF0alo<<j|=UIql>P0>BW`y=mALU+c?N944PC_4k`-'
    'AFJi|uy<4NyTvLNM)3^H<cCMrj6MHR6x|=^oPN)cIu56oW=5>5(tQ$-'
    'Ex3c$yc%?1W72Y<`NfZXqXXOc{&id>ATnPz`v{kWjw`HSDgPEc<wJ1XR2KgF9lKyLQ~;LN551et>a!9*{FHL;I~a4=~w0`dwJQKe'
    '7nfh&(bec)NlW57@^KTi8Xq7eNlWEV|NzM}k+ASWFWmhnFw2v{<B{06YQ(WEij1?AZErIadoK5q4l`G>UQPl$F>-'
    '^#X0t%V$(0CxSa85PzMk=$N+Z9uq$m;Bp>JayhgOoy_eBw2ws&@k?wV4QDP9jT!j~GijgC$MF?Gq+JcU*FrC4$4W5H7P|0{2HmL7'
    'RA5PaF(l|t0^3vRkh^5`H_Qp<`(U<{YqJRFc%|zZCzYNxawwVXtB-'
    'jCP``SsY;+Zd=vzV65urin61G(3Nvz+xzOYTI3pkbmE{A$yZ(ZYw+ThnVby!p*hEl$al5L3Kgl!Ckt8QWwtyLi%ycoemm@Vi-'
    'JPnCFSY4T8`z_;lE6xfN;_qcfBR2Ch**Bv{75*iFZS(r_f{1}|nU`nG-xI(aJ^-'
    'rloHk+EL^^Wez*mgSRA?d1(e%F0T4)I(Z0Nmid}m}6jX;4)^(AHD8RhvQ9v(y+*wh>@+=Bt6)Ys9Z`41DNGEZwuT2DNd)4T=;ekh'
    'Hw{{jy*$23i;^%1LR?xNeeogvhqRte)|9NUarHkr_oigkY93J&^o-#~fCf|O2Z@&grFzU>?%X?-'
    'OO?|>y5g{V!;Vh4%oI#y2g5hpNi6Da!Nr0A_TPg{N07f|pE${?+k^7qs6(BVf88NlliS!_=UtbY>3_@K1rP_~r?=}`$e+|dH4rte'
    'w(_U7P*QY9)N=0EOEh)@`NUH?r%5N~)z-gWWSU<Bh-dTKbLcWP$xhj)JNpL|-'
    'u?T~6tUNKtQn=L!1GN9yRKbRchg_?xxM|(kU6)uoc$*JIizTLO7G50tR&5!drN=lo6xN@u=c^qs&EgFWuV&n-'
    'zwTqoS`m<BBTD1LmZ|Rl7_y_>u?p(ygs4FTZ;t|tp=R`DP{aEu1I3zD|YdQR6La2-'
    '7dHL9)5)z0|eh5H)>|=@49DRB8+?rs4?DU<Is`F7^Z^ZBpKPcE`VS~+QXb>|itFKvW%1<k+6oO3XdT}BYM0*mU3lyKhzZh2-'
    '6^A;RXrGTuBz6uWSU|iTnE9dkE2N-`uw8kkGK4MXM8jCJ&D!Q|*-'
    'z)WC~$c;h=LZK=$V}vuQ(fdEcg33)*42f(}_9k7=L9hVW#(Lvx7cOH&>EAcwd`vtJUg=3vF{c)9`=oW6QQC-hp>1N7=DZ_6_O-OS'
    '0B1!lCcN`bgRtu*5XD^p0aU|4ruK&LD$^W=XOjMk-'
    'l*UCBFI!;jmy7DW(Rd}_TXsh@k=kfy5ru{+V+^$0cwpG5b(IN_8CW6?%&t4Y{#MIjq^_XD}*$tK+TyJ2FGa($puehZy-'
    'PFMnWr5EqRLO!`dx*HX`WZuY>PvG>ILhbx57@9B@rT>}}Am6lFAaIVjc-Ep8ky4ZfgQ+A~V3{&_pRx!Vx|N%PQFn1)*E*e|LlU0^'
    'Hb4CTUla74f%l8Wl^Cn$F=|Z7m{=P^G_VlNF_z#<)uDP1qVIZHs01Va7zm;~6C5Xc>$)1WfO_#tdM_cfj35wIa1R#R>5Iq?6w*7y'
    'SZvFQ(5VJSMnz}H?JlA%w4yQY@A}3*qI!d3)l}J|qxjXNrlU%gZTh@`PTSfCm{Fw}r9PbFdWbzmfaH`>mc%fn{Q3ETEbC0|Sy(hV'
    '4d=3|i@HaFA{|w>`h<v|t{C-Q6csIF!}uGNu%P`zgSxwis`vs7?|FN9p>UG8Xg;7e<&@GGm7E2u$yGABs3nQKBG$-'
    'x!>{FXTZ@~5@_;t8o3Xm;{UN=Y!N|5zn^uw=oHh-2<8Sc@RArg~j6~=lsa~-hqw<)Ir14K-R8q>S6GdKz-BobUuN|6OJ)bLX7Dnk'
    'm`}NX}U0a!YV6>qE#5br_KsW^r2zm07$KTk+GEyd4t<`y1=(ucRr!{F7btA}uDwG5qCDEe<S#&%upf@aiO(s{FA+sx1m!-'
    'J0XNt@a`ACPZQH?L<z5j{e9#)hapv3duUTjIN%Xr)cQNtp^Ma|o_H3*+l2alJBBRgi>td&W@+DKzldaGM+X^3GMH0~G{O~EuPzxk'
    'ky68YOIH6&WG%)9D5%~;U~2?^NeD0a}Rs;3nZ8_{yoy+YBF#4{3^M_@Q7`7qMfCs|=zJCz#Hc!Qp1=ON;8m4j=JY=rCQiGzZ+>;v'
    'WM<2|$lLWI48HC`$|<t*SRFAGV$_gKcyRugqOamX5tE-z2+-'
    'z}7r%OaS%WfJ$B&@c5chj1WVDFBjB<Z@(sBr?G_TG20M=Oe!p#zjL69EIi|5J&(1r!GA5b+|#(Pr7b9WD<*?cCox&z##)H73A}<t'
    's@8&nTk~*q-'
    '^VykB9|;9F`p&%88fc2m62u?}_<m1j28u>Z@LCxJ}_{9dG+fgfPoGxI}NWzOsfYY_${L298P(SIs>MEYM@xqZGC4DRT|lZT{@ce='
    '3ml{hRvRc<zA}Zu7(jE)+@#k64v3N}&XOoX+nV66+GEmBrpvi$1yQmygn(%0CVJj*bz?<#8ZyZc6V)siXSdz`r&$X`-'
    '&L`%Mmrc#yIoMU{A?@kyMEor3>vxrE;4nI@koSVsjV-ypP5B7$vQ#L9c&C9<T(4mcH@aW`1o+BBxaQ?=U|SNZX2d6dl(GG1XM@iL'
    ')9>M6h?<*U(~(^J&lky3C%!rC}3Ud6<dTVVE;H-%8z9|dbtxM=r(he6_+m8|YqIrRK6k&-'
    'AC&4?H4IVTX;S_g^NZ{4JCMamQu^B3EEs#M7A6nkp4b|yuoJX6qMl2O>R_Xk9MA=#h4{kF&y!?J7u>8a{%mq=XkOVhjSyy@!PN@f'
    'E|F}&+7Ad@={gi>ydSrMZoTRr?RZ*tX(#1MY43LPP*tFYZs!(S&_YYs!m9aU*R#16j9;C48x%Z2%8jWw({v#(?2WS~P+V()he$_I'
    '>^yu9VY*Q;A#>*`{UC2B$=r(;`rh|>kJJ8FYx?{}+70#G<RH!y%*z>=gO7Z)%qQ%K7)t#oXKH<9lr-_}>J+~84-'
    'gLh5EH}aY<d@~pGdnvLpa_J1=xlPDUv-'
    'Cg7<uxw!)gI+)^*)FBSGQ5RD9ZGoTIqTF6tW;Ll1t}nmdO)GjgMA5e@gzNwhj*62_33aM$zO5*ygkP>nVhVFSTPfe-rA<ug~h=$m'
    'ZH+-Av29X07m*<B+(eXps1F_&NHi;$<@aCCk`JVq0^c-'
    '7U#&KAZw(gkS?YcCSoC>lmKSdSV7tAMH1teij8NWWHlkI6e#I_+|cYeRZ^9X_GY$pTuGhYB5y2S!mLhiUrrzSuR_Nb)Wwq4Ke`j?'
    '&#0oi?2i;`~1|~1#Fgs{`l|J7$YG)dco`2AHXX$i#dQp-OI-tb7gVsQ`*yCsEs45zUrbw{`#{%n=B_FCE0iiDhz^szLtn(r92HuC'
    '?v64N~HEZjgHcV@)ZJTx*JaVlrVvjlmH}~ooM#H2I2R=qcfB&oR;5Y0r1P!;rB6NHvCtmT`@{m9@)|irF4gADO`&^t6=N~VM!_Do'
    'A!!Gw?k|WEpkgT=XeBj)2n%<sQvHJTVi|oa=YcQ6XKy-VqQHUh72TvuPIX@jyq@uprfOnj=mWoBB)#t4BWvMwwRm(cP2PSb34NOx'
    'LNJ6OK7WBXuYqbO>}QOq`h@O<PDcizZ=)&k?5tf;Xa-u(!LkOL72n?<2}ot)8Xzq6w7(karXx)<HpS!slOyhV3!!mfw0l-'
    '8HqzKhNNu(<}>V}&Ps#~&xCXUvww6=KqaS{8uf0LKr!)?*{a@=H{GDxCNkJ+K<K%Hik*$?Wn>^(ipi%VqfB83c_gwEeaeuCfBG~{'
    '?FgJ+%$oUQ_8KHs3+<P9^(TO%)jbW7H2#{0b?B~cK;z(*5_;TOg+dnQHA&e4<y3g4QGvy_pC>XC$(599&=JTk_m1&0JBubj$2RWd'
    '6}FMyUWwG0Py;PZYk~2>%A&^=WRN|>gMBO7D9E~N5O)b&X}W@MPmMIYYuyk|eOUbn!Tr@0z!z)p3OF-1qlCtt^&Iy}gRl7hO-'
    '}x>Dmg8A`U*2WKGkYbyKfFYVs6~Bf<9{CR4nQNLko5{76XJ`uPA@0=nVB!bvlW7{Ml65CrxzZPG#2zA279tE1Oz^Hj*cGuL?U{=5'
    'cdK8eGs#WpdCwy41jMnX20BiBCd||Fh|Oi<r}|^i>hb0_#SpUXQ~<gfb9Q=xIsZ&|Y70w3Yuw*zA&x`7oK^x%fErs98CY{oai`Fp'
    '&!&mk&v7q=;nB=d;tt|Isu2bhwsebBvi1uwEDDx6zym1N;YS4>1%u+h{CYpr)wnS=0wdvj_|7Hj;YRqXdrpQoK<CILrNL!$_4U|8'
    'HO&X!=3}1SSX0$)_5vGF|7UTZ<?(*qZE|Kl<<W3ZEMcW!e`~73samg{_A`manoFw>sQxL#h=3Ca{zfHz<tDZVp>Mf*NtSlvi9Xiu'
    '^6MKHaDrK*n8whVXJlO+#znD?&?-'
    'rnXuHbj0NLf4&^wMW$tS92#JeZ1c}z5&~CE5KP{&Vyb+X{V;sMDo&O4>Fh>{FFR9rw;u&r%U>vxtRV3O!J>^rWv6sacBE&JH*=!Z'
    'k$}q7U1$9}$SBJAy(4cVoA%Yi@TVcK#VA{7jh7RlGB5g)?%tl@w(N!OM#NVWZ})`p49sV8><o6Z%b_6{Fae{5u)LI|q13<1-'
    'DxCSR~@PY({c)O$D@>Y+*T@sHQ5mp8&4<R>W;LdQkK6<A^a(AdQ2S**sRNcTNU`C^0hQ=UNz5R3(Sa^xYYLb_+uC=a~w;m<}bf_='
    '<^)0UBq>WXW)64q_+DG>rK?W<E3%4KMKlDP`gp?u!R$_sD_wx_nxft6X`j??v;(*r5~X*Pmvk;4Mp(XbP-'
    'g<H)@H>>IpK9<p`&4ROO+s#SHHaZ~>SbJ~kD)$l@bPhW6#!`T!6PRUT|ra_HoeB6Bx1i*$!-'
    'pc8UA0>V?saSnzz8mojrr5IiQYcNq)m*((pb{C68H@^L0Zwf<B%vx&o-_-'
    '7YZ^d7o+!{(~pQ*_l#>r1dDQo^neKZ?)KVA1#2=7#zpu6T+KnsQ>6+NC!L~hTQPu6B4pB`p)M0KBKiD|^QH%6WF0P-'
    'FK`fq7Y77|0wUt+V4gpL?cMlTPWr(O{`*Xo?#>%E+_MK_$K&fwkjgY1IKt)UuG+E(CEDb993pvn0)@e7$>(zFK%?X-'
    'w`#oBtL444YIm$y>^La-Jcp)?Z)0bHS{%jM=(;V>r<;e`dVdpj3C=`#2?h>}li{y;C3*>qkC2wcZmnKoJ<*j0**(XJ#2)zY;89=}'
    '&rf33|^0ul!?7Ebyg5wgz~a7aWf3jESYcPw#YbltaG6p|mFm`=(Ukl6i(ZI1~p$CnoMyaBLQ>)^FYt;%~EN2P~_4ck13ERC7FJCm'
    'q`ewvRy*Dp&3eC7C@3)YH~QUU;T?6FgfRcnuxw@L28gq~UfEM0RfX|j^%iaHsh>nBaVpJ*gfIwuM2#II;mRuz9FGM=dSjO+)oesM'
    '$MkO?lW_#k>>;ZSw&4EGATHiado+zikt0|ayI?1}v^vPK<1)~DOJ(XK<7{ip65VJgwD<J$oNR%{LV>2(Eyp{+P3(Vuc|qj!-'
    'Js;L*I<1%M>dvDO5uZT5eF6$d)R&>0u=twwQf_aG96w#79HXqW(ALM*%y)5mNt&}gNN@FkFWpip21StS~;Y$;KlD;3Dq4UrU*BsI'
    'f$gE*i5laM!9)T7LUMUbSj-'
    'q9DRn;#s?;<PNQABNbGfIMzze%rT2PD}o@N%KK<*$9E`u+74|6LdBQ`NrP0D{B1AN_|)AUM@BG~3BwkPn)(_6Pj;?sE|UODN+>4`'
    'gXd@`fnK`8K5OFvdqySRMU8+7i%`ikW$8y=2eqw-BOq6lL#zLF;Ud-q;e&(cPC-YiJ+9K{KB!V!2YJ%o97{&m${Is^oZ)t&^qq)l'
    'Cofq#Tknm`;IPS5{^1>$kEK5t&s+gRAz@48CA;)EG-L;XjW-'
    'M<Rg548w{N92eNJ80?Q?^|BFn@En7wD6!Sa4Z$S<t%sBvhbGQxv{JB#WZQ_dLsw(=UP?oSgr<wK>-'
    '(;;0cU)r(f9<<pDg&D>HH20qd-|~cT#31usO-'
    '@bYY*b6<F2n^F~}o?vE1%!@dFeDsvjuEV*0@n~uuWxTs=m<LM79Z%gGSpajqRyUcT&xpROQO2SN(rY;`Y>i;U|ay_RO`1mBWD^nQ'
    'S^>qnT2To>~aDcWC^N>QO;oPBoVS5wws=g=uN4`{9O$<eGwU1toT?WDnANm$bTBfFO&}4$90jb_0%616!v_DC7&lOM>2CQJqVG;%'
    '}eXqRh@s+UMab3IP`RJGHv*pAOEv4fNd9)1d9(zTJ(O?ywE)*GpczvPFO_mvTNoRJv(axRA<oXCt`JAKGA+I<)j|)E)oW43hy=)X'
    'sY66HJl_01!y<HpPfnMiUvsC~kT%(j8;BdUYQJZZj!dY@;cd%4R5+(01z^Dj`k%9n$%3Yv+U$C6A5v($@gR#BXGW&ko2EW74SD>$'
    'e*>q7>GN5-^tM{3S3I(9BC~fj0m*9mXTYI0B%Wz7qW862qNM~|1Cjk1j-'
    'T?$>rwPhXl+Wg=X=Gk0bi8kFa&@3XgZp?WdQd!da<U33Q%#I4bi&X9TBe}h%yH371E1_^;eClA=cz739kX-Dy_M40KgMXkuHXhLp'
    'U2-eMqCFJXjuo?r^I-~ZqGE?SK*bJc)3Abn_FXeIHD*^n-'
    'y|gM23%b+|@IE<RL>t@CVNqpLuRwgaACLK>1!mb{4UOdau%X$QqBwr&Q_hW-'
    'J?5+DBN5F?yBVvoBpF4;KN(^uwB+$PL*?k55iXr%$96Vp$e13K^=3&@sz=hwYSeXed8KN=)5M5>pl$U-'
    ')=tMB`Cwi8cQ%_5`YLL|O*FE%6FA9y%9E1Nsk%I7Q+4ET@O~1ns|Ua<b%vp^rlJMAVD$yMoe&YqzBdU_~N+JYG9YdOpPFR5Bu;5>'
    'bHj*}-'
    'El$_{lEs6qRkk30fq;S5w|#>8c&II;)2qYRLQuJPjgLGEvRf#AVF;8p^n1Z^jd0qL4__fUY<djIoZpUC~%oC|x*3ce=^NSI|KWVR'
    'u7H>S|``VKNZ4hIUhcx6J0vPIZ;x-'
    'K(TTXeF%HHzhe48%+HUApqb`!}<7_6BKKcGK=fW0|Ql74aZ7*G*yt5c&6y)_dK^^Fl|X5k0czuc5k?TtBsr&#yNUs^6O5P-'
    ')}{c3$pI43f7po@P9hRBc`Qs5TgK2$bhUf=u?fQ?zLLo?oWMWtfR5)j-'
    'cU3&&x!9M{09wVc|3b#6$FsiD_oJ7Fo1eTuCU%omoBIvgy6Yg@JFz4BQ&vwj@r6<VTvPPL(bwfg7S()A)XqporO8(uEcmfXspKn7'
    'kd=R(8l)H%8hOevaoShkiq25@494;)-)0CW1NR{hLsv-V%ub2<F>`~5Fz{#-n`w*37ju#T(<_A?pF8bgv4BM}j)WC-MA&Mc^LlHw'
    '*-G+mUFFb`K*(bQ`D?8;KejIx$|ooeAvTJY%6N4@4jhVzBPP2fK9xdko6S9?s-`MG6-Q-'
    '4QQD%(}#(V|80z5QHp#dgsKawcjFG8EQQN=komU1@=0ih@|D1p|GtBG;H#G2}?fxeIE>UNi8hvx%Wi9wNUb1&5oRW)X+cX;mNbD*'
    'k{%FgpjrVw^?^gmROKu-XGZf0@8|Ps&IZ_MiUu7fS%_nQerSWKGdcIym7e`qhx$EBJZVY~@XgxZ2GsJdy>Xf%X|j*87q%n+&$HF_'
    '?)#=A1<Vb4)e3D4q)=UOf-'
    '`#rrUeonWv1ame1{Kui|vqC+lBYHNs`i(zNwW(q%?CoP5XzoFDr1|050a3jc~1Cl%^0Cw^Z@JIUI!&c_w8J5R6RB`ns&vW>d#Z3<'
    'p1;3$lCCxdVPa|0~K>}3nJ3cR-5_gfZxNe~W&m7=FI1ObZp{b~D5LynC+`0m(4N#VUy-&Pz-'
    '+0xdR5VnwT=6O7mx=?S&vH;LkC+_z((f%*fStL|pBqJX30>6bOsVTIh}iivtlYQ08jLwu<~+!>8uUL4i-&}pOIttw)PwF))-'
    '9#cFf4Qw^@%9W9N(k7l%_fBL9&=D$Ce%$m$VARKc5+E71x}{rF|9%U$=HKAD52Mpax$bBxKVI`*#vcgLMp9r^y{JClwZ{`VQHYGX'
    '@l$8O5p`poc@@-'
    'd(hYp~WO4LId$TE_#*Ua>+4@I7lL~u=g3tdGn_Z>UMWjWTR09&0^$9mrbGAdQrdho~BZy@D$9;pAue*VE=;Oby2W{cIO+mUBSKCW'
    'RxoxO4+(R&VY_(7St^&0w3mz44g>Dzhf)20MRVcShlMNK+%{rW<ERayN})BaFOj?Boa_2OE9MJ!)!k)&h~UoIts8P_Lm&(*zIx5U'
    '0-{>God`tSm)pO@4Wz{+Wx0d$hUq1eqw^ToD1p`c521y!>Q)pAAa!>CM;8OH-z|TIoj%i<wnCQHW%-'
    'dGP11j1@Rqp!f$cm%LE2^f#{n7S)GL2;Q4eOpT3ap&=E?aI?DvEGMHU~kQ9xHRq&gqtP)9crjcmff*xBRr9~8}Enc_ImaH8vC$Fb'
    '8!o6R`7lAEu*08kOlGx6%=O!bl_y&aldp^k3{lSPNVeWqRthY=U+`9Yr9dgyYKn*#O+gvOwbd_l2ab`v5B~H3LTFgFYR2J)2!$8s'
    'azTuM%WTUOKhnS@lv$;^3GPQX!7Ub8ALwc0GCNje$>&f0@xTMZC*r$8BWItZC(M{jUBwH3D(>ZI34XPBgSVxDwLsTg{U`6PlwrLN'
    'KwHaDfIntoGEfcfOa@k3kC(2WiCYCVcY70g|Kf-'
    '|t<Xauc1qzyqhJKAK$bjQ2SdBU}NygNt^@&S_Sr{t%9{*Y;vYaB^UQQ&l3(06}20a{T7!zD&EU&WOU6R?l>b{f3sAUxF?fxOt#p3'
    '`#iWCkzSYyysL8+-DSY}T8a>c+`tIiZ+7VQnv?+<QCfn$UrvFb*`t*Tg4N#}>dx8D^-f32Mu*ozw}5hMQ_$oLD8!c-'
    's@K!|5!km*nhqh2PS()-'
    'd>%mZb#ot+P{R~6A6NcmoVO)3GWyXFe^m8cW%6@jM}pOu;Ln|RBmx?Jlg&vUbWf%so+CeSBZ;6Mu3D)~G)wv;NQWgshv=^lHSKF9'
    'PYYsyVA8EZ-$CK`AluHeU;0Q)eRYA`Yn&Z@`1LvFS(;Kjgunc`&V$2%+kqtmc3{Sn*-B-18wx7c-'
    'F&>e_lHt(sDjHK2dHN3{8`%lki(5OO=aiu(rad&HFJ4eTp_f(8X>^l7dROoPq!&XhVvCxf+e-'
    'p${)!RDeD^F%dm9d>KRbA~EaA5A*I`Hp$CaM@zGrE-$zu`X|b`3JHYpi^n@E`f$Q(Y6{^J9dE$R7M-'
    '8hNm2V$h<LVN0gcs1}WuVhGKD*TKz1FMOW*a9FLwA-zD#6r{QhSQhtirNPStx8KX6HM2p@t5J;!AyYx+1b6$gJLDXd8v^^kNmL2@'
    '`F13)mo<!J61ZSl*`5+WTvoHyMQI&?7qtxJ)Z`l<Uy)@Xd*<|kVMjiO!z7^~MlgOgwv{BPMN`xiEuIB*nRagNo`4^m2m|b@fzg^?'
    '{ViNjZxV^2{XobnKGxQV<7<9{5x`(ui0QNfqJzBV6<%Eww1Q*zo!ApnY(^f;gBNQEC;&vr9@H$Y<b?<gDKk`r-'
    'Tx(s155K~g3#Ju7ud0Sl=4+khiUb@ff<o#r-'
    '*YHCL@V{KX{4&aFk@D;GYPE1ymj`ySC4?rGFGBy&;hC66YQVAxu;}!i)FAM;75T1(0bl!QdAxp7f_=j&>lDf2N6xGN3Fzj1<~0jP'
    'hlcO<upCYEI<2OU=(wuq2dqk(j@g71)wbS1pljK4yd*$Y)3JMHL@il$^O3XZQd*j^ii$B;94h6D>79!cdG*G`N&pgNk&b=P$Y!d<'
    '!pWn(LkUU;8Pu|7|IAU}q49G}Y;%mtPC2T-g9A>TAplf_lW%XCw4`O(wgbe{@>iauRq)1}XX;*aW-JtQK%a4RxmRI>_su@1TLkt<'
    'HGI`Q%H)Puy@G?gP(<(&TybcT~^2?Na-J6+2GL=B`+A{f6_RZpY|pDmStEeyV3~PozU#sGe58B+IH3LX|;UoltC8)4~PWa;Cnf-'
    'j#+9UeOvej9PH$d2d96UofG@Ra-yYq5-'
    'uEiUv7HpouXp&ZUC^59|zwJ<zLtz(C}Q{B3EOEa(Y+u`a3pZo=g%PHd>0Fowyc4D>66i5hR%8hlxMr~{Q_9Q!;CB#o@FU^<02uAl'
    'ppwAPwDAagcmPio<(i9mdG#n&YJ(`l8Z()D_#2F3|U<+5X#{kA$_CtMf7_&Bm?9c$Qa0t|LfuaQsaB9pLiAqal<s|L=m-'
    'oj6KiUs@1_@`@O$~p+~V^&8;!(olQae;v}U-pgEXW?P_7T(p_-'
    'w#9lPE<s$+PfR3czNDcQDhP;QOlqkKLCNvL1qtpu~X&g4fss)4MpP+=Uk<<(_8dpdg_Lh(q~kG=BZ)^IH=U5Can?(@~v(H*4_1rW'
    '3D!Pai|~5pA9BSCI9CsQ5M%&B0oKn|Ckm3jZeO_^Rn_Wlsn{cK}O3gm`o9?cW(6XBYuHnb+NUrEgB^W?pRi^T8qE#Ex9~@?AqkwT'
    '4x^1bH@C+0#y=m(LxcH+h79#T*qfz68+gUz^EqZj^|ri?j)-mDfiBP<>3wlOq`Rk=Pl_GY4N8Qi5w00<-'
    'LqKxqqx4BuvWO82?|~H?laIg+FblALW$G>RN#5FVXW=BF&cINTw&&hHSDisSabwfZK48W}KvD$$3yex~aL*CulMAv(qX-'
    'Wh<nWHTEU}%2lW51o-6`kVI&#qLKU6678yZC+OBbvvyFJZClYxIuCm!ON9tM--U=}2C?BBm1ou6(HSWNd|tXxH-'
    '_}bw^KCd?{rJtBv7c|QznWocrZy>@KS@D^D{j*qgzTZtdRlEjhBKlaW2w*tE`UB8(qPi(jlCvi4yC$M6gpPJ7wsF?*mE6)7!&eZe'
    'SY*7^!6p{A(L6F7$W7k2vJTPdVLSjT);bMpZUEnD9nSrkcMSq=1##%$+Ii6*n@fd29g5ChaR5IgfP!9rr3%0cFN`-'
    'EC%LQWlCZ2VzMzTNpF@Cy8YbvK=-Ji}1Oc^~ga4C>NA^A8z_J6kiH+Q$K<>%Kh88@+>`M)7_xbhjR`Kkn_mQT7r4L-'
    'e}ne_Cbv`#`AB${q(rGBxURud3a-SZ!hi6;V0$&d{whz0|}aYOBr~h+xM{4H4{e*H1m5A+_3{05H_kO9TXF<4<zh1AV&ew(-'
    'Sa>Vid<i^mU$&p2of^;lhXcgB*!7{vp0YzeA^iQ?iJGI5nq<CG|whNE~QBNsox=r)uCyI#D`mJC*Vvz9gp&!_V;Y*<sORJzCOJ+P'
    '7_#bGrOIvj|{ViFHE)=1qj)ttAXQTmGe<v9wr5{m50w#2?-m5zIj%6ug5`VA}e^z&&w^zF6^-R;__Sfb;ylX-9)x;ukU$l-'
    'rWl24j@xT96Y8dku%A=ew>KD&3WRcm+o7X?*z%m%E7#@0R%560{4augQwzkF-'
    '95Lqg^a#(2xJ5<N>3@qz8h`YY~d=J$ZyGU6u>Hr#oJEad$h1jc3P^fGi7(21(xITUL5g{8YKrwJUOE$EDPKonWMe1TsNTv1y6EN#'
    '8S_qhZrI~Vp*9nN;M6^BSq-`P)|q&vWyb_H6D2>b>*u58-'
    '9<Td2p;3~WMttG~#Cngy~)jpCY{``ST{iRP)P@|UO@F+RczOjF_s%N=zVj!1aod9aD5v79y0fA-'
    '`8Q{4McjG7HK@<*}0Vwh`@>dD;jNI>IFrefD`(H^pwIRRt6<U=&h|?yKK$aE>&x4Zh<^s8pm$U&ED1`3Y0~$*BMTqH^Ot@Af2xgL'
    'Ew&5IAiB#F|;u|AIHOj3Ox2xHsV9bgVh4J<@d@Qn;y~uHxXiflNKM<nj4U$H_@Wfrbtu1rSO4kiTglop7GuG2P8V~^;>|M)*q`@9'
    ')hwGz=pCHyVlVB#gW#kzR^3<Q$<s3>1RM)fF1(`bs5ZWfCM>M54c1RURbs-'
    '`4193q?mqg_6S%mliJ#C!T<p^PNwWvk<0Z<&B25DC*(a58a5$X#hJ4%_vTUg|_=WTm6R)<}s9tMu}AS~&nc=3S=I{a(yb!pkl^lP'
    'UVO1*^_VLVdk`MmL1ZNR~HN#xWY-gJ|dILDsUZoFsYkd%NQ4s_&UBJAXL;)t5n>3D*7aoclnUby!QU+{y;Rt=YQtsusbScl~TE;r'
    'mEwedv6-lVx^NOQ%wT#ScQ{5o?#XSXLEs=y@VCI>eK;a@=+MU9PXx`DN7#X&EGF^$mvi+q_YJG6-qV_lG}y3r=1Z&nO-'
    'SOtoo1>`|<p>PI7QlPFF6geq2lG0mNys<XhZk$?Fjuj-XY*ApY{W={@qdJ{gn(VrPGG@w0I3rHf%jy6JjbrbyRbd?dh~CSW`@YW4'
    'Je_iVOWc7=PdnGj(w-5@Sx{&-'
    '48Zqb7xF2DfyLh_Hg0fRqJf8OdIUfA7isiPl_G%$g<yIwXi1KZvfA4CcDRy(sI%b)oByXJ9K*(H21i5#steC#RzA&X0WCL%Rtyz='
    'Iokjs+$!*t8BIb}#e4J1jobckQ@W3a1I0d1;){yU8Qaqc^<;k9dh=5%!x>vCgbd2!5^%3&`9D`DfXCY4GGTYF$<;EvVlCcgQ{aN7'
    'HPrhTsJ`D&WqZB9a$J;+a#ef0Xt(;ay@@VE2{4kRFUydL?>JzBKCQL0!*oa<O>uPE5nvztYiOZS(2MU`@yIrO{kq7vLs5}pFJaEL'
    'QN7i2JDbUA48(!pSob&6*A9DSFM=UN4?EmOQo7G#{m?H_rG1{>o+92pI<)<1dqVO_*h$KgJ|StEzP~H?b#WI3h1l}70LNXBtSw8D'
    'AGe2{H;Kse>Y;h@;tvXL5<*_AC_NGE7io1X9M-'
    'TiZ1zl+#5_;&h0L@VDuF6`@2*}iA+$dpWlCsXizQp}rO%jCW)!+s1o%PYv|O#i)c+l{w737KWVz*HfT0aH$LdO1xdP|fe<+I5o9G'
    'BZ2Fb3MpFmMWb+TCGTpgPuQU<0{j!Ul^RlN$?PPV4Q@!5BcJOh=z8H`5Ys>$R&_-'
    'O}Jio>hBTaT7|0@T1p7l;mqlp8F45*G81Og}1ToLLNC?<je}FZ$JA#OOxcFNVj86=zGTZ2-'
    'wfdU}giOQP}MRtzX^WKNfO#1T6l(e4|s5v#vN{9YxziAJ_zB+VD+1FS#P4fWrUXK#T!(AAVeO^plFB-'
    '?nF5!&(PSLD@lQMZK(jmeqrUW0?H(A2URTNBWYu%#|P=r>1Bh=72z{-kf&lY1{5iZcRr=oTAtw58o>kAwj5?=F%IYEf*5-'
    'cbHTq281c{Dln0go!BKth8_2ONKH?kEWGFLjo76q^7h>w5URJ*k6*`zgH^zkC3Dk&hfsI0R?^jSx=%b<H36}d3ApAU)VZ-'
    'Dfhd*OU}}b(LnY=fppwM4}tOJXU(e<7{%@Rh3&Q0enPoQ#W9^o0_-&lmm-WnpL<8u%f3p%op=$}(DvqGM(o3$YoS~^3NJ7CmK&qh'
    'TlZrB{gPR#E87k>Nu!lBN4f6z4NKABxS^d!7b@y~`;1w3su8Rd1F-hb+-h8lmg@I2*ru>wacP$qa-l<6iFm6y{Y-'
    '4bKB4n|ImMXRyqpQ69ZwL>OI5=6(GAZ22082yiEM`pd=t^cJ1}jcYOU?E?yrC-'
    'Y}Tjx|NAT2hS5<qvNIiVwkbb2>k{f_4>fHQKjzHvRS95#gT%^*nzO?vLTQccIla3?7PU7)jb1(Plx59VDAT&%RLC4S(l3p2ml-'
    '#ePh7(zMKwK7h<b3R#nfe)$torWxXp|YpOA_V^TKK5?sg=u9BKFTl8Xd2h>K3Y@kTmJhg{jQ69XV{?&@4_wGGre;OxbH%ctzyQRy'
    ')Tw@ER)_+&c*dK+hZ{Typq(-p_y$V^uKX0Z)UtPvS0pBeCWP7OP!IkVjIn_4oDD9GJ^)^Fv;Z9UL%0`ut+dkb@9is-'
    'N)W?C0Gtfm}m#T-'
    '!lmopKsQ{|LEEXi%D_{2J`3%qs$8n&lv{3*$&#c}Zsw(q`dwXHwuDP44nW8=_GrGY&h^Ovg2tiM!>AkXl^jYKxZ17e;@hCd6Wc7F'
    '1x`(Tjhh?RDFCNGCOkoXx749D0kodxUcy^k+Qxg`V;!q5Rx2@;niCqDu+1t(+}P1s%8f;=9h4h+;WJ4;~pEda0Oxe24{fYvA7vi7'
    'z*6~p2Wl8CBsU?^1{(|{E4qMT-T>)kZ*^oX}gw74aA-'
    'A&<gLsaEEA+ON0Lx0j1G*9w`bk0DVK(w|JdMUupYeMZ;W;}BBFj8h1EM9xDt80TAdj20#%U<KEKvqqmDVBsy8-'
    'o)`%rFew%O#=+r~{4#x;`1qEf77=ad8RyPlfE3wbHOXz@!6g3zm)B<9l}pN<J{MU6J(kiTo$7AASDK3QD+WGFtIxt?R48VT~h6?t'
    'b1}Ni49zx(Y+t#FjR|uu^9`#8l)?)M~_IXj!-'
    'N?^uzPbGHlbKQ>Ze)HKg$YSA~s96M!WUhc!>dj)+W{nOTje=e*}q9bDugBVvkyedFQDL@j3$kP+?kBnG2&-'
    'uBx(JNI0#;XWjyB%yc;QEOaS<+_5iKW(0)LpJhgt#~&XVo*mB-{%~%B)(ms3Qqu-Km(lSVadkj7y8Vm<ADgKkMA>^eAMasc6w&N9'
    'VS5f$EjIC%KjG;pF#F3LWd<pGbgKE`g=xN8c6OwqK3~b8D!{hB|mak5xj+8ZcJ<r5c7vu-'
    'J~IyV7(e$#No`$7?JpT>p~yQ`PTN>^Jb8MT}0wjEJ8bv?B}=fr%crRyu@XlMh9ONFBG^F9XZ*M@6VZ5<K^4Al`P2<cfb8g*GSU=8'
    '`Ahu~HYLm^>(^fCT#lCR^-CI0(^hs^z{t*`_m_2XDYvWw*;2H<T4V*uA3iS80O}oH`vG$mm_&6?T>W8mK-92D%y(^7soq%-'
    'dZm6Zox(%GX7Am1?06oo?E&G-'
    '`xU4OF?B?d4$<w+1O*$Qm8tYM<WzB&{G<L#N29CP^S$WPOyqz1o_6i=rU5A{(p;gRxA?(ijfDHZvE3KqTj}(<4TR^-'
    'CgFF;SgxiblCrLBOyo+rA*I^d#Riv8ARp7XW8sw!|FzClE#DPV#`yrZ8I!C+#OorHp=5*8$Z=rq%Hin*s?Z|F6kA`YawQ6$q-'
    '9q*bDh70;Nq&$ECqB{fg>htrVB_O?+KkdTQ!D4l70&a+7=otUu6*S|Kzl!$>LA~M9$SFG8^Y5Sv;KbTavcz#r|2djXZfbFj(3{3b'
    'VUs0I*>8GbpTiPC`bRK61wh*T0lZ<R^Ld$}8nQDLWx51?(2{~urZLu2HRx@x9`<lAF{s9l1M)!SDFtIt|y`nx=Wqc*9S&d?)VeF`'
    '+ea*BnC<952aon?r&{}f1H4GDrZKgn*Rj;4_01nXr>~mA6{k~`zM06~s9Q~rlWSrwq2^cm{jrG#`bk1UV2hko7`oxO<-oAB4-'
    'w&<jYByilz<4oR7dT+)Pav#9a~pfh&h>>my7H3&ECVj;283sy>bakZq3oY{lalt2ysYM8JDYf%w+w+M@~QaX%#^$5fL1c}isql_m'
    'BcO_zE;-'
    '0HSPt;I?s5@AQ;1uq}I#XjH=FLk#r33doorR*E@SGIf+?<G1kza0_FUxIdT?<Mu`QPn1{uwMmPc`kZe5x>IXnUf&+!tP!jOTE+Yu'
    'jZ!35s943~z39Ifzo92L!B(W%9I!<YnA#SK=Aj&9Uoke88E`;M;m*BEBI=fOvv#`eS0N?S<!cbU<X=VUor(gx3D*P-c1~->(BV-'
    '%;<bW@W_RwMgAQYYjx3(FL1r3=E0T6SA=|ma9v4!Kpcn=MUc>5lhWmFdhN&`^>{@ql-'
    'z+x%^N0hQ`+uOr|<5RrCo*)33LiSiYI7sHP^}g$yGgg9td%tg&ZQ!AGUgl`-'
    'codjGpo{|x<$3MYc)=|(EUuc;XV4!@0!qZ*gYk6(>z1({)$N|C5~P&j*FXO)y~%+{70a_edzBl~53?DK;_J%jvG(jz6ZMYkvog*4'
    'U{0`O2#u3ak)~5^xIZSy$UG0Mn;0?oOPuQbISGU)|2ZbdP?+G0J*0&W7Nf6abDmyJbkluj8I8o%?m{mASAR%Gm;cG_to(EWh(d{K'
    'sXVvYCxwO?H?aaGW*}io@jYuUx$~$T^gf<sw3l4-ZTJ-G@N;P#CvBPBp^QsX2Ud>u%Ai4<81X}eJo(~YK-ctxn$uNb0TGR1xYj6z'
    'lNM$X02cZOOAk5oT|I>Op|WzUFRmy*w<8ygCxl+!=9%S+(*aJ$b=R=Y0JB8Z7z;jVSMY~>BlK)MF$tR%@pl^t{`l)*T_^{D*%11S'
    '3z|fQPn#e<jLT;zAaX;%#}vgIebdhO9ry>yNg(|`tJSt>Ca{mKlS>;9JiPhtyT|SDK*OG(F*aU|WhwFve;W3%hLAv}(d@#K`wZ(W'
    'yRGU>yUUmo;%QJ_vp`E{ztn)oqRTzPL{Fmn*NU?hLh0CJm6BUNR~{d&N<>wKCX{XzLvjbh%tzkYfXWcf^0<jMXBIgk<kN@?yc&&f'
    '*|qm=2`k(l<8WrKO_?q&c>j_FDMl$-HC#ty*!^M-|099B^X=T%xlnjLam~e&n3JMq%f|r9KaA~?YR@phs>u^_38Us*ag?-'
    'RVR7*Xd~k#?2Udoh1a8O{*BDocU8hp~!4Saz$91hS#+2Aqz3Ev&nXQZ%AvG{$OQ9fFSw3mu_L0aBc%6L~+Bg?P>p6Wi2x*eA)qGv'
    '3jh&_-O`3w_l#4`8>6xnA2lFt>#A{X#Yvto9YZxH-'
    '#qmBxLszNK&)d#>dz>g;wO78~rK+qKTB0!KXj#ZYB}YI?0CX*I^>VV8c3!senA(x=10vuvw8>)B1Km-'
    '{NGqd!jM8N5iWSLSrNH_;?RbmTAUC_;*5U)nWNFOI6-;~2P3*a~8cv!_#njGh$UAS-RoYPHB(uX(&UsjV1C_c<7Pj&z)xcL!C*<d'
    '4E8fAYN#tHLFDT{1uRM5Rnu+lN4eE)2PxI}PD+iJmNFT~v)goj0F%kx?{t69s?G?Iy_4(HQL-'
    'n%Wu2k{pD`(;M_?_Dz+gs|F=5gWI79_(fMe%IBmq?ja`k`$TV8VON3xe#!Pq8znZ1eeglDyNOWD7%<#w*h57W%MgAhj}bndv~nk|'
    '4wG!#ItF&38Da@9T8C5am9(i)uqL!1y+dzj;OTd~-'
    'ImW1l127{xrShTcKY#{+SbI}52lSY*4`g@OWHEf9!EcqI1%1_1BK`c;E)v5o2=)`^V=xxzdZWjZ55twN$X2C=(hj7N(%35$1xWJk'
    '=sEf3(%VmdBVx}9!S{PqE~zZqb_ber`BYgO&g5ZuA}V7pUj=PjYC!QMVWx=AR^A89<w0M}eEOBh`hAsz}!t+IHbbQ%L^#KZ{sBl~'
    'PzCcj_rCEe4MK4DY7BL;YE=mO{Kl0F%m36Ua=p!;~7A%5K_MJ~2QE4iVJ-'
    'N1?7S|d|mbce!ec%7Ji5{K9T{qO)<wBK}BcuAqNPa;&9c+SA>jCGLZiA(zaacO-+O8H0eNmJC3Pyq#~rE&|r-'
    'Wcwkk@%+oM0XlekSy&tjuP^$cVDr!OI=1V0F?Aclj8rax<s|1hv}+Zi%>r39gLKvnaN`7*w9BpGGPxB@u#y?BZc35>l!bz`k+V-'
    '?LdpsZ(u-RWO{%<P*Epa*pTXP=n(9G!8I&rV)a!#PT&;tvOt=r=oZ?&43QajMJ$dt)=b3K;Q2F_YI@j>3qr3-'
    '8*CL?C<wsWy$1hg=vbb=8OPbKc$|GPkuPZqqDK@exeQtWcg7`ho^gF`F0h&IalD&e&_Lp60ZO}>@G0Q+;j;Gm+yaDsT1OBd9mDZX'
    '5>maUzzaC2Rmir@T|Xq5IGJ~?@4t5mey_b!aD3JtHz2%B$>{AxGweryH$H@JaZ{NQO3Il<AwufZH%&RKIL^_j&)UrbSWAjN+Qk|f'
    'hnCJ91K3K(RqAhUjHeWv?%zj2JK5G4Cx@cIvX9|>0=^mnr>$Wlia;OE25ce1{D0zSsiuYYhf;(;T07)L$$hwPD}AE}qJJqUD{l4#'
    'iHW<Dw7>($7j`(Y=;;FkbvDZ#*?ulUw{i`=RY@5rVjWKwV9<FBajL_ha)q~m5Dlecrkq2k2GUF7L=G?@ZgqLZ%NUm;OgEYWr71is'
    'E4?yT7g!@CN{AO}Ou4rY>XgU+Kvh`jkksQ3Ok%Qrb>ZijSuLtPpzK#aW$(U{-'
    '_YYucgwsQmy*3opan&*xnBn_S=gtQ*P}u1h&YEL0w$TvYbcVIo8zcvQn}q|*qVcH6AChH0hY8@YE~5L`vVjk)~%Tig~Jz>|H_i-J'
    'JJh%>#UaIgnYariN}DQYgq@2(<YX99h61VV8667Li$ETfPL8W&%4l3LeUid%0P~FUt}YsX<6>CXU8MlQPxE02pyc$x0E6s$QgHBh'
    'ljr)Vz@(oIV4vfq%tKByh|b@w&ZmIj_rI5RJmx{Z+2Y)eMLs^a9Pf8kqzh~u?giUgR*ihIrFRUTCuMLPCgoDTLhUasEy#D?mZr^5'
    'k=ZO{^=WoweQK!1~pZVgrW$gE)aR+DW_;_KVuG})4VGxPQ9~B#7h1|q9^uo39Y}{J*7LZ2QG=&#yW@}4AOnWDy4o!MuW76yX7?>_'
    'vfOCf{#A!3sq~K9Yj@_aSXcx9lPhYqn+Ldt+X2O2*dwQ`B~l5AH3K~jK#tc;pu$aE!&sm2jC8)V1Hf%l`~yA$boMg>g*n@bN90w='
    'Mzimz$Bg5Xv&=g<tzSXkZ=8B0%jRenei-s-`Ep<W8TIN^<a0C&z&p-'
    'dKS#2fkeUF*UOnHNzNEB_ccd~@R~^EPoFdKT6OwW5wZkad`yDtmMLHaUP=ppdzyT$JyuH6Jd6Erf;j@eM-'
    's;7kTYOsoA%8iKkpY%>|6CWcm7J=B<c!)s6rtDO=$HKg~oirNr!D|)fk<#j1IT=b{(h5gul8eQ}<%Jx|(ZFzhvNhcD6@>;)fAoa@'
    'TfrT&N;HyGenL2l&yrY~j}B8d{S4_f$yA?1RxEp@d~WdP{fEV7C?BB*HQx$L<1k9(`!9efD`Zz&X2o&jt{8(=nS1%k0V7FQHSt<5'
    'SW;+_hwRd1f*@uI2&${^+kn_wTLC@R%SS#_UY#qgMs0oB-g^oSbe|pi~YHStUh74s*vA(BL3{JTf_-SAjzCwW#tAwBI!8%!+4rZ-'
    '8p}@T=KG(ss|G2?btpIQaV{N%4sd6?|_FJL<>k(tR5QHApZ<{1(o@s#2Ix6j7J>BYngvH^B7c8Zu&Q(RhiFDJ%M;b`1TbB{!U^Y5'
    'bmFlwGL~?I@Tt5sUr{aVp*^nW${vMb}fM$}kzj`E}iU^_WO~<9UPkVfomiCMO0PY@L-'
    '`YtzqEyc*2Rr0R*oxQnyr(KxB#SaopZ6fh-'
    'K<E+yV{{Lpbh*#=Stw5)fpcbSmSf^s>Ox0BMNG0JjKbAC4Veq8tYMomCo#k(2cfzm?mWyO(J<2~Py-'
    'DEWw@D?c1J`<^({$X8>Z+jm6=;L8V|Db0MloUXe#I$Xo913=0zn;107X}5{*w1%7V60HpOk8EK>nKOb-Lj-``g;bV+pse&VO>B-'
    'BVCKziPAt47RV31X3RLiuu?qW<)x5rRR=9HZIX5UXF*X!`os72EuX?cU?k<bOt~G?oa}!1(v-'
    '&ivm^NPW+HvP*$68ac{lNlzaA8YMLwnoR8}Lfu8SU#p4);aiB;7+S$VI!RhpR`-m%6<s5RAbI|}+tC+nSM0S@FXpSjqG{lV>ug-K'
    'kW9Bdwr^_0ocytE2Bh3DJjhHuKbFz_xreHyXKrYm@TW-+;GJ52>@3_uAf-'
    'K8#0wCBR*N>14XmMLGdB;I2&Ohph8~N<yAQ?1OSZOXHP-'
    '6qkKeZ(WiJK=zkWJP!IXUo6q0>55L3|<A8r%V^ulH*nR(b49$1rlVcs-!-'
    'f1oo>bU@d9M_wB)t`RG(;umjd(CH<WW}=nnLC5h{N1p><R*xUyEacrLX(|?<-'
    '?csH@a4nAFj<Sji}wY&YK&gR+^?P$EWXth3F)u@;jW}H-'
    '(YkGhLtCP=r;NrP$r@GKs+L6=^2u30}>R`6d2gnLAVetpuhl>A)DraowOkgHx&i86$>Mw(;oz=RLP8>ULS$KAbdDYL2rmf6$y>)b'
    'Mt+KbFU)c^6B>nrm;+sHZYLi?~>y$%`i9idgzDOB<U<feTjxy7xbrcL{`bnmrO5=fy_rO3JE9ALik)Z>*^Qh$j5*L+2ZGhj}-'
    'x>;@i{N-+D6Cf@}4oY(xX{kFLuwOHm8ajZ&(B%PMT&wL9!dNi)>HsWATjz(uPvkm20!jeX90-'
    'kq5=YyjG6r=S10Ak6^mb5oPeS0{qs_PPu0F3SLR4>Od_lkF5!&reoAea^AxCL^f$23-'
    'yPXl^CgU0x!+mhF^&i2eZ9($UAz#7=O4Rfsd1s*?z7zuq6s38hfoT(M~^t4po9UDl$CysquP>#b`_BhXGpP0Zf`JkXg^oRLj{2#G'
    '({fG8OoN`^G>MXvFBQ4<2kQ3v-'
    'TFw|4iIb<i8jrABL4yEcZYUc#8x7vLWLoj}t^!ZPAtEY$tMw^qwjCDLXvbn^M<~yvjcL2=Nztd;TE!WsN+Y=t3*aew+m$?0LC9i+'
    'j95`d)Vr|hD7|)4ykp4WSFMRC0<|elo8!e@rGFWXGC=@4n!;$;u=$pH27PxqcM_>{%e~3)sagF9Iq&+6reO1kb20in0B^dmb!nwL'
    '~C-'
    'q7&zdhSDJ<uo4+pYc_Sn9LNTcmUVvjfL_c!=Wilu+)&b4Yyk?0z8!FPA#;9Dt({FNDMj(*|%FW_MPv(1!S3)L5g{8NI=XwguFUd7'
    'CJ9POT>1rv0#jP<dpqUFtE<oiLTjW`-'
    '`+b5!{FNl`G*j>n^&`zi<z{5z4kS)VoNa!ERV<M{S_uv|Fu9p3nLL)DkH3|7Pxh;#lp&S1@za-'
    '*2{faZP>Meb@q&GKmYrotThGdGAcprvAm4*;3X{Fwp&!<3g-'
    'ZbH9Q_HInErZhUg+2kIz>YvjrxW23rO2zf__>W%2i__!V2V5#@6$xBHW!HxM34&#UiR+)dwi-'
    ';)AwJMH8%1t!$1U;1*xbZNs(zTR#6QX<119%rPzoF<?p#J4wPV1>Z1mIhCFTHop3+fvn(CGyS1LS7y4K{LRE7{ts<E1mpz;Z)ngo'
    '}D7xwhm-a6p3WaJZ)@C(GFy-McRg!r`A0^TvMZ9{{)=%)a$l1U5V+Hl=NP*Q_o@IL@bjuL%|KTC6{7V=&e=XGsAfsvIl4QiCG&4j'
    'hAeQj7`sWy{$S+r3d54esh$5=r}FQFE|MMWD_RwqNrj4zV}qW@lCrt5?$G_oDZ%s2!u-'
    'QzAOgnaJsKBIOfNOU;vr5{~*thtG1T>F3oWFMU<EaD3c0O{k<E7~jjl7H><<F1U%<Y~@|G|K{Kjz_uF5(nqr<w{`q7(H=4$5tQQ8'
    'dX#-`N2S{)!UMhe1+2#{cSw-'
    'v0uE<E_D+HX}REPg@6;Sf<`sJGxbV8=;n|)sN2;UqD9yt@OG3<e&tskJ`zK}fAlS%P*mrZV9NW85l9gJp&OXIf8RMNu|G^*;ir9N'
    'EANqxp8~%Dj)E=4<HqhFKT_;G??g@{1I?qd-oPpl^Z&~`)+-'
    '$pNI_f(8}u@O1|KUkR!%4Aj_fRISA|14b<f8QtEG&FZ|QpnLU^XU4F##A@D)ao)VnxmL59}{y3wL`RGkUCR3CXMW81LKz3Qfv76E'
    ')F67=UDB5;xDoq{}s=Up!b6`OA^2wXFo6BEGQxHHhD05LzQ4N`es$f5;e1B)u>4Z~b(;q>v*4{}b0kxA5@JY#&h9>-'
    'yWM}ijSRc>Y~v>v$+G6;sp*?rIRo-YjoURciZoOKqUi4gc`OHvfqp4*~dC?Bhq^>}bv)#v%K?AsFpr6}Uk#WGjp{+ecDe9#IGqDZ'
    'iM9vfIRa2|Suc1h75j_R5#d=}>DskOkgIWwU>i-'
    '5L${GR2odC1bdaAe|(5(CA2vJMW^dyt)dx0px_mfBTWQ$4l!v%n5$>nHhix=W&2JldE*+Baiu)OeL3bZ{~Nl8OyZ6A&KjctX|1%R'
    '@v6!%@Vx_z<7JF#0-'
    'Df_C&>L=%!RH5xX`EoZCb8YKM%UE#oeceX3iB_kgOr8EpvWMlBZ4Zgd2Uumi8Fy)*|>>cI@kKK{iB0+2I&m2QvrhjiBm9N;pu<tx'
    '}YhI@~bi7D0zbe5fNp=UMo_A&i1E$)f67a<9U0Z%3ij_LoU(-'
    'C)Z8=6A0KV+5gc8#DM1rxGYE*Qk=+0`^OXz85gZ3*$hmU<@4pMkwoI>ybC3HwnhX_}`U`o^{+A-'
    'L4T_vE&EiTkXb7ygE#jL=v_ZnG>B~VyKC)1OhS~*`&qP>KT=qVo1p7zNYM63CfJ6B}hG?xS`C#6Q_SvR1yE}eAtrJ*|q$r(rP$t`'
    'Ua#{466AD1FT25VJeQexWH_XUxW6mnvr+r*SOu+T%Gk@je-GkV*;rk7E_m92a=2l(pvZ13usFZ4j4KF%KJNPGuseN!Dx*&9i)D&5'
    'Lv`f6O{vmg$6w<9_ST-'
    ')MwUYL{k7P3393DPxVe*5)g4R<T4%D;%phF;sZpywVx0E*m`cz(d~hcU^`Tq+!8fk6>0Be*+|Gnij)FQ*v(jSw`Pi_OXEiZlCr9e'
    '9$|5}1KhihT;}2$k#f!E5DjV3MQ58`V@L!I0*WYKt4K!jMqK&%q|4=zieSASiXlBX-VAHGy;5h{h|bA0+8z3w%*2y$)cu2PPvI)S'
    '?ND`%eo_Ou;Yg7{kCJw&g<pGZn4~80Q`Ma#KY#7;+LI#>X=hxz*uQI3pPIqy+$#fgZ;viP=PIOhg0z)movYuIvn|sFb8LmJP#7Zf'
    'j;k`U<jlx=2foo>Y6cmJ$3}Onx_5;Bl)28Ck(jZ2f-'
    'OlOEJ_*K7ID$Z}{fHflWYGAKFcya8vrDzh_(S@U=JNUz~;mmxyfBk6#ggh`FXguI{A(rc7W^qWlQ`eR_xcBki*%pFtTbh*Iq$kP0'
    'qIot4YKjm?aGhLB=BR~FYY_>V=)FKYo5|Xpo_iv`D)}N<+v}cjj;_>s%nzR{cSCvVCV5R5W68Qr2S}q@Dmj_~hb}JQ?39)644<RF'
    'fV-9~FW(kc40yZDKXmL^zbuqrA(TPDe0lDIi$h3Y2@OMs?YhNdgxAE7{_O)H5!VOXL)5Xp-RyMSZ!{hr93^H`}U_dT#0!!sgWyYh'
    'XqATGTN7SYt<Y)*Go7fCC#pFva`(uwO%>PhP>O&B+o>Ci(q8R0``IsveC!p#NeH@vKhw(rQ!Ak%R`_(JC1e1!r)UHlr)Ob?DmS#r'
    '<DC?`Cr!<j#HU^B-&IZ}L6h2iz#KOx%9Y^QcrUiYe--kupv&xgE$||u-i%78}_mba=5?V-'
    'mLXC5nERns%WI&A_B)*L%U#QKEd6)l1+xpkkXn=!tWi`gi5IjZwyP+Bxm`@>wg_dOUAD)8>1OL6=zNIEo|5EV`%bi0y?IZ8wYb)b'
    'Cz|1=9C}z)?HS(1oICSqJJizv~i%}<DCr8G6jh;dOqLlfWM&eAY=y4}B`o_iUxy%?<{)5^n;{ajs&zwyfP4cYHo&)A)ecfj;i9|D'
    'FoRNsz45>D)pX42s=hbvabfiS_MPg+Wcgx66d$P2q8)b?>$fAlzso@(MVFS3)d8`Ns4_IQo9Xi{{e8rKv2k(YBDe?A^gLguN!)!v'
    '8i1x_iS}4i6FN0{~e)v|zC*7_|TwNVfsY+@BO5a~Kc=;mcgEqj)nrk#LQfx>$3@IlCmV2@n7r0ad=4;mFMND24oDfjy&&cCG*IQ&'
    'ZFqX%NysCzpR>pKo(AX7nNyZ>Wnh^R{+K1;mw){m|61Ml!`H83T&;iOvPn%VVjbwmZrWQVeoc`o|KR9<bIoz!M+0|+ZHVEdX(Pxr'
    'fg{dm8$;g{m2TH3BX@{VflV*>Ld)sTy6=VElfJR7^fkUxo6sLkNTAZO<C-<b(5t^uv-c&Rkv7vt*>eu@cG}C2xJY@-'
    'Dyk&;j=lCI?IghyZa$pI%%6uT*J;dl`u>V`aBmr^5XhOy#?>Hfn9BSS3H|FnWn460s*GvS~RCv$kHqJeKF(8R?NHPvjpKm=Nf5I3'
    'ab#4wd<i8!z)ouvdnyW&$JAY1kwvAqjHxZ8CK#{dsIsrtB++qSfRb`~jK+FK?SGg@!!h*y&a{C%ZgOcGevGrZ}@c6h;8N6-'
    '%E^OOCL0Wcb=dm1JVsx<gT__j+mdWE#vtgLkMw|nq0?5Nk_Sy}y0_T=Agr9E{GI}WnX237cAX{UmgJL&N4@P$6Ry9!)0f@lvD%uk'
    '?{m%rwjxNHbVhMD7GT<#MyYkbK4tUaf4~t`=lF0|rQ<EK|Cy`!5Hr6Qdg5ZZFsUX2L;WA#1E@RdVhN-'
    '1+S<>FCP^RNQ(RHo2zUtU=8u{du&S7x|2s_FX)cPOdY?(gW@7@-'
    '%c<P>GvauF|`3!JQ{c2|g276M>w+^E?n@zT&>|N9f{nN>?QI*H9yJKng`^%gB6N}shHPJqo^FYk1s68y&01PgVhq^wHky$`$g&KA'
    'tekel18C7YDRWugJ9!-'
    '`yr;fm!GiBb_DK;SWQmm$tM8BAKJ&eMn!Dc|<(fxuWk*NXpqn+W0){W%a1QrlA9%o4LX2FBZ!qLkPm$<>t?Pd)n@`fbXJmKBT6%C'
    'QDwoe!!$yYLBW{4c9&uw&KC;aAVq3^T>u*@|@9g-{uQ~cbtn$zcl!5FXLBOh_A3PsrgpgCPy*`2)*KRHcb-Q;?1v-'
    '_ZsK&mizfP%@;i`fNj?Ui$-'
    '$qSZ88m)uf{TyVfjgwdfDyYpZ6>GHeh4z=!I|`u_hR0M);pC7dQg1&Oh}e~?Zh(_<2f+%`L^agN9_bz=921LoR3Cb<aT)t1F^#zZ'
    '0-QNu|M4LyB8M~@@A<J}R|qdIh$@mec8g{A*U0D6tF@{T=;&OncBUwlDQ6t=S(1}1u+VhO$;=bH8+yOyf|_dOHMI!zB?Tk-'
    ';~b#x%nG1lR~+zuxiBMRPOzv%M?7sUA2iS9z;o=OQ-'
    '5c};A`6!5SWfB846)6t(HX|UpO89^o^cH8rH{}4p5NV1hYxrnTrYLa=83iW+6oFe<HP>X1G@C-m~H_-'
    '`0#o^NjD>wV1JfBj1O0o*SbzwC|O<CW4)skNq4!*{ALJJ@;4ghVx6QyKOvyCCV0rMW{^$fZ28ibvT>&W_6R!ihcoC7Aa#$SWp{f3'
    'NYQXdOg2pS1V|lKUL!N*EYc=tyM&LbbqFo<7xr=Sm_93bQ`=__x}-'
    '_F){>~E5jr;l6BoGXnCqAo5MJe8w#Z|sVwKMm~nDP@ws{C@q3sU$cwzUU^~9hZbnI0`}W~_!;C7%U(^o!W6uWAW;h8T1wSi%^0;n'
    'T^J7~o%cckR;*yFk^!4KXiXm$;m$Jt#{r}IqRkReBR(a{{3>Clj+@xRq{4N-'
    'zggwi@M(~lgg`IzjPqk&+=TzLK`T;<lhp!sGQLq6R`L#wxf`868yb(G~A#fI;>#D|VUomnufKU_EV-J{jy+;r?uKAeeou2w;-'
    ')q_$Mm6(PG@N#!fUi?^;5X>|p5+uwJ|19(hKBN#jp9?fQE&XLX)0QoaonPWK}kL@A5sr=w;ViVo-'
    'w`|Ntq(r7sPi)_yimL3x90qzk@LT@$-BKsU!$hYV`BjRfGceNBx1@5f{7c#ck_?3lP|6q394#U{TDlrzuV-'
    '_;Ei9m778NV2t#9mo%`|sqRP5v&!Bx3qW9cq8)H#7pI(VWFi|Vq*C+P=!^VeL{e=O8w@$eQM!XW;#3G<jzaK%+k@4k#s$&C`=4-'
    'naop{E>CH1Qb#9cC*Z_!ATDhL%Yh&A4B#Y<lBT_lbvjgMZQ<=l13@-'
    '>7xo;@=wu(aA5iP=#6^vl_PW<ONaMSY@^07W1tR!9!NsNnF%AFA&Qav<7>d7Y9xy{~E2NKR&j`m#-'
    'kGB!?c3hco;~LhSc*`&aTFrxc@RWV3J#<?^$ocBk@|C<Aahmx=tB_|PHr#<CRAQ^VkHb}K_AnH3X00|1SRHnURKMC#Cnqw(E);e3'
    'Lj*RW0u2ZlayPsZoGjNWa7kkxlAiPdRh#mFd=#%|V=czN6kK-fa0+L{^@<6t#^6Z_#M*D6$N97d8ze8uITN0IFmNkMo%&7>^B8|g'
    'a|8oS+b!{`C2)@Sw+Yxv5_`;=jr}yv*Kx7e!8_dyykJY1*lL1mIQ{Z;?RqU`@3B~TdTO%0(Q*1EZ|?Ir<J1)KiRPCY-BVX+mH2}W'
    '!dE_G0&H{+mg}Q7twzvd5)+7Q^rct%8+L0qq>G9_YR;(8OY3<Ls~4?Pq#2*GihynbwD|w(N9pV5@E$FnRXX+-'
    '?LVd&y#54FUTt_FGH+AP-Qw)bK}zKh%A?Wi03R+Tpl^Nb*DQxcqOedy%B5g87uYE7czJK|xmZzceB?p-'
    'HO(`GSOn{;C#1s~xvwe#*^M0;1FXfkKG)zYqw?jkgy?UV4*W`gul_c^@>dld8xp&uRVxx58l0%FM`Nxz!M%`CZY98=a4kd#rP8zv'
    '2??v^xa==c)(&wzArby-'
    '0kww@?7#y;t6CY71eT^5#ud#G$sx#}g(G#6@1vhW9UciYqywy0i~EY+Lk<%PsfV!R%SbZwfalc4q+zTpQmc*P^-'
    '5RLBBz_94eW?S91PKZxz}vu*wKlf9{v3g1D0%bqRr96d;ORuD#XboJnrO}f>l6GYBytg2F~zZ&jhW9;mx8QJvQ^E)XZIXfL6-'
    '?oCcjIn0CAk;vnrpk_|R9ybEZ15Cl|9OLpxi-'
    '@n_W<ZA?ZKXO)8`jRi+M?671rD#T4)?l#t(7y)Ueops>er!$iz_BkJ`Gt`vNKwK=azT(++?FxkJSbJz4zzkWES{ek3=_z)^(pE@^'
    'l2L{b^b{KYn7Azvopy+jz!mOf>NdtERH=2(;R~%A<Ewu_k%H-'
    '2pnAE509~&q3@QTY^1iUMG9O~ZeyWv{8yhO54W@r)|ppKxMyK+`&5itI#=e$;yJQ6AL>*zg)PDGeP=(>g%kL*aYH^^|JvA2aLSi&'
    'C&ecB4Y|h9E>L7F`r(_=9-@_!dJ8G2EYGPDe3>-QAah&>CoG@3*Q$26JOT@|mI~Aq`R14!AI{@Cy-'
    '$&ed!yhOAt9*)dGcfJAZIelP?vex4-'
    '5@fdGElv9N=!?hS#BG2_SH&n5nbjZj)*kiXM`{3GRDHR91G=AHuSy^t!c+6cTR90?az@iY76p0}9Ib@GIxO0&p!v<`&Njg!ZENim'
    't2uR)S~^Sl<xn7m<7)wQ2Ubw=E^Z_tbxUqv@xMq-npW8OXjK3=HV5@=7q#(m`F)!|AnuAgW#ayn}KKV@l}u;=1GlQ$M(-'
    'n_sO3`Cg*sB+5;)+X|dK-2oxPHNks3+0TGar|OX?Q}SwQ%AN+ae-JdW`sU>k9GJf~0;|a<2=^g%)||d&v)=*lLswEkIT#hYBe3(m'
    'Ts99Bq|Q=FQGY);IwRSM>~%8trN1Tln-'
    '40_M<crExWC}4dnOH^2vukWp;tAHp9_}v<0Yg1OCbSI_$tHZ2Ur&h7TJ=hGL`D_lq0ypw@V%gOW$fSrXDB-'
    '{b@4+kFU&XuRL9JR+_jZc_vmSKGzcz@F-'
    '*Da3VVL2U;|&?ZpE^MbYsiS`ZruB~SAW_4USO+Qd0G34pOF;+fRcLrtt)ym9))OvphBBjxbEg=+0EUvPharow4$gN6SSW3H!ThnU'
    ';aU&w#O3o$ZtLKDm|Jn@7*XG|PQQ$Tei9MNk2TLCOkJzmUsnd!v)h*YJM1!?q&{h>!)2M3FVBn`A-'
    '!zu~RtO6q%LjrqoXJ+3ne^HHn#BXFV35J(&L{iHP^O*oY#_(eYo_utFLi>haN25+eHAVEfGziihKwqM<K9{tb-o&|+d-'
    '^ay6onctw;}1e$}VK2d&R;SZ-$T17nR$AQk8&R6HTQ3R^!bfP>YW(bU!%W3#VceNLryEPcD>d=;-1i$V^7=P&-'
    '=YDtZ1z_Wu;uksCe;zk9XqIfme{0g6yOc1l@E(X1y!{hsj{^uXH_ca_bRy^oiR%+?)nE3J+AL*dn~AtxF?tHHj;?!@@MRCus2hqZ'
    'r(y;<J$fz6Ny%?Ebg78{Ho0%6Iw_@swdHjn838gtoYDfz79t5dk_1N92=^BUbveq*yUk#}dHwY@9_)a5``9ZUZi@VvAnf0~wsz0}'
    'x;3e6m0k{Kn(h=T&gtm{&XK%^!422H7geDgUYJ0^lsj=(OlD=+vEg;g8|%D8{L)k!LtucFiAtDjAmXFas!2U}W&fB$tOzCU@G4)#'
    'VGUI)PFI=q<QFFcn%NQ=>@t=FBo`)j^%I;*G%${pGg#~lZ4_%cCDsT>>Ac1IGqf|tYfU*X`cQSZBfnU!r<_M?9qt+KOb-'
    '1Ba`4R^1dCiNl;DUBQ|`e3jX2s^9Pl*K$5isM||)YB8mX3d1MN>o{pZXWhFE}%7OoOm&cRZIBT{%En18a`O6t|)(CBXSR~sv^BCM'
    '_M0@vsxb8*(e6NPlb^+vZDe7WHA!)1=`nh&?S)hCf`z>4a$WDMK$z&VF)#EF^1~+nM=drQqsOr@Q>h<{A+anFqshj$C-'
    'V}_Y38Ufa7y{we2rewakKJ46*j2Rm80nDy!b)$ZR*4#?yfz!+XjWoLyTPc?rX=Ewu?2bl!oJ)s0hbTvqJ&vP_Y=^FU*C?yZ$SeyT'
    'N_POKKa9mnx?vevM`<REOL{k+aGCn2$acWvrb+*$AM4R(+OmkC}<ZF-}-'
    'cUjh<z{M^n&yUwGS!VHnYs8FAw76sc@GvW>R2?ftn{{*XU4<HYJ6(0~_Mm&P`}CnVwqjw~scs#P%T<Jchnv=Z^^)OltKJc4=00NR'
    'GI``tM4CuKLrx6mu$DH9y%eVu2)ytS<vUKl)#Ti>Jv0=DM^+Cq@P>!By?zH70tssmgaf%?izS5LOnV21Nafzi>q}h5n_^1m20How'
    'khmFR&9ue`Unz_P2mB|7+ijYVaSi9qBwPnS8%8O?WhR!9irj8>@20++20`Fa_O((aQmtxzOVz6}e>qInb1mds(ZRJ017g$Or?a5m'
    'tFj*o++h*xmEl<14Oz`8Jw;X8^Q5a7Jfx1{#g{<GG;>xZkj)!S-'
    '97ORc9AM{+CHS&U@0HR2z6V|K6w>_jo_(h*%~sBoDu7!vG^NXgo}(_-|r6tE-N2c=dK1j{2D=V1ElWDedry-'
    '{=vJ=N$Os|>A;TRz*NvxJxHdGNO7e0P^N>D32uY{RCpRTq9za#0vuJVimav)V*jn0zo$0M0hO&Occ1{EDQ}T1^z%e({2Pq1Lz)x{'
    'B$bqFhO;;BMRQl%yIW;5B$Vm0F9qSC*pya!7;YO(>m_{~g3q7X$^x}qU;`idu=y+=eW55-'
    'b8E3h+mg)pAn4I#3G=n=Jvwk`0B*AlnQbo@qr#K$2hA~h@RauxbV>&Hg#9ZGZQ;S8)m=tOCD*EzlLU#0av!DmJt(1{69meq!}hX8'
    'e%wFVRyU)3WN!@tdDR2<Ma#!wP>p|rUBlL!t)|%vaXN#l)*si|sCIBiXw#}Qw6IIO#!-#6;%y%OXmx^Tr%z;ShDEzb7VE%HZ?=$-'
    'xnR<v!Q<5X)3eWSg+Iwd5LU49POdY=YBLMJ$E6iE;uvXqcVd*KV){&(PQ<PNQbaZF^LqV!ZoxmNw*P$hXn}&jy#)=w7KMj=sdAPv'
    'n5Ovo0r|?&B2~b1Qn`<_alYSTlXlv#c867MTd@<^w(m!06iaI<OXQ5k9=?mw{9NH=t<uw3WEn`h>G`isWA(3$2(y~TL-'
    '{okXfPum$P@qqOW*4QjVYegTI_5_3EnW(m|sog#4i{bl$QU=JqOymwmzph28@bO<+T>VDibz6VtTIu*j)WhC8&fXE40J?zdjyvTU'
    'UxHc)nF7MI$qd+R%4U&0>JI1}fS4I$7a9jcQbxPCd_94Wk0v^mE4xPj-Dfp6O}y<VnC<$iVG_yH$<0I;X3p<ZcjUz+F;vQB9e^Jo'
    'Fo8d<6O+1G}mdd`%6wesxfFUqqime9i)af%L(9;jUrU)ipqW-U-{=KVv-'
    '(3|*;6SV1KQ*l&^L*<s5qD)wURVdI7%f^pidg=6>A=TLtLryUQgk-`M4Z<_rHM{K#}FUn&9b3&bZB@zZTPNxe%@q!|-'
    'H!h_~w%7dG(Xv4asa>D5)_HTy|L=z%SUnFiuAc2h-'
    '<6(rpGCR9?C#qqwex*R>ybzTt{o(&0dZ^ew__x~STkl64oQqEe?Od)h_P5OY&JydUY@(H{eC7jc^B23jrm`3YH2UXPSy*~qWFTK8'
    'ptCIaU87pFGW`B5biaCGu^;GdcP=W_WZf_SlwAdz)MZVI!1XnsrxE=dZDhqNJ`Ob($qNr<FVxaQA@sA9=e!@fRYBzWI9}`d$BU#p'
    '~B5S(0Ui@?rI6gWY4Q3QsG3KJSP-eNwwXG+uXM?jwuQN70|Xb1p8qwgfL38kZknd*TRsX{QNd1S0^pB59723`Oj6AyXDWQ=>hJK;'
    'A!xynxY{TR!su#AJ7R>Zgx+mnaR(5rYiKFh^C*PW((FS;miivSRF)%r7oweeDk-'
    'HS_TZkXpDgL9EH35nVFIWyV4JRG4^ZR_Zu+bDOM}hOvCl3spTGl5U2yjq8q&)9%r}ckA<PEd-Pbl|M7^JD=!KLqR&oYL5H)WKCF('
    '$PqdS0Pp6az$<);Wrn%;%AG70RKVKij=DNRA5b`BSD}9d9DOLTDcBetEjCM@RdogEe?%Meg_);o(|F*lVrvt6h6EQXo%)%6nUBTB'
    'Quss1M6w&hHJCOghK__ee3A0`T_3ii$C=g(_@-'
    '3<6Hb*o!N`VLN8cLbzhwzO6a{}rDgX}Zg+eJaJP>hv>ni$=6;5xaE+GUyC8E|3uHD7E~qD@NN^iwLEEqnaCt`-'
    '0X`_^c+X_c4Ht@r%Q6-6+1$`mZfJS00%Df!X7SD|Y4HF=ozYVZ#&6(ksW{cH3B=i8ZXWZWL@`y&5@%p(U|;~5z9g|qcw-'
    '79hOJ+f#&j}=BKjSHq~tY#07{zL*!$4%R{{xRmL)VYF&4lC)~b*Q9UQv71=L*z3!Y~#w!Mo^J?J?NC$MhaONQ+azXeeB*`gV#5qV'
    'nc+xe0oH=)IaISz9b^7o9N--D}l9In&Z1qcmUk0S08$9-'
    '~ses?XptZOhyoamPky;;QpxG@E=3}$_{ld;JPM$e@U7o%$)Sht1Rvslw;ME`~cw$OoA7e`kP0yKdThioq%i$ngHx`Qlt;OC?CSOs'
    '4r?Xvk*K-Fj{qwP^zXvg{w+a0Oc<Cr<<K$4bNhaB(hqKjbp9S*!ipR6UDjC7Uj>uk-'
    'k|CY=Y8V5T<%{8Kjrppis{Blmeix)L%n1;vG_#abub_ipfZ3u_3OCwh5bG>;dA9N=1?ni%(~v;XZ7d1g(+J7*H^~pf{#8PBo^9+%'
    '2*h{d4z<!M!%=O|CE;VP@VIkbMBJie9Oh4uwMY;9)D(>$V#*-'
    'Bd$T2R3Vpn`GRDZm(X;YDD@kETqAKPR$)~yNuz6$iFky$gTLLPt<9tvo{8fZi!#i5DEssPv4#hR;$uJ4cj(!C~7>y(D3V-'
    'lVfB4OjrJUpt^nQfDQ>Rm)+8RY`YdsmL#5O(cs42nceyb1v1ywKue~fFn4ius#$x>YW7Ig8lO{vZH^`3QncVTzgo%N>vEyDTOPio'
    'NF<98@z_oHcW^ZC=^hhT`{tAVFgt^y?Da)&*{N;P#;o^`x^5`HvmK|~n?n&aG4POwWL_=A^BH(i0*Z$7(oX=z8K;6`I^NNmpJ`!o'
    '%%QdMVc}NQIlM-kw{yRl;8`4$W<6`Fm7_Z*8^bz$?Uv1UUA8{Iv<O5txjqnc11|nHP@@>xZj8p?*f4A9N%(~Q8WfaAX6&nFyI>*u'
    '!}flO80n<dF|JIogJnEsi>FaIcKkIH-'
    '2|fgm{26+ogEIyX+CCHymX&ULY6({I<J@xlmD$t?Za+sa9Cn|d+v5Z=RydXT$>@V3`<>eK{rTr$&xihq`zErY^w$J-'
    'w0@T{IzuOi>tnMtXHqS5cPmU!2|U@!#^I39!U#H=HXCb?1qxFj%TskKCBl3ZBf+8F~%w-'
    'S)E`)LdwD+)9yB|;N#5qRPLf9;}Yp8<oN$HBe^a9O6uhpya$4cP@l7pI}as{Ji+p?X~W3Y{Q5LEzlb+;jJNYw&ISg7HHNM02Ij43'
    '`+b(Ly9l+Qn9q1~dIL<(gPh-b8qn&+EMHiA?ljYGcS-aSJK_T9haKTY1#RfO-'
    ';$W_9+}bGRS;A}29d^ncwQq+H<#dk`YDB3QI_TZPaY$*w(}mN7E$b+_5&DOCpD{!M_1PQSPA>t%3wvBs9e~7HXNH^TK?xJcLU*bs'
    '9CQU1a^JI1gVZ1!j+5kVWE6{8C$|-'
    '098vX6pItzg03P#xILkhWo9`k1|7IjpyxoOKST;g*q1!eYsYyn5sd+HIc?||7P(Z@DID(C@13qI0!t^P$qRKj_Wg!c*!xAZJuw~I'
    'lk#BHt6RVC3HdtjD;uQ@6B;CaekeHz+3(El!Whf@6UAx{IE8S#JMck$z2_F}{7g>2(>X6z8(I;)llJK|N9iS!4yrs=(eTx8yMbI&'
    'jy5hSQ68`utsuP-$tmhWGuT{QJ6LA;M~u8&!JlixnilUG>D}5X3W^7K)KRK-'
    '0f(;_cwYxB_4>y*#^r6T$iw7rszXq=hFD}Q_R^~VM(l<G6By_7^)yfv&O6AnDUpCfXmiqC_co6sE|4QbJO!n@mwasNDYrh^`t&+Z'
    'gTh8OTflRj&SWx0Y$Y&{fvPmaxZV)o_}V;z)<4y>(rP9DnM8gAgfiL@LxXvhSVkJcq*VxVpdMjZS*wm}a%5yFbyx2;1K2PqbWshx'
    'urCUuxBfhuCig$=9i;RN4fg=ZEAh^nTeS0FZG37g#a;2XzcCCT=OP4?SN64!pt*%B#n~8LnA9+SEmS!&9Tfd}gCY29^F9<)Vs@-'
    'qhc!w4V^Q?mx1RE?d8RZU=Prlb8sipc4SzDHzxZ(jsVx{o*cSwh&%=t2Bj|kpu=CS%REKq(^!58X8O`CG0&2!?-'
    'u~T=SZW{CfbuWq7EQGS6zi@H27-'
    'MPUa21ngnpRKX59@j>u$*SOAyuRW_PDCPXk}cO)2Y}mRWS{{71kuI@(tBX|I1`clOy2sbfW4XRMAHRLnCcqY)sB5?G+;K*$}^s*='
    '7-'
    'U@A6Ub8S2AqDu^zFlI3ty04uP1JHvQ%h7!4IHncsb2K|_T9+eZG$C?=mVL5Vm(qV1<oz+K9dUv)Ay0~gevGy)5hfezhztgZ&`GBN'
    '$UAee=hC-'
    '3PSG>4><+NfJAZ_NSw3?5^#rZVB0KG`mZ{YFztTU#%;^X9O}TlzR*JD98hmrJ7oSe2H}(4+<iOVS6Z+rDEaZpZ^z8$PafsCPDmG4'
    'WS{@mq`_EBY7tjPHJ!ZNn1ox*!u6Lz$#ZRQ~B7A;;N8I$ioO^KHm+pntU-'
    '&mGL;@51^Z0`_WEq#_x+MO)=__jhsV4O|fniTZq8r}>;1IIQXV&$}YiZP%k<D6;VkP7K8fA}xC3?P;Cfw1q@g~1=4Rc|R*lORz8w'
    '@$tFhu5`0G+8wR8wpeVS4_V1Q@%ei8lia3(UJ%<#Q|Y*>Z;`*(`gIP2)4Fm;_sbgr_Kwo)l)Scv-GZ!QdJ!)4-'
    'T1kbI)wQYF0X`zEX4I8=zqy-56U335$8ixeWFK!Ogz<Bp*Kt~!+U><_d2{JX4duzHkrd=YAv&;yK|bbwrpAQ3^u+Ing-'
    '1Rs~eiom<Syq}!acHcwN7Jmx?Ve)1u0+)8aBqLgBdD2|hyu!c+m_Ye@Zv7qShMqUEsMBT}HiaKJ8v=CFUeE-mZaMp*rV2AQ+hizS'
    'i94Li#;>r21Y<P^kN@bf6T1@CYrrFzZR{g*ZM6<<d%l{k7=<1D)CMp>P~0dRgXQ|sK`apw9|*xP)?`wMDu8gXYgqkeT;pvPE8v{<'
    'I`v4TsO?5MkjfQ&sI#Fc#T2wl+rg*fM9t*n9Pc;WrW)MitN;f#vxM7Gr%pHOw^kLj2Cfh0VSt@=^%HG>-'
    'HrwXRJ(;O^Q+SYPk0Br?geWRcYYG$g2=>`<{>=KhQd7Rm+}n9eWbPG@;LXq6QmvQs$c;+xVwR|N&OfOz=K*N(@=42ZlXCInGYf@m'
    'd^x1R<E@-RC5M`JwWMU2T6-'
    'Lm}{L^TX0|M&iAv81N+Ll$#8G^uSs9YM%|~#@fTFfh0&Fmihd@;P5hy$AnnYuv8<7<SYSpMP4$BjWY;3o-K7&%m^*e#9}-'
    '}USoW61h1m3R7Pd?|%3VyXwcy6C(etLa|KuLUS~4c+9Y@7Lmm9d?r-'
    'RV>`B&tUI)CM>1HPr9!4pxVwOj|e^b@9yJAo~68MG<Ms{F^Ph6)0S_-'
    '?Ix5Wz+*%m}VD!^Cx6G{fOMUCEL`)Ng>u6eUym1{<WY#gL|f5E0kid?$kry?~V=km>9DO#5buZ<=C5V~$CLd%M_97tB;jkqL$PPH'
    '9xx;-324C}E(~B<Bw+Z4%=qw#LhBMHbZEx1G!)FriNFFgEee4@6nFaEO}BY>vM!fEMJhWwWczqZyrH>U_xa1#o6%6EEhsM#-'
    'beOx$^I5%v{0Q4jR%kH_*Z*N@(F?tZGS@qSf3Cz?XUgC#*ug!+PfoSW?t>FF^pOaD{a925-hm5^-kAtW%9WW2--tQTD$lbsL2@CG'
    ';yGd_}zdaTZ!#QdrR(O8<=)cg-2$v$1Ycuv!!c@cnwyyc9{_zOXVMZxp!j|3_h^f9vU6RZq`5ywspXLs@-E!fTmer@-'
    '_c)$4{yG8s18NOzno>vDYGAs|<8LbN-KXL@{h>wY6e*w-f^n`oex})iLY8Oc7yKJW9yBDz>){rxfnhjjoV<&?Y-'
    '3_@8XN2zjM8o#YEb=n_kzPH$E)Y4|@n(-#3134ZTQrd0a@+W|B*B(fb%y0ss@7LHAFOwLnQ6}H)UFPjId(>5&851Bi@|ya-'
    'W*FDQh&;Fw2^B|x(RG0WC-j6&g6OQD9>EUhoL(}%h$Q3x-U~-'
    '6ILI+9xv(mF(~*Qy?lLwlsWWZ8WEv@DoHEZm@}>Je=1fy#*IXkP-'
    '&R>@bRlRmMD1X00000`l#Dq$w9QR00E)!1%UAN4FCWDr9th@6c;-%0{{R300dcD'
)


class NativeForkControls(unittest.TestCase):
    """All successful transcripts below are exact retained native executions."""
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory()
        cls.root=Path(cls.directory.name)
        packed=base64.b85decode(FIXTURE_ARCHIVE_B85)
        assert hashlib.sha256(packed).hexdigest()==FIXTURE_ARCHIVE_SHA256
        cls.rows={};cls.results={}
        with tarfile.open(fileobj=io.BytesIO(lzma.decompress(packed)),mode='r:')as archive:
            assert {member.name for member in archive.getmembers()}=={name+'.stdout'for name in FIXTURE_MEMBERS}
            for name,metadata in FIXTURE_MEMBERS.items():
                content=archive.extractfile(name+'.stdout').read()
                assert len(content)==metadata['raw_bytes'] and hashlib.sha256(content).hexdigest()==metadata['raw_sha256']
                path=cls.root/(name+'.stdout');path.write_bytes(content)
                rows,_=native.load(path);cls.rows[name]=rows
                cls.results[name]=native.read_fork(path,rows[0]['options'])
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()
    def reject(self,name,mutate,pattern=None):
        # Mutations exercise the same exact-field/type checks as load(), then
        # the real Reader and full scalar oracle. No acceptance is mocked.
        rows=copy.deepcopy(self.rows[name]);mutate(rows)
        with self.assertRaisesRegex(ValueError,pattern or '.'):
            for row in rows:
                native.exact(row,native.COMMON|set(native.FIELDS[row['kind']].split()),'ROW_FIELDS')
                native.parent.stamp(row['observed']);native.numeric_fields(row)
            native.Reader(rows).run()
    @staticmethod
    def first(rows,kind,**fields):
        return next(row for row in rows if row['kind']==kind and all(row.get(k)==v for k,v in fields.items()))
    def test_all_actual_full_proof_records_replay(self):
        self.assertEqual(len(self.results),12)
        self.assertEqual(sum(r['retained_proof_records_replayed']for r in self.results.values()),271)
        for result in self.results.values():
            counts=result['counts']
            self.assertEqual(counts['all_full_proof_records'],counts['research_proof_records']+counts['original_winner_records']+counts['original_reconstruction_records'])
            self.assertFalse(result['limits']['arbitrary_fork_forest'])
            self.assertFalse(result['limits']['minimum_attacker_cost_established'])
    def test_real_sibling_forest_is_not_a_relabelled_ancestor_bank(self):
        result=self.results['four-rr-lifetime'];leaves=result['forest']['leaves']
        self.assertEqual(len({leaf['parent']for leaf in leaves}),4)
        self.assertEqual(len({leaf['parent_height']for leaf in leaves}),1)
        self.assertEqual(len({leaf['state_root']for leaf in leaves}),4)
        first=[a for a in result['acquisitions']if a['role']=='fork-node' and a['level']==1]
        self.assertEqual(len(first),4)
        self.assertEqual({a['parent']for a in first},{result['forest']['base']})
        self.assertEqual({a['miner_actor']for a in first},{3,4,5,6})
        self.assertTrue(all(a['native_observation']['stored_exact'] and not a['native_observation']['active_chain_member']for a in first))
        self.assertEqual(result['receiver']['active_chain_growth_from_research'],0)
    def test_setup_known_winners_and_original_misses_are_paid_and_separate(self):
        result=self.results['four-rr-lifetime'];known={a['semantic_id']for a in result['acquisitions']}
        self.assertEqual(len(known),17)
        self.assertFalse(known.intersection(a['semantic_id']for a in result['attempts']))
        self.assertEqual(result['audit']['original_target_miss_reconstructions'],15)
        self.assertEqual(result['audit']['new_work_credit'],0)
        self.assertGreater(result['setup']['transaction_fee_units'],0)
    def test_lifetime_and_window_cache_reuse_are_actual_paid_operations(self):
        lifetime=self.results['four-rr-lifetime'];window=self.results['two-window']
        self.assertEqual(len(lifetime['epochs']),3)
        self.assertEqual(lifetime['setup']['lifetime_preparations'],2)
        self.assertTrue(all(a['cache_hit']for a in lifetime['attempts']))
        prepares=[r for r in self.rows['two-window']if r['kind']=='charge' and r['stage']=='arithmetic-prepare']
        self.assertEqual(len(prepares),6)
        self.assertTrue(all(r['phase']=='miner'for r in prepares))
        self.assertEqual([r['detail']['epoch']for r in prepares],[0,0,1,1,2,2])
        self.assertEqual(window['setup']['lifetime_preparations'],0)
        self.assertEqual(window['miner']['one_total_budget_across_epochs'],True)
    def test_adaptive_warmup_and_reuse_are_observed_without_receiver_feedback(self):
        rows=self.rows['four-adaptive-lifetime'];selections=[r for r in rows if r['kind']=='selection']
        self.assertEqual([r['template_index']for r in selections[:8]],list(range(8)))
        self.assertTrue(all(r['receiver_feedback']is False and r['ticket_observed']is False for r in selections))
        self.assertEqual(sum(x['samples']for x in selections[8]['adaptive_observations']),8)
        self.assertEqual(sum(x['samples']for x in self.results['four-adaptive-lifetime']['miner']['adaptive_history']),10)
    def test_zero_and_tight_budget_controls_really_stop(self):
        for name in ('setup-zero','setup-tight'):
            self.assertFalse(self.results[name]['setup_complete']);self.assertEqual(self.results[name]['counts']['research_proof_records'],0)
        self.assertEqual(self.results['miner-zero']['epochs'],[])
        late=self.results['miner-tight'];self.assertEqual(late['counts']['research_late_target_hits'],1)
        self.assertTrue(late['attempts'][0]['native_accepted'])
        self.assertEqual(late['counts']['eventually_native_accepted_from_B'],0)
        self.assertEqual(late['miner_status'],'miner-cpu-budget-stopped')
    def test_cold_and_selective_tasks_keep_real_setup_scope(self):
        cold=self.results['zero-cold'];maintenance=self.results['maintenance-selective']
        self.assertEqual(cold['setup']['acquired_tasks'],[1]);self.assertTrue(all(not a['cache_hit']for a in cold['attempts']))
        self.assertEqual(maintenance['setup']['acquired_tasks'],[0]);self.assertEqual(maintenance['setup']['transaction_count'],0)
        self.assertEqual(self.results['maximum-depth']['forest']['leaves'][0]['parent_height'],5)
        self.assertEqual(self.results['strassen-zero']['options']['arm'],'structure-strassen')
    def test_original_schema_and_invalid_options_cannot_be_accepted(self):
        for changes in ({'branches':True},{'depth':0},{'depth':5},{'window_attempts':0},{'max_attempts':4097},{'policy':'oracle-best'},{'reuse':'free'}):
            options=dict(self.rows['setup-zero'][0]['options'],**changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):native.validate_options(options)
        raw=(self.root/'setup-zero.stdout').read_bytes().replace(native.SCHEMA.encode(),b'pon-w1-miner-budget-research-v1')
        path=self.root/'bad-schema.stdout';path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'RAW_RECORD'):native.read_fork(path)
    def test_fake_branch_actor_or_location_is_rejected(self):
        self.reject('four-rr-lifetime',lambda rows:self.first(rows,'setup-acquisition',role='fork-node',branch=1).__setitem__('miner_actor',3))
        self.reject('four-rr-lifetime',lambda rows:self.first(rows,'setup-acquisition',role='fork-node',branch=1).__setitem__('branch',0),'ACQUISITION_GRID')
    def test_forest_cannot_reuse_one_leaf_or_change_the_paid_base(self):
        self.reject('four-rr-lifetime',lambda rows:self.first(rows,'forest')['leaves'].__setitem__(1,copy.deepcopy(self.first(rows,'forest')['leaves'][0])),'FOREST_LEAF_BINDING')
        self.reject('four-rr-lifetime',lambda rows:self.first(rows,'forest').__setitem__('base','0'*64),'FOREST_TOPOLOGY')
    def test_sibling_work_is_not_summed_into_the_active_chain(self):
        def mutate(rows):
            boundary=self.first(rows,'boundary',**{'from':'setup'})
            boundary['detail']['native_stats']['chainwork_hex']=(20).to_bytes(64,'big').hex()
        self.reject('four-rr-lifetime',mutate,'NATIVE_STATS')
    def test_material_key_and_cold_cache_hit_forgery_are_rejected(self):
        self.reject('zero-cold',lambda rows:self.first(rows,'charge',stage='arithmetic-prepare')['detail'].__setitem__('material_task','0'*64),'PREPARE_BINDING')
        self.reject('zero-cold',lambda rows:self.first(rows,'attempt').__setitem__('cache_hit',True),'MATERIAL_CACHE_BINDING')
    def test_window_budget_cannot_be_reset_or_relabelled_as_free(self):
        self.reject('two-window',lambda rows:self.first(rows,'epoch',epoch=1).__setitem__('reset_miner_budget',True))
        self.reject('two-window',lambda rows:self.first(rows,'epoch',epoch=1).__setitem__('one_total_miner_budget_ns',2_000_000_000),'EPOCH_ONE_BUDGET')
        def mutate(rows):
            charge=next(r for r in rows if r['kind']=='charge' and r['stage']=='reuse-window' and r['detail']['epoch']==1)
            charge['detail']['cache_after']=charge['detail']['cache_before']
        self.reject('two-window',mutate,'WINDOW_CACHE_RESET')
    def test_adaptive_history_cannot_hide_paid_exploration_or_use_future_samples(self):
        def mutate(rows):
            selection=self.first(rows,'selection',attempt_id=8)
            selection['adaptive_observations'][0]['service_cpu_ns']=0
        self.reject('four-adaptive-lifetime',mutate,'ADAPTIVE_PAID_HISTORY')
        self.reject('four-adaptive-lifetime',lambda rows:self.first(rows,'selection',attempt_id=8)['adaptive_observations'][0].__setitem__('samples',2),'ADAPTIVE_PAID_HISTORY')
        self.reject('four-adaptive-lifetime',lambda rows:self.first(rows,'selection',attempt_id=8)['adaptive_observations'][0].__setitem__('samples',1.0),'ADAPTIVE_PAID_HISTORY')
    def test_adaptive_choice_is_checked_even_with_a_correctly_reencoded_other_header(self):
        def mutate(rows):
            selection=self.first(rows,'selection',attempt_id=8);index=(selection['template_index']+1)%8
            template=self.results['four-adaptive-lifetime']['templates'][index]
            header=native.parent.header_decode(bytes.fromhex(template['header_hex']))
            selection.update(template_index=index,branch=template['branch'],task_index=template['task_index'],header_hex=native.candidate(rows[0]['options'],8,dict(template,header=header),0).hex())
        self.reject('four-adaptive-lifetime',mutate,'ADAPTIVE_PAID_HISTORY')
    def test_screened_candidates_and_no_feedback_flags_are_checked(self):
        self.reject('two-screen',lambda rows:self.first(rows,'screen').__setitem__('score',0),'SCREEN_REPLAY')
        self.reject('four-adaptive-lifetime',lambda rows:self.first(rows,'selection').__setitem__('receiver_feedback',True))
        self.reject('miner-tight',lambda rows:self.first(rows,'attempt').__setitem__('node_called',True))
    def test_complete_output_availability_is_after_the_actual_proof_record(self):
        def mutate(rows):
            attempt=self.first(rows,'attempt');available=self.first(rows,'available')
            available['available']=dict(attempt['observed'],process_cpu_ns=attempt['observed']['process_cpu_ns']-1)
        self.reject('miner-tight',mutate,'AVAILABILITY_BEFORE_BYTES')
        self.reject('miner-tight',lambda rows:self.first(rows,'available').__setitem__('within_miner_budget',True),'AVAILABILITY_BUDGET')
        self.reject('miner-tight',lambda rows:self.first(rows,'available').__setitem__('service_cpu_ns',0),'SERVICE_CPU_BINDING')
    def test_proof_content_and_receiver_outcome_are_not_trusted_labels(self):
        self.reject('miner-tight',lambda rows:self.first(rows,'attempt')['proof'].__setitem__('proof_sha256','0'*64),'PROOF_DIGEST')
        self.reject('miner-tight',lambda rows:self.first(rows,'receiver').__setitem__('accepted',False),'NATIVE_ADMISSION_RESULT')
    def test_missing_misses_and_reconstruction_credit_are_rejected(self):
        def mutate(rows):
            target=next(r for r in rows if r['kind']=='reconstruction' and r['original_winner']is False)
            rows.remove(target)
            for sequence,row in enumerate(rows):row['sequence']=sequence
        self.reject('miner-tight',mutate)
        self.reject('miner-zero',lambda rows:self.first(rows,'reconstruction').__setitem__('new_work_credit',True))
    def test_phase_endpoints_and_summary_types_are_not_aliased(self):
        self.reject('setup-zero',lambda rows:self.first(rows,'boundary')['begin'].__setitem__('process_cpu_ns',False),'PHASE_BOUNDARY_ORDER')
        self.reject('setup-zero',lambda rows:self.first(rows,'boundary')['detail'].__setitem__('original_acquisitions',False),'SETUP_SUMMARY_BINDING')
        self.reject('miner-tight',lambda rows:self.first(rows,'end').__setitem__('total_process_cpu_ns',0),'GLOBAL_CPU_ENDPOINT')
        self.reject('setup-zero',lambda rows:self.first(rows,'end').__setitem__('arbitrary_strategy_cost_bound_established',True))
    def test_caps_are_not_budget_exhaustion_or_uncensored_measurements(self):
        result=copy.deepcopy(self.results['four-rr-lifetime']);result.update(job='parser-control',whole_command_usage={'scope':'not a performance observation'},cpu_observer_reconciliation={'scope':'not a performance observation'})
        metric=analysis.miner_metrics(result)
        self.assertFalse(metric['complete_uncensored_miner_budget_observation'])
        self.assertTrue(metric['safety_cap_reached'])
        self.assertEqual(metric['canonical_chainwork_added_by_research'],0)
    def test_semantic_stream_divergence_is_not_a_matched_pair(self):
        original=self.results['four-adaptive-lifetime']['attempts'];changed=copy.deepcopy(original)
        changed[8]['semantic_id']='0'*64
        self.assertEqual(analysis.matching_prefix(original,changed),(False,8))
        self.assertEqual(analysis.matching_prefix(original,original[:5]),(True,5))
    def test_registered_pair_counts_are_fixed_without_running_measurements(self):
        frozen=runner.decode(analysis.PLAN.read_bytes());groups={field:{} for field in ('arm','reuse','policy')}
        for job in frozen['jobs']:
            if frozen['cohorts'][job['name']]=='control':continue
            options=native.options_from_args(job['args'])
            for field in groups:groups[field].setdefault(analysis.key_without(options,field),set()).add(options[field])
        counts={field:sum(len(labels)-1 for labels in group.values()if reference in labels)for field,reference in (('arm','integer-paired-general'),('reuse','lifetime'),('policy','round-robin'))for group in (groups[field],)}
        self.assertEqual(counts,dict(arm=20,reuse=4,policy=14))
        self.assertEqual(sum({'structure-specialized','structure-strassen'}<=labels for labels in groups['arm'].values()),4)


if __name__=='__main__':
    unittest.main()
