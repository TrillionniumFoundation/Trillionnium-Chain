"""Concrete public admission controls; no native or Cargo success is simulated."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from .build import ROOT, HERE, OWNED, identity, read_json, source_manifest, write_json
from .bundle import (artifacts, canonical_file, require_output_and_target, include_graph,
                     validate_control_roster, TRACE_CONTROL_PROFILE, SIGNAL_CONTROL_PROFILE, physical_frame)
from .native_io import decode
from .cases import corpus, original_cases, PROTOCOL_ONLY
from .rust_oracle import original_artifact
from hia.platform.paid_cpu.dependency import FORBIDDEN, forbidden_override

class Admission(unittest.TestCase):
    def cli(self, root, *, env=None, bundle=None, output=None, target=None, optimized=False):
        bundle = bundle or root / "bundle"; bundle.mkdir(exist_ok=True)
        output = output or root / "original"
        target = target or root / "cargo"
        argv = [sys.executable, "-O" if optimized else "-B", "-m", "hia.platform.work_owner.rust_oracle",
                "--repository", str(ROOT), "--bundle", str(bundle), "--output", str(output),
                "--target-dir", str(target)]
        actual_env = dict(os.environ); actual_env["PYTHONDONTWRITEBYTECODE"] = "1"
        for key in list(actual_env):
            if forbidden_override(key): actual_env.pop(key)
        if env: actual_env.update(env)
        result = subprocess.run(argv, cwd=ROOT, env=actual_env, capture_output=True, timeout=40)
        self.assertNotEqual(result.returncode, 0, result.stdout.decode(errors="replace"))
        self.assertFalse(output.exists(), "Rejected public input created an original output/source copy")
        self.assertFalse(target.exists(), "Rejected public input created a Cargo target")
        return result.stderr.decode(errors="replace")

    def test_complete_declared_source_closure(self):
        rows = source_manifest()
        self.assertEqual(len(OWNED), 30)
        self.assertEqual(sum(name.endswith(".hepta") for name in OWNED), 8)
        actual = {p.name for p in HERE.iterdir() if p.suffix in {".py", ".rs", ".hepta", ".json", ".md"}}
        self.assertEqual(actual, set(OWNED))
        for name in OWNED:
            self.assertEqual(rows["hia/platform/work_owner/" + name], identity(HERE / name))
        self.assertIn("hia/platform/paid_cpu/dependency.py", rows)
        self.assertIn("hia/platform/host_resource/rust_reference.rs", rows)
        self.assertIn("trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs", rows)

    def test_public_compiler_runtime_override_rejected_before_copy(self):
        names = ["RUSTC", "CARGO_BUILD_RUSTC", "RUSTDOC", "CARGO_BUILD_RUSTDOC", "RUSTFLAGS",
                 "CARGO_BUILD_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTC_WRAPPER",
                 "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                 "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "CARGO_PROFILE_TEST_OPT_LEVEL",
                 "LD_PRELOAD", "LD_LIBRARY_PATH", "CARGO_TARGET_DIR"]
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="hia-work-gate-") as tmp:
                error = self.cli(Path(tmp), env={name: "/unbound/private-negative-control"})
                self.assertIn("Unbound original compilation/runtime override: " + name, error)

    def test_public_optimized_python_refused(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-optimized-") as tmp:
            self.assertIn("refuses optimized Python", self.cli(Path(tmp), optimized=True))

    def test_public_complete_source_sets_required(self):
        current = source_manifest()
        key = "hia/platform/work_owner/rust_reference.rs"
        variants = []
        for which in ("top", "build", "both"):
            top = copy.deepcopy(current); built = copy.deepcopy(current)
            if which in ("top", "both"): del top[key]
            if which in ("build", "both"): del built[key]
            variants.append((which + "-omission", top, built))
        top = copy.deepcopy(current); top[key] = {**top[key], "sha256": "0" * 64}
        variants.append(("both-mutated", top, copy.deepcopy(top)))
        top = copy.deepcopy(current); top["hia/platform/work_owner/unlisted.py"] = {"bytes": 0, "sha256": "0" * 64}
        variants.append(("both-added", top, copy.deepcopy(top)))
        for name, top, built in variants:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="hia-work-source-gate-") as tmp:
                root = Path(tmp); bundle = root / "bundle"; bundle.mkdir()
                write_json(bundle / "report.json", {"schema": "trnm.hia.work-owner-qualification.v1",
                           "status": "PASS", "source_inputs": top, "build": {"source_inputs": built}})
                self.assertIn("complete source maps differ", self.cli(root, bundle=bundle))

    def test_public_duplicate_json_fields_rejected(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-duplicate-gate-") as tmp:
            root = Path(tmp); bundle = root / "bundle"; bundle.mkdir()
            (bundle / "report.json").write_text('{"status":"FAIL","status":"PASS"}\n')
            self.assertIn("Duplicate JSON field", self.cli(root, bundle=bundle))

    def test_public_nonfinite_json_refused_before_copy(self):
        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), tempfile.TemporaryDirectory(prefix="hia-work-nonfinite-") as tmp:
                root = Path(tmp); bundle = root / "bundle"; bundle.mkdir()
                (bundle / "report.json").write_text('{"status":"PASS","unbound":' + value + '}\n')
                self.assertIn("Non-finite JSON number", self.cli(root, bundle=bundle))

    def test_public_source_identity_counts_keep_integer_type(self):
        current = source_manifest()
        key = "hia/platform/work_owner/bundle.py"
        top = copy.deepcopy(current)
        top[key]["bytes"] = float(top[key]["bytes"])
        with tempfile.TemporaryDirectory(prefix="hia-work-source-type-") as tmp:
            root = Path(tmp); bundle = root / "bundle"; bundle.mkdir()
            write_json(bundle / "report.json", {"schema": "trnm.hia.work-owner-qualification.v1",
                       "status": "PASS", "source_inputs": top, "build": {"source_inputs": top}})
            self.assertIn("complete source maps differ", self.cli(root, bundle=bundle))

    def test_raw_frame_reader_rejects_coherent_numeric_type_changes(self):
        # A deliberately encoded reader fixture, not a new native execution.
        # Actual ELF regressions and their complete raw bytes are separate.
        words = [0] * 64
        words[0] = int.from_bytes(b"HIAWO001", "little")
        words[1:4] = [1, 2, 1]
        words[5] = 1
        words[10:14] = [11, 12, 1, 1]
        raw = struct.pack("<64Q", *words) + bytes(768) + struct.pack("<5Q", 64, 0, 0, 0, 1)
        with tempfile.TemporaryDirectory(prefix="hia-work-frame-type-") as tmp:
            directory = Path(tmp)
            (directory / "stdout.raw").write_bytes(raw)
            (directory / "stderr.raw").write_bytes(b"")
            physical = {
                "image_sha256": "0" * 64, "decoded": decode(raw),
                "stdout": identity(directory / "stdout.raw"), "stderr": identity(directory / "stderr.raw"),
                "status": "PHYSICAL_FRAME_PASS_SEMANTIC_EXPECTATIONS_PENDING", "fixture": True,
                "production_authority": False, "actual_original_rust": False,
                "exit_code": 66, "stderr_hex": "",
            }
            write_json(directory / "physical.json", physical)
            self.assertEqual(physical_frame(physical, directory, "0" * 64), decode(raw))
            variants = [
                (("decoded", "header", "domain"), 2.0),
                (("decoded", "header", "code"), True),
                (("decoded", "progress", 0, 4), True),
                (("decoded", "host_after", 0), False),
                (("decoded", "product_bytes"), False),
                (("exit_code",), 66.0),
                (("stdout", "bytes"), float(len(raw))),
                (("fixture",), 1),
                (("production_authority",), 0),
                (("actual_original_rust",), 0),
            ]
            for path, value in variants:
                changed = copy.deepcopy(physical); target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                write_json(directory / "physical.json", changed)
                with self.subTest(path=path), self.assertRaises(ValueError):
                    physical_frame(changed, directory, "0" * 64)
                self.assertEqual((directory / "stdout.raw").read_bytes(), raw)

    def test_targets_cannot_overlap_isolated_or_source_trees(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-target-gate-") as tmp:
            root = Path(tmp); protected = root / "source"; protected.mkdir()
            output = root / "result"
            for target in (output, output / "isolated-source", root, protected, protected / "target"):
                with self.subTest(target=str(target)), self.assertRaises(ValueError):
                    require_output_and_target(output, target, protected)
            with self.assertRaises(ValueError):
                require_output_and_target(protected / "output", root / "cargo", protected)
            link = root / "linked"; link.symlink_to(protected, target_is_directory=True)
            with self.assertRaises(ValueError):
                require_output_and_target(output, link / "target", protected)

    def test_actual_artifact_selector_excludes_build_scripts_and_other_library(self):
        isolated = Path("/private/isolated-source")
        valid = {"reason": "compiler-artifact", "target": {"name": "trnm_pon_node", "kind": ["lib"],
                 "src_path": str(isolated / "trillionnium/crates/trnm-pon-node/src/lib.rs")},
                 "manifest_path": str(isolated / "trillionnium/crates/trnm-pon-node/Cargo.toml"),
                 "profile": {"test": True}, "executable": "/private/cargo/actual-node"}
        build_script = copy.deepcopy(valid); build_script["target"]["kind"] = ["custom-build"]
        self.assertEqual(original_artifact([build_script, valid], isolated), valid)
        for values in ([build_script], [valid, valid]):
            with self.assertRaises(ValueError): original_artifact(values, isolated)
        wrong = copy.deepcopy(valid); wrong["target"]["src_path"] = "/foreign/src/lib.rs"
        with self.assertRaises(ValueError): original_artifact([wrong], isolated)

    def test_artifact_path_alias_and_extra_files_are_observed(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-files-gate-") as tmp:
            root = Path(tmp); (root / "raw").write_bytes(b"actual complete raw")
            first = artifacts(root)
            (root / "unlisted").write_bytes(b"extra")
            self.assertNotEqual(first, artifacts(root))
            for name in ("../raw", "/raw", "a/../raw", "a//raw"):
                with self.subTest(name=name), self.assertRaises(ValueError): canonical_file(root, name)
            (root / "alias").symlink_to(root / "raw")
            with self.assertRaises(ValueError): artifacts(root)
            (root / "alias").unlink(); os.link(root / "raw", root / "hard")
            with self.assertRaises(ValueError): canonical_file(root, "raw")

    def test_literal_and_bound_manifest_include_graph(self):
        with tempfile.TemporaryDirectory(prefix="hia-work-includes-") as tmp:
            root = Path(tmp); package = root / "trillionnium/crates/trnm-pon-node"
            (package / "src").mkdir(parents=True)
            (root / "trillionnium/Cargo.toml").write_text('[workspace]\nmembers=["crates/trnm-pon-node"]\n')
            (package / "Cargo.toml").write_text('[package]\nname="trnm-pon-node"\nversion="0.1.0"\n')
            (package / "src/data.txt").write_text("actual literal input")
            source = package / "src/lib.rs"
            source.write_text('const A:&str=include_str!("data.txt");\n'
                'const B:&[u8]=include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/src/data.txt"));\n')
            graph = include_graph(root)
            self.assertEqual(graph["local_packages"], ["trillionnium/crates/trnm-pon-node"])
            self.assertEqual(set(graph["includes"]), {"trillionnium/crates/trnm-pon-node/src/data.txt"})
            self.assertEqual({r["form"] for r in next(iter(graph["includes"].values()))},
                             {"file-relative", "bound-CARGO_MANIFEST_DIR"})
            for expression in ('include_str!(concat!(env!("HOME"),"/src/data.txt"))',
                               'include_str!(concat!("data",".txt"))',
                               'include_str!("../../../../../escaped")'):
                source.write_text("const X:&str=" + expression + ";")
                with self.subTest(expression=expression), self.assertRaises(ValueError): include_graph(root)

    def test_control_claims_cannot_omit_duplicate_or_relabel_actual_rows(self):
        for profile, schema in (
                (TRACE_CONTROL_PROFILE, "trnm.hia.work-owner-trace-controls.v1"),
                (SIGNAL_CONTROL_PROFILE, "trnm.hia.work-owner-signal-trace-controls.v1")):
            positive = sum(accepted for _, accepted in profile)
            valid = {"schema": schema, "status": "PASS", "count": len(profile),
                     "positive": positive, "negative": len(profile) - positive,
                     "rows": [{"name": name, "expected_acceptance": accepted,
                               "actual_acceptance": accepted, "status": "PASS"} for name, accepted in profile]}
            validate_control_roster(valid, profile, schema)
            variants = []
            for key in ("count", "positive", "negative"):
                value = copy.deepcopy(valid); value[key] = float(value[key]); variants.append(value)
            value = copy.deepcopy(valid); value["rows"] = []; variants.append(value)
            value = copy.deepcopy(valid); value["rows"].pop(); variants.append(value)
            value = copy.deepcopy(valid); value["rows"][-1] = value["rows"][0]; variants.append(value)
            value = copy.deepcopy(valid); value["rows"] = value["rows"][::-1]; variants.append(value)
            value = copy.deepcopy(valid); value["rows"][0]["actual_acceptance"] = False; variants.append(value)
            value = copy.deepcopy(valid); value["rows"][0]["actual_acceptance"] = 1; variants.append(value)
            value = copy.deepcopy(valid); value["rows"][0]["status"] = "NOT_RUN"; variants.append(value)
            value = copy.deepcopy(valid); value["rows"][-1]["expected_acceptance"] = not value["rows"][-1]["expected_acceptance"]; variants.append(value)
            for index, value in enumerate(variants):
                with self.subTest(schema=schema, index=index), self.assertRaises(ValueError):
                    validate_control_roster(value, profile, schema)

    def test_independent_complete_corpus_and_protocol_separation(self):
        rows = corpus(); original = original_cases()
        self.assertEqual((len(rows), len(original)), (61, 57))
        self.assertEqual(set(c["name"] for c in rows) - set(c["name"] for c in original), set(PROTOCOL_ONLY))
        self.assertEqual(sum(len(c["progress"]) for c in rows), 27843)
        self.assertEqual(len(rows[0]["progress"]), 1099)
        self.assertEqual(rows[0]["progress"][0], [64, 0, 0, 0, 1])
        self.assertEqual(rows[0]["progress"][-1], [69, 0, 0, 0, 1099])
        self.assertEqual([c["name"] for c in rows[52:]], [
            "zero-times-max", "identity-times-pattern", "max-pattern", "exact-ticket-equality",
            "ticket-minus-one", "changed-challenge", "transcript-before-product-error",
            "target-before-field-error", "version-before-target-error"])

if __name__ == "__main__":
    unittest.main()
