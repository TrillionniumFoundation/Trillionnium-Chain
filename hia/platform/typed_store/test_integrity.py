"""Real fail-closed controller checks; no native or Rust qualification is claimed.

The synthetic comparison documents below exercise admission only. Their PASS
fields are fixture inputs, never an observed native result. Public CLI checks
have an empty PATH and must either reject the bundle or report NOT_RUN.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

OPTIONS = None
CONTROLS = []
PUBLIC_CALLS = []


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def put_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def load_oracle(path):
    spec = importlib.util.spec_from_file_location("_typed_integrity_oracle", path)
    module = importlib.util.module_from_spec(spec)
    # Read exact source bytes rather than accepting an unrelated pyc cache.
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


class Integrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository = OPTIONS.repository.resolve(strict=True)
        cls.oracle_path = (OPTIONS.oracle or cls.repository /
            "hia/platform/typed_store/rust_oracle.py").resolve(strict=True)
        cls.oracle = load_oracle(cls.oracle_path)
        cls.root = Path(tempfile.mkdtemp(prefix="trnm-typed-store-integrity-"))
        cls.before = cls.oracle.complete_source_manifest(cls.repository)
        cls.corpus = cls.oracle.canonical_corpus(cls.repository)
        cls.names = [json.loads(line)["name"] for line in cls.corpus.splitlines()]
        cls.compressed = lzma.compress(cls.corpus, preset=1)
        cls.template = cls.root / "template"
        cls.template.mkdir()
        components = json.loads((cls.repository / "hia/components.json").read_bytes())
        required = set(cls.before)
        required.update("hia/" + name for name in components["includes"])
        required.update("hia/" + row["source"] for rows in components["includes"].values() for row in rows)
        for relative in sorted(required):
            source = cls.oracle.canonical_path(cls.repository, relative)
            destination = cls.template / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        (cls.template / "hia/platform/typed_store/rust_oracle.py").write_bytes(cls.oracle_path.read_bytes())
        # Include the installed test as a real future owned input, even when
        # reviewing this proposal outside the source repository.
        (cls.template / "hia/platform/typed_store/test_integrity.py").write_bytes(Path(__file__).read_bytes())
        cls.original = {}
        for relative in ("trillionnium/Cargo.lock", "trillionnium/crates/trnm-pon-node/src/store.rs"):
            raw = cls.oracle.canonical_path(cls.repository, relative).read_bytes()
            destination = cls.template / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            cls.original[relative] = identity(raw)

    def fixture(self):
        parent = Path(tempfile.mkdtemp(prefix="case-", dir=self.root))
        repository, bundle = parent / "source", parent / "bundle"
        shutil.copytree(self.template, repository)
        bundle.mkdir()
        inputs = self.oracle.complete_source_manifest(repository)
        comparison = {
            "schema": "trnm.hia.typed-staging-native-comparison.v1", "status": "PASS",
            "controller_test_fixture_not_native_evidence": True,
            "build": {"schema": "trnm.hia.typed-staging-build.v1", "status": "PASS",
                "source_inputs": inputs, "source_set_sha256": self.oracle.canonical_json_hash(inputs),
                "original_sources": self.original},
            "corpus": identity(self.corpus), "cases": [{"name": name} for name in self.names],
        }
        put_json(bundle / "native-comparison.json", comparison)
        (bundle / "corpus.jsonl.xz").write_bytes(self.compressed)
        return repository, bundle, comparison

    def rejected(self, name, call, message=None):
        with self.assertRaises((ValueError, OSError, lzma.LZMAError)) as context:
            call()
        error = str(context.exception)
        if message is not None:
            self.assertIn(message, error)
        CONTROLS.append({"name": name, "status": "PASS", "observed_rejection": error})

    def accepted(self, name, call):
        result = call()
        CONTROLS.append({"name": name, "status": "PASS", "binding_only": True})
        return result

    def rebind(self, repository, comparison):
        comparison["build"]["source_inputs"] = self.oracle.complete_source_manifest(repository)
        comparison["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(
            comparison["build"]["source_inputs"])

    def test_complete_current_source_and_optional_real_bundle(self):
        repository, bundle, comparison = self.fixture()
        actual = self.accepted("complete-fixture-source-and-corpus", lambda:
            self.oracle.validate_bundle(repository, bundle))
        self.assertEqual(actual[3], self.corpus)
        self.assertEqual(actual[2], comparison["build"]["source_inputs"])
        self.assertIn("hia/platform/typed_store/test_integrity.py", actual[2])
        if OPTIONS.native_bundle is not None:
            if OPTIONS.native_bundle.is_dir():
                original = json.loads((OPTIONS.native_bundle / "native-comparison.json").read_bytes())
            else:
                with tarfile.open(OPTIONS.native_bundle, "r:*") as archive:
                    matches = [row for row in archive.getmembers() if row.isfile()
                        and row.name == "bundle/native-comparison.json"]
                    self.assertEqual(len(matches), 1)
                    original = json.load(archive.extractfile(matches[0]))
            self.assertEqual(self.accepted("actual-native-source-map", lambda:
                self.oracle.validate_source_bindings(self.repository, original)), self.before)
            self.assertEqual(original["corpus"], identity(self.corpus))
            self.assertEqual([row["name"] for row in original["cases"]], self.names)
            CONTROLS.append({"name": "actual-native-entire-input-corpus", "status": "PASS",
                "corpus": identity(self.corpus), "cases": len(self.names)})

    def test_every_omission_and_digest_forgery(self):
        repository, _, comparison = self.fixture()
        for missing in comparison["build"]["source_inputs"]:
            bad = copy.deepcopy(comparison)
            del bad["build"]["source_inputs"][missing]
            bad["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(bad["build"]["source_inputs"])
            self.rejected("omit-" + missing, lambda: self.oracle.validate_source_bindings(repository, bad),
                          "Incomplete or extra")
        for field, value in (("sha256", "0" * 64), ("bytes", 0), ("bytes", True)):
            bad = copy.deepcopy(comparison)
            bad["build"]["source_inputs"]["hia/platform/typed_store/cases.py"][field] = value
            bad["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(bad["build"]["source_inputs"])
            self.rejected("forged-identity-" + field + "-" + str(value), lambda:
                self.oracle.validate_source_bindings(repository, bad))
        bad = copy.deepcopy(comparison)
        bad["build"]["source_set_sha256"] = "0" * 64
        self.rejected("forged-source-set-digest", lambda: self.oracle.validate_source_bindings(repository, bad),
                      "source-set digest")
        extra = repository / "hia/extra-native-input.txt"
        extra.write_text("An existing extra path is still not part of the source closure.\n")
        bad = copy.deepcopy(comparison)
        bad["build"]["source_inputs"]["hia/extra-native-input.txt"] = identity(extra.read_bytes())
        bad["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(bad["build"]["source_inputs"])
        self.rejected("extra-existing-source", lambda: self.oracle.validate_source_bindings(repository, bad),
                      "Incomplete or extra")

    def test_future_owned_source_and_mandatory_source(self):
        repository, _, comparison = self.fixture()
        future = repository / "hia/platform/typed_store/future_helper.py"
        future.write_text("# An owned source added after this test was written.\n")
        self.rejected("future-owned-source-omitted", lambda:
            self.oracle.validate_source_bindings(repository, comparison), "Incomplete or extra")
        self.rebind(repository, comparison)
        self.accepted("future-owned-source-included", lambda:
            self.oracle.validate_source_bindings(repository, comparison))
        (repository / "hia/platform/typed_store/README.md").unlink()
        del comparison["build"]["source_inputs"]["hia/platform/typed_store/README.md"]
        comparison["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(comparison["build"]["source_inputs"])
        self.rejected("mandatory-owner-source-deleted-and-unbound", lambda:
            self.oracle.validate_source_bindings(repository, comparison), "mandatory typed Store")

    def test_recursive_independent_admission_closure(self):
        repository, _, comparison = self.fixture()
        parent = "src/protocol/integrity_parent.hepta"
        leaf = "src/protocol/integrity_leaf.hepta"
        (repository / "hia" / leaf).write_text(
            'hia-asm.v1 hepta.hia.program.v8 integrity_leaf\n'
            'fn integrity_leaf() -> (u64) effects(read,write,trap) entry(b0)\n'
            'block b0()\n  v0:u64 = const() {"value":1}\n  ret(v0)\nend\n')
        (repository / "hia" / parent).write_text(
            'hia-asm.v1 hepta.hia.program.v8 integrity_parent\n'
            'fn integrity_parent() -> (u64) effects(read,write,trap) entry(b0)\n'
            'block b0()\n  v0:u64 = call() {"function":"integrity_leaf"}\n  ret(v0)\nend\n')
        component_path = repository / "hia/components.json"
        typed_path = repository / "hia/platform/typed_store/includes.json"
        components, typed = json.loads(component_path.read_bytes()), json.loads(typed_path.read_bytes())
        components["includes"][parent] = [{"source": leaf, "functions": ["integrity_leaf"]}]
        typed["includes"]["stage_policy.hepta"].append({"source": parent, "functions": ["integrity_parent"]})
        put_json(component_path, components)
        put_json(typed_path, typed)
        self.rebind(repository, comparison)
        self.assertIn("hia/" + leaf, comparison["build"]["source_inputs"])
        self.accepted("recursive-independent-source-included", lambda:
            self.oracle.validate_source_bindings(repository, comparison))
        bad = copy.deepcopy(comparison)
        del bad["build"]["source_inputs"]["hia/" + leaf]
        bad["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(bad["build"]["source_inputs"])
        self.rejected("recursive-independent-source-omitted", lambda:
            self.oracle.validate_source_bindings(repository, bad), "Incomplete or extra")
        for name, names in (("unknown-callee", ["integrity_missing"]),
                            ("reexported-callee", ["integrity_leaf"]),
                            ("duplicate-callee", ["integrity_parent", "integrity_parent"])):
            bad_typed = copy.deepcopy(typed)
            bad_typed["includes"]["stage_policy.hepta"][-1]["functions"] = names
            put_json(typed_path, bad_typed)
            self.rejected(name, lambda: self.oracle.complete_source_manifest(repository), "callee")
        put_json(typed_path, typed)
        components["includes"][leaf] = [{"source": parent, "functions": ["integrity_parent"]}]
        put_json(component_path, components)
        self.rejected("recursive-include-cycle", lambda:
            self.oracle.complete_source_manifest(repository), "Cyclic")

    def test_noncanonical_paths_and_symlinks(self):
        repository, bundle, comparison = self.fixture()
        source = "hia/platform/typed_store/cases.py"
        for alias in ("/" + source, "hia/../" + source, "./" + source,
                      "hia//platform/typed_store/cases.py", "hia\\platform\\typed_store\\cases.py"):
            bad = copy.deepcopy(comparison)
            bad["build"]["source_inputs"][alias] = bad["build"]["source_inputs"].pop(source)
            bad["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(bad["build"]["source_inputs"])
            self.rejected("noncanonical-" + repr(alias), lambda:
                self.oracle.validate_source_bindings(repository, bad), "canonical source path")
        path = repository / source
        backup = path.with_suffix(".saved")
        path.rename(backup)
        path.symlink_to(backup.name)
        self.rejected("same-bytes-leaf-symlink", lambda:
            self.oracle.validate_source_bindings(repository, comparison), "Symlinked")
        path.unlink()
        backup.rename(path)
        path = repository / "hia/src/codec"
        backup = path.with_name("codec-saved")
        path.rename(backup)
        path.symlink_to(backup.name, target_is_directory=True)
        self.rejected("same-bytes-ancestor-symlink", lambda:
            self.oracle.validate_source_bindings(repository, comparison), "Symlinked")
        path.unlink()
        backup.rename(path)
        archive = bundle / "corpus.jsonl.xz"
        archive.rename(bundle / "corpus.saved")
        archive.symlink_to("corpus.saved")
        self.rejected("corpus-symlink", lambda:
            self.oracle.validate_bundle(repository, bundle), "Symlinked")

    def test_duplicate_json_keys(self):
        repository, bundle, comparison = self.fixture()
        for name in ("hia/components.json", "hia/platform/typed_store/includes.json"):
            path = repository / name
            saved = path.read_bytes()
            path.write_bytes(saved.replace(b'{', b'{"schema":"unbound-duplicate",', 1))
            self.rejected("duplicate-key-" + name, lambda:
                self.oracle.complete_source_manifest(repository), "Duplicate")
            path.write_bytes(saved)
        path = bundle / "native-comparison.json"
        path.write_bytes(path.read_bytes().replace(b'{', b'{"schema":"unbound-duplicate",', 1))
        self.rejected("duplicate-key-native-comparison", lambda:
            self.oracle.validate_bundle(repository, bundle), "Duplicate")

    def test_source_defined_full_corpus_and_native_case_order(self):
        repository, bundle, comparison = self.fixture()
        lines = self.corpus.splitlines(keepends=True)
        for name, raw in (("omitted-input-with-self-consistent-hash", b"".join(lines[1:])),
                          ("reordered-input-with-self-consistent-hash", b"".join([lines[1], lines[0], *lines[2:]])),
                          ("altered-input-with-self-consistent-hash", self.corpus.replace(b'"root":true', b'"root":false', 1))):
            bad = copy.deepcopy(comparison)
            bad["corpus"] = identity(raw)
            (bundle / "corpus.jsonl").write_bytes(raw)
            self.rejected(name, lambda: self.oracle.validate_corpus(repository, bundle, bad),
                          "complete source-defined")
        (bundle / "corpus.jsonl").unlink()
        for name, rows in (("missing-native-case", comparison["cases"][1:]),
                           ("duplicate-native-case", [comparison["cases"][0], *comparison["cases"]]),
                           ("reordered-native-case", [comparison["cases"][1], comparison["cases"][0], *comparison["cases"][2:]]),
                           ("nondict-native-case", [None, *comparison["cases"][1:]])):
            bad = copy.deepcopy(comparison)
            bad["cases"] = rows
            self.rejected(name, lambda: self.oracle.validate_corpus(repository, bundle, bad),
                          "Native corpus cases")

    def test_actual_plain_and_compressed_corpus_bytes(self):
        repository, bundle, comparison = self.fixture()
        archive = bundle / "corpus.jsonl.xz"
        for name, compressed in (("truncated-xz", self.compressed[:-7]),
                                 ("trailing-xz", self.compressed + b"trailing"),
                                 ("concatenated-xz", self.compressed + lzma.compress(b"")),
                                 ("oversized-xz", lzma.compress(self.corpus + b"x", preset=1)),
                                 ("same-extent-wrong-xz", lzma.compress(self.corpus[:-1] + b" ", preset=1))):
            archive.write_bytes(compressed)
            self.rejected(name, lambda: self.oracle.validate_corpus(repository, bundle, comparison))
        archive.write_bytes(self.compressed)
        for name, raw in (("truncated-plain", self.corpus[:-1]),
                          ("oversized-plain", self.corpus + b"x"),
                          ("same-extent-wrong-plain", self.corpus[:-1] + b" ")):
            (bundle / "corpus.jsonl").write_bytes(raw)
            self.rejected(name, lambda: self.oracle.validate_corpus(repository, bundle, comparison),
                          "Actual corpus bytes")
        (bundle / "corpus.jsonl").write_bytes(self.corpus)
        self.assertEqual(self.accepted("valid-plain-corpus", lambda:
            self.oracle.validate_corpus(repository, bundle, comparison)), self.corpus)

    def cli(self, repository, bundle, name, optimization=None):
        output = repository.parent / ("output-" + name)
        target = repository.parent / ("target-" + name)
        argv = [sys.executable, "-B"] + ([] if optimization is None else [optimization]) + [
            "-m", "hia.platform.typed_store.rust_oracle", "--repository", str(repository),
            "--bundle", str(bundle), "--output", str(output), "--target-dir", str(target)]
        environment = {"PATH": "", "PYTHONPATH": str(repository), "PYTHONDONTWRITEBYTECODE": "1"}
        process = subprocess.run(argv, cwd=repository, env=environment, capture_output=True, timeout=30)
        report = json.loads((output / "report.json").read_bytes()) if (output / "report.json").is_file() else None
        self.assertNotEqual(process.returncode, 0)
        self.assertFalse((output / "isolated-source").exists())
        self.assertFalse(target.exists())
        if report is not None:
            self.assertFalse(report.get("stages"))
        PUBLIC_CALLS.append({"name": name, "argv": argv, "exit_code": process.returncode,
            "stdout": identity(process.stdout), "stderr": identity(process.stderr),
            "stderr_utf8": process.stderr.decode(errors="replace"), "report": report,
            "empty_path": True, "hia_toolchain_environment_absent": True,
            "no_isolated_source": True, "no_cargo_target": True})
        return report, process

    def test_public_cli_rejects_before_tools_source_copy_and_cargo(self):
        repository, bundle, comparison = self.fixture()
        report, _ = self.cli(repository, bundle, "valid-binding-no-tools")
        self.assertEqual(report["status"], "NOT_RUN")
        self.assertEqual(set(report["missing_tools"]), {"cargo", "rustc"})
        CONTROLS.append({"name": "public-valid-binding-not-run-without-tools", "status": "PASS"})
        changes = []
        for relative in ("hia/platform/typed_store/rust_reference.rs", "hia/platform/typed_store/capacity.py",
                         "hia/platform/typed_store/test_integrity.py", "hia/platform/build.py",
                         "hia/src/codec/json_number.hepta", "hia/src/protocol/state_root.hepta"):
            bad = copy.deepcopy(comparison)
            del bad["build"]["source_inputs"][relative]
            bad["build"]["source_set_sha256"] = self.oracle.canonical_json_hash(bad["build"]["source_inputs"])
            changes.append(("missing-" + Path(relative).name, bad))
        bad = copy.deepcopy(comparison)
        bad["build"]["source_set_sha256"] = "0" * 64
        changes.append(("forged-set-digest", bad))
        bad = copy.deepcopy(comparison)
        bad["corpus"] = identity(b"".join(self.corpus.splitlines(keepends=True)[1:]))
        changes.append(("forged-corpus-digest", bad))
        for name, bad in changes:
            put_json(bundle / "native-comparison.json", bad)
            report, _ = self.cli(repository, bundle, name)
            self.assertEqual(report["status"], "FAIL")
            CONTROLS.append({"name": "public-" + name, "status": "PASS", "error": report["error"]})
        put_json(bundle / "native-comparison.json", comparison)
        for option in ("-O", "-OO"):
            report, process = self.cli(repository, bundle, "optimized" + option, option)
            self.assertIsNone(report)
            self.assertIn(b"Optimized Python is not admitted", process.stderr)
            CONTROLS.append({"name": "public-reject-" + option, "status": "PASS"})


def main():
    if not __debug__:
        raise RuntimeError("Optimized Python is not admitted by the integrity tests")
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--native-bundle", type=Path)
    parser.add_argument("--output", type=Path)
    OPTIONS = parser.parse_args()
    started = time.monotonic_ns()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Integrity))
    stable = hasattr(Integrity, "before") and Integrity.before == Integrity.oracle.complete_source_manifest(Integrity.repository)
    report = {"schema": "trnm.hia.typed-store-oracle-integrity-controls.v1",
        "status": "PASS" if result.wasSuccessful() and stable else "FAIL",
        "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "controls": CONTROLS, "public_cli_calls": PUBLIC_CALLS, "elapsed_ns": time.monotonic_ns() - started,
        "rust_executions": 0, "cargo_executions": 0, "native_executions": 0, "core_compiler_executions": 0,
        "native_or_original_runtime_qualification_claimed": False,
        "test_source": identity(Path(__file__).read_bytes()),
        "oracle_source": identity(Integrity.oracle_path.read_bytes()) if hasattr(Integrity, "oracle_path") else None,
        "bound_sources_before": getattr(Integrity, "before", None), "bound_sources_stable": stable,
        "exact_source_defined_corpus": identity(Integrity.corpus) if hasattr(Integrity, "corpus") else None,
        "case_count": len(Integrity.names) if hasattr(Integrity, "names") else None,
        "test_failures": result.failures, "test_errors": result.errors}
    # unittest stores TestCase objects; preserve readable names with full trace.
    for key in ("test_failures", "test_errors"):
        report[key] = [[str(test), trace] for test, trace in report[key]]
    if report["status"] == "PASS":
        shutil.rmtree(Integrity.root)
    elif hasattr(Integrity, "root"):
        report["retained_failed_fixture"] = str(Integrity.root)
    if OPTIONS.output:
        if OPTIONS.output.exists() or OPTIONS.output.is_symlink():
            raise FileExistsError("Use a fresh integrity report path")
        OPTIONS.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "tests": report["tests"],
        "controls": len(CONTROLS), "public_cli_calls": len(PUBLIC_CALLS),
        "report": str(OPTIONS.output) if OPTIONS.output else None}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
