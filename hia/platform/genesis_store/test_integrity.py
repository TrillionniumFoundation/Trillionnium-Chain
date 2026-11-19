"""Adversarial source/corpus admission controls; these do not execute a Rust oracle."""
from __future__ import annotations
import copy
import importlib.util
import io
import tarfile
import json
import lzma
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).with_name("rust_oracle.py")
spec = importlib.util.spec_from_file_location("_genesis_admission_under_test", SOURCE)
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
CONTROLS = []


class Fixture:
    def __init__(self, root):
        self.root = root
        self.repo = root / "repo"
        self.bundle = root / "bundle"
        self.repo.mkdir()
        self.bundle.mkdir()
        self.write("trillionnium/Cargo.lock", b"version = 4\n")
        self.write("trillionnium/Cargo.toml", b"[workspace]\nmembers=[]\n")
        self.write(oracle.STORE, b"// Admission fixture, never compiled as original Rust.\n")
        self.write("formal/source-boundary.txt", b"admission fixture\n")
        self.write("config/other.json", b"{}\n")
        for name in oracle.OWNED_REQUIRED:
            self.write(oracle.OWNED + "/" + name, b"{}" if name.endswith(".json") else b"")
        self.write(oracle.OWNED + "/rust_oracle.py", SOURCE.read_bytes())
        self.write(oracle.OWNED + "/test_integrity.py", Path(__file__).read_bytes())
        self.write(oracle.OWNED + "/cases.py", Path(__file__).with_name("cases.py").read_bytes())
        self.write(oracle.OWNED + "/native_io.py", b"def identity(raw): return None\n"
                   b"def parse_record(raw): return None\n"
                   b"def parse_success(raw): return None\n")
        self.write(oracle.OWNED + "/source-inputs.json", oracle.canonical_json({
            "schema": "trnm.hia.genesis-default-inputs.v1",
            "files": sorted(oracle.CONFIGURATION_INPUTS)}))
        for name in oracle.CONFIGURATION_INPUTS:
            self.write(name, b"{}\n")
        for name in oracle.EXPLICIT_INPUTS:
            self.write(name, b"fixture\n")
        self.write("hia/platform/build.py", b"INPUTS = ('platform/pinned-fixture.txt',)\n")
        self.write("hia/platform/pinned-fixture.txt", b"pinned input\n")
        self.write("hia/src/node/settings_development.hepta", b"fn f0() -> u32\n  return 0\nend\n")
        self.write("hia/src/protocol/state_root_compact.hepta", b"fn f0() -> u32\n  return 0\nend\n")
        self.write("hia/src/test/helper.hepta", b"fn helper() -> u32\n  return 0\nend\n")
        self.write("hia/src/test/leaf.hepta", b"fn leaf() -> u32\n  return 0\nend\n")
        self.components = {"schema": "trnm.hia.component-includes.v1", "includes": {
            "src/node/settings_development.hepta": [
                {"source": "src/test/helper.hepta", "functions": ["helper"]}],
            "src/test/helper.hepta": [
                {"source": "src/test/leaf.hepta", "functions": ["leaf"]}],
        }}
        self.write_components()
        corpus, rows = oracle.bound_corpus(self.repo)
        compressed = lzma.compress(corpus)
        (self.bundle / "corpus.jsonl").write_bytes(corpus)
        (self.bundle / "corpus.jsonl.xz").write_bytes(compressed)
        self.corpus = corpus
        self.rows = rows
        sources = oracle.complete_source_manifest(self.repo)
        self.comparison = {
            "schema": oracle.COMP_SCHEMA, "status": "PASS", "case_count": len(rows),
            "build": {"schema": oracle.BUILD_SCHEMA, "status": "PASS",
                "source_inputs": sources, "source_set_sha256": oracle.digest(oracle.canonical_json(sources)),
                "original_sources": oracle.original_manifest(self.repo),
                "source_inputs_stable": True, "runtime_host_proxy": False,
                "rust_or_interpreter_fallback": False, "complete_node": False,
                "successor_block_admission": False},
            "corpus": {"path": "corpus.jsonl.xz", "raw": oracle.identity(corpus),
                       "compressed": oracle.identity(compressed)},
            # Intentionally no native PASS observations. Only source/corpus admission
            # functions may accept this fixture; a complete oracle must refuse it.
            "cases": copy.deepcopy(rows),
        }
        self.write_bundle()

    def write(self, name, raw):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def write_components(self):
        self.write("hia/components.json", oracle.canonical_json(self.components))

    def write_bundle(self, comparison=None):
        if comparison is not None:
            self.comparison = comparison
        (self.bundle / "native-comparison.json").write_bytes(oracle.canonical_json(self.comparison))

    def rebind(self, comparison=None):
        target = self.comparison if comparison is None else comparison
        sources = oracle.complete_source_manifest(self.repo)
        target["build"]["source_inputs"] = sources
        target["build"]["source_set_sha256"] = oracle.digest(oracle.canonical_json(sources))
        return target


class RegistryFixture:
    """Small real tar/cache/source tree; never a Rust implementation."""
    def __init__(self, root):
        self.root = root
        self.crate_name = "serde_json-1.0.149"
        self.crate = root / "registry/src/test-index" / self.crate_name
        self.cache = root / "registry/cache/test-index"
        self.archive = self.cache / (self.crate_name + ".crate")
        self.crate.mkdir(parents=True)
        self.cache.mkdir(parents=True)
        self.isolated = root / "isolated"
        (self.isolated / "trillionnium").mkdir(parents=True)
        self.sources = {"Cargo.toml": b'[package]\nname="serde_json"\nversion="1.0.149"\n',
                        "src/lib.rs": b"// Dependency provenance fixture only.\n"}
        for name, raw in self.sources.items():
            path = self.crate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        (self.crate / ".cargo-ok").write_bytes(b'{"v":1}')
        self.package = {"name": "serde_json", "version": "1.0.149",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                        "id": "registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.149",
                        "manifest_path": str(self.crate / "Cargo.toml")}
        self.metadata = {"packages": [self.package],
                         "resolve": {"nodes": [{"id": self.package["id"], "features": ["default", "std"]}]}}
        self.repack()

    def repack(self, members=None):
        if members is None:
            members = [(self.crate_name + "/" + key, "file", value) for key, value in self.sources.items()]
        with tarfile.open(self.archive, "w:gz") as packed:
            for name, kind, raw in members:
                member = tarfile.TarInfo(name)
                member.mode = 0o644
                if kind == "file":
                    member.size = len(raw)
                    packed.addfile(member, io.BytesIO(raw))
                else:
                    member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                   "fifo": tarfile.FIFOTYPE, "directory": tarfile.DIRTYPE}[kind]
                    member.linkname = "/outside-source"
                    packed.addfile(member)
        self.bind_lock()

    def bind_lock(self):
        checksum = oracle.digest(self.archive.read_bytes())
        (self.isolated / "trillionnium/Cargo.lock").write_text(
            'version=4\n[[package]]\nname="serde_json"\nversion="1.0.149"\nsource="'
            + self.package["source"] + '"\nchecksum="' + checksum + '"\n')

    def capture(self):
        output = Path(tempfile.mkdtemp(prefix="capture-", dir=self.root))
        return oracle.capture_serde_graph(self.metadata, self.isolated, output)



class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="trnm-genesis-integrity-")
        self.fixture = Fixture(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def reject(self, name, operation, message=None):
        with self.subTest(control=name):
            try:
                operation()
            except (ValueError, OSError, lzma.LZMAError, tarfile.TarError, SyntaxError, TypeError, KeyError) as error:
                if message is not None:
                    self.assertIn(message, str(error))
                CONTROLS.append({"name": name, "status": "PASS", "observed_error": repr(error)})
                return
            self.fail("Invalid admission input was accepted: " + name)

    def accept(self, name, operation):
        with self.subTest(control=name):
            result = operation()
            CONTROLS.append({"name": name, "status": "PASS", "scope": "ADMISSION_FIXTURE_ONLY"})
            return result

    def test_complete_dynamic_closure_and_omissions(self):
        f = self.fixture
        expected = self.accept("complete fixture source closure",
            lambda: oracle.validate_source_bindings(f.repo, f.comparison))
        self.assertEqual(expected, oracle.complete_source_manifest(f.repo))
        for name in expected:
            candidate = copy.deepcopy(f.comparison)
            del candidate["build"]["source_inputs"][name]
            # Recompute the submitted digest so the complete-set check, not merely
            # a stale digest, must detect every missing dependency.
            candidate["build"]["source_set_sha256"] = oracle.digest(
                oracle.canonical_json(candidate["build"]["source_inputs"]))
            self.reject("omit source " + name,
                lambda c=candidate: oracle.validate_source_bindings(f.repo, c), "closure")
        f.write(oracle.OWNED + "/future_guard.py", b"# future owned source\n")
        self.reject("new owned source omitted",
            lambda: oracle.validate_source_bindings(f.repo, f.comparison), "closure")
        f.rebind()
        self.accept("new owned source included", lambda: oracle.validate_source_bindings(f.repo, f.comparison))
        f.write("hia/platform/future-pinned.txt", b"new required compiler input\n")
        f.write("hia/platform/build.py",
                b"INPUTS = ('platform/pinned-fixture.txt', 'platform/future-pinned.txt')\n")
        old = copy.deepcopy(f.comparison)
        old["build"]["source_inputs"]["hia/platform/build.py"] = oracle.file_identity(f.repo / "hia/platform/build.py")
        old["build"]["source_set_sha256"] = oracle.digest(oracle.canonical_json(old["build"]["source_inputs"]))
        self.reject("new dynamic pinned input omitted",
            lambda: oracle.validate_source_bindings(f.repo, old), "closure")
        f.rebind()
        self.accept("new dynamic pinned input included", lambda: oracle.validate_source_bindings(f.repo, f.comparison))

    def test_manifest_identity_and_document_controls(self):
        f = self.fixture
        name = next(iter(f.comparison["build"]["source_inputs"]))
        mutations = {
            "wrong source-set digest": lambda c: c["build"].update(source_set_sha256="0" * 64),
            "boolean source extent": lambda c: c["build"]["source_inputs"][name].update(bytes=True),
            "wrong source bytes": lambda c: c["build"]["source_inputs"][name].update(bytes=123456789),
            "uppercase source digest": lambda c: c["build"]["source_inputs"][name].update(sha256="A" * 64),
            "extra identity field": lambda c: c["build"]["source_inputs"][name].update(version=1),
            "top-level map mismatch": lambda c: c.update(source_inputs={}),
            "unqualified native status": lambda c: c.update(status="NOT_RUN"),
            "build host fallback": lambda c: c["build"].update(runtime_host_proxy=True),
        }
        for label, mutate in mutations.items():
            candidate = copy.deepcopy(f.comparison)
            mutate(candidate)
            self.reject(label, lambda c=candidate: oracle.validate_source_bindings(f.repo, c))
        extra = f.write("unbound.txt", b"present but not an input\n")
        candidate = copy.deepcopy(f.comparison)
        candidate["build"]["source_inputs"]["unbound.txt"] = oracle.file_identity(extra)
        candidate["build"]["source_set_sha256"] = oracle.digest(oracle.canonical_json(candidate["build"]["source_inputs"]))
        self.reject("extra physically present source", lambda: oracle.validate_source_bindings(f.repo, candidate), "closure")
        for bad in ("../escape", "/absolute", "hia//components.json", "./hia/components.json", "hia\\components.json"):
            candidate = copy.deepcopy(f.comparison)
            candidate["build"]["source_inputs"][bad] = oracle.identity(b"")
            self.reject("noncanonical map key " + bad, lambda c=candidate: oracle.validate_source_bindings(f.repo, c))
        f.write("hia/components.json",
                b'{"schema":"trnm.hia.component-includes.v1","includes":{},"includes":{}}\n')
        self.reject("duplicate manifest key", lambda: oracle.complete_source_manifest(f.repo), "Duplicate")
        self.reject("duplicate comparison key",
            lambda: oracle.load_json(b'{"status":"PASS","status":"FAIL"}'), "Duplicate")
        self.reject("nonfinite comparison number", lambda: oracle.load_json(b'{"x":NaN}'), "Non-finite")

    def test_recursive_dependency_and_symbolic_paths(self):
        f = self.fixture
        old = copy.deepcopy(f.components)
        variants = {}
        cycle = copy.deepcopy(old)
        cycle["includes"]["src/test/leaf.hepta"] = [
            {"source": "src/node/settings_development.hepta", "functions": ["f0"]}]
        variants["dependency cycle"] = cycle
        missing = copy.deepcopy(old)
        missing["includes"]["src/node/settings_development.hepta"][0]["functions"] = ["absent"]
        variants["unknown selected function"] = missing
        duplicate = copy.deepcopy(old)
        duplicate["includes"]["src/node/settings_development.hepta"][0]["functions"] = ["helper", "helper"]
        variants["duplicate selected function"] = duplicate
        reexport = copy.deepcopy(old)
        reexport["includes"]["src/node/settings_development.hepta"][0]["functions"] = ["leaf"]
        variants["implicit re-export"] = reexport
        for label, value in variants.items():
            f.components = value
            f.write_components()
            self.reject(label, lambda: oracle.complete_source_manifest(f.repo))
        f.components = old
        f.write_components()
        leaf = f.repo / "hia/src/test/leaf.hepta"
        raw = leaf.read_bytes()
        leaf.write_bytes(raw + raw)
        self.reject("duplicate HIA declaration", lambda: oracle.complete_source_manifest(f.repo), "Ambiguous")
        leaf.write_bytes(raw)
        copied = f.repo / "leaf-copy"
        copied.write_bytes(raw)
        leaf.unlink()
        leaf.symlink_to(copied)
        self.reject("dependency symlink", lambda: oracle.complete_source_manifest(f.repo), "Symlink")
        leaf.unlink()
        leaf.write_bytes(raw)
        owned = f.repo / oracle.OWNED
        (owned / "unknown-symlink").symlink_to(copied)
        self.reject("unselected owned symlink", lambda: oracle.complete_source_manifest(f.repo), "symbolic")
        (owned / "unknown-symlink").unlink()
        (owned / "cache.pyc").write_bytes(b"not executable")
        self.reject("stale direct pyc", lambda: oracle.complete_source_manifest(f.repo), "cache")
        (owned / "cache.pyc").unlink()
        (owned / "__pycache__").mkdir()
        self.reject("stale cache directory", lambda: oracle.complete_source_manifest(f.repo), "cache")
        (owned / "__pycache__").rmdir()
        ancestor = f.repo / "config/pon"
        parked = f.repo / "config/pon-real"
        ancestor.rename(parked)
        ancestor.symlink_to(parked, target_is_directory=True)
        self.reject("configuration ancestor symlink", lambda: oracle.complete_source_manifest(f.repo), "Symlink")

    def test_exact_corpus_and_bounded_archives(self):
        f = self.fixture
        self.accept("both exact corpus encodings",
            lambda: oracle.validate_corpus(f.repo, f.bundle, f.comparison))
        raw_path, archive = f.bundle / "corpus.jsonl", f.bundle / "corpus.jsonl.xz"
        pristine = archive.read_bytes()
        for label, raw in (
            ("raw trailing byte", f.corpus + b" "),
            ("raw truncation", f.corpus[:-1]),
            ("raw reordering", b"\n".join(reversed(f.corpus.splitlines())) + b"\n"),
        ):
            raw_path.write_bytes(raw)
            self.reject(label, lambda: oracle.validate_corpus(f.repo, f.bundle, f.comparison), "plain corpus")
        raw_path.write_bytes(f.corpus)
        for label, data in (
            ("XZ extra stream", pristine + pristine),
            ("XZ trailing bytes", pristine + b"trailing"),
            ("XZ missing footer", pristine[:-5]),
            ("XZ oversized decoded extent", lzma.compress(f.corpus + b"x")),
        ):
            archive.write_bytes(data)
            candidate = copy.deepcopy(f.comparison)
            candidate["corpus"]["compressed"] = oracle.identity(data)
            self.reject(label, lambda c=candidate: oracle.validate_corpus(f.repo, f.bundle, c))
        archive.write_bytes(pristine)
        for label, mutate in (
            ("wrong raw corpus hash", lambda c: c["corpus"]["raw"].update(sha256="0" * 64)),
            ("wrong compressed hash", lambda c: c["corpus"]["compressed"].update(sha256="0" * 64)),
            ("wrong corpus path", lambda c: c["corpus"].update(path="../corpus.jsonl.xz")),
            ("native case reorder", lambda c: c["cases"].reverse()),
            ("native missing last case", lambda c: c["cases"].pop()),
            ("native duplicate name", lambda c: c["cases"][1].update(name=c["cases"][0]["name"])),
            ("boolean native workers", lambda c: c["cases"][0].update(workers=True)),
            ("boolean case count", lambda c: c.update(case_count=True)),
        ):
            candidate = copy.deepcopy(f.comparison)
            mutate(candidate)
            self.reject(label, lambda c=candidate: oracle.validate_corpus(f.repo, f.bundle, c))

    def test_original_source_set_is_complete(self):
        f = self.fixture
        actual = self.accept("complete original fixture manifest", lambda: oracle.original_manifest(f.repo))
        self.assertIn("config/other.json", actual)
        self.assertIn("formal/source-boundary.txt", actual)
        path = f.repo / "trillionnium/Cargo.lock"
        raw = path.read_bytes()
        path.write_bytes(raw + b"# exact byte change\n")
        self.assertNotEqual(oracle.original_manifest(f.repo), actual)
        CONTROLS.append({"name": "changed original lock identity", "status": "PASS"})
        path.write_bytes(raw)
        target = f.repo / "formal/source-boundary.txt"
        target.unlink()
        target.symlink_to(path)
        self.reject("original source symlink", lambda: oracle.original_manifest(f.repo), "Symlink")

    def test_final_source_and_cleanup_verification(self):
        f = self.fixture
        built = f.comparison["build"]
        report = {"verification": {
            "source_after": {"status": "PASS", "source_set_sha256": built["source_set_sha256"],
                             "native_source_files": len(built["source_inputs"]),
                             "original_source_files": len(built["original_sources"])},
            "primary_error": None, "cleanup_errors": []}}
        self.accept("complete post-run verification fixture",
            lambda: oracle.validate_native_verification(report, f.comparison))
        variants = (
            ("missing final verification", lambda r: r.clear()),
            ("failed source-after", lambda r: r["verification"]["source_after"].update(status="FAIL")),
            ("different source-after digest", lambda r: r["verification"]["source_after"].update(source_set_sha256="0"*64)),
            ("omitted source-after native member", lambda r: r["verification"]["source_after"].update(native_source_files=1)),
            ("omitted source-after original member", lambda r: r["verification"]["source_after"].update(original_source_files=1)),
            ("primary failure mislabeled PASS", lambda r: r["verification"].update(primary_error="actual failure")),
            ("cleanup failure mislabeled PASS", lambda r: r["verification"].update(cleanup_errors=["actual cleanup failure"])),
            ("boolean source-after count", lambda r: r["verification"]["source_after"].update(native_source_files=True)),
            ("unrecognized final failure field", lambda r: r["verification"].update(write_errors=["actual write failure"])),
        )
        for label, mutate in variants:
            candidate = copy.deepcopy(report)
            mutate(candidate)
            self.reject(label, lambda c=candidate: oracle.validate_native_verification(c, f.comparison),
                        "verification")

    def test_actual_bootstrap_diagnostic_validation(self):
        # Literal protocol fixture only: no native process or Rust is run here.
        item = {"name": "protocol-fixture", "timestamp": 0, "workers": 1}
        image = oracle.identity(b"explicit protocol fixture, not an ELF")
        build = {"executable": image}
        attempted = b"NGBOOT01" + struct.pack("<7Q", 5, 0, 1, 0, 1, oracle.MAX_U64, oracle.MAX_U64)
        attempted += b"NGCMD001" + struct.pack("<Q", 1) + b"NGCMD001" + struct.pack("<Q", 2)
        diagnostic = [68, 2, 4294967295, 0, 0, 0, 0]
        stderr = struct.pack("<7Q", *diagnostic)
        base = {"schema": "trnm.native-genesis-process.v1", "pid": 1,
            "timestamp": 0, "workers": 1, "mode": 0, "exit_code": 68, "timed_out": False,
            "elapsed_ns": 1, "child_budget_seconds": 240, "cleanup_budget_seconds": 3,
            "executable": image, "stdout": oracle.identity(b""), "stderr": oracle.identity(stderr),
            "stderr_hex": stderr.hex(), "diagnostic": diagnostic, "events": [],
            "stdin": oracle.identity(attempted), "stdin_hex": attempted.hex(),
            "stdin_actual_hex": attempted[:64].hex(), "stdin_actual_write_bytes": 64}
        invoke = lambda value: oracle.process_receipt(value, item, build, mode=0, code=68, stdout=b"")
        self.accept("protocol actual bootstrap prefix after EPIPE", lambda: invoke(base))
        for label, mutate in (
            ("short actual bootstrap", lambda p: p.update(stdin_actual_write_bytes=63, stdin_actual_hex=attempted[:63].hex())),
            ("forged actual input bytes", lambda p: p.update(stdin_actual_hex=bytes(64).hex())),
            ("boolean process worker", lambda p: p.update(workers=True)),
            ("wrong process input hash", lambda p: p["stdin"].update(sha256="0" * 64)),
            ("forged diagnostic field", lambda p: p["diagnostic"].__setitem__(2, 1)),
            ("wrong diagnostic errno byte", lambda p: p.update(stderr_hex=(b"x" + stderr[1:]).hex())),
        ):
            candidate = copy.deepcopy(base)
            mutate(candidate)
            self.reject(label, lambda c=candidate: invoke(c))
        candidate = copy.deepcopy(base)
        altered = bytearray(attempted)
        struct.pack_into("<Q", altered, 32, 1)
        candidate.update(stdin_hex=altered.hex(), stdin=oracle.identity(altered),
                         stdin_actual_hex=altered[:64].hex())
        self.reject("self-consistent but wrong bootstrap timestamp", lambda: invoke(candidate))

    def test_real_cli_refuses_before_source_copy_and_tools(self):
        f = self.fixture
        fake_bin = Path(self.tmp.name) / "tools"
        fake_bin.mkdir()
        marker = Path(self.tmp.name) / "tool-was-run"
        for name in ("cargo", "rustc"):
            path = fake_bin / name
            path.write_text("#!" + sys.executable + "\nfrom pathlib import Path\n"
                            "Path(" + repr(str(marker)) + ").write_text('UNEXPECTED')\nraise SystemExit(99)\n")
            path.chmod(0o700)
        environment = dict(os.environ, PATH=str(fake_bin), PYTHONDONTWRITEBYTECODE="1")
        environment.pop("PYTHONOPTIMIZE", None)
        original = copy.deepcopy(f.comparison)
        name = next(iter(original["build"]["source_inputs"]))
        candidates = []
        missing = copy.deepcopy(original)
        del missing["build"]["source_inputs"][name]
        candidates.append(("omitted source", missing, "closure"))
        changed = copy.deepcopy(original)
        changed["build"]["source_inputs"][name]["bytes"] += 1
        candidates.append(("changed source", changed, "closure"))
        digest = copy.deepcopy(original)
        digest["build"]["source_set_sha256"] = "0" * 64
        candidates.append(("wrong set digest", digest, "digest"))
        changed_corpus = copy.deepcopy(original)
        changed_corpus["corpus"]["raw"]["sha256"] = "0" * 64
        candidates.append(("changed corpus", changed_corpus, "corpus identity"))
        reordered = copy.deepcopy(original)
        reordered["cases"].reverse()
        candidates.append(("reordered corpus cases", reordered, "reordered"))
        missing_original = copy.deepcopy(original)
        missing_original["build"]["original_sources"].pop("formal/source-boundary.txt")
        candidates.append(("omitted original source", missing_original, "original source"))
        for index, (label, candidate, message) in enumerate(candidates):
            f.write_bundle(candidate)
            output = Path(self.tmp.name) / ("cli-" + str(index))
            result = subprocess.run([sys.executable, "-B", str(f.repo / oracle.OWNED / "rust_oracle.py"),
                "--repository", str(f.repo), "--bundle", str(f.bundle), "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=30)
            with self.subTest(control=label):
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertFalse((output / "isolated-source").exists())
                report = oracle.load_json((output / "report.json").read_bytes())
                self.assertEqual(report["status"], "FAIL")
                self.assertIn(message, report["primary_error"])
                self.assertEqual(report["stages"], [])
                CONTROLS.append({"name": "actual CLI " + label, "status": "PASS",
                    "exit_code": result.returncode, "original_stage_count": 0,
                    "stdout": oracle.identity(result.stdout), "stderr": oracle.identity(result.stderr)})
        f.write_bundle(original)
        for flag in ("-O", "-OO"):
            output = Path(self.tmp.name) / ("optimized-" + flag[1:])
            result = subprocess.run([sys.executable, flag, "-B", str(f.repo / oracle.OWNED / "rust_oracle.py"),
                "--repository", str(f.repo), "--bundle", str(f.bundle), "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"Optimized Python", result.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(marker.exists())
            CONTROLS.append({"name": "actual CLI " + flag, "status": "PASS", "exit_code": result.returncode,
                "original_stage_count": 0, "stdout": oracle.identity(result.stdout),
                "stderr": oracle.identity(result.stderr)})


    def test_real_registry_archive_provenance_controls(self):
        def scenario(label, mutate, *, message=None, accept=False):
            with tempfile.TemporaryDirectory(prefix="trnm-genesis-registry-fixture-") as directory:
                fixture = RegistryFixture(Path(directory))
                mutate(fixture)
                if accept:
                    return self.accept(label, fixture.capture)
                self.reject(label, fixture.capture, message)
        binding, _ = scenario("real registry layout without vendor checksum", lambda f: None, accept=True)
        self.assertEqual(set(binding["optional_cargo_generated_files"]), {".cargo-ok"})
        self.assertEqual(len(binding["archive_source_files"]), 2)
        scenario("registry without optional readiness marker",
                 lambda f: (f.crate / ".cargo-ok").unlink(), accept=True)
        scenario("registry archive missing", lambda f: f.archive.unlink())
        scenario("registry archive checksum mismatch",
                 lambda f: f.archive.write_bytes(f.archive.read_bytes() + b"changed"),
                 message="Cargo.lock checksum")
        scenario("registry actual Rust source modified",
                 lambda f: (f.crate / "src/lib.rs").write_bytes(b"changed\n"),
                 message="locked registry archive")
        scenario("registry actual source missing", lambda f: (f.crate / "src/lib.rs").unlink(),
                 message="Missing or unexpected")
        scenario("registry unbound appended Rust source",
                 lambda f: (f.crate / "src/injected.rs").write_bytes(b"// extra\n"),
                 message="Missing or unexpected")
        scenario("registry unbound vendor checksum file",
                 lambda f: (f.crate / ".cargo-checksum.json").write_bytes(b"{}"),
                 message="Missing or unexpected")
        scenario("registry readiness marker wrong JSON type",
                 lambda f: (f.crate / ".cargo-ok").write_bytes(b'{"v":true}'),
                 message="readiness marker")
        scenario("registry source differs from locked origin",
                 lambda f: f.package.update(source="registry+https://different.invalid/index"),
                 message="Cargo.lock")
        scenario("registry metadata lacks actual std feature",
                 lambda f: f.metadata["resolve"]["nodes"][0].update(features=["default"]),
                 message="feature graph")
        def archive_symlink(f):
            outside = f.root / "outside.crate"
            outside.write_bytes(f.archive.read_bytes())
            f.archive.unlink()
            f.archive.symlink_to(outside)
        scenario("registry cache archive symbolic", archive_symlink)
        def crate_symlink(f):
            replacement = f.root / "actual-unpacked"
            f.crate.rename(replacement)
            f.crate.symlink_to(replacement, target_is_directory=True)
        scenario("registry source root symbolic", crate_symlink)
        def source_symlink(f):
            outside = f.root / "outside.rs"
            outside.write_bytes(f.sources["src/lib.rs"])
            (f.crate / "src/lib.rs").unlink()
            (f.crate / "src/lib.rs").symlink_to(outside)
        scenario("registry member source symbolic", source_symlink)
        def special_source(f):
            (f.crate / "src/lib.rs").unlink()
            os.mkfifo(f.crate / "src/lib.rs")
        scenario("registry member source actual FIFO", special_source)
        def repacked(f, item):
            f.repack([(f.crate_name + "/" + key, "file", value)
                      for key, value in f.sources.items()] + [item])
        for suffix, kind in (
            ("../escape.rs", "file"), ("src//extra.rs", "file"), ("./extra.rs", "file"),
            ("src\\extra.rs", "file"), ("link.rs", "symlink"), ("hard.rs", "hardlink"),
            ("pipe", "fifo"), ("dir", "directory"), (".cargo-ok", "file"),
            ("src/lib.rs", "file"),
        ):
            scenario("registry authenticated unsafe member " + repr((suffix, kind)),
                lambda f, s=suffix, k=kind: repacked(f, (f.crate_name + "/" + s, k, b"bad")))
        scenario("registry authenticated absolute member",
                 lambda f: repacked(f, ("/absolute.rs", "file", b"bad")))
        scenario("registry authenticated wrong package prefix",
                 lambda f: repacked(f, ("other-package/src/lib.rs", "file", b"bad")))
        scenario("registry authenticated member missing",
                 lambda f: f.repack([(f.crate_name + "/Cargo.toml", "file", f.sources["Cargo.toml"])]),
                 message="Incomplete")
        def malformed(f):
            f.archive.write_bytes(b"not a gzip tar")
            f.bind_lock()
        scenario("registry authenticated malformed archive", malformed)

    def test_registry_before_after_fence_controls(self):
        with tempfile.TemporaryDirectory(prefix="trnm-genesis-registry-drift-") as directory:
            fixture = RegistryFixture(Path(directory))
            binding, capture = self.accept("registry initial complete source and archive binding", fixture.capture)
            self.assertEqual(capture(), binding["crate_sources"])
            archive_before = fixture.archive.read_bytes()
            source = fixture.crate / "src/lib.rs"
            source_before = source.read_bytes()
            source.write_bytes(source_before + b"// drift\n")
            self.reject("registry post-run source drift", capture)
            source.write_bytes(source_before)
            extra = fixture.crate / "src/late.rs"
            extra.write_bytes(b"// added after compile\n")
            self.reject("registry post-run appended source", capture)
            extra.unlink()
            fixture.archive.write_bytes(archive_before + b"drift")
            self.reject("registry post-run cache archive drift", capture)
            fixture.archive.write_bytes(archive_before)
            marker = fixture.crate / ".cargo-ok"
            marker_before = marker.read_bytes()
            marker.write_bytes(b'{"v": 1}')
            self.reject("registry post-run generated marker drift",
                lambda: oracle.need(capture() == binding["crate_sources"], "Dependency source fence changed"))
            marker.write_bytes(marker_before)
            original_cache = fixture.cache
            relocated = fixture.root / "relocated-cache"
            original_cache.rename(relocated)
            original_cache.symlink_to(relocated, target_is_directory=True)
            self.reject("registry post-run cache ancestor symbolic", capture)
            original_cache.unlink()
            relocated.rename(original_cache)
            self.assertEqual(capture(), binding["crate_sources"])
            CONTROLS.append({"name": "registry restored exact initial dependency identity",
                             "status": "PASS", "scope": "ADMISSION_FIXTURE_ONLY"})


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.report:
        oracle.write_json(args.report, {
            "schema": "trnm.hia.default-genesis-source-integrity-controls.v1",
            "status": "PASS" if result.wasSuccessful() else "FAIL",
            "test_groups": result.testsRun, "controls": CONTROLS,
            "controls_completed": len(CONTROLS), "failures": len(result.failures), "errors": len(result.errors),
            "oracle_source": oracle.identity(SOURCE.read_bytes()),
            "test_source": oracle.identity(Path(__file__).read_bytes()),
            "fixture_corpus_source": oracle.identity(Path(__file__).with_name("cases.py").read_bytes()),
            "actual_original_rust_executed": False, "actual_native_executed": False,
        })
    raise SystemExit(0 if result.wasSuccessful() else 1)
