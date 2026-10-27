"""Actual local file/native-runtime controls; no model/I10 qualification."""
import base64
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from unittest import mock
import zipfile
from packaging.markers import default_environment

import llm_runtime_release as release


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o644)


def runtime_fixture(root):
    """Copy real local ELF dependencies; never execute an input-supplied binary."""
    mapped = {}
    for line in Path("/proc/self/maps").read_text().splitlines():
        parts = line.split()
        if len(parts) == 6 and parts[-1].startswith("/"):
            source = Path(parts[-1]).resolve(strict=True)
            mapped.setdefault(source.name, set()).add(source)
    mapped_files = {source for sources in mapped.values() for source in sources}
    mapped_directories = {source.parent for source in mapped_files}

    def mapped_dependency(name):
        # /proc maps records real filenames (e.g. libz.so.1.3), whereas
        # DT_NEEDED uses SONAME aliases (libz.so.1). A host alias is usable
        # only when it resolves to bytes already mapped into this process.
        # This is fixture assembly, not a resolver for untrusted runtimes.
        candidates = set(mapped.get(name, ()))
        for directory in mapped_directories:
            alias = directory / name
            if alias.is_file():
                source = alias.resolve(strict=True)
                if source in mapped_files:
                    candidates.add(source)
        if len(candidates) != 1:
            raise RuntimeError("fixture dependency unavailable or ambiguous: " + name)
        return candidates.pop()

    machine = platform.machine()
    pending = [(Path(sys.executable).resolve(), "bin/python3.12")]
    copied = set()
    loader = None
    while pending:
        source, target = pending.pop()
        if target in copied:
            continue
        copied.add(target)
        path = root / target
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, path)
        path.chmod(0o755)
        with path.open("rb") as handle:
            native = release.elf_dependencies(handle.fileno(), path.stat().st_size, machine)
        for name in native["needed"]:
            pending.append((mapped_dependency(name), "lib/" + name))
        if native["interpreter"]:
            loader = native["interpreter"][1:]
            pending.append((Path(native["interpreter"]).resolve(), loader))
    stdlib = Path(sysconfig.get_path("stdlib"))
    target_stdlib = root / "lib/python3.12"
    shutil.copytree(stdlib / "encodings", target_stdlib / "encodings",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    put(target_stdlib / "os.py", (stdlib / "os.py").read_bytes())
    (target_stdlib / "lib-dynload").mkdir()
    site = target_stdlib / "site-packages"
    entries = {"pon_closure_probe/__init__.py": b"VALUE = 42\n",
               "pon_closure_probe-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: pon-closure-probe\nVersion: 1.0\n",
               "pon_closure_probe-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    record = "pon_closure_probe-1.0.dist-info/RECORD"
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for path, raw in sorted(entries.items()):
        writer.writerow([path, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode(), len(raw)])
    writer.writerow([record, "", ""])
    entries[record] = text.getvalue().encode()
    archive = root / "wheels/pon_closure_probe-1.0-py3-none-any.whl"
    archive.parent.mkdir()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
        for path, raw in entries.items():
            wheel.writestr(path, raw)
            put(site / path, raw)
    put(root / "project/check.py", b"import sys\nassert sys.prefix == sys.argv[1]\n"
        b"sys.path.insert(0, sys.prefix + '/lib/python3.12/site-packages')\n"
        b"from pon_closure_probe import VALUE\nassert VALUE == 42\n"
        b"assert all(p.startswith(sys.prefix + '/') for p in sys.path)\n"
        b"print('COLD_RUNTIME_MATERIAL_SMOKE_ONLY')\n")
    context = {"chain_source": "c96022b897c1235fdbdbfcfa32764403511c6aab",
               "hepta_source": "e1537d7deea32f29ec9612c0a7b90655b14aa904",
               "execution_profile_sha256": sha(b"test-only-cpython-material-profile"),
               "model_release_sha256": sha(b"no-model-test-only-materials")}
    spec = {"schema": release.SPEC_SCHEMA,
            "platform": {"os": "linux", "machine": machine, "python_abi": sysconfig.get_config_var("SOABI")},
            "context": context, "interpreter": "bin/python3.12", "stdlib": "lib/python3.12",
            "entrypoint": "project/check.py", "import_roots": ["lib/python3.12", "lib/python3.12/site-packages"],
            "native_search_paths": ["lib"], "marker_environment": default_environment(), "policy": dict(release.POLICY),
            "wheels": [{"archive": str(archive.relative_to(root)),
                        "installed_record": "lib/python3.12/site-packages/" + record,
                        "origin": "https://example.invalid/test-fixture-original-wheel",
                        "sha256": sha(archive.read_bytes()), "extras": []}]}
    return spec, loader


@unittest.skipUnless(sys.platform == "linux" and sys.version_info[:2] == (3, 12)
                     and platform.machine() in {"x86_64", "aarch64"}, "explicit CPython 3.12 Linux profile")
class RuntimeMaterialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.area = tempfile.TemporaryDirectory(prefix="runtime-material-", dir=Path(__file__).resolve().parents[2])
        cls.template = Path(cls.area.name) / "template"
        cls.template.mkdir(mode=0o700)
        cls.spec, cls.loader = runtime_fixture(cls.template)

    @classmethod
    def tearDownClass(cls):
        cls.area.cleanup()

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="case-", dir=self.area.name)
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name) / "material"
        shutil.copytree(self.template, self.root)
        self.raw = release.canonical(self.spec)
        self.limit = 128 * 1024 * 1024

    def declare(self, spec=None):
        raw = release.canonical(spec) if spec is not None else self.raw
        return release.declare_runtime_release(self.root, raw, sha(raw), self.limit)

    def verify(self, raw, root=None):
        identity = sha(b"hepta.runtime-material-release.v1\0" + len(raw).to_bytes(8, "big") + raw)
        return release.verify_runtime_release(root or self.root, raw, identity, self.spec["context"], self.limit)

    def test_actual_cold_python_and_original_wheel_bytes_roundtrip(self):
        raw = self.declare()
        result = self.verify(raw)
        self.assertEqual({k: result[k] for k in ("runtime_execution_qualified", "ordinary_installation_qualified",
                                               "public_reward_eligible")},
                         dict(runtime_execution_qualified=False, ordinary_installation_qualified=False,
                              public_reward_eligible=False))
        child = subprocess.run([str(self.root / self.loader), "--inhibit-cache", "--library-path", str(self.root / "lib"),
            str(self.root / "bin/python3.12"), "-I", "-S", "-B", str(self.root / "project/check.py"), str(self.root)],
            capture_output=True, text=True, timeout=15)
        self.assertEqual((child.returncode, child.stdout, child.stderr), (0, "COLD_RUNTIME_MATERIAL_SMOKE_ONLY\n", ""))
        self.assertEqual(self.verify(raw), result)

    def test_byte_copy_survives_origin_removal(self):
        raw = self.declare()
        replica = Path(self.work.name) / "replica"
        shutil.copytree(self.root, replica)
        shutil.rmtree(self.root)
        self.assertGreater(self.verify(raw, replica)["files"], 0)

    def test_changed_missing_and_extra_materials_refuse(self):
        raw = self.declare()
        path = self.root / "project/check.py"
        old = path.read_bytes()
        for mutate in (lambda: path.write_bytes(b"substitute"), lambda: path.unlink(),
                       lambda: path.chmod(0o600), lambda: put(self.root / "project/extra.py", b"extra")):
            with self.subTest(mutation=mutate):
                mutate()
                with self.assertRaises((ValueError, OSError)):
                    self.verify(raw)
                put(path, old)
                (self.root / "project/extra.py").unlink(missing_ok=True)

    def test_missing_native_dependency_and_ambiguous_shadow_refuse(self):
        path = self.root / "lib/libc.so.6"
        old = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "NATIVE_DEPENDENCY"):
            self.declare()
        put(path, old)
        put(self.root / "shadow/libc.so.6", old)
        spec = copy.deepcopy(self.spec)
        spec["native_search_paths"].append("shadow")
        with self.assertRaisesRegex(ValueError, "NATIVE_DEPENDENCY"):
            self.declare(spec)

    def test_installed_wheel_change_or_undeclared_distribution_refuse(self):
        path = self.root / "lib/python3.12/site-packages/pon_closure_probe/__init__.py"
        put(path, b"VALUE = 0\n")
        with self.assertRaisesRegex(ValueError, "WHEEL_INSTALL_CHANGED"):
            self.declare()
        put(path, b"VALUE = 42\n")
        spec = copy.deepcopy(self.spec)
        spec["wheels"] = []
        with self.assertRaisesRegex(ValueError, "DISTRIBUTION_NOT_DECLARED"):
            self.declare(spec)

    def test_real_pip_installation_is_not_canonical_extracted_wheel_layout(self):
        # The real installer may rewrite RECORD; V1 must not claim that closure.
        wheel = self.spec["wheels"][0]
        archive = self.root / wheel["archive"]
        record = self.root / wheel["installed_record"]
        original_record = record.read_bytes()
        site = record.parent.parent
        shutil.rmtree(site)
        child = subprocess.run([sys.executable, "-I", "-m", "pip", "--isolated", "install",
            "--disable-pip-version-check", "--no-index", "--no-deps", "--no-compile",
            "--target", str(site), str(archive)], capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertNotEqual(record.read_bytes(), original_record)
        self.assertEqual((site / "pon_closure_probe/__init__.py").read_bytes(), b"VALUE = 42\n")
        self.assertTrue((record.parent / "INSTALLER").is_file())
        with self.assertRaisesRegex(ValueError, "WHEEL_INSTALL_CHANGED"):
            self.declare()

    def repack_metadata(self, additional_headers):
        spec = copy.deepcopy(self.spec)
        archive = self.root / spec["wheels"][0]["archive"]
        with zipfile.ZipFile(archive) as wheel:
            entries = {name: wheel.read(name) for name in wheel.namelist()}
        metadata = "pon_closure_probe-1.0.dist-info/METADATA"
        entries[metadata] = (b"Metadata-Version: 2.1\nName: pon-closure-probe\nVersion: 1.0\n"
                             + additional_headers.encode())
        record = "pon_closure_probe-1.0.dist-info/RECORD"
        rows = io.StringIO(newline="")
        writer = csv.writer(rows, lineterminator="\n")
        for name, raw in sorted(entries.items()):
            if name != record:
                writer.writerow([name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode(), len(raw)])
        writer.writerow([record, "", ""])
        entries[record] = rows.getvalue().encode()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
            for name, raw in entries.items():
                wheel.writestr(name, raw)
                put(self.root / "lib/python3.12/site-packages" / name, raw)
        spec["wheels"][0]["sha256"] = sha(archive.read_bytes())
        return spec

    def test_real_metadata_dependency_markers_extras_and_python_version(self):
        for header in ("Requires-Dist: absent-runtime>=1\n",
                       'Requires-Dist: absent-runtime; python_version >= "3.12"\n'):
            with self.subTest(header=header), self.assertRaisesRegex(ValueError, "PYTHON_DEPENDENCY_MISSING"):
                self.declare(self.repack_metadata(header))
        spec = self.repack_metadata('Requires-Dist: absent-runtime; python_version < "3.0"\n')
        self.assertEqual(json.loads(self.declare(spec))["python_dependencies"][0]["dependencies"], [])
        spec = self.repack_metadata('Provides-Extra: audit\nRequires-Dist: absent-runtime; extra == "audit"\n')
        self.declare(spec)
        spec["wheels"][0]["extras"] = ["audit"]
        with self.assertRaisesRegex(ValueError, "PYTHON_DEPENDENCY_MISSING"):
            self.declare(spec)
        with self.assertRaisesRegex(ValueError, "PYTHON_DEPENDENCY_BINDING"):
            self.declare(self.repack_metadata("Requires-Dist: pon-closure-probe>=2\n"))
        with self.assertRaisesRegex(ValueError, "WHEEL_PYTHON_VERSION"):
            self.declare(self.repack_metadata("Requires-Python: >=4\n"))

    def test_symlink_hardlink_fifo_and_import_side_effect_files_refuse(self):
        path = self.root / "project/untrusted"
        for create in (lambda: path.symlink_to(self.root / "project/check.py"),
                       lambda: os.link(self.root / "project/check.py", path), lambda: os.mkfifo(path)):
            create()
            with self.assertRaises((ValueError, OSError)):
                self.declare()
            path.unlink()
        for name in ("active.pth", "cached.pyc", "cached.pyo"):
            path = self.root / "project" / name
            put(path, b"import os")
            with self.assertRaisesRegex(ValueError, "IMPORT_POLICY"):
                self.declare()
            path.unlink()

    def test_bad_pins_context_budget_and_manifest_encoding_refuse(self):
        raw = self.declare()
        root = sha(release.DOMAIN + len(raw).to_bytes(8, "big") + raw)
        for value, identity, context, budget in ((raw, "1" * 64, self.spec["context"], self.limit),
                (raw, root, {}, self.limit), (raw, root, self.spec["context"], 1),
                (raw + b"\n", root, self.spec["context"], self.limit)):
            with self.subTest(budget=budget, context=context), self.assertRaises(ValueError):
                release.verify_runtime_release(self.root, value, identity, context, budget)
        with self.assertRaisesRegex(ValueError, "DUPLICATE"):
            release.decode(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, "PATH"):
            release.relative("../escape")

    def test_float_integer_alias_cannot_change_the_exact_wire_contract(self):
        manifest = json.loads(self.declare())
        manifest["total_file_bytes"] = float(manifest["total_file_bytes"])
        with self.assertRaisesRegex(ValueError, "MATERIAL_MISMATCH"):
            self.verify(release.canonical(manifest))

    def test_mid_inspection_mutation_cannot_publish_a_readback(self):
        original = release.native_closure
        def mutate(*args):
            result = original(*args)
            put(self.root / "project/check.py", b"changed during observation")
            return result
        with mock.patch.object(release, "native_closure", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "CHANGED_DURING_INSPECTION"):
                self.declare()

    def test_change_then_restore_bytes_is_still_a_changed_observation(self):
        original = release.native_closure
        def replace_and_restore(*args):
            result = original(*args)
            path = self.root / "project/check.py"
            raw = path.read_bytes()
            path.write_bytes(b"temporary substitution")
            path.write_bytes(raw)
            return result
        with mock.patch.object(release, "native_closure", side_effect=replace_and_restore):
            with self.assertRaisesRegex(ValueError, "CHANGED_DURING_INSPECTION"):
                self.declare()

    def test_original_release_cli_is_create_only_and_wrong_pin_writes_no_result(self):
        area = Path(self.work.name)
        spec, output = area / "spec.json", area / "runtime.json"
        put(spec, self.raw)
        command = [sys.executable, str(Path(__file__).with_name("llm_cell_release.py")), "declare-runtime-material",
            "--root", str(self.root), "--spec", str(spec), "--spec-sha256", "1" * 64,
            "--output", str(output), "--maximum-bytes", str(self.limit)]
        failed = subprocess.run(command, capture_output=True, timeout=15)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse(output.exists())
        command[command.index("--spec-sha256") + 1] = sha(self.raw)
        accepted = subprocess.run(command, capture_output=True, timeout=15)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        before = output.read_bytes()
        rejected = subprocess.run(command, capture_output=True, timeout=15)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
