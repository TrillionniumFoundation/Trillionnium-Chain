"""Real file/process admission controls; no Torch/model/VRAM qualification."""
import copy
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest

import llm_python_runtime_contract as contract

SCRIPTS = Path(__file__).resolve().parent


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeAdmissionTests(unittest.TestCase):
    def fixture(self, root):
        prefix, stdlib = root / "venv", root / "base/lib/python3.12"
        (prefix / "lib").mkdir(parents=True)
        stdlib.mkdir(parents=True)
        module = prefix / "dependency.py"
        module.write_text("__version__='same-public-version'\nVALUE='approved'\n")
        (stdlib / "stdlib.py").write_text("# explicit unused standard-library fixture\n")
        executable = str(Path(sys.executable).resolve())
        value = dict(schema=contract.SCHEMA, prefix=str(prefix), stdlib_root=str(stdlib),
            python=dict(executable=executable, version=sys.version, abi=sysconfig.get_config_var("SOABI")),
            files={executable: checksum(Path(executable))})
        inventory = contract.managed_inventory(value)
        value["managed_inventory"] = inventory
        value["files"].update({path: checksum(Path(path)) for path in inventory})
        snapshot = root / "snapshot.json"
        snapshot.write_text(json.dumps(value, sort_keys=True))
        return snapshot, value, module

    def child(self, source, *, environment=None):
        return subprocess.run([sys.executable, "-I", "-S", "-B", "-c", source],
            capture_output=True, text=True, timeout=10, env=environment)

    def bootstrap(self):
        return f"import sys; sys.path.insert(0,{str(SCRIPTS)!r}); import llm_python_runtime_contract as c; "

    def test_real_snapshot_roundtrip_and_same_version_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, value, module = self.fixture(Path(directory))
            loaded = contract.load_snapshot(snapshot, checksum(snapshot))
            self.assertEqual(loaded, value)
            contract.verify_files(loaded)
            module.write_text("__version__='same-public-version'\nVALUE='modified'\n")
            with self.assertRaisesRegex(ValueError, "BYTE_DRIFT"):
                contract.verify_files(loaded)

    def test_new_file_omission_duplicate_and_replaced_snapshot_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, value, module = self.fixture(Path(directory))
            added = module.with_name("undeclared.py")
            added.write_text("# unapproved dependency\n")
            with self.assertRaisesRegex(ValueError, "INVENTORY_DRIFT"):
                contract.verify_files(value)
            added.unlink()
            incomplete = copy.deepcopy(value)
            del incomplete["files"][str(module)]
            snapshot.write_text(json.dumps(incomplete))
            with self.assertRaisesRegex(ValueError, "INVENTORY"):
                contract.load_snapshot(snapshot, checksum(snapshot))
            snapshot.write_bytes(b'{"schema":"one","schema":"two"}')
            with self.assertRaisesRegex(ValueError, "DUPLICATE_FIELD"):
                contract.load_snapshot(snapshot, checksum(snapshot))
            digest = checksum(snapshot)
            snapshot.write_text("{}")
            with self.assertRaisesRegex(ValueError, "SNAPSHOT_BYTES"):
                contract.load_snapshot(snapshot, digest)

    def test_fifo_and_symlink_are_refused_without_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"
            os.mkfifo(path)
            result = self.child(self.bootstrap() + f"c.load_snapshot({str(path)!r},{'00' * 32!r})")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FILE_TYPE", result.stderr)
            path.unlink()
            actual = Path(directory) / "actual"
            actual.write_text("{}")
            path.symlink_to(actual)
            with self.assertRaises((ValueError, OSError)):
                contract.load_snapshot(path, checksum(actual))

    def test_real_dist_info_discovery_survives_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = root / "review_dist-1.2.3.dist-info"
            info.mkdir()
            (info / "METADATA").write_text("Metadata-Version: 2.1\nName: review-dist\nVersion: 1.2.3\n")
            helper = str(SCRIPTS / "llm_python_runtime_contract.py")
            script = (self.bootstrap() + "import importlib.metadata; "
                f"sys.path.insert(0,{str(root)!r}); "
                "assert importlib.metadata.version('review-dist')=='1.2.3'; "
                f"c.install_import_guard({{'files':{{}}}},{{{helper!r}:{checksum(Path(helper))!r}}}); "
                "assert importlib.metadata.version('review-dist')=='1.2.3'; print('metadata-preserved')")
            result = self.child(script)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "metadata-preserved")

    def test_unpinned_import_shadow_rejects_before_canary_executes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "must-not-execute"
            (root / "fixture_dependency.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            helper = str(SCRIPTS / "llm_python_runtime_contract.py")
            script = (self.bootstrap() +
                f"c.install_import_guard({{'files':{{}}}},{{{helper!r}:{checksum(Path(helper))!r}}}); "
                f"sys.path.insert(0,{str(root)!r}); import fixture_dependency")
            result = self.child(script)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("UNDECLARED_IMPORT", result.stderr)
            self.assertFalse(marker.exists())

    def test_pinned_source_executes_snapshot_despite_poisoned_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "fixture_dependency.py"
            module.write_text("VALUE='approved'\n")
            helper = str(SCRIPTS / "llm_python_runtime_contract.py")
            script = (self.bootstrap() +
                f"c.install_import_guard({{'files':{{{str(module)!r}:{checksum(module)!r}}}}},{{{helper!r}:{checksum(Path(helper))!r}}}); "
                f"sys.path.insert(0,{str(root)!r}); import fixture_dependency; assert fixture_dependency.VALUE=='approved'")
            (root / "__pycache__").mkdir()
            cache = root / "__pycache__" / ("fixture_dependency." + sys.implementation.cache_tag + ".pyc")
            cache.write_bytes(b"invalid, unpinned bytecode must never be selected")
            result = self.child(script)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_worker_startup_rejects_ambient_python_shadow_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "llm_neural_read_worker.py"
            shutil.copyfile(SCRIPTS / worker.name, worker)
            marker = root / "bootstrap-canary"
            (root / "hashlib.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
            unsafe = subprocess.run([sys.executable, str(worker), "--help"],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("NEURAL_READ_ISOLATED_ENTRY", unsafe.stderr)
            self.assertFalse(marker.exists())
            safe = subprocess.run([sys.executable, "-I", "-S", "-B", str(worker), "--help"],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(safe.returncode, 0, safe.stderr)
            self.assertFalse(marker.exists())


class GeneratedSourceMechanismTests(unittest.TestCase):
    """Synthetic loader/AST controls only; never a Torch or model qualification."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / "generated"
        self.directory.mkdir(mode=0o700)
        self.raw = b"VALUE = 'approved'\n"
        self.path = self.directory / (contract.TORCH_GENERATED_NAME + ".py")
        self.path.write_bytes(self.raw)
        self.producer_path = self.root / "synthetic_producer.py"
        self.producer_path.write_text("INSTANTIATED_TEMPLATE_DIR_PATH = " + repr(str(self.directory)) + "\n")
        self.admission = contract._GeneratedSourceAdmission(self.raw, str(self.producer_path))
        self.files = {str(self.producer_path): checksum(self.producer_path)}
        self.guard = contract.PinnedImports(dict(self.files), self.admission)
        self.old_path = list(sys.path)
        self.old_modules = {name: sys.modules.get(name) for name in
                            (contract.TORCH_INSTANTIATOR, contract.TORCH_GENERATED_NAME)}
        sys.path.insert(0, str(self.directory))
        loader = contract.PinnedPythonSource(contract.TORCH_INSTANTIATOR, str(self.producer_path),
                    checksum(self.producer_path), self.admission.producer_executed)
        spec = importlib.util.spec_from_loader(contract.TORCH_INSTANTIATOR, loader)
        self.producer = importlib.util.module_from_spec(spec)
        sys.modules[contract.TORCH_INSTANTIATOR] = self.producer
        loader.exec_module(self.producer)

    def tearDown(self):
        sys.path[:] = self.old_path
        for name, value in self.old_modules.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
        self.temporary.cleanup()
        importlib.invalidate_caches()

    def load(self, spec=None):
        spec = spec or self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        module = importlib.util.module_from_spec(spec)
        sys.modules[contract.TORCH_GENERATED_NAME] = module
        spec.loader.exec_module(module)
        return module

    def observed_fixture(self):
        # A fresh synthetic consistency fixture, not an independently provisioned
        # production snapshot. The real model gate supplies that external root.
        paths = {str(Path(module.__file__).resolve()) for module in tuple(sys.modules.values())
                 if type(getattr(module, "__file__", None)) is str}
        for line in Path("/proc/self/maps").read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and "x" in fields[1] and fields[5].startswith("/"):
                paths.add(str(Path(fields[5]).resolve()))
        paths.discard(str(self.path))
        files = {path: contract.file_digest(path)[0] for path in paths}
        self.guard.files = files
        return {"files": files}

    def verify_observation(self, value):
        sys.meta_path.insert(0, self.guard)
        try:
            contract.verify_loaded(value, {}, self.guard)
        finally:
            sys.meta_path.remove(self.guard)

    def test_generated_fixture_executes_exact_bytes_without_expanding_declared_files(self):
        module = self.load()
        self.assertEqual(module.VALUE, "approved")
        self.assertEqual(self.guard.files, self.files)
        self.assertEqual(self.admission.verify_loaded(), str(self.path))
        value = self.observed_fixture()
        self.verify_observation(value)
        with self.assertRaisesRegex(ValueError, "IMPORT_GUARD_IDENTITY"):
            contract.verify_loaded(value, {}, contract.PinnedImports(value["files"]))

    def test_generated_changed_output_is_rejected_before_canary_executes(self):
        marker = self.root / "canary"
        self.path.write_text(f"open({str(marker)!r}, 'w').close()\n")
        with self.assertRaisesRegex(ValueError, "GENERATED_BYTE_DRIFT"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        self.assertFalse(marker.exists())
        self.assertIsNone(self.admission.origin)

    def test_generated_loader_holds_verified_bytes_and_ready_refuses_later_drift(self):
        spec = self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        self.path.write_text("raise RuntimeError('unverified-path-must-not-run')\n")
        module = self.load(spec)
        self.assertEqual(module.VALUE, "approved")
        value = self.observed_fixture()
        with self.assertRaisesRegex(ValueError, "GENERATED_FILE_CHANGED"):
            self.verify_observation(value)

    def test_generated_wrong_fullname_and_scriptable_name_are_not_authorized(self):
        for name in ("unrelated_generated", "_remote_module_scriptable"):
            with self.subTest(name=name):
                (self.directory / (name + ".py")).write_bytes(self.raw)
                with self.assertRaisesRegex(ValueError, "UNDECLARED_IMPORT"):
                    self.guard.find_spec(name)
        self.assertIsNone(self.admission.origin)

    def test_generated_same_bytes_on_earlier_search_path_are_not_producer_output(self):
        other = self.root / "earlier"
        other.mkdir()
        (other / self.path.name).write_bytes(self.raw)
        sys.path.insert(0, str(other))
        with self.assertRaisesRegex(ValueError, "GENERATED_ORIGIN"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        self.assertIsNone(self.admission.origin)

    def test_generated_symlink_fifo_and_oversized_file_fail_without_execution(self):
        original = self.root / "same-bytes"
        original.write_bytes(self.raw)
        self.path.unlink()
        self.path.symlink_to(original)
        with self.assertRaises((ValueError, OSError)):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        self.path.unlink()
        os.mkfifo(self.path)
        script = (f"import sys; sys.path.insert(0,{str(SCRIPTS)!r}); "
                  "import llm_python_runtime_contract as c; "
                  f"c._stable_regular_bytes({str(self.path)!r}, c.MAX_GENERATED_SOURCE)")
        child = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script],
                               capture_output=True, text=True, timeout=5)
        self.assertNotEqual(child.returncode, 0)
        self.assertIn("GENERATED_FILE_BOUND", child.stderr)
        self.path.unlink()
        self.path.write_bytes(b"x" * (contract.MAX_GENERATED_SOURCE + 1))
        with self.assertRaisesRegex(ValueError, "GENERATED_FILE_BOUND"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)

    def test_generated_requires_this_guard_executed_producer_and_unchanged_directory(self):
        self.admission.producer = None
        with self.assertRaisesRegex(ValueError, "GENERATED_PRODUCER"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        self.admission.producer_executed(self.producer)
        old = sys.modules[contract.TORCH_INSTANTIATOR]
        sys.modules[contract.TORCH_INSTANTIATOR] = type(old)(old.__name__)
        with self.assertRaisesRegex(ValueError, "GENERATED_PRODUCER"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        sys.modules[contract.TORCH_INSTANTIATOR] = old
        other = self.root / "replacement"
        other.mkdir(mode=0o700)
        old.INSTANTIATED_TEMPLATE_DIR_PATH = str(other)
        with self.assertRaisesRegex(ValueError, "GENERATED_PRODUCER"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)

    def test_generated_second_admission_and_different_origin_are_refused(self):
        self.load()
        with self.assertRaisesRegex(ValueError, "GENERATED_ALREADY_ADMITTED"):
            self.guard.find_spec(contract.TORCH_GENERATED_NAME)
        with self.assertRaisesRegex(ValueError, "GENERATED_ORIGIN"):
            self.admission.admit(contract.TORCH_GENERATED_NAME, str(self.root / self.path.name))

    def test_generated_profile_requires_all_three_independent_pins_and_actual_bytes(self):
        prefix = self.root / "runtime"
        site = prefix / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
        files = {}
        for relative, expected in contract.TORCH_GENERATED_SOURCES:
            path = site / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# synthetic changed dependency, not Torch qualification\n")
            files[str(path)] = expected
        value = {"prefix": str(prefix), "files": dict(files)}
        with self.assertRaisesRegex(ValueError, "GENERATED_SOURCE_DRIFT"):
            contract._generated_source_profile(value)
        value["files"] = {path: checksum(Path(path)) for path in files}
        with self.assertRaisesRegex(ValueError, "GENERATED_PROFILE_PIN"):
            contract._generated_source_profile(value)
        for missing in files:
            value["files"] = dict(files)
            del value["files"][missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "GENERATED_PROFILE_PIN"):
                contract._generated_source_profile(value)

    def test_generated_literal_derivation_rejects_code_arguments_branch_and_caller_changes(self):
        generator = ('_FILE_PREFIX = "_remote_module_"\n'
            'def instantiate_non_scriptable_remote_module_template():\n'
            '    generated_module_name = f"{_FILE_PREFIX}non_scriptable"\n'
            '    str_dict = dict(' + ", ".join(name + "=" + repr(value)
                for name, value in contract.TORCH_GENERATED_ARGS.items()) + ')\n'
            '    return _do_instantiate_remote_module_template(generated_module_name, str_dict, True)\n')
        template = ('def get_remote_module_template(enable_moving_cpu_tensors_to_cuda: bool):\n'
            '    return _TEMPLATE_PREFIX + (_REMOTE_FORWARD_TEMPLATE_ENABLE_MOVING_CPU_TENSORS_TO_CUDA '
            'if enable_moving_cpu_tensors_to_cuda else _REMOTE_FORWARD_TEMPLATE)\n'
            '_TEMPLATE_PREFIX = "VALUE = \'approved\'\\n"\n'
            '_REMOTE_FORWARD_TEMPLATE_ENABLE_MOVING_CPU_TENSORS_TO_CUDA = ""\n'
            '_REMOTE_FORWARD_TEMPLATE = ""\n')
        caller = ('_NON_SCRIPTABLE_REMOTE_MODULE_MODULE = '
                  'instantiator.instantiate_non_scriptable_remote_module_template()\n')
        derive = contract._derive_torch_generated_source
        self.assertEqual(derive(generator, template, caller), self.raw)
        for changed in (
            (generator.replace("str_dict, True)", "str_dict, False)"), template, caller),
            (generator.replace("args='*args'", "args=unknown_function()"), template, caller),
            (generator.replace("kwargs='**kwargs'", "kwargs='different'"), template, caller),
            (generator, template.replace('= ""', '= unknown_function()', 1), caller),
            (generator, template, caller.replace("template()", "template(1)")),
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                derive(*changed)


if __name__ == "__main__":
    unittest.main()
