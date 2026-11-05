"""Real file/process admission controls; no Torch/model/VRAM qualification."""
import copy
import hashlib
import importlib.metadata
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


if __name__ == "__main__":
    unittest.main()
