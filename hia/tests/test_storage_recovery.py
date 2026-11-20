"""CLI admission of the independent physical genesis-recovery qualification."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class StorageRecoveryCliTests(unittest.TestCase):
    def test_absolute_cli_is_independent_of_import_environment(self):
        script = Path(__file__).resolve().parents[1] / "tools/qualify_storage_recovery.py"
        environment = os.environ.copy()
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE"):
            environment.pop(name, None)
        with tempfile.TemporaryDirectory(prefix="trnm-storage-recovery-cli-") as directory:
            result = subprocess.run([sys.executable, "-B", str(script), "--help"],
                cwd=directory, env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--output", result.stdout)

    def test_optimized_python_cannot_disable_physical_recovery_oracles(self):
        script = Path(__file__).resolve().parents[1] / "tools/qualify_storage_recovery.py"
        environment = os.environ.copy()
        for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE"):
            environment.pop(name, None)
        with tempfile.TemporaryDirectory(prefix="trnm-storage-recovery-opt-") as directory:
            for arguments, optimization in ((("-O",), None), (("-OO",), None), ((), "2")):
                with self.subTest(arguments=arguments, optimization=optimization):
                    env = environment.copy()
                    if optimization:
                        env["PYTHONOPTIMIZE"] = optimization
                    result = subprocess.run([sys.executable, *arguments, "-B", str(script), "--help"],
                        cwd=directory, env=env, capture_output=True, text=True, timeout=10)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("optimized Python is forbidden", result.stderr)


if __name__ == "__main__":
    unittest.main()
