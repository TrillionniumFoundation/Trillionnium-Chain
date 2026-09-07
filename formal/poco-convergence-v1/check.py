"""Run the abstract suite and retained mutation checks; no production authority."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPECTED_TESTS = 32
MUTANTS = {
    "simple-majority": [("return (2 * total) // 3 + 1", "return total // 2 + 1")],
    "proof-class-laundering": [("kind == \"poco-three-chain-v0\"", "True")],
    "cross-context-proof": [("header.context == context", "True")],
    "publish-before-signature-record": [("new in (old, old + 1)", "new >= old")],
    "aggregate-overcommit": [
        ("all(a + b <= c for a, b, c in zip(self.reserved, work, self.caps))", "True"),
        ("all(0 <= n <= c for n, c in zip(expected, self.caps))", "True"),
    ],
    "early-storage-release": [
        ("for i in (0, 2):\n            self.reserved[i] -= task.work[i]",
         "for i in (0, 1, 2):\n            self.reserved[i] -= task.work[i]"),
    ],
    "new-work-overtakes-old": [("sorted((t.ready_at, key)", "sorted((0, key)")],
}


def run_suite(root):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s",
         "formal/poco-convergence-v1", "-v"], cwd=root,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if f"Ran {EXPECTED_TESTS} tests" not in result.stdout:
        raise RuntimeError("incomplete/empty test collection:\n" + result.stdout)
    if "skipped=" in result.stdout or "expected failures=" in result.stdout:
        raise RuntimeError("skipped or expected-failure tests are not acceptance")
    return result


def main():
    baseline = run_suite(ROOT)
    print(baseline.stdout, end="")
    if baseline.returncode:
        return baseline.returncode
    source = (HERE / "model.py").read_text(encoding="utf-8")
    killed = []
    for name, changes in MUTANTS.items():
        mutated = source
        for old, new in changes:
            if mutated.count(old) != 1:
                raise RuntimeError(f"mutation anchor changed: {name}: {old}")
            mutated = mutated.replace(old, new, 1)
        compile(mutated, name, "exec")  # Syntax/import failures are not killed mutants.
        with tempfile.TemporaryDirectory(prefix="trnm-pcc1-") as tmp:
            root = Path(tmp)
            work = root / "formal/poco-convergence-v1"
            work.mkdir(parents=True)
            (root / "config").mkdir()
            (work / "model.py").write_text(mutated, encoding="utf-8")
            shutil.copyfile(HERE / "test_model.py", work / "test_model.py")
            shutil.copyfile(ROOT / "config/poco-convergence-v1.json",
                            root / "config/poco-convergence-v1.json")
            result = run_suite(root)
            if result.returncode == 0 or "FAILED (" not in result.stdout:
                raise RuntimeError(f"mutant not detected: {name}\n{result.stdout}")
            killed.append(name)
    print(json.dumps({"scope": "abstract-examples-only", "baseline_tests": EXPECTED_TESTS,
                      "mutants_detected": killed, "production_evidence": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
