#!/usr/bin/env python3
"""Run the nine retained regressions on the exact newly frozen executable."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("native_binding", HERE / "run_history_native.py")
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)

attempt = HERE / sys.argv[1]
receipt = json.loads((attempt / "attempt.json").read_text())
binary = Path(receipt["binary"])
assert binding.sha(binary) == receipt["binary_sha256"]
before = binding.snapshot()
assert before == json.loads((attempt / "source-after.json").read_text())
cases = [
    ("original-cpu-six", "operator_continuous_cpu::tests::", 6, False),
    ("original-history-internal-activation", "ingress::history_activation_tests::complete_history_checks_resources_inside_activation_and_can_retry", 1, True),
    ("original-history-unknown-crash-fence", "ingress::tests::history_paid_epoch_crash_cut_refuses_new_cold_credit", 1, True),
    ("original-history-malformed-known-close", "ingress::tests::malformed_paid_history_rejection_closes_known_epoch_without_poisoning_cold_reopen", 1, True),
]
out = attempt / "retained"
out.mkdir(exist_ok=False)
results = []
for name, selector, count, exact in cases:
    command = [str(binary), selector, *(["--exact"] if exact else []), "--test-threads=1", "--nocapture"]
    log = out / f"{name}.log"
    with log.open("w") as stream:
        run = subprocess.run(command, cwd=binding.ROOT, stdout=stream, stderr=subprocess.STDOUT)
    raw = log.read_text()
    results.append({"name": name, "command": command, "returncode": run.returncode,
                    "expected_passed": count, "log_sha256": binding.sha(log),
                    "summary": [line for line in raw.splitlines() if line.startswith("test result:")],
                    "passed": run.returncode == 0 and bool(re.search(rf"test result: ok\. {count} passed; 0 failed; 0 ignored;", raw))})
after = binding.snapshot()
record = {"schema": "retained-nine-history-native-regressions-v1", "binary_sha256": binding.sha(binary),
          "source_stable": before == after, "binary_stable": binding.sha(binary) == receipt["binary_sha256"],
          "distinct_native_tests": 9, "cases": results, "production_qualified": False}
record["passed"] = record["source_stable"] and record["binary_stable"] and all(item["passed"] for item in results)
(out / "retained-summary.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))
raise SystemExit(0 if record["passed"] else 1)
