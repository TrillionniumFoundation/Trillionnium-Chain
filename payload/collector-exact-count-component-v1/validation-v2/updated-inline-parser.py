from pathlib import Path
import re, sys
root = Path(sys.argv[1])
expected = (("cancellation-handoff", 22), ("coordinator-contract", 20),
            ("provider-contract", 11), ("generation-target", 13), ("owner-cancellation", 8),
            ("source-builder", 8),
            ("owned-runtime-reader", 7), ("kaggle-worker-contract", 12), ("winner-identity", 4),
            ("deployment-evidence-binding", 12), ("deployment-comparison-audit", 20),
            ("owned-process-collector", 16))
for name, count in expected:
    text = (root / (name + ".log")).read_text()
    if (re.findall(r"^Ran ([0-9]+) tests in ", text, re.M) != [str(count)]
            or not re.search(r"^OK$", text, re.M) or "skipped=" in text):
        raise SystemExit(f"{name}: all {count} controls must execute without skips")
