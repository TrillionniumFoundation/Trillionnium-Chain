# Chain source-only Library recovery (2026-11-03)

This is an **isolated historical source snapshot**, not a consensus activation or production qualification. It retains 14 distinct research-only files from ChatGPT Library whose exact Git blob SHA was not found in the target Trillionnium-Chain repository when checked. The original 59 Chain-named files included 44 remote-present snapshots and one duplicate of these 14 entries.

**Content preservation:** `python3 verify_snapshot.py` verifies exact source sizes, SHA-256 digests and Git blob SHA-1 identities against `MANIFEST.json`. Python syntax-only check: `python3 -m compileall -q files`. Neither test constitutes a native PoN chain run.

**Runtime scope:** The `*.rs` files are snippets, not standalone Rust crates; they require integration with the original native module and its matching dependency versions. Some Python scripts import other separately archived or project modules. To reproduce behavior, prepare the exact declared original source tree, verify fixture identities, execute each named test in isolation and record exit status and environment. Do not infer a passing original source test, valid production consensus behavior, or authorization to enable this research from file hashes.

No model weights, training data, raw traces, secrets or large evidence archives are included. `q4_cold_audit_smoke(1).py` is a byte-identical duplicate of the retained `q4_cold_audit_smoke.py` and was not duplicated.
