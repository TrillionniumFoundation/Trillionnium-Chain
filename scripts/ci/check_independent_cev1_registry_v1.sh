#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

PARSER="$ROOT/tools/independent-cev1-parser/registry_conformance.py"
EVIDENCE="$(mktemp "${TMPDIR:-/tmp}/trnm-independent-cev1-evidence.XXXXXX.json")"
trap 'rm -f "$EVIDENCE"' EXIT

[[ -f "$PARSER" ]] || { echo "independent CEV1 parser is missing" >&2; exit 1; }

# A08 remains a separate subprocess cross-check.  The A09 parser never imports
# its implementation.  The operation-map fixture carries the exact corrected
# source pin; requiring it here prevents a stale/pending map from looking like
# a successful replay.  A direct parser invocation without this flag remains
# available for the explicit pending/blocked test branch.
python3 "$PARSER" \
  --root "$ROOT" \
  --a08-checker "$ROOT/scripts/ci/check_cev1_registry_spec_v1.py" \
  --require-a08-pin \
  --evidence-out "$EVIDENCE" >/dev/null

python3 - "$EVIDENCE" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
assert data["schema"] == "trnm-independent-cev1-registry-evidence-v2"
assert data["agent_id"] == "A09"
assert data["package_id"] == "G15_INDEPENDENT_CONFORMANCE_V1"
assert data["gate_id"] == "G1.5"
assert data["classification"] == "candidate-non-normative"
assert data["scope"] == "fixture"
assert data["authority"] == "candidate"
assert data["global_cev1_conformance_complete"] is False
assert data["normative_freeze"] is False
assert data["node_support"] is False
assert data["production_candidate"] is False
assert data["negative_case_count"] >= 30
assert len(data["negative_cases"]) == data["negative_case_count"]
assert all(case["result"] == "rejected" for case in data["negative_cases"])
assert any(case["id"] == "evidence-id-payload-mutation" and case["result"] == "rejected" for case in data["negative_controls"])
assert data["negative_control_count"] == len(data["negative_controls"]) == 1
assert data["upstream"]["a08_checker"]["returncode"] == 0
assert data["source"]["commit"] and data["source"]["tree"]
assert data["source"]["dirty"] is False
assert data["source"]["dirty_paths"] == []
evidence_id = data.get("evidence_id")
assert isinstance(evidence_id, str) and evidence_id.startswith("g15-a09-") and len(evidence_id) == len("g15-a09-") + 32
# Recompute the ID from the parser's stable projection.  Checkout branch,
# dirty-path diagnostics and absolute checker paths are intentionally omitted
# so an exact replay in another worktree has the same identity.
stable_fields = (
    "schema", "agent_id", "package_id", "gate_id", "plan_id", "plan_sha256",
    "status", "classification", "scope", "evidence_scope", "data_scope",
    "authority", "inputs", "negative_cases", "negative_case_count",
    "negative_controls", "negative_control_count",
    "global_cev1_conformance_complete", "normative_freeze", "node_support",
    "production_candidate", "known_gaps", "evidence_id_algorithm",
)
assert all(key in data for key in stable_fields)
payload = {key: data[key] for key in stable_fields}
payload["source"] = {"commit": data["source"]["commit"], "tree": data["source"]["tree"]}
checker = data["upstream"]["a08_checker"]
payload["upstream"] = {
    "agent_id": data["upstream"]["agent_id"],
    "registry_source": data["upstream"]["registry_source"],
    "a08_checker": {key: checker[key] for key in ("status", "returncode", "script_sha256", "stdout_sha256", "stderr_sha256") if key in checker},
}
canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
import hashlib
expected_id = "g15-a09-" + hashlib.sha256(canonical).hexdigest()[:32]
assert evidence_id == expected_id
# A payload mutation must not retain the original identity.
mutated = dict(payload)
mutated["status"] = "MUTATED"
mutated_id = "g15-a09-" + hashlib.sha256(json.dumps(mutated, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()[:32]
assert mutated_id != evidence_id
# Ephemeral checkout metadata is outside the preimage and must not alter ID.
ephemeral = dict(data)
ephemeral_source = dict(data["source"])
ephemeral_source.update({"branch": "other/ephemeral", "dirty": True, "dirty_paths": ["/tmp/not-a-repo-path"]})
ephemeral["source"] = ephemeral_source
ephemeral_upstream = dict(data["upstream"])
ephemeral_checker = dict(checker)
ephemeral_checker["path"] = "/tmp/ephemeral-checker.py"
ephemeral_upstream["a08_checker"] = ephemeral_checker
ephemeral["upstream"] = ephemeral_upstream
ephemeral_payload = {key: ephemeral[key] for key in stable_fields}
ephemeral_payload["source"] = {"commit": ephemeral["source"]["commit"], "tree": ephemeral["source"]["tree"]}
ephemeral_payload["upstream"] = {
    "agent_id": ephemeral["upstream"]["agent_id"],
    "registry_source": ephemeral["upstream"]["registry_source"],
    "a08_checker": {key: ephemeral_checker[key] for key in ("status", "returncode", "script_sha256", "stdout_sha256", "stderr_sha256") if key in ephemeral_checker},
}
assert "g15-a09-" + hashlib.sha256(json.dumps(ephemeral_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()[:32] == evidence_id
assert len(data["inputs"]["registries"]) == 6
for item in data["inputs"]["registries"]:
    assert len(item["raw_sha256"]) == 64
    assert len(item["canonical_sha256"]) == 64
pin = data["upstream"]["registry_source"]
assert pin["verified"] is True
assert pin["status"] == "verified"
assert pin["commit"] == "6c42673db5bc46f82934dddc678a1752a092ca04"
assert pin["tree"] == "df8f6bf0cfe0868668f86ba9b41fc34ce1a085c4"
assert data["status"] == "MODULE_CLOSED_CANDIDATE"
print(f"independent CEV1 registry conformance: ok negatives={data['negative_case_count']} status={data['status']}")
PY

# Run the local retained corpus once more without A08 to prove that the
# independent implementation, rather than the canonical checker, rejects each
# malformed candidate.
python3 "$PARSER" --root "$ROOT" --skip-a08-checker --mutants-only
