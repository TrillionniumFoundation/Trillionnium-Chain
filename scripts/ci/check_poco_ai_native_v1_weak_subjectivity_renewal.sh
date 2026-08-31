#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-weak-subjectivity-checkpoint-renewal-v1.json"
CORPUS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-weak-subjectivity-checkpoint-renewal-v1.json"
TRUST_PATH_SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-order-trust-path-iterator-v1.json"

for required in "$CHECKER" "$SCHEMA" "$CORPUS" "$TRUST_PATH_SCHEMA"; do
  if [[ ! -f "$required" ]]; then
    printf 'FAIL: missing bounded weak-subjectivity renewal evidence file: %s\n' "$required" >&2
    exit 1
  fi
done

python3 -B - "$CHECKER" "$SCHEMA" "$CORPUS" <<'PY'
import ast
import json
from pathlib import Path
import sys

checker = Path(sys.argv[1])
schema_path = Path(sys.argv[2])
corpus_path = Path(sys.argv[3])
source = checker.read_text(encoding="utf-8")
tree = ast.parse(source, filename=str(checker))
allowed = {
    "__future__", "argparse", "copy", "hashlib", "json", "pathlib",
    "struct", "sys", "typing",
}
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        names = {alias.name.split(".", 1)[0] for alias in node.names}
    elif isinstance(node, ast.ImportFrom):
        names = {(node.module or "").split(".", 1)[0]}
    else:
        continue
    unexpected = names - allowed
    if unexpected:
        raise SystemExit(
            "FAIL: independent weak-subjectivity checker imports unexpected "
            f"modules: {sorted(unexpected)}"
        )

for marker in (
    "dec_weak_subjectivity_renewal",
    "noncanonical_reencode",
    "verify_weak_subjectivity_checkpoint_renewal",
    "weak_subjectivity_anchor_from_checkpoint",
    "weak_subjectivity_context_lineage",
    "weak_subjectivity_epoch_monotonicity",
    "weak_subjectivity_height_monotonicity",
    "weak_subjectivity_same_height_conflict",
    "weak_subjectivity_prior_age_epoch",
    "weak_subjectivity_prior_age_block",
    "weak_subjectivity_prior_authority",
    "weak_subjectivity_renewed_authority",
    "weak_subjectivity_prior_roots",
    "weak_subjectivity_renewed_roots",
    "--self-test-weak-subjectivity-mutants",
):
    if marker not in source:
        raise SystemExit(
            f"FAIL: independent weak-subjectivity checker is missing marker: {marker}"
        )

schema = json.loads(schema_path.read_text(encoding="utf-8"))
corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
if schema.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: weak-subjectivity schema must remain candidate-non-normative")
if corpus.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: weak-subjectivity corpus must remain candidate-non-normative")
if schema.get("negative_inventory_count") != 45:
    raise SystemExit("FAIL: weak-subjectivity schema negative inventory drift")
if len(corpus.get("negative_cases", [])) != 45:
    raise SystemExit("FAIL: weak-subjectivity corpus must bind all 45 exact-error mutants")
if [case.get("case_id") for case in corpus.get("positive_cases", [])] != [
    "three_hop_first_to_latest_checkpoint_renewal",
    "exact_raw_reencode_and_replay",
]:
    raise SystemExit("FAIL: weak-subjectivity positive inventory drift")

exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
for marker in (
    "wall-clock", "operator key", "arbitrary checkpoint", "arbitrary-length",
    "v0 activation", "state sync", "complete wire", "second implementation",
    "global light client", "normative freeze", "production activation",
):
    if marker not in exclusions:
        raise SystemExit(
            f"FAIL: weak-subjectivity corpus is missing explicit exclusion: {marker}"
        )
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" \
  --check-weak-subjectivity-renewal --self-test-weak-subjectivity-mutants
