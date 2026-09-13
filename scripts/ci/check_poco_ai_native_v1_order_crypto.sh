#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_crypto.py"
CORPUS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-order-signature-crypto-v1.json"

for required in "$CHECKER" "$CORPUS"; do
  if [[ ! -f "$required" ]]; then
    printf 'FAIL: missing bounded v1 order crypto evidence file: %s\n' "$required" >&2
    exit 1
  fi
done

python3 -B - "$CHECKER" "$CORPUS" <<'PY'
import ast
import json
from pathlib import Path
import sys

checker = Path(sys.argv[1])
corpus_path = Path(sys.argv[2])
source = checker.read_text(encoding="utf-8")
tree = ast.parse(source, filename=str(checker))
allowed = {
    "__future__",
    "argparse",
    "copy",
    "hashlib",
    "json",
    "pathlib",
    "struct",
    "sys",
    "typing",
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
        raise SystemExit(f"FAIL: independent crypto checker imports unexpected modules: {sorted(unexpected)}")

for forbidden in (
    "check_poco_ai_native_v1_foundation_vectors",
    "check_poco_ai_native_v1_foundation_independent",
    "trnm_poco",
    "trnm-native",
    "nacl",
    "cryptography",
    "openssl",
    "subprocess",
):
    if forbidden in source:
        raise SystemExit(f"FAIL: independent crypto checker contains forbidden dependency marker: {forbidden}")

required_markers = (
    "strict_ed25519_verify",
    "rfc8032_control",
    "VOTE_DOMAIN",
    "TIMEOUT_DOMAIN",
    "verify_timeout_statement_authority",
    "qc_duplicate_signer",
    "tc_duplicate_signer",
    "tc_statement_mutation",
    "tc_statement_swap",
    "tc_statement_substitution",
    "tc_entry_missing_statement",
    "tc_statement_missing_pacemaker_generation",
    "candidate-only",
)
for marker in required_markers:
    if marker not in source:
        raise SystemExit(f"FAIL: independent crypto checker is missing marker: {marker}")

corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
if corpus.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: crypto corpus must remain candidate-non-normative")
if corpus.get("signature_scheme") != "strict-ed25519-v1-draft":
    raise SystemExit("FAIL: crypto corpus signature scheme drift")
if len(corpus.get("negative_cases", [])) != 18:
    raise SystemExit("FAIL: crypto corpus negative inventory drift")
entries = corpus.get("claims", {}).get("timeout_certificate_signatures", [])
if len(entries) < 3:
    raise SystemExit("FAIL: crypto corpus needs quorum-sized Timeout entries")
for index, entry in enumerate(entries):
    if set(entry) != {"validator_id", "statement", "signature_scheme", "signature"}:
        raise SystemExit(f"FAIL: TimeoutSignatureEntryV1 field drift at index {index}")
if len({json.dumps(entry["statement"], sort_keys=True, separators=(",", ":")) for entry in entries}) < 2:
    raise SystemExit("FAIL: crypto corpus needs at least two distinct Timeout statements")
exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
for marker in ("light-client", "upgrade", "normative freeze", "activation", "release"):
    if marker not in exclusions:
        raise SystemExit(f"FAIL: crypto corpus is missing explicit exclusion: {marker}")
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" --self-test
