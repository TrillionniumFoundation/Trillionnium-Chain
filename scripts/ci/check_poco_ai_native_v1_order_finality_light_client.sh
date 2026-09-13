#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-order-finality-light-client-kernel-v1.json"
CORPUS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-order-finality-light-client-kernel-v1.json"

for required in "$CHECKER" "$SCHEMA" "$CORPUS"; do
  if [[ ! -f "$required" ]]; then
    printf 'FAIL: missing bounded v1 OrderFinality light-client evidence file: %s\n' "$required" >&2
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
        raise SystemExit(f"FAIL: independent light-client checker imports unexpected modules: {sorted(unexpected)}")

for forbidden in (
    "check_poco_ai_native_v1_foundation_vectors",
    "check_poco_ai_native_v1_foundation_independent",
    "check_poco_ai_native_v1_order_crypto",
    "trnm_poco", "trnm-native", "nacl", "cryptography", "subprocess",
):
    if forbidden in source:
        raise SystemExit(f"FAIL: independent light-client checker contains forbidden dependency marker: {forbidden}")

for marker in (
    "decode_exact", "noncanonical_reencode", "strict_ed25519_verify",
    "load_json_document", "json_duplicate_key_accepted",
    "direct_three_chain_cardinality", "verify_tc", "missing_timeout_certificate",
    "TIMEOUT_SIGNATURE_DOMAIN", "TC_DOMAIN", "proof_target",
    "EPOCH_CHECKPOINT_DOMAIN", "EPOCH_HANDOFF_DOMAIN", "verify_epoch_transition",
    "old_handoff_quorum", "new_handoff_quorum", "new_epoch_first_handoff",
    "finalized_monotonicity", "--self-test-mutants", "candidate-only",
):
    if marker not in source:
        raise SystemExit(f"FAIL: independent light-client checker is missing marker: {marker}")

def unique_object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise SystemExit(f"FAIL: duplicate JSON object name: {key}")
        value[key] = child
    return value


schema = json.loads(
    schema_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
)
corpus = json.loads(
    corpus_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object,
)
if schema.get("status") != "candidate-non-normative" or corpus.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: light-client schema/corpus must remain candidate-non-normative")
if corpus.get("scope") != "fresh-genesis-ordinary-checkpoint-and-one-epoch-handoff-bounded-trust-progression":
    raise SystemExit("FAIL: light-client corpus scope drift")
if len(corpus.get("positive_cases", [])) != 9:
    raise SystemExit("FAIL: light-client positive inventory drift")
if len(corpus.get("negative_cases", [])) < 30:
    raise SystemExit("FAIL: light-client corpus requires at least 30 rejection mutants")
if len(corpus.get("tc_negative_cases", [])) < 20:
    raise SystemExit("FAIL: light-client corpus requires at least 20 TC rejection mutants")
if len(corpus.get("transition_negative_cases", [])) < 60:
    raise SystemExit("FAIL: light-client corpus requires at least 60 transition rejection mutants")
if corpus.get("expected", {}).get("valid_qc_signatures_checked") != 12:
    raise SystemExit("FAIL: light-client corpus must bind all 12 three-chain QC signatures")
ordinary = corpus.get("ordinary_target_case", {}).get("expected", {})
if ordinary.get("valid_qc_signatures_checked") != 16 or ordinary.get("valid_tc_signatures_checked") != 4:
    raise SystemExit("FAIL: Ordinary-target corpus must bind 16 QC and 4 timeout signatures")
direct = corpus.get("direct_ordinary_target_case", {}).get("expected", {})
if (
    direct.get("finalized_height") != 2
    or direct.get("target_kind") != "Ordinary"
    or direct.get("valid_qc_signatures_checked") != 16
    or direct.get("tc_ids") != []
):
    raise SystemExit("FAIL: direct Ordinary-target corpus must bind 16 QC signatures and no TC")
transition = corpus.get("epoch_transition_case", {}).get("expected", {})
if (
    transition.get("old_qc_signatures_checked") != 16
    or transition.get("new_qc_signatures_checked") != 16
    or transition.get("old_handoff_signatures") != 4
    or transition.get("new_handoff_signatures") != 4
    or transition.get("finalized_kind") != "Ordinary"
):
    raise SystemExit("FAIL: epoch-transition corpus signature/finality inventory drift")
exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
for marker in ("more than one epoch handoff", "arbitrary-length", "proposer-signature", "state-sync", "second implementation", "activation", "normative freeze"):
    if marker not in exclusions:
        raise SystemExit(f"FAIL: light-client corpus is missing explicit exclusion: {marker}")
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" --check --self-test-mutants

command -v openssl >/dev/null 2>&1 || {
  printf 'FAIL: OpenSSL is required for independent Ed25519 cross-checks\n' >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

records="$tmp_dir/records.tsv"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" --emit-openssl-records >"$records"
[[ "$(wc -l <"$records" | tr -d ' ')" == 72 ]] || {
  printf 'FAIL: expected 72 proof QC/TC/handoff signature records for OpenSSL cross-check\n' >&2
  exit 1
}

count=0
while IFS=$'\t' read -r public_hex signature_hex message_hex; do
  count=$((count + 1))
  printf '%s' "$public_hex" | xxd -r -p >"$tmp_dir/public.raw"
  printf '%s' "$signature_hex" | xxd -r -p >"$tmp_dir/signature.raw"
  printf '%s' "$message_hex" | xxd -r -p >"$tmp_dir/message.raw"
  {
    printf '302a300506032b6570032100' | xxd -r -p
    cat "$tmp_dir/public.raw"
  } >"$tmp_dir/public.der"
  openssl pkey -pubin -inform DER -in "$tmp_dir/public.der" -out "$tmp_dir/public.pem" >/dev/null 2>&1
  openssl pkeyutl -verify -pubin -inkey "$tmp_dir/public.pem" -rawin \
    -in "$tmp_dir/message.raw" -sigfile "$tmp_dir/signature.raw" >/dev/null 2>&1 || {
      printf 'FAIL: OpenSSL rejected proof QC/TC/handoff signature %d\n' "$count" >&2
      exit 1
    }
done <"$records"

cp "$tmp_dir/signature.raw" "$tmp_dir/signature-bad.raw"
python3 -B - "$tmp_dir/signature-bad.raw" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
raw = bytearray(path.read_bytes())
raw[7] ^= 1
path.write_bytes(raw)
PY
if openssl pkeyutl -verify -pubin -inkey "$tmp_dir/public.pem" -rawin \
  -in "$tmp_dir/message.raw" -sigfile "$tmp_dir/signature-bad.raw" >/dev/null 2>&1; then
  printf 'FAIL: OpenSSL accepted mutated proof QC/TC/handoff signature\n' >&2
  exit 1
fi

printf 'PASS: OpenSSL independently verified %d/72 proof QC/TC/handoff signatures and rejected the mutated control\n' "$count"
