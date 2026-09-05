#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-order-ordinary-finality-advance-v1.json"
CORPUS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-order-ordinary-finality-advance-v1.json"

for required in "$CHECKER" "$SCHEMA" "$CORPUS"; do
  if [[ ! -f "$required" ]]; then
    printf 'FAIL: missing bounded Ordinary finality advance evidence file: %s\n' "$required" >&2
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
            "FAIL: independent Ordinary advance checker imports unexpected "
            f"modules: {sorted(unexpected)}"
        )

for marker in (
    "dec_ordinary_advance", "noncanonical_reencode",
    "load_json_document", "json_duplicate_key_accepted",
    "trusted_state_from_direct_ordinary_proof",
    "verify_ordinary_finality_advance", "ordinary_advance_input_state",
    "ordinary_advance_first_parent", "ordinary_advance_first_justify",
    "ordinary_advance_single_skipped_view", "ordinary_advance_tc_count",
    "ordinary_advance_output_state", "ORDINARY_FINALITY_ADVANCE_DOMAIN",
    "--self-test-ordinary-advance-mutants",
):
    if marker not in source:
        raise SystemExit(
            f"FAIL: independent Ordinary advance checker is missing marker: {marker}"
        )

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
if schema.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: Ordinary advance schema must remain candidate-non-normative")
if corpus.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: Ordinary advance corpus must remain candidate-non-normative")
if schema.get("negative_inventory_count") != 52:
    raise SystemExit("FAIL: Ordinary advance schema negative inventory drift")
if len(corpus.get("negative_cases", [])) != 52:
    raise SystemExit("FAIL: Ordinary advance corpus must bind all 52 exact-error mutants")
if [case.get("case_id") for case in corpus.get("advance_cases", [])] != [
    "same_epoch_one_skipped_view_tc", "same_epoch_consecutive_views",
]:
    raise SystemExit("FAIL: Ordinary advance positive inventory drift")
openssl_contract = corpus.get("openssl_cross_check", {})
if (
    openssl_contract.get("valid_signatures") != 48
    or openssl_contract.get("breakdown")
    != {"qc_signatures": 40, "tc_signatures": 8}
):
    raise SystemExit("FAIL: Ordinary advance OpenSSL inventory drift")
exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
for marker in (
    "payload bytes", "proposer signature", "checkpoint transition",
    "v0 activation", "more than one skipped view", "arbitrary-length",
    "state sync", "complete wire", "second implementation",
    "global light-client", "normative freeze", "production activation",
):
    if marker not in exclusions:
        raise SystemExit(
            f"FAIL: Ordinary advance corpus is missing explicit exclusion: {marker}"
        )
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" \
  --check-ordinary-advance --self-test-ordinary-advance-mutants

command -v openssl >/dev/null 2>&1 || {
  printf 'FAIL: OpenSSL is required for independent Ed25519 cross-checks\n' >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

records="$tmp_dir/records.tsv"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" \
  --emit-ordinary-advance-openssl-records >"$records"
[[ "$(wc -l <"$records" | tr -d ' ')" == 48 ]] || {
  printf 'FAIL: expected 48 Ordinary advance QC/TC signature records\n' >&2
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
  openssl pkey -pubin -inform DER -in "$tmp_dir/public.der" \
    -out "$tmp_dir/public.pem" >/dev/null 2>&1
  openssl pkeyutl -verify -pubin -inkey "$tmp_dir/public.pem" -rawin \
    -in "$tmp_dir/message.raw" -sigfile "$tmp_dir/signature.raw" >/dev/null 2>&1 || {
      printf 'FAIL: OpenSSL rejected Ordinary advance signature %d\n' "$count" >&2
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
  printf 'FAIL: OpenSSL accepted mutated Ordinary advance signature\n' >&2
  exit 1
fi

printf 'PASS: OpenSSL independently verified %d/48 Ordinary advance QC/TC signatures and rejected the mutated control\n' "$count"
