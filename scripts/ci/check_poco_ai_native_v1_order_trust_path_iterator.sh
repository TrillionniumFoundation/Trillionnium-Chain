#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_order_finality_light_client.py"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-order-trust-path-iterator-v1.json"
CORPUS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-order-trust-path-iterator-v1.json"

for required in "$CHECKER" "$SCHEMA" "$CORPUS"; do
  if [[ ! -f "$required" ]]; then
    printf 'FAIL: missing bounded v1 Order trust-path evidence file: %s\n' "$required" >&2
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
            f"FAIL: independent trust-path checker imports unexpected modules: {sorted(unexpected)}"
        )

for marker in (
    "dec_trust_path", "noncanonical_reencode", "verify_order_trust_path",
    "verify_existing_fresh_genesis_path_step",
    "verify_checkpoint_anchored_transition_step", "trust_path_step0_variant",
    "trust_path_step_order", "checkpoint_step_input_state",
    "checkpoint_step_chain_justify", "checkpoint_step_handoff_terminal",
    "checkpoint_step_output_state", "trust_path_height_monotonicity",
    "enc_epoch_handoff_protocol_sidecar", "epoch_handoff_protocol_objects_root",
    "checkpoint_step_new_first_handoff_sidecar_root",
    "MAX_TRUST_PATH_STEPS = 3", "--self-test-trust-path-mutants",
    "candidate-only, max_hops=3",
):
    if marker not in source:
        raise SystemExit(f"FAIL: independent trust-path checker is missing marker: {marker}")

schema = json.loads(schema_path.read_text(encoding="utf-8"))
corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
if schema.get("status") != "candidate-non-normative" or corpus.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: trust-path schema/corpus must remain candidate-non-normative")
if schema.get("resource_bounds", {}).get("max_steps") != 3:
    raise SystemExit("FAIL: trust-path schema max_steps drift")
if len(corpus.get("positive_cases", [])) != 4:
    raise SystemExit("FAIL: trust-path corpus must contain exact hop 0/1/2/3 positives")
if [case.get("expected", {}).get("hop_count") for case in corpus.get("positive_cases", [])] != [0, 1, 2, 3]:
    raise SystemExit("FAIL: trust-path positive hop inventory drift")
if len(corpus.get("negative_cases", [])) != 63:
    raise SystemExit("FAIL: trust-path corpus must bind all 63 exact-error mutants")
openssl_contract = corpus.get("openssl_cross_check", {})
if (
    openssl_contract.get("three_hop_valid_signatures") != 116
    or openssl_contract.get("breakdown") != {
        "qc_signatures": 88, "tc_signatures": 4, "handoff_signatures": 24,
    }
):
    raise SystemExit("FAIL: trust-path OpenSSL signature inventory drift")
exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
for marker in (
    "v0 activation", "weak subjectivity", "arbitrary-length", "state sync",
    "complete wire", "second implementation", "global light client",
    "normative freeze", "production activation",
):
    if marker not in exclusions:
        raise SystemExit(f"FAIL: trust-path corpus is missing explicit exclusion: {marker}")
PY

PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" \
  --check-trust-path --self-test-trust-path-mutants

command -v openssl >/dev/null 2>&1 || {
  printf 'FAIL: OpenSSL is required for independent Ed25519 cross-checks\n' >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

records="$tmp_dir/records.tsv"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" \
  --emit-trust-path-openssl-records >"$records"
[[ "$(wc -l <"$records" | tr -d ' ')" == 116 ]] || {
  printf 'FAIL: expected 116 trust-path QC/TC/handoff signature records\n' >&2
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
      printf 'FAIL: OpenSSL rejected trust-path signature %d\n' "$count" >&2
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
  printf 'FAIL: OpenSSL accepted mutated trust-path signature\n' >&2
  exit 1
fi

printf 'PASS: OpenSSL independently verified %d/116 trust-path QC/TC/handoff signatures and rejected the mutated control\n' "$count"
