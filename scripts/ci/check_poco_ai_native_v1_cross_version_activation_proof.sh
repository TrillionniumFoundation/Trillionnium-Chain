#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
CHECKER="$ROOT/scripts/ci/check_poco_ai_native_v1_cross_version_activation_proof.py"
SCHEMA="$ROOT/docs/protocol/poco-ai-native-v1/schema/cev1-cross-version-activation-proof-kernel-v1.json"
CORPUS="$ROOT/docs/protocol/poco-ai-native-v1/vectors/cev1-cross-version-activation-proof-kernel-v1.json"

for required in "$CHECKER" "$SCHEMA" "$CORPUS"; do
  if [[ ! -f "$required" ]]; then
    printf 'FAIL: missing bounded cross-version activation-proof evidence file: %s\n' "$required" >&2
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
    "__future__", "argparse", "copy", "hashlib", "importlib", "json",
    "pathlib", "struct", "sys", "typing",
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
            f"FAIL: cross-version activation checker imports unexpected modules: {sorted(unexpected)}"
        )

for forbidden in (
    "trnm_poco", "trnm-native", "nacl", "cryptography", "subprocess",
    "admitted_by_frozen_v0_verifier=true",
):
    if forbidden in source:
        raise SystemExit(
            f"FAIL: cross-version activation checker contains forbidden dependency/trust marker: {forbidden}"
        )

for marker in (
    "dec_v0_plan", "enc_v0_plan", "digest_v0",
    "frozen_v0_field13_present", "frozen_v0_field14_present",
    "ed25519_verify", "PROPOSAL_SIGNATURE_DOMAIN", "VOTE_DOMAIN",
    "verify_activation_proof", "source_upgrade_plan_hash", "three-chain=true",
    "complete_v0_authority_verification", "complete_migration_verification",
):
    if marker not in source:
        raise SystemExit(
            f"FAIL: cross-version activation checker is missing marker: {marker}"
        )

schema = json.loads(schema_path.read_text(encoding="utf-8"))
corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
if schema.get("status") != "candidate-non-normative" or corpus.get("status") != "candidate-non-normative":
    raise SystemExit("FAIL: cross-version activation schema/corpus must remain candidate-non-normative")
if schema.get("frozen_v0_field_policy") != {
    "field_12": "exact-raw-CEV0-required",
    "field_13": "forbidden-for-v0-to-v1",
    "field_14": "forbidden-for-v0-to-v1",
}:
    raise SystemExit("FAIL: frozen-v0 cross-version field policy drift")
if len(corpus.get("positive_cases", [])) != 1 or len(corpus.get("negative_cases", [])) != 44:
    raise SystemExit("FAIL: cross-version activation proof vector inventory drift")
completion = schema.get("global_completion_flags", {})
if completion != {
    "complete_v0_authority_verification": False,
    "complete_migration_verification": False,
    "upgrade_contract_complete": False,
    "normative_freeze": False,
}:
    raise SystemExit("FAIL: cross-version activation completion flags drift")
exclusions = " ".join(corpus.get("explicit_exclusions", [])).lower()
for marker in (
    "governance-state membership", "migration execution", "full orderproposalv1",
    "signer durability", "production", "normative freeze",
):
    if marker not in exclusions:
        raise SystemExit(
            f"FAIL: cross-version activation corpus is missing explicit exclusion: {marker}"
        )
PY

# Re-run the source activation kernel first so this carrier cannot replace or
# bypass its frozen-v0 fields-1-through-11, NoFallback, boundary, and dual-
# quorum checks.
bash "$ROOT/scripts/ci/check_poco_ai_native_v1_upgrade_kernel.sh"
PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER"

command -v openssl >/dev/null 2>&1 || {
  printf 'FAIL: OpenSSL is required for independent activation signature cross-checks\n' >&2
  exit 1
}
command -v xxd >/dev/null 2>&1 || {
  printf 'FAIL: xxd is required for independent activation signature cross-checks\n' >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
manifest="$tmp_dir/openssl-manifest.json"
records="$tmp_dir/records.tsv"
invalid="$tmp_dir/invalid.tsv"

PYTHONDONTWRITEBYTECODE=1 python3 -B "$CHECKER" --emit-openssl-manifest "$manifest" >/dev/null
python3 -B - "$manifest" "$records" "$invalid" <<'PY'
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
valid = manifest.get("valid")
invalid = manifest.get("invalid")
if not isinstance(valid, list) or len(valid) != 13:
    raise SystemExit("FAIL: expected one proposer plus twelve QC signatures")
required = {"label", "public_key", "message", "signature"}
if any(set(record) != required for record in valid):
    raise SystemExit("FAIL: valid OpenSSL record shape drift")
if not isinstance(invalid, dict) or set(invalid) != required:
    raise SystemExit("FAIL: invalid OpenSSL record shape drift")
Path(sys.argv[2]).write_text(
    "".join(
        f'{record["label"]}\t{record["public_key"]}\t{record["message"]}\t{record["signature"]}\n'
        for record in valid
    ),
    encoding="ascii",
)
Path(sys.argv[3]).write_text(
    f'{invalid["label"]}\t{invalid["public_key"]}\t{invalid["message"]}\t{invalid["signature"]}\n',
    encoding="ascii",
)
PY

verify_record() {
  local label="$1"
  local public_hex="$2"
  local message_hex="$3"
  local signature_hex="$4"
  printf '302a300506032b6570032100%s' "$public_hex" | xxd -r -p >"$tmp_dir/public.der"
  printf '%s' "$message_hex" | xxd -r -p >"$tmp_dir/message.raw"
  printf '%s' "$signature_hex" | xxd -r -p >"$tmp_dir/signature.raw"
  openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp_dir/public.der" -rawin \
    -in "$tmp_dir/message.raw" -sigfile "$tmp_dir/signature.raw" >/dev/null 2>&1 || {
      printf 'FAIL: OpenSSL rejected cross-version activation signature: %s\n' "$label" >&2
      return 1
    }
}

count=0
while IFS=$'\t' read -r label public_hex message_hex signature_hex; do
  verify_record "$label" "$public_hex" "$message_hex" "$signature_hex"
  count=$((count + 1))
done <"$records"
[[ "$count" == 13 ]] || {
  printf 'FAIL: OpenSSL activation signature count drift: %d\n' "$count" >&2
  exit 1
}

IFS=$'\t' read -r label public_hex message_hex signature_hex <"$invalid"
printf '302a300506032b6570032100%s' "$public_hex" | xxd -r -p >"$tmp_dir/public.der"
printf '%s' "$message_hex" | xxd -r -p >"$tmp_dir/message.raw"
printf '%s' "$signature_hex" | xxd -r -p >"$tmp_dir/signature.raw"
if openssl pkeyutl -verify -pubin -keyform DER -inkey "$tmp_dir/public.der" -rawin \
  -in "$tmp_dir/message.raw" -sigfile "$tmp_dir/signature.raw" >/dev/null 2>&1; then
  printf 'FAIL: OpenSSL accepted mutated cross-version activation signature: %s\n' "$label" >&2
  exit 1
fi

printf 'PASS: OpenSSL independently verified %d/13 activation proposer/QC signatures and rejected the mutated control\n' "$count"
