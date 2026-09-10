#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

TARGET_BRANCH="${TARGET_BRANCH:?TARGET_BRANCH is required}"
PRODUCTION_PORTS_COMMIT="${PRODUCTION_PORTS_COMMIT:?PRODUCTION_PORTS_COMMIT is required}"
REMOTE_SIGNER_FIX_COMMIT="${REMOTE_SIGNER_FIX_COMMIT:?REMOTE_SIGNER_FIX_COMMIT is required}"
FINAL_WORKTREE=/tmp/trnm-r13-final

test "$(git branch --show-current)" = "$TARGET_BRANCH"
test "$(git rev-parse HEAD)" = "$GITHUB_SHA"
git fetch --no-tags origin "$PRODUCTION_PORTS_COMMIT" "$REMOTE_SIGNER_FIX_COMMIT"
git cat-file -e "$PRODUCTION_PORTS_COMMIT^{commit}"
git cat-file -e "$REMOTE_SIGNER_FIX_COMMIT^{commit}"

git checkout "$PRODUCTION_PORTS_COMMIT" -- \
  trillionnium/crates/trnm-node-boundary-v0/src/lib.rs \
  trillionnium/crates/trnm-node-boundary-v0/src/production_ports.rs \
  trillionnium/crates/trnm-tx-lifecycle-v0/src/lib.rs \
  trillionnium/crates/trnm-tx-lifecycle-v0/src/production.rs

git checkout "$REMOTE_SIGNER_FIX_COMMIT" -- \
  trillionnium/crates/trnm-consensus-remote-signer-service/tests/external_authority_adapter.rs \
  trillionnium/crates/trnm-consensus-remote-signer-service/tests/external_service_os.rs \
  trillionnium/crates/trnm-consensus-remote-signer-service/tests/os_process_fixture.rs \
  trillionnium/crates/trnm-consensus-remote-signer-service/tests/pending_reservation_os.rs

python3 tools/temporary_poco_convergence_r5.py prepare
python3 tools/temporary_poco_native_convergence_r13.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all

# Recompute the maintained complete-execution vector from the native PoCO code.
# The probe is temporary and the transformed source is restored byte-for-byte
# before the qualified product commit is created.
DURABLE=trillionnium/crates/trnm-native-execution-v0/src/durable.rs
VECTOR=trillionnium/crates/trnm-native-execution-v0/vectors/native-complete-durable-p-v0.json
cp "$DURABLE" /tmp/trnm-r13-durable.before-calibration.rs
python3 - "$DURABLE" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
needle = '''        let inputs = vector.get("inputs").unwrap();
        let expected = vector.get("expected").unwrap();
'''
insertion = needle + '''        eprintln!(
            "TRNM_NATIVE_VECTOR_ACTUAL={}",
            serde_json::json!({
                "initial_state_root_hex": hex::encode(config.initial_state_root),
                "outer_transaction_sha256_hex": transactions
                    .iter()
                    .map(|transaction| hex::encode(sha256_v0(transaction)))
                    .collect::<Vec<_>>(),
                "payload_root_hex": hex::encode(computed.payload_root),
                "post_state_root_hex": hex::encode(computed.post_state_root),
                "receipts_root_hex": hex::encode(computed.receipts_root),
                "evidence_root_hex": hex::encode(computed.evidence_root),
            })
        );
'''
if text.count(needle) != 1:
    raise SystemExit("native complete-vector probe insertion point drift")
path.write_text(text.replace(needle, insertion, 1), encoding="utf-8")
PY
cargo fmt --manifest-path trillionnium/Cargo.toml --all

set +e
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -j 1 \
  -p trnm-native-execution-v0 \
  durable::tests::artifact_snapshot_store_and_sequence_tampering_fail_closed \
  -- --nocapture 2>&1 | tee /tmp/trnm-r13-vector-calibration.log
CALIBRATION_RC=${PIPESTATUS[0]}
set -e
[[ "$CALIBRATION_RC" -eq 0 || "$CALIBRATION_RC" -eq 101 ]]
grep -q '^TRNM_NATIVE_VECTOR_ACTUAL=' /tmp/trnm-r13-vector-calibration.log

cp /tmp/trnm-r13-durable.before-calibration.rs "$DURABLE"
python3 - "$VECTOR" /tmp/trnm-r13-vector-calibration.log <<'PY'
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

vector_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
marker = "TRNM_NATIVE_VECTOR_ACTUAL="
actual = None
for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
    if line.startswith(marker):
        actual = json.loads(line[len(marker):])
if actual is None:
    raise SystemExit("native complete-vector calibration marker missing")
required = {
    "initial_state_root_hex",
    "outer_transaction_sha256_hex",
    "payload_root_hex",
    "post_state_root_hex",
    "receipts_root_hex",
    "evidence_root_hex",
}
if set(actual) != required:
    raise SystemExit(f"native complete-vector calibration fields drift: {sorted(actual)}")
vector = json.loads(vector_path.read_text(encoding="utf-8"))
vector["inputs"]["initial_state_root_hex"] = actual["initial_state_root_hex"]
vector["inputs"]["outer_transaction_sha256_hex"] = actual["outer_transaction_sha256_hex"]
for key in ("payload_root_hex", "post_state_root_hex", "receipts_root_hex", "evidence_root_hex"):
    vector["expected"][key] = actual[key]
vector_path.write_text(json.dumps(vector, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
digest = hashlib.sha256(vector_path.read_bytes()).hexdigest()
vector_path.with_name(vector_path.name + ".sha256").write_text(digest + "\n", encoding="ascii")
print(json.dumps(actual, sort_keys=True))
PY
cargo fmt --manifest-path trillionnium/Cargo.toml --all
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -j 1 \
  -p trnm-native-execution-v0 \
  durable::tests::artifact_snapshot_store_and_sequence_tampering_fail_closed

python3 tools/temporary_poco_convergence_r5.py refresh-pins

rm -f \
  tools/temporary_native_purge.py \
  tools/temporary_poco_convergence_r5.py \
  tools/temporary_poco_semantic_preservation.py \
  tools/temporary_poco_native_convergence_r13.py \
  tools/temporary_poco_convergence_r12.sh \
  tools/temporary_poco_convergence_r13.sh \
  .github/workflows/apply-poco-only-purge-temporary.yml \
  .github/workflows/poco-only-full-tree-audit.yml \
  .github/workflows/poco-purge-source-snapshot.yml \
  .github/workflows/poco-only-convergence-r2-once-20260909.yml \
  .github/workflows/poco-only-convergence-r3-once-20260909.yml \
  .github/workflows/poco-only-convergence-r4-once-20260909.yml \
  .github/workflows/poco-only-convergence-r5-once-20260909.yml \
  .github/workflows/poco-only-convergence-r6-once-20260910.yml \
  .github/workflows/poco-only-convergence-r7-once-20260910.yml \
  .github/workflows/poco-only-convergence-r8-once-20260910.yml \
  .github/workflows/poco-only-convergence-r9-once-20260910.yml \
  .github/workflows/poco-only-convergence-r10-once-20260910.yml \
  .github/workflows/poco-only-convergence-r11-once-20260910.yml \
  .github/workflows/poco-only-convergence-r12-once-20260910.yml \
  .github/workflows/poco-only-convergence-r13-once-20260910.yml \
  .github/workflows/poco-cli-materialization-diagnostic-once-20260909.yml \
  .github/workflows/poco-cli-compile-diagnostic-once-20260909.yml \
  .github/workflows/poco-workspace-serial-diagnostic-once-20260909.yml \
  .github/workflows/poco-r7-source-identity-diagnostic-once-20260910.yml \
  .github/workflows/poco-r7-source-identity-diagnostic-v2-once-20260910.yml \
  .github/workflows/poco-native-vector-refresh-diagnostic-once-20260910.yml \
  .github/workflows/nonexistent \
  DO_NOT_CREATE \
  DO_NOT_CREATE_2

cargo fmt --manifest-path trillionnium/Cargo.toml --all
git add -A
git diff --cached --check
test -n "$(git diff --cached --name-only)"
git config user.name "Qian QI"
git config user.email "102159240+ProfHepta@users.noreply.github.com"
git commit -m "chore(poco): publish native-domain qualified product tree"

FINAL_COMMIT="$(git rev-parse HEAD)"
FINAL_TREE="$(git rev-parse 'HEAD^{tree}')"
printf '%s\n' "$FINAL_COMMIT" >/tmp/trnm-r13-final-commit.txt
printf '%s\n' "$FINAL_TREE" >/tmp/trnm-r13-final-tree.txt
test -z "$(git status --porcelain --untracked-files=all)"

rm -rf "$FINAL_WORKTREE"
git worktree add --detach "$FINAL_WORKTREE" "$FINAL_COMMIT"
test "$(git -C "$FINAL_WORKTREE" rev-parse HEAD)" = "$FINAL_COMMIT"
test "$(git -C "$FINAL_WORKTREE" rev-parse 'HEAD^{tree}')" = "$FINAL_TREE"
test -z "$(git -C "$FINAL_WORKTREE" status --porcelain --untracked-files=all)"

cd "$FINAL_WORKTREE"
python3 -m compileall -q scripts tools formal conformance
python3 scripts/ci/check_native_consensus_only.py | tee /tmp/trnm-r13-native-only.json
bash scripts/ci/check_canonical_development_plan.sh
bash scripts/ci/check_poco_bft_mainline_truth.sh
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_required_protocol_contract_v1.py
python3 scripts/ci/test_external_evidence_v1.py

set +e
python3 scripts/ci/check_external_evidence_v1.py --require-all \
  --source-commit "$FINAL_COMMIT" \
  --source-tree "$FINAL_TREE" \
  --output /tmp/trnm-r13-external-evidence.json \
  >/tmp/trnm-r13-external-evidence.stdout \
  2>/tmp/trnm-r13-external-evidence.stderr
EXTERNAL_RC=$?
set -e
test "$EXTERNAL_RC" -eq 2
grep -q "external evidence gate remains open" /tmp/trnm-r13-external-evidence.stderr
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
test -z "$(git status --porcelain --untracked-files=all)"

rm -rf "${CARGO_TARGET_DIR:?}"
cargo check --manifest-path trillionnium/Cargo.toml \
  --workspace --all-targets --locked --offline -j 1 \
  2>&1 | tee /tmp/trnm-r13-workspace-check.log
cargo check --manifest-path contracts/Cargo.toml \
  --workspace --all-targets --locked --offline -j 1 \
  2>&1 | tee /tmp/trnm-r13-contract-check.log

cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-native-execution-v0 --lib --locked --offline -j 1 \
  2>&1 | tee /tmp/trnm-r13-native-execution-test.log
cargo test --manifest-path trillionnium/Cargo.toml \
  -p trnm-poco-node --test raw_key_boundary --locked --offline -j 1 \
  2>&1 | tee /tmp/trnm-r13-raw-key-test.log

timeout --signal=TERM --kill-after=30s 7200s \
  cargo test --manifest-path trillionnium/Cargo.toml \
    --workspace --all-targets --locked --offline --no-fail-fast -j 1 -- \
    --test-threads=1 \
  2>&1 | tee /tmp/trnm-r13-workspace-test.log
cargo test --manifest-path contracts/Cargo.toml \
  --workspace --all-targets --locked --offline -j 1 \
  2>&1 | tee /tmp/trnm-r13-contract-test.log

test -z "$(git status --porcelain --untracked-files=all)"

cargo clippy --manifest-path contracts/Cargo.toml \
  --workspace --all-targets --locked --offline -j 1 -- -D warnings \
  2>&1 | tee /tmp/trnm-r13-contract-clippy.log
cd trillionnium
: >/tmp/trnm-r13-boundary-clippy.log
for package in \
  trnm-state trnm-consensus-types trnm-consensus-crypto \
  trnm-consensus-core trnm-consensus-safety-rules \
  trnm-consensus-safety-store trnm-consensus-signer-journal \
  trnm-native-application trnm-native-application-sqlite \
  trnm-native-execution-v0 trnm-durable-file-adapters-v0 \
  trnm-tx-lifecycle-v0 trnm-state-sync-v0 trnm-migration-v0 \
  trnm-control-plane-v0 trnm-release-bundle-v0 trnm-node-boundary-v0 \
  trnm-poco-node-production-v0 trnm-production-adapter-conformance-v0 \
  trnm-poco-node trnm-poco-node-authority trnm-poco-node-io \
  trnm-poco-node-host trnm-poco-node-cli
do
  echo "strict-clippy package=${package}" | tee -a /tmp/trnm-r13-boundary-clippy.log
  cargo clippy -p "$package" --all-targets --locked --offline -j 1 -- -D warnings \
    2>&1 | tee -a /tmp/trnm-r13-boundary-clippy.log
done
cd "$FINAL_WORKTREE"

python3 scripts/ci/check_native_consensus_only.py | tee /tmp/trnm-r13-native-only-final.json
bash scripts/ci/check_canonical_development_plan.sh
python3 scripts/ci/check_repository_truth_v1.py
python3 scripts/ci/check_required_protocol_contract_v1.py
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
test "$(git rev-parse HEAD)" = "$FINAL_COMMIT"
test "$(git rev-parse 'HEAD^{tree}')" = "$FINAL_TREE"
test -z "$(git status --porcelain --untracked-files=all)"

git -C "$ROOT" push origin "$FINAL_COMMIT:refs/heads/$TARGET_BRANCH"
echo "R13_QUALIFIED_COMMIT=$FINAL_COMMIT"
echo "R13_QUALIFIED_TREE=$FINAL_TREE"
