set -euo pipefail
rustc --version
rustc --edition=2021 -O hia/tests/rust_reference.rs -o "$RUNNER_TEMP/trnm-hia-rust-reference"
rustc --edition=2021 --test hia/tests/rust_reference.rs -o "$RUNNER_TEMP/trnm-rust-original-tests"
"$RUNNER_TEMP/trnm-rust-original-tests"
cargo build --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol -p trnm-checkpoint-types -p trnm-crypto-primitives -p trnm-mvcc-fee -p trnm-types -p trnm-research-protocol --target-dir "$RUNNER_TEMP/original-rust-values" --message-format=json | tee "$RUNNER_TEMP/original-rust-build.jsonl"
python3 - "$RUNNER_TEMP/original-rust-build.jsonl" "$RUNNER_TEMP" <<'PYCODE'
import json, os, pathlib, subprocess, sys
events = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if line.startswith('{')]
serde = [row for row in events if row.get('reason') == 'compiler-artifact' and row['target']['name'] == 'serde_json']
if len(serde) != 1:
    raise SystemExit('one actual locked serde_json artifact required')
if not serde[0]['package_id'].endswith('serde_json@1.0.149'):
    raise SystemExit('unexpected serde_json package_id: ' + serde[0]['package_id'])
if set(serde[0]['features']) != {'default', 'std'}:
    raise SystemExit('unexpected serde_json features: ' + repr(serde[0]['features']))
rlibs = [name for name in serde[0]['filenames'] if name.endswith('.rlib')]
if len(rlibs) != 1:
    raise SystemExit('one original serde_json rlib required')
sha2 = [row for row in events if row.get('reason') == 'compiler-artifact'
        and row['target']['name'] == 'sha2' and row['package_id'].endswith('sha2@0.10.9')]
if len(sha2) != 1:
    raise SystemExit('one locked sha2 0.10.9 artifact required for the original control-plane crate')
sha2_rlibs = [name for name in sha2[0]['filenames'] if name.endswith('.rlib')]
if len(sha2_rlibs) != 1:
    raise SystemExit('one original sha2 rlib required')
types = [row for row in events if row.get('reason') == 'compiler-artifact'
         and row['target']['name'] == 'trnm_types']
if len(types) != 1 or types[0]['features'] != []:
    raise SystemExit('one unchanged original trnm-types dependency profile required')
types_rlibs = [name for name in types[0]['filenames'] if name.endswith('.rlib')]
if len(types_rlibs) != 1:
    raise SystemExit('one original trnm-types rlib required')
with open(os.environ['GITHUB_ENV'], 'a') as out:
    out.write('HIA_CONTROL_PLANE_SHA2=' + sha2_rlibs[0] + '\n')
    out.write('TRNM_HIA_RUST_TYPES_RLIB=' + types_rlibs[0] + '\n')
target = pathlib.Path(sys.argv[2]) / 'original-rust-values/debug'
subprocess.run(['rustc', '--edition=2021', '-O', 'hia/tests/rust_state_reference.rs', '--extern', 'trnm_mvcc_fee=' + str(target / 'libtrnm_mvcc_fee.rlib'), '--extern', 'serde_json=' + rlibs[0], '-L', 'dependency=' + str(target / 'deps'), '-o', str(pathlib.Path(sys.argv[2]) / 'trnm-rust-state')], check=True)
PYCODE
rustc --edition=2021 -O hia/tests/rust_protocol_reference.rs --extern trnm_protocol="$RUNNER_TEMP/original-rust-values/debug/libtrnm_protocol.rlib" -L dependency="$RUNNER_TEMP/original-rust-values/debug/deps" -o "$RUNNER_TEMP/trnm-rust-protocol"
rustc --edition=2021 -O hia/tests/rust_checkpoint_reference.rs --extern trnm_checkpoint_types="$RUNNER_TEMP/original-rust-values/debug/libtrnm_checkpoint_types.rlib" -L dependency="$RUNNER_TEMP/original-rust-values/debug/deps" -o "$RUNNER_TEMP/trnm-rust-checkpoint"
rustc --edition=2021 -O hia/tests/rust_crypto_reference.rs --extern trnm_crypto_primitives="$RUNNER_TEMP/original-rust-values/debug/libtrnm_crypto_primitives.rlib" -L dependency="$RUNNER_TEMP/original-rust-values/debug/deps" -o "$RUNNER_TEMP/trnm-rust-crypto"
printf 'TRNM_HIA_RUST_REFERENCE=%s/trnm-hia-rust-reference\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
printf 'TRNM_HIA_RUST_PROTOCOL_REFERENCE=%s/trnm-rust-protocol\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
printf 'TRNM_HIA_RUST_CHECKPOINT_REFERENCE=%s/trnm-rust-checkpoint\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
printf 'TRNM_HIA_RUST_CRYPTO_REFERENCE=%s/trnm-rust-crypto\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
printf 'TRNM_HIA_RUST_STATE_REFERENCE=%s/trnm-rust-state\n' "$RUNNER_TEMP" >> "$GITHUB_ENV"
