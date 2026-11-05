# Reproduce the grouped research observation at e0fc4df

This recipe fixes the published source to
[`e0fc4df37bed96050db2a07d91d427829921e5fa`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/e0fc4df37bed96050db2a07d91d427829921e5fa)
and reconstructs the original public corpus/model from source commit
`ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155`. It uses the retained
[model producer](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e0fc4df37bed96050db2a07d91d427829921e5fa/formal/pon-nakamoto-v1/experiments/model_loop.py)
and [grouped runner](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e0fc4df37bed96050db2a07d91d427829921e5fa/formal/pon-nakamoto-v1/experiments/grouped_cell_operator_v0.py).

Reconstruction re-executes the existing deterministic parameter-optimization
recipe solely to recover the frozen bytes. It is **not a new candidate, a new
adoption decision, or independent future evaluation**. All three file hashes
below must match before benchmarking. A mismatch stops the recipe; retain that
failure and do not substitute another hash or candidate.

## 1. Exact checkout and environment

Use a Linux/POSIX host with Bash, Git, Python 3.12, `venv`/`pip`, rustup and the
usual native C build tools. The recorded Python version was 3.12.14. Run the
blocks in the same Bash shell. The fresh clone uses a named local development
branch because the normal project preflight rejects detached/protected branches.
Generated inputs, logs, the Python environment and build output remain outside
the clone. These commands do not modify an existing checkout or publish files.

```bash
set -euo pipefail
TRNM_REPRO_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pon-grouped-e0fc4df.XXXXXX")"
TRNM_PUBLISHED_SOURCE=e0fc4df37bed96050db2a07d91d427829921e5fa
TRNM_ARTIFACT_SOURCE=ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155
TRNM_FROZEN_BUNDLE_ID=0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5

git clone --no-checkout \
  https://github.com/TrillionniumFoundation/Trillionnium-Chain.git \
  "$TRNM_REPRO_ROOT/chain"
cd "$TRNM_REPRO_ROOT/chain"
git fetch origin "$TRNM_PUBLISHED_SOURCE" "$TRNM_ARTIFACT_SOURCE"
git switch --create test/chain-grouped-e0fc4df-reproduce "$TRNM_PUBLISHED_SOURCE"
test "$(git rev-parse HEAD)" = "$TRNM_PUBLISHED_SOURCE"
git cat-file -e "${TRNM_ARTIFACT_SOURCE}^{commit}"

python3.12 -m venv "$TRNM_REPRO_ROOT/python-env"
source "$TRNM_REPRO_ROOT/python-env/bin/activate"
export OPENBLAS_NUM_THREADS=1
export OMP_NUM_THREADS=1
export RUST_TEST_THREADS=1
export CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR="$TRNM_REPRO_ROOT/cargo-target"
python -m pip install -r formal/pon-nakamoto-v1/requirements.txt
python - <<'PY'
import importlib.metadata
for package, expected in [('numpy', '1.26.4'), ('cryptography', '50.0.2')]:
    observed = importlib.metadata.version(package)
    if observed != expected:
        raise SystemExit(f'REQUIREMENT_MISMATCH: {package}: {observed}')
    print(package, observed)
PY
rustup toolchain install 1.95.0 --profile minimal --component clippy --component rustfmt
export RUSTUP_TOOLCHAIN=1.95.0
bash scripts/project-preflight.sh
rustc --version --verbose
cargo --version
```

Rust 1.95.0 is pinned by
[`rust-toolchain.toml`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e0fc4df37bed96050db2a07d91d427829921e5fa/rust-toolchain.toml);
NumPy 1.26.4 and cryptography 50.0.2 are pinned in the
[scientific requirements](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/e0fc4df37bed96050db2a07d91d427829921e5fa/formal/pon-nakamoto-v1/requirements.txt).

## 2. Reconstruct and reject any different frozen inputs

The producer requires a new output directory; do not create `frozen-model-inputs`
in advance. Its other outputs and reconstruction log stay alongside the three
inputs rather than being committed to Git.

```bash
TRNM_INPUTS="$TRNM_REPRO_ROOT/frozen-model-inputs"
python formal/pon-nakamoto-v1/experiments/model_loop.py \
  --mode run \
  --source "$TRNM_ARTIFACT_SOURCE" \
  --out "$TRNM_INPUTS" \
  > "$TRNM_REPRO_ROOT/reconstruct-model.log" 2>&1

PYTHONPATH=formal/pon-nakamoto-v1 python - "$TRNM_INPUTS" <<'PY'
import hashlib
import sys
from pathlib import Path
from evaluation_bundle import verify_bundle
from model_contract import load_model

root = Path(sys.argv[1])
expected_sha256 = {
    'model.json': '755e512410cfa6a1f463c48f6bfe5da240908258483be150c7ac2f1fe1249afd',
    'consumer.json': 'f93722be0d3b0baaf3cc3bf92a3a6d5dc5600e814c3aa2fa6d51c4cdfad57f10',
    'evaluation-bundle.json': 'ace2fbf9bdbbd4ca4c9b17bff338487687ef09ba5d97aee9853412953d602e3a',
}
for name, expected in expected_sha256.items():
    observed = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if observed != expected:
        raise SystemExit(f'FROZEN_INPUT_SHA256_MISMATCH: {name}: {observed}')
    print(name, observed)
bundle_id = '0308341b06b152167da48dc706ee82b7e691aa9ebb2c4d2d7d5cd6a55d12acd5'
model_id = '16443887511f5ffbcdf611ce3ca6b6811bc699aad649961fce5a83c168534671'
bundle = verify_bundle((root / 'evaluation-bundle.json').read_bytes(), bundle_id)
if (bundle['candidate_artifact'] != model_id or
        bundle['source_commit'] != 'ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155'):
    raise SystemExit('FROZEN_MODEL_OR_SOURCE_MISMATCH')
load_model(root / 'model.json', bytes.fromhex(model_id))
print('Frozen input bytes and protocol identities verified.')
PY
```

The model artifact ID and evaluation-bundle ID are domain-separated protocol
hashes. They are intentionally different from the plain file SHA-256 values.
The benchmark's `--bundle-hash` argument uses the fixed bundle ID above.

## 3. Build and verify the retained controls

```bash
bash scripts/project-preflight.sh
cargo build --locked --release --jobs 2 \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_routed_int257_grouped
export TRNM_GROUPED_NATIVE="$CARGO_TARGET_DIR/release/examples/pon_routed_int257_grouped"
test -x "$TRNM_GROUPED_NATIVE"

python -m unittest discover -s formal/pon-nakamoto-v1 \
  -p 'test_grouped*.py' -v
python -m unittest discover -s formal/pon-nakamoto-v1 \
  -p 'test_shared_cell_operator_v1.py' -v

bash scripts/project-preflight.sh
cargo test --locked --release --jobs 2 \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --all-targets
```

The grouped suite has 32 tests, including actual native differential and hostile
transport tests when `TRNM_GROUPED_NATIVE` is set. An unset variable produces
explicit skips and does not constitute native integration validation. The
retained W1 consumer suite has nine tests; the native all-targets command retains
the existing cryptographic/W1 tests as well as the new research tests.

## 3b. Reproduce the remaining recorded validation gates

```bash
cargo clippy --locked --release --jobs 2 \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --all-targets -- -D warnings
cargo fmt --all --manifest-path trillionnium/Cargo.toml --check
python scripts/ci/test_ci_source_integrity.py
python scripts/ci/test_pq_research_integration.py
python scripts/ci/test_ci_contract.py
python scripts/ci/check_pq_research_integration.py
python scripts/refresh_distributed_source_inventory.py --check
python scripts/ci/check_repository.py
cargo metadata --locked --offline --format-version 1 \
  --manifest-path trillionnium/Cargo.toml > "$TRNM_REPRO_ROOT/cargo-metadata.json"
python scripts/ci/verify_ci_source.py --kind head \
  --expected-head "$TRNM_PUBLISHED_SOURCE" \
  --output "$TRNM_REPRO_ROOT/source-identity.json"
git diff --check
```

Source registration can pass its consistency checks while its printed
qualification status remains `HOLD_NO_GO`. Do not change qualification flags to
make the status look like acceptance. These commands match the scope recorded in
[validation.json](validation.json), without claiming full-workspace execution.

## 4. One predeclared 120-sample / 12-warmup observation

Run once after the preceding checks. Use the same consumer offset and batch sizes;
keep every successful, failed and negative observation. The runner creates the
new output directory itself and records source, binary, input and wire identities.

```bash
test "$(git rev-parse HEAD)" = "$TRNM_PUBLISHED_SOURCE"
test -z "$(git status --porcelain --untracked-files=normal)"
TRNM_OBSERVATION="$TRNM_REPRO_ROOT/grouped-e0fc4df-120x12"
python formal/pon-nakamoto-v1/experiments/grouped_cell_operator_v0.py \
  --model "$TRNM_INPUTS/model.json" \
  --tasks "$TRNM_INPUTS/consumer.json" \
  --evaluation-bundle "$TRNM_INPUTS/evaluation-bundle.json" \
  --bundle-hash "$TRNM_FROZEN_BUNDLE_ID" \
  --partition consumer --offset 0 --batch-sizes 1,4,16,64 \
  --samples 120 --warmup 12 --timeout 60 --replay-source \
  --runner "$TRNM_GROUPED_NATIVE" \
  --out "$TRNM_OBSERVATION"
```

Read `report.json` together with `native-input.ndjson`, `native-stdout.ndjson` and
`native-stderr.txt`; retain `failure.json` and any partial output when a run fails.
No generated model, raw input, raw output or benchmark material belongs in a Git
commit. Earlier `d95f8c5` observations remain earlier observations rather than
being replaced or relabelled as measurements of the published composition.

Timings depend on the host, runtime and contention. Compare the three disclosed
hot implementation scopes separately from the single full selected producer and
the complete process exchange. Packed grouped includes its internal phase-clock
probes, while ordinary/direct do not. The selected producer includes fresh batch
validation/input commitment, execution, statement commitment and full independent
verification; it still excludes model setup and transport.

There is no real arrival trace. Queue/deadline statistics remain `null`, the
logical fixture interval does not establish service utility, and repeated
samples do not create new demand. Arithmetic agreement and local timings leave
PoUW qualification, production activation, adoption changes and model rewards
closed. They do not revise the earlier `not_adopted` / zero-model-reward result.

## 5. Separate later compatibility receipt

The main recipe deliberately retains the measured `e0fc4df` source. To reproduce
[the later compatibility checks](composition-validation.json), start another
fresh checkout rooted at `32c3d63c907d0060a5b02cd678c74b01e54ec0f9`, set
`TRNM_PUBLISHED_SOURCE` to that full commit, and follow the environment/build/test
commands in sections 1, 3 and 3b. Use a distinct local branch and output directory.
The recorded later check did not rebuild the frozen corpus or perform section 4.
It has its own binary and expanded inherited test counts; it does not move the
performance measurements to the later source.
