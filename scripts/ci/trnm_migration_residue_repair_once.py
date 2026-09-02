from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(".")
SELF = Path(".github/workflows/trnm-migration-residue-repair-once.yml")
SCRIPT = Path("scripts/ci/trnm_migration_residue_repair_once.py")
LEGACY_BASE = "b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9"
LEGACY_FILES = [
    "trillionnium/crates/trnm-node/src/bin/trnm-chain-cli.rs",
    "trillionnium/crates/trnm-node/src/bin/trnm-chain-node.rs",
    "trillionnium/crates/trnm-node/src/bin/trnm-chain-validator.rs",
    "trillionnium/crates/trnm-node/src/main.rs",
]


def replace_exact(path: Path, old: str, new: str, count: int = 1) -> None:
    text = path.read_text(encoding="utf-8")
    found = text.count(old)
    if found != count:
        raise SystemExit(
            f"{path}: expected {count} exact occurrence(s), found {found}: {old[:120]!r}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


subprocess.run(["git", "checkout", LEGACY_BASE, "--", *LEGACY_FILES], check=True)

deny = Path("deny.toml")
deny_text = deny.read_text(encoding="utf-8")
if "[graph]" not in deny_text:
    deny.write_text(
        '[graph]\ntargets = ["x86_64-unknown-linux-gnu"]\n\n' + deny_text,
        encoding="utf-8",
    )

node_manifest = Path("trillionnium/crates/trnm-node/Cargo.toml")
node_text = node_manifest.read_text(encoding="utf-8")
if "\n[workspace]\n" not in node_text:
    node_text = (
        node_text.rstrip()
        + "\n\n# This legacy package is excluded from the active native workspace. The\n"
        + "# standalone archive workspace exists only for migration-residue\n"
        + "# differential verification and does not re-enter the mainline graph.\n"
        + "[workspace]\nresolver = \"2\"\n"
    )
node_manifest.write_text(node_text, encoding="utf-8")

persistent = Path("trillionnium/scripts/consensus/run_persistent_scale_gate.sh")
replace_exact(
    persistent,
    'BIN="${TRNM_PERSISTENT_SCALE_BIN:-}"\n',
    'BIN="${TRNM_PERSISTENT_SCALE_BIN:-}"\n'
    'MANIFEST="${TRNM_CONSENSUS_APP_MANIFEST:-Cargo.toml}"\n',
)
replace_exact(
    persistent,
    "  cargo build \\\n    --release \\\n    --locked \\\n    -p trnm-consensus-app \\\n    --features scale-gate \\\n    --bin trnm-persistent-scale\n",
    "  cargo build \\\n    --manifest-path \"$MANIFEST\" \\\n    --release \\\n    --locked \\\n    --offline \\\n    --features scale-gate \\\n    --bin trnm-persistent-scale\n",
)

comet = Path(".github/workflows/trnm-cometbft-spike.yml")
replace_exact(
    comet,
    '      - "trillionnium/Cargo.lock"\n',
    '      - "trillionnium/Cargo.lock"\n'
    '      - "trillionnium/crates/trnm-consensus-app/Cargo.lock"\n'
    '      - "trillionnium/crates/trnm-node/Cargo.lock"\n',
    count=2,
)

single_preheat = (
    '            trillionnium/Cargo.toml:trillionnium/Cargo.lock\n'
)
expanded_preheat = (
    '            trillionnium/Cargo.toml:trillionnium/Cargo.lock \\\n'
    '            trillionnium/crates/trnm-consensus-app/Cargo.toml:'
    'trillionnium/crates/trnm-consensus-app/Cargo.lock \\\n'
    '            trillionnium/crates/trnm-node/Cargo.toml:'
    'trillionnium/crates/trnm-node/Cargo.lock\n'
)
replace_exact(comet, single_preheat, expanded_preheat, count=2)

replace_exact(
    comet,
    '      - name: Adapter unit gate\n'
    '        run: cargo test --manifest-path trillionnium/Cargo.toml --locked -p trnm-consensus-app\n',
    '      - name: Adapter unit gate (excluded Comet migration residue)\n'
    '        run: >-\n'
    '          CARGO_TARGET_DIR=${{ github.workspace }}/trillionnium/target\n'
    '          cargo test --manifest-path\n'
    '          trillionnium/crates/trnm-consensus-app/Cargo.toml\n'
    '          --locked --offline\n',
)

replace_exact(
    comet,
    '          cargo run --manifest-path trillionnium/Cargo.toml --locked \\\n'
    '            -p trnm-consensus-app \\\n'
    '            --features scale-gate \\\n',
    '          CARGO_TARGET_DIR="${GITHUB_WORKSPACE}/trillionnium/target" \\\n'
    '          cargo run --manifest-path '
    'trillionnium/crates/trnm-consensus-app/Cargo.toml \\\n'
    '            --locked --offline \\\n'
    '            --features scale-gate \\\n',
)

persistent_marker = (
    '          TRNM_PERSISTENT_SCALE_EVIDENCE_ROOT: '
    '${{ runner.temp }}/trnm-persistent-scale-${{ github.run_id }}-${{ github.run_attempt }}\n'
)
replace_exact(
    comet,
    persistent_marker,
    persistent_marker
    + '          TRNM_CONSENSUS_APP_MANIFEST: crates/trnm-consensus-app/Cargo.toml\n'
    + '          CARGO_TARGET_DIR: ${{ github.workspace }}/trillionnium/target\n',
)

build_step = '''      - name: Build excluded Comet migration-residue fixtures
        run: |
          set -euo pipefail
          CARGO_TARGET_DIR="${GITHUB_WORKSPACE}/trillionnium/target" \
            cargo build --manifest-path trillionnium/crates/trnm-consensus-app/Cargo.toml \
              --locked --offline --bin trnm-cometbft-app
          CARGO_TARGET_DIR="${GITHUB_WORKSPACE}/trillionnium/target" \
            cargo build --manifest-path trillionnium/crates/trnm-node/Cargo.toml \
              --locked --offline --features legacy-harness --bin trnm-chain-cli

'''
replace_exact(
    comet,
    '      - name: Single-node live-process gate\n',
    build_step + '      - name: Single-node live-process gate\n',
)

for step_name in (
    "Single-node live-process gate",
    "Four-validator crash-boundary, safety, and state-sync gate",
    "Six-node validator lifecycle gate",
):
    marker = (
        f"      - name: {step_name}\n"
        "        env:\n"
        "          TRNM_COMETBFT_BIN: /tmp/cometbft\n"
    )
    replace_exact(
        comet,
        marker,
        marker
        + "          TRNM_COMETBFT_APP_BIN: "
        + "${{ github.workspace }}/trillionnium/target/debug/trnm-cometbft-app\n"
        + "          TRNM_COMETBFT_CLI_BIN: "
        + "${{ github.workspace }}/trillionnium/target/debug/trnm-chain-cli\n",
    )

replace_exact(
    comet,
    '      - name: Build partition gate binaries\n'
    '        run: >-\n'
    '          cargo build --manifest-path trillionnium/Cargo.toml --locked\n'
    '          -p trnm-consensus-app --bin trnm-cometbft-app\n'
    '          -p trnm-node --features trnm-node/legacy-harness --bin trnm-chain-cli\n',
    '      - name: Build excluded partition gate binaries\n'
    '        run: |\n'
    '          set -euo pipefail\n'
    '          CARGO_TARGET_DIR="${GITHUB_WORKSPACE}/trillionnium/target" \\\n'
    '            cargo build --manifest-path '
    'trillionnium/crates/trnm-consensus-app/Cargo.toml \\\n'
    '              --locked --offline --bin trnm-cometbft-app\n'
    '          CARGO_TARGET_DIR="${GITHUB_WORKSPACE}/trillionnium/target" \\\n'
    '            cargo build --manifest-path '
    'trillionnium/crates/trnm-node/Cargo.toml \\\n'
    '              --locked --offline --features legacy-harness --bin trnm-chain-cli\n',
)

for path in (deny, node_manifest, Path("trillionnium/crates/trnm-consensus-app/Cargo.toml")):
    with path.open("rb") as handle:
        tomllib.load(handle)

# Cargo.lock is generated and validated by the enclosing workflow after this
# deterministic source transformation.
SELF.unlink()
SCRIPT.unlink()
print("migration_residue_repair=prepared")
