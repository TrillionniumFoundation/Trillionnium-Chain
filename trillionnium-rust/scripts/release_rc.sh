#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"

TS="$(date +%Y%m%d-%H%M%S)"
OUT="release/rc-$TS"
mkdir -p "$OUT"

echo "[rc] output=$OUT"

cargo test --workspace | tee "$OUT/cargo-test.log"
cargo build --workspace | tee "$OUT/cargo-build.log"

cat > "$OUT/manifest.txt" <<EOF
release_id=rc-$TS
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
workspace=$ROOT
EOF

cp -f configs/node1.toml "$OUT/" || true
cp -f configs/node2.toml "$OUT/" || true
cp -f configs/node3.toml "$OUT/" || true

printf '[rc] done\n[rc] manifest=%s\n' "$OUT/manifest.txt"
