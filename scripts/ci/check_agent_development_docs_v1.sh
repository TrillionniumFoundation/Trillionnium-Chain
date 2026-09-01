#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry point retained for existing workflows. The former
# per-agent prompt/package document fleet has been removed. The canonical plan,
# module registry, release train and snapshot now provide the only active
# development control surface.

root="$(git rev-parse --show-toplevel)"
cd "$root"

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "development truth gate: dirty worktree rejected" >&2
  git status --short >&2
  exit 2
fi

bash scripts/ci/check_canonical_development_plan.sh

python3 - <<'PY'
from pathlib import Path
import json
import tomllib

root = Path('.')
dev = root / 'docs/development'
assert not (dev / 'agents').exists()
assert not (dev / 'packages').exists()
assert not (root / 'docs/archive').exists()
assert len(list(dev.glob('*.md'))) == 2  # one plan plus one symlink alias
assert len([p for p in dev.rglob('*.md') if p.is_file() and not p.is_symlink()]) == 1
assert (dev / 'TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md').is_symlink()

snapshot = json.loads((dev / 'CURRENT_SNAPSHOT_V1.json').read_text())
registry = tomllib.loads((dev / 'module-registry-v1.toml').read_text())
train = tomllib.loads((dev / 'release-train-v1.toml').read_text())
assert snapshot['latest_candidate']['pull_request'] == 58
assert registry['module_count'] == 18
assert train['source']['selected_successor_pull_request'] == 58
assert all(not value for value in (
    snapshot['machine_truth']['production_candidate'],
    snapshot['machine_truth']['production_consensus_activation'],
    train['production_candidate'],
    train['production_consensus_activation'],
    train['public_testnet_ready'],
    train['release_ready'],
))
print('development truth gate: ok; one plan, 18 modules, no legacy development archive')
PY

git diff --check
