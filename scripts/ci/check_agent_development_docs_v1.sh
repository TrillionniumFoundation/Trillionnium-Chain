#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

required=(
  docs/development/CURRENT_SNAPSHOT_V1.json
  docs/development/TRNM_DEVELOPMENT_DOCUMENTATION_UPGRADE_V1.md
  docs/development/agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md
  docs/development/agents/AGENT_REGISTRY_V1.yaml
  docs/development/agents/AGENT_PROMPT_PACK_V1.md
  docs/development/packages/TRNM_G1_R4_FULL_CLOSURE_DOCUMENTATION_V1.md
  docs/development/packages/TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing or empty: $path" >&2; exit 2; }
done

python3 - <<'PY'
import json, pathlib, re
try:
    import yaml
except ImportError as exc:
    raise SystemExit(f"PyYAML required by documentation gate: {exc}")
root = pathlib.Path(".")
snap = json.loads((root/"docs/development/CURRENT_SNAPSHOT_V1.json").read_text())
assert snap["schema"] == "trnm-current-snapshot-v1"
registry = yaml.safe_load((root/"docs/development/agents/AGENT_REGISTRY_V1.yaml").read_text())
agents = registry["agents"]
assert len(agents) == 18
ids = [a["id"] for a in agents]
assert len(ids) == len(set(ids))
pack = (root/"docs/development/agents/AGENT_PROMPT_PACK_V1.md").read_text()
for agent_id in ids:
    assert f"# {agent_id} " in pack or f"# {agent_id} —" in pack, agent_id
for path in root.glob("docs/development/**/*.md"):
    text = path.read_text()
    if re.search(r'(?m)^\s*(production_candidate|production_consensus_activation|release_ready|protocol_activation|node_support|normative_freeze)\s*=\s*true\s*$', text):
        raise SystemExit(f"unscoped promotion-looking truth in {path}")
print("agent development docs gate: ok")
PY

git diff --check
