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
  docs/development/agents/AGENT_PROMPTS_A00_A02_V1.md
  docs/development/agents/AGENT_PROMPTS_A03_A05_V1.md
  docs/development/agents/AGENT_PROMPTS_A06_A08_V1.md
  docs/development/agents/AGENT_PROMPTS_A09_A11_V1.md
  docs/development/agents/AGENT_PROMPTS_A12_A14_V1.md
  docs/development/agents/AGENT_PROMPTS_A15_A17_V1.md
  docs/development/packages/TRNM_G1_R4_FULL_CLOSURE_DOCUMENTATION_V1.md
  docs/development/packages/TRNM_G15_G5_DOCUMENTATION_COMPLETION_MATRIX_V1.md
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing or empty: $path" >&2; exit 2; }
done

python3 - <<'PY'
import json, pathlib, re
root = pathlib.Path(".")
snap = json.loads((root/"docs/development/CURRENT_SNAPSHOT_V1.json").read_text())
assert snap["schema"] == "trnm-current-snapshot-v1"
assert snap["latest_candidate"]["commit"] == "6e0189e351015ef3230f217ca7ff86149baedcf0"
assert snap["latest_candidate"]["tree"] == "efea864cb2fbc4835a59a089b3dbab8934e71231"
assert snap["machine_truth"]["production_candidate"] is False
assert snap["machine_truth"]["production_consensus_activation"] is False

registry = (root/"docs/development/agents/AGENT_REGISTRY_V1.yaml").read_text()
ids = re.findall(r"(?m)^- id: (A\d\d)$", registry)
assert ids == [f"A{i:02d}" for i in range(18)], ids
assert len(ids) == len(set(ids))

prompt_files = sorted((root/"docs/development/agents").glob("AGENT_PROMPTS_A*_V1.md"))
prompt_text = "\n".join(path.read_text() for path in prompt_files)
for agent_id in ids:
    assert re.search(rf"(?m)^## {agent_id} — ", prompt_text), agent_id
    assert f"prompt_anchor: {agent_id}" in registry, agent_id
for token in [
    "MODULE_CLOSED_CANDIDATE",
    "BLOCKED_UPSTREAM",
    "BASE_DRIFT",
    "STOP_CONDITION",
    "RESUME_REQUIRED",
]:
    assert token in prompt_text, token

for path in root.glob("docs/development/**/*.md"):
    text = path.read_text()
    if re.search(r'(?m)^\s*(production_candidate|production_consensus_activation|release_ready|protocol_activation|node_support|normative_freeze)\s*=\s*true\s*$', text):
        raise SystemExit(f"unscoped promotion-looking truth in {path}")
print("agent development docs gate: ok")
PY

git diff --check
