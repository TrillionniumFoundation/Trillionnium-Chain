#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

required=(
  docs/development/CURRENT_SNAPSHOT_V1.json
  docs/schemas/current-snapshot-v1.schema.json
  docs/schemas/agent-handoff-v1.schema.json
  docs/development/TRNM_DEVELOPMENT_DOCUMENTATION_UPGRADE_V1.md
  docs/development/AGENT_WORK_PACKAGE_TEMPLATE_V1.md
  docs/development/agents/AGENT_CONTROL_AND_OPERATING_CONTRACT_V1.md
  docs/development/agents/AGENT_REGISTRY_V1.yaml
  docs/development/agents/AGENT_DEPENDENCY_GRAPH_V1.yaml
  docs/development/agents/AGENT_MERGE_QUEUE_V1.md
  docs/development/agents/ACTIVE_PR_PACKAGE_LEDGER_V1.yaml
  docs/development/agents/INTERFACE_CHANGE_REQUEST_V1.md
  docs/development/agents/GPT_WORK_AGENT_SETUP_V1.md
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
snapshot_schema = json.loads((root/"docs/schemas/current-snapshot-v1.schema.json").read_text())
handoff_schema = json.loads((root/"docs/schemas/agent-handoff-v1.schema.json").read_text())
assert snap["schema"] == "trnm-current-snapshot-v1"
assert snapshot_schema["title"] == "TRNM Current Snapshot v1"
assert handoff_schema["title"] == "TRNM Agent Handoff v1"
assert snap["latest_candidate"]["commit"] == "6e0189e351015ef3230f217ca7ff86149baedcf0"
assert snap["latest_candidate"]["tree"] == "efea864cb2fbc4835a59a089b3dbab8934e71231"
assert snap["machine_truth"]["production_candidate"] is False
assert snap["machine_truth"]["production_consensus_activation"] is False

registry = (root/"docs/development/agents/AGENT_REGISTRY_V1.yaml").read_text()
ids = re.findall(r"(?m)^- id: (A\d\d)$", registry)
expected = [f"A{i:02d}" for i in range(18)]
assert ids == expected, ids
assert len(ids) == len(set(ids))

a00_block = registry.split("- id: A00", 1)[1].split("- id: A01", 1)[0]
a01_block = registry.split("- id: A01", 1)[1].split("- id: A02", 1)[0]
assert "docs/development/CURRENT_SNAPSHOT_V1.*" not in a00_block
assert "writes to docs/development/CURRENT_SNAPSHOT_V1.* owned by A01" in a00_block
assert "scripts/ci/check_agent_development_docs_v1.sh" in a00_block
assert "docs/development/CURRENT_SNAPSHOT_V1.json" in a01_block

ledger = (root/"docs/development/agents/ACTIVE_PR_PACKAGE_LEDGER_V1.yaml").read_text()
assert re.search(r"(?m)^schema: trnm-active-pr-package-ledger-v1$", ledger)
assert re.search(r"(?m)^  one_package_per_pull_request: true$", ledger)
assert re.search(r"(?m)^  one_owner_per_pull_request: true$", ledger)
assert re.search(r"(?m)^  self_merge_allowed: false$", ledger)
open_section = ledger.split("open_pull_requests:", 1)[1].split("terminal_pull_requests:", 1)[0]
open_entries = re.split(r"(?m)^- number: ", open_section)[1:]
open_numbers = []
for entry in open_entries:
    number = int(entry.splitlines()[0])
    open_numbers.append(number)
    assert re.search(r"(?m)^  package_id: [A-Z0-9][A-Z0-9_]{2,127}$", entry), number
    assert re.search(r"(?m)^  owner: [A-Za-z0-9][A-Za-z0-9_-]{1,127}$", entry), number
    assert re.search(r"(?m)^    pr_bound_commit: [0-9a-f]{40}$", entry), number
    assert re.search(r"(?m)^    pr_bound_tree: [0-9a-f]{40}$", entry), number
assert open_numbers == [1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19], open_numbers
pr10 = next(entry for entry in open_entries if int(entry.splitlines()[0]) == 10)
assert re.search(r"(?m)^  terminal_state: BASE_DRIFT$", pr10)
assert re.search(r"(?m)^  classification: base-drift-root-candidate$", pr10)
assert pr10.count("  - ") >= 9
assert ledger.count("  invalidated_by_pr: 10") == 9
terminal_section = ledger.split("terminal_pull_requests:", 1)[1]
assert re.search(r"(?m)^- number: 6$", terminal_section)
assert re.search(r"(?m)^  terminal_state: BASE_DRIFT$", terminal_section)
assert re.search(r"(?m)^  closed_without_merge: true$", terminal_section)
assert re.search(r"(?m)^  sole_writer: A01$", ledger)
assert re.search(r"(?m)^  read_only_observer: A00$", ledger)

graph = (root/"docs/development/agents/AGENT_DEPENDENCY_GRAPH_V1.yaml").read_text()
for agent_id in expected:
    assert re.search(rf"(?m)^  {agent_id}: ", graph), agent_id

prompt_files = sorted((root/"docs/development/agents").glob("AGENT_PROMPTS_A*_V1.md"))
assert len(prompt_files) == 6, prompt_files
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
