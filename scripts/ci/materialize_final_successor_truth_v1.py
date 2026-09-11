#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRANCH = "refs/heads/fix/chain-plan-v2-repository-closure-20260911"
PR = 121


def replace(path: str, pairs: list[tuple[str,str]]) -> None:
    p = ROOT / path
    text = p.read_text()
    for old, new in pairs:
        if old not in text:
            raise SystemExit(f"missing expected text in {path}: {old[:100]!r}")
        text = text.replace(old, new)
    p.write_text(text)

plan = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
replace(plan, [
    ("Selected integration entry: Draft PR **#62**, `refs/heads/work/plan-v2-full-gap-closure-20260902`\\", f"Selected integration entry: PR **#{PR}**, `{BRANCH}`\\"),
    ("Observed bounded child stack: **#62 <- #85 (PCC1 contract) <- #86 (implementation continuation)**. Children are not additional integration successors and their presence does not prove absorption into a parent. Verify current refs, ancestry and file content before integrating or transferring evidence.", "Historical source stack **#62 <- #85 (PCC1 contract) <- #86 (implementation continuation)** has been absorbed into the selected #121 convergence line and is provenance only. No historical pull request or branch is an alternate integration authority."),
    ("Draft PR #62 is the sole selected integration successor into protected main. PCC1/#85 and its implementation continuation #86 are bounded children on that line, not independent release authorities. Their latest source must be assessed separately from this historical integration baseline, which combines:", "PR #121 is the sole selected integration successor into protected main. It absorbs the former #62/#85/#86 integration line plus the validated branch-convergence work; those pull requests are historical provenance, not independent release authorities. The retained historical baseline combines:"),
    ("1. keep PR #62 as the sole successor and supersede overlapping PRs without losing immutable evidence;", "1. keep PR #121 as the sole successor, prove absorbed branch history, and supersede overlapping PRs without losing immutable evidence;"),
    ("PR #62 is the sole selected successor.", "PR #121 is the sole selected successor; #62/#85/#86 are absorbed historical provenance."),
    ("PR #62 sole successor; overlaps superseded; all required exact-head/merge checks and independent review pass", "PR #121 sole successor; absorbed/overlapping refs superseded; all required exact-head/merge checks and independent review pass"),
    ("current PR #62 head", "current PR #121 head"),
])

snap_path = ROOT / "docs/development/CURRENT_SNAPSHOT_V1.json"
snap = json.loads(snap_path.read_text())
snap["as_of"] = "2026-09-11"
s = snap["selected_successor"]
s["pull_request"] = PR
s["ref"] = BRANCH
s["status"] = "convergence-integration-candidate-independent-acceptance-pending"
s["supersedes_intent_of"] = sorted(set(s.get("supersedes_intent_of", []) + [62, 85, 86]))
snap["current_promotion_critical_stack"] = [x.replace("PR62", "PR121").replace("PR 62", "PR 121") for x in snap["current_promotion_critical_stack"]]
snap_path.write_text(json.dumps(snap, indent=2) + "\n")

train = "docs/development/release-train-v1.toml"
replace(train, [
    ("as_of = \"2026-09-02\"", "as_of = \"2026-09-11\""),
    ("selected_successor_pull_request = 62", f"selected_successor_pull_request = {PR}"),
    ("head_ref = \"refs/heads/work/plan-v2-full-gap-closure-20260902\"", f"head_ref = \"{BRANCH}\""),
    ("candidate_ref = \"refs/heads/work/plan-v2-full-gap-closure-20260902\"", f"candidate_ref = \"{BRANCH}\""),
    ("exit = \"PR62 is the sole successor, overlaps are superseded, and non-skipped exact-head plus prospective-merge checks pass with independent acceptance\"", "exit = \"PR121 is the sole successor, absorbed and overlapping refs are superseded, and non-skipped exact-head plus prospective-merge checks pass with independent acceptance\""),
])

block_path = ROOT / "config/blocker-execution-v1.json"
block = json.loads(block_path.read_text())
block["as_of"] = "2026-09-11"
block["implementation"]["selected_successor"] = PR
for item in block.get("repository_blockers", []):
    if item.get("id") == "P0-TRUTH-001":
        item.setdefault("implementation", {})["successor_pr"] = PR
        item["implementation"]["absorbed_source_pull_requests"] = [62, 85, 86]
    item["next_actions"] = [x.replace("PR 62", "PR 121").replace("PR62", "PR121") for x in item.get("next_actions", [])]
block_path.write_text(json.dumps(block, indent=2) + "\n")

replace("RELEASE_READINESS.md", [
    ("Updated: **2026-09-02**", "Updated: **2026-09-11**"),
    ("Draft PR #62 on\n`work/plan-v2-full-gap-closure-20260902` is the sole selected integration\nsuccessor.", "PR #121 on\n`fix/chain-plan-v2-repository-closure-20260911` is the sole selected integration\nsuccessor and absorbs the former #62/#85/#86 integration line as historical provenance."),
    ("all required checks on one unchanged PR #62 head and its prospective merge;", "all required checks on one unchanged PR #121 head and its prospective merge;"),
])

manifest_path = ROOT / "docs/development/plan-manifest-v1.toml"
manifest = manifest_path.read_text()
manifest = manifest.replace('candidate_ref = "refs/heads/work/plan-v2-full-gap-closure-20260902"', f'candidate_ref = "{BRANCH}"')
manifest = manifest.replace("selected_successor_pull_request = 62", f"selected_successor_pull_request = {PR}")

def sha256(path: str) -> str:
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

def git_blob(path: str) -> str:
    return subprocess.check_output(["git", "hash-object", path], cwd=ROOT, text=True).strip()

import re
manifest = re.sub(r'plan_sha256 = "[0-9a-f]{64}"', f'plan_sha256 = "{sha256(plan)}"', manifest)
manifest = re.sub(r'evidence_contract_sha256 = "[0-9a-f]{64}"', f'evidence_contract_sha256 = "{sha256("docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_ENGINEERING_EVIDENCE_CONTRACT_V1.md")}"', manifest)
manifest = re.sub(r'blocker_execution_git_blob = "[0-9a-f]{40}"', f'blocker_execution_git_blob = "{git_blob("config/blocker-execution-v1.json")}"', manifest)
manifest = re.sub(r'current_snapshot_git_blob = "[0-9a-f]{40}"', f'current_snapshot_git_blob = "{git_blob("docs/development/CURRENT_SNAPSHOT_V1.json")}"', manifest)
manifest_path.write_text(manifest)

# Active integration truth must not point back to PR62/old candidate branch.
for rel in [plan, "docs/development/CURRENT_SNAPSHOT_V1.json", train, "config/blocker-execution-v1.json", "RELEASE_READINESS.md", "docs/development/plan-manifest-v1.toml"]:
    text = (ROOT/rel).read_text()
    if "sole selected" in text and "PR #62 is the sole selected" in text:
        raise SystemExit(f"stale sole-successor truth remains in {rel}")

print("final_successor_truth_materialized=ok")
