#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PLAN_REL="docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
MANIFEST_REL="docs/development/plan-manifest-v1.toml"
MODULES_REL="docs/development/module-registry-v1.toml"
TRAIN_REL="docs/development/release-train-v1.toml"
SNAPSHOT_REL="docs/development/CURRENT_SNAPSHOT_V1.json"
POLICY_REL="config/documentation-truth-v1.json"
REFERENCE_GATE="scripts/ci/check_documentation_reference_closure_v1.py"
fail() { printf 'canonical development plan gate failed: %s\n' "$*" >&2; exit 2; }
for path in "$PLAN_REL" "$MANIFEST_REL" "$MODULES_REL" "$TRAIN_REL" "$SNAPSHOT_REL" "$POLICY_REL" "$REFERENCE_GATE"; do [[ -s "$path" ]] || fail "missing canonical input: $path"; done
if [[ "${TRNM_PLAN_EDITING:-0}" != "1" ]]; then
  for path in "$PLAN_REL" "$MANIFEST_REL" "$MODULES_REL" "$TRAIN_REL" "$SNAPSHOT_REL" "$POLICY_REL" "$REFERENCE_GATE"; do
    git ls-files --error-unmatch -- "$path" >/dev/null || fail "canonical input is untracked: $path"
    git cat-file -e "HEAD:$path" >/dev/null 2>&1 || fail "canonical input is absent from HEAD: $path"
  done
  git diff --quiet -- "$PLAN_REL" "$MANIFEST_REL" "$MODULES_REL" "$TRAIN_REL" "$SNAPSHOT_REL" "$POLICY_REL" "$REFERENCE_GATE" || fail "canonical development inputs are dirty"
  git diff --cached --quiet -- "$PLAN_REL" "$MANIFEST_REL" "$MODULES_REL" "$TRAIN_REL" "$SNAPSHOT_REL" "$POLICY_REL" "$REFERENCE_GATE" || fail "canonical development inputs are staged against another source"
fi
python3 - "$ROOT" "$PLAN_REL" "$MANIFEST_REL" "$MODULES_REL" "$TRAIN_REL" "$SNAPSHOT_REL" "$POLICY_REL" <<'PY'
from pathlib import Path
import hashlib,json,os,re,subprocess,sys,tomllib
from typing import Any
root=Path(sys.argv[1]); plan_rel,manifest_rel,modules_rel,train_rel,snapshot_rel,policy_rel=sys.argv[2:]
class GateError(RuntimeError): pass
def require(c,m):
    if not c: raise GateError(m)
def strict(pairs):
    out={}
    for k,v in pairs:
        if k in out: raise GateError(f"duplicate JSON member: {k}")
        out[k]=v
    return out
def j(p):
    value=json.loads((root/p).read_text(encoding="utf-8"),object_pairs_hook=strict); require(isinstance(value,dict),f"{p}: object required"); return value
def t(p):
    with (root/p).open("rb") as h: value=tomllib.load(h)
    require(isinstance(value,dict),f"{p}: table required"); return value
def vals(value,key):
    found=[]
    if isinstance(value,dict):
        for k,v in value.items():
            if k==key: found.append(v)
            found.extend(vals(v,key))
    elif isinstance(value,list):
        for v in value: found.extend(vals(v,key))
    return found
def one_sha(value,key):
    found=sorted({v for v in vals(value,key) if isinstance(v,str) and re.fullmatch(r"[0-9a-f]{40}",v)}); require(len(found)==1,f"{key} must be unique: {found}"); return found[0]
plan=(root/plan_rel).read_text(encoding="utf-8"); lower=plan.lower(); manifest=t(manifest_rel); modules=t(modules_rel); train=t(train_rel)
snapshot=j(snapshot_rel); policy=j(policy_rel); truth=j("config/consensus-mainline.json"); repo=j("config/repository-policy-v1.json"); boundary=j("PROJECT_BOUNDARY.json")
require(policy.get("schema")=="trnm-documentation-truth-v1","documentation policy schema drift")
require(policy.get("canonical_plan")==plan_rel and manifest.get("plan_path")==plan_rel,"canonical plan path drift")
plan_id=manifest.get("plan_id"); require(plan_id=="trnm-chain-development-plan-v2",f"plan id drift: {plan_id!r}")
require("plan id: `trnm-chain-development-plan-v2`" in lower,"plan body id drift")
actual=hashlib.sha256((root/plan_rel).read_bytes()).hexdigest(); declared=manifest.get("plan_sha256")
require(declared==actual or (os.environ.get("TRNM_PLAN_EDITING")=="1" and declared=="PENDING_FINAL_PLAN_HASH"),f"plan SHA mismatch: {declared} != {actual}")
commit=one_sha(manifest,"assessed_commit"); tree=one_sha(manifest,"assessed_tree")
actual_tree=subprocess.run(["git","rev-parse",f"{commit}^{{tree}}"],cwd=root,check=True,capture_output=True,text=True).stdout.strip(); require(actual_tree==tree,"assessed tree mismatch")
require(subprocess.run(["git","merge-base","--is-ancestor",commit,"HEAD"],cwd=root).returncode==0,"assessed source is not ancestor of HEAD")
mt=repr(manifest).lower(); require("runtime-git-commit-and-tree" in mt or "derived-at-verification-time" in mt or manifest.get("document_candidate_binding") in {"runtime","runtime-git-commit-and-tree"},"runtime document binding missing")
rows=modules.get("module",modules.get("modules")); require(isinstance(rows,list),"module rows missing")
ids=[r.get("id") for r in rows if isinstance(r,dict)]; require(ids==[f"M{i:02d}" for i in range(18)],f"module IDs drift: {ids}")
staff=0
for row in rows:
    count=next((row.get(k) for k in ("staff","staff_target","target_staff","recommended_staff") if isinstance(row.get(k),int)),None); require(isinstance(count,int) and count>0,f"staff missing for {row.get('id')}"); staff+=count
require(staff==48,f"staff target drift: {staff}")
for marker in ("one active engineering plan","18 long-lived","node commit ledger","pinnedsqlitenamespace","global control plane","production_candidate = false","no machine flag is promoted","g5"): require(marker in lower,f"plan missing {marker}")
for forbidden in ("production_candidate = true","production_consensus_activation = true","release_ready = true","public_testnet_ready = true"): require(forbidden not in lower,f"plan contains {forbidden}")
for doc in (snapshot,truth,repo,boundary,train):
    for key in ("production_candidate","production_consensus_activation","release_ready","public_testnet_ready"): require(all(v is False for v in vals(doc,key) if isinstance(v,bool)),f"{key} promoted")
require(snapshot.get("machine_truth",{}).get("stage")=="G1-native-host-incomplete","snapshot stage drift")
require(truth.get("stage")=="G1-native-host-incomplete" and truth.get("consensus_mainline")=="native-poco-bft" and truth.get("protocol_target")=="poco-bft-v0","machine truth drift")
train_lower=repr(train).lower()
for marker in ("selected","successor","sqlite","schema","review","production_candidate"): require(marker in train_lower,f"release train missing {marker}")
print(f"canonical_development_plan=passed plan_id={plan_id} plan_sha256={actual} regular_markdown=1 modules={len(rows)} staff_target={staff} archive=absent assessed_commit={commit} assessed_tree={tree} document_binding=runtime-git-commit-and-tree duplicate_json_keys=rejected")
PY
args=(--self-test --binding-mode "${TRNM_DOC_BINDING_MODE:-local}")
if [[ -n "${TRNM_DOC_BINDING_OUTPUT:-}" ]]; then args+=(--binding-output "$TRNM_DOC_BINDING_OUTPUT"); fi
python3 "$REFERENCE_GATE" "${args[@]}"
git diff --check
