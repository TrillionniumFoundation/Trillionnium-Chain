#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
cd "$root"

tmp=${TMPDIR:-/tmp}/trnm-whole-node-light-client-v1
rm -rf "$tmp"
mkdir -p "$tmp"

evidence=$(python3 tools/whole-node-model/model.py \
  --self-test \
  --bundle-out "$tmp/bundle.json")

python3 - "$evidence" <<'PY'
import json, sys
v=json.loads(sys.argv[1])
assert v["schema"]=="trnm-whole-node-light-client-model-evidence-v1"
assert v["positive"]["checkpoint_cas"] is True
assert v["positive"]["response_loss_replay"] is True
assert v["positive"]["external_anchor_reopen"] is True
assert v["positive"]["state_sync_staging_and_swap"] is True
assert v["positive"]["proof_families"]==["order","da","execution","result","settlement","upgrade"]
assert len(v["negative"])==18
assert v["candidate_only"] is True
assert v["production_jmt_authority"] is False
assert v["signing_or_voting_authority"] is False
assert v["node_support"] is False
PY

client=$(python3 tools/independent-light-client-v1/client.py --bundle "$tmp/bundle.json")
python3 - "$client" <<'PY'
import json, sys
v=json.loads(sys.argv[1])
assert v["chain_id"]=="chain"
assert v["height"]==10
assert v["block_id"]=="block-10"
assert len(v["checkpoint"])==64
assert len(v["application_root"])==64
print("whole-node and independent light-client models: ok")
PY

python3 - "$tmp/bundle.json" "$tmp" <<'PY'
import copy, json, pathlib, subprocess, sys
source=pathlib.Path(sys.argv[1])
tmp=pathlib.Path(sys.argv[2])
base=json.loads(source.read_text())
cases={}
x=copy.deepcopy(base); del x["families"]["result"]; cases["missing-family"]=x
x=copy.deepcopy(base); x["families"]["da"]["mode"]="DA-DAS-V1"; cases["das-disabled"]=x
x=copy.deepcopy(base); x["families"]["execution"]["composite_root"]=True; cases["composite-root"]=x
x=copy.deepcopy(base); x["families"]["settlement"]["poco_weight"]=True; cases["poco-weight"]=x
x=copy.deepcopy(base); x["families"]["upgrade"]["no_downgrade"]=False; cases["downgrade"]=x
for name, value in cases.items():
    path=tmp/f"{name}.json"
    path.write_text(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
    proc=subprocess.run(
        [sys.executable, "tools/independent-light-client-v1/client.py", "--bundle", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if proc.returncode == 0:
        raise SystemExit(f"independent client accepted mutant: {name}")
print("independent light-client mutants: rejected")
PY
