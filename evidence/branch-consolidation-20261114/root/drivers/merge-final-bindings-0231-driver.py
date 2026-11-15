import sys,pathlib,json,hashlib,argparse,re
sys.path.insert(0,"/private/tmp/chain-consolidation-20261114-root")
import root_merge_helpers as h
p=argparse.ArgumentParser();p.add_argument("--target",required=True);a=p.parse_args()
assert not sys.flags.optimize and re.fullmatch(r"[0-9a-f]{40}",a.target)
h.setup("merge-final-current-bindings-v1")
base="5c04c60e463462d9df8884786e0d5bb32af08a64";prior="51c215b45c41180fc044ec806fde39c7ceffb75c";target=a.target
assert h.git("rev-parse","HEAD").decode().strip()==prior and not h.git("status","--porcelain").strip()
assert h.git("rev-parse",target+"^").decode().strip()==base
paths=h.git("diff","--name-only",base,target).decode().splitlines()
assert len(paths)==34 and not any(x.endswith((".rs",".toml")) or x.endswith("Cargo.lock") for x in paths)
h.reviewed.update(paths)
h.run("preflight-audit",["bash","scripts/project-preflight.sh","--audit"])
q=h.run("merge-bindings",["git","merge","--no-ff","--no-commit",target],allowed=(0,1))
conflicts=set(h.git("diff","--name-only","--diff-filter=U").decode().splitlines())
assert conflicts in (set(),{h.manifest}),sorted(conflicts)
assert q.returncode==0 or conflicts
if h.manifest in conflicts:
 merged=h.merge_json(*[json.loads(h.show(rev,h.manifest)) for rev in (base,prior,target)])
 (h.src/h.manifest).write_text(json.dumps(merged,indent=2,ensure_ascii=False)+"\n")
 h.run("resolve-corpus-pin-union",["git","add","--",h.manifest])
assert not h.git("diff","--name-only","--diff-filter=U").strip()
assert h.blob("scripts/ci/test_ci_contract.py")=="8683f6b319cb6104bf7dc201e3b363c648901468"
for path in paths:
 if path!=h.manifest:
  assert (h.src/path).read_bytes()==h.show(target,path),path
manifest=json.loads((h.src/h.manifest).read_bytes())
assert manifest["pinned_blobs"]["scripts/ci/test_ci_contract.py"]=="8683f6b319cb6104bf7dc201e3b363c648901468"
for path in paths:
 if path in manifest["pinned_blobs"]:assert manifest["pinned_blobs"][path]==h.blob(path),path
h.run("diff-check",["git","diff","--cached","--check"])
h.run("distributed-inventory-check",["python3","-B","scripts/refresh_distributed_source_inventory.py","--check"])
h.run("precommit-preflight",["bash","scripts/project-preflight.sh","--audit"])
h.run("commit-bindings",["git","commit","-m","Integrate reviewed current source bindings and retained consumer controls"])
assert not h.git("status","--porcelain").strip()
result={"head":h.git("rev-parse","HEAD").decode().strip(),"tree":h.git("rev-parse","HEAD^{tree}").decode().strip(),"prior":prior,"base":base,"target":target,"target_paths":paths,"ci225_fixture_retained":True,"no_rust_source_changes":True,"conflicts_resolved":sorted(conflicts),"steps":h.steps}
(h.ev/"summary.json").write_text(json.dumps(result,indent=2)+"\n")
(h.ev/"integration.patch").write_bytes(h.git("diff",prior,"HEAD"))
print(json.dumps({k:v for k,v in result.items() if k not in {"target_paths","steps"}}),flush=True)
