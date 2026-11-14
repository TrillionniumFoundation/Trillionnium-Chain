import pathlib,sys,json,hashlib,difflib
sys.path.insert(0,"/private/tmp/chain-consolidation-20261114-root")
import root_merge_helpers as h
h.setup("merge-final-current-bindings-finish-v1")
prior="51c215b45c41180fc044ec806fde39c7ceffb75c";target="b84568a714e24070d9554008660f1382e2c1b1b5"
assert h.git("rev-parse","HEAD").decode().strip()==prior
assert h.git("rev-parse","MERGE_HEAD").decode().strip()==target
assert not h.git("diff","--name-only","--diff-filter=U").strip()
path=h.inventory;before=(h.src/path).read_bytes()
h.run("preflight-audit",["bash","scripts/project-preflight.sh","--audit"])
h.run("refresh-generated-inventory",["python3","-B","scripts/refresh_distributed_source_inventory.py"])
after=(h.src/path).read_bytes()
block='''    (
        "trillionnium/crates/trnm-pon-node/tests/mining_timestamp_liveness.rs",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../trillionnium/crates/trnm-pon-node/tests/mining_timestamp_liveness.rs"
        )),
    ),
'''.encode()
assert after.count(block)==1 and after.replace(block,b"")==before
h.refresh_pins([path])
h.run("stage-derived-metadata",["git","add","--",path,h.manifest])
h.run("distributed-inventory-check",["python3","-B","scripts/refresh_distributed_source_inventory.py","--check"])
h.run("diff-check",["git","diff","--cached","--check"])
h.run("fmt",["cargo","fmt","--manifest-path","trillionnium/Cargo.toml","--all","--","--check"])
assert h.blob("scripts/ci/test_ci_contract.py")=="8683f6b319cb6104bf7dc201e3b363c648901468"
h.run("precommit-preflight",["bash","scripts/project-preflight.sh","--audit"])
h.run("commit-bindings",["git","commit","-m","Integrate reviewed source bindings and complete native source inventory"])
assert not h.git("status","--porcelain").strip()
res={"head":h.git("rev-parse","HEAD").decode().strip(),"tree":h.git("rev-parse","HEAD^{tree}").decode().strip(),"prior":prior,"target":target,
"binding_patch_paths":34,"generated_inventory_addition":"trillionnium/crates/trnm-pon-node/tests/mining_timestamp_liveness.rs","production_runtime_logic_changed":False,
"ci225_fixture_retained":True,"original_inventory_refusal_preserved":"../merge-final-current-bindings-v1","inventory_before_sha256":hashlib.sha256(before).hexdigest(),"inventory_after_sha256":hashlib.sha256(after).hexdigest(),"steps":h.steps}
(h.ev/"summary.json").write_text(json.dumps(res,indent=2)+"\n")
(h.ev/"integration.patch").write_bytes(h.git("diff",prior,"HEAD"))
print(json.dumps({k:v for k,v in res.items() if k!="steps"}),flush=True)
