import hashlib,json,pathlib,sys,types
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");helper=root/"root_merge_helpers.py"
raw=helper.read_bytes();assert hashlib.sha256(raw).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(raw,str(helper),"exec"),h.__dict__);h.setup("integrate-policy-prefix-6a8cd5-v1")
(h.ev/"producer.py").write_text(sys.argv[1])
h.env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
head="6a8cd55573065ceb50cdb65a7834615f79b521ae";tree="cbd6b4552c87af27c72c0189806baeb33ecb8bf5";base="ed0d35487f2a67239e4d646fd41c2c7acb5cc740"
expected=json.loads("[\"config/pon/pq-cross-branch-corpus-v1.json\",\"config/pon/pq128-lifetime-composition-current-v3.json\",\"config/pon/pq128-source-correspondence-current-v2.json\",\"docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md\",\"docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md\",\"docs/security/PQ128_LIFETIME_BUDGET_V1.md\",\"docs/security/PQ128_LIFETIME_COMPOSITION_V2.md\",\"scripts/ci/pq_lifetime_composition.py\",\"scripts/ci/pq_lifetime_current_v2.py\",\"trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs\"]")
manifest=json.loads("[{\"path\":\"config/pon/pq-cross-branch-corpus-v1.json\",\"bytes\":523769,\"sha256\":\"983a1fedd7e90c515e6a33581385541afefdfc69cc06ee63315edcd368ddbf2e\",\"git_blob\":\"3f4c9edc80103c78474203caaf5f2f3c781289d2\",\"mode\":\"100644\"},{\"path\":\"config/pon/pq128-lifetime-composition-current-v3.json\",\"bytes\":13647,\"sha256\":\"217266780480623cfec459eb61b533f437690c1234cd0b78e49902a78321eab5\",\"git_blob\":\"a7a3005cc86f0202e8465390e058055b2678baa7\",\"mode\":\"100644\"},{\"path\":\"config/pon/pq128-source-correspondence-current-v2.json\",\"bytes\":3782,\"sha256\":\"4f234fbff89fdf5693b4d7b82676a46574f92e297fdd535101110a76b9abb3e0\",\"git_blob\":\"1fad2b3ae6a5ae61d021f612a6cc8ccc1aa8dc63\",\"mode\":\"100644\"},{\"path\":\"docs/development/BRANCH_CONSOLIDATION_AUDIT_20261114.md\",\"bytes\":57076,\"sha256\":\"cc44eeae1dc20baecc0a0371494f8f3fe06f6732090e8805756d4b8de3bbeb2d\",\"git_blob\":\"c07b6a40eb8e5825803cb3c84ebe9e94688d25ff\",\"mode\":\"100644\"},{\"path\":\"docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md\",\"bytes\":1153099,\"sha256\":\"02301a593700ac92d6d412ba5265bde2cb8dca30350122c28dd83f9089513a02\",\"git_blob\":\"d91790c0b53fa11908d2026ad23bcb58520677a5\",\"mode\":\"100644\"},{\"path\":\"docs/security/PQ128_LIFETIME_BUDGET_V1.md\",\"bytes\":36093,\"sha256\":\"4e84e389686568106be0f728bd9c9e20ef53cb0798ed4ebe3c74fe328ae9a064\",\"git_blob\":\"4e4ac98c9fde929db5de9269f1efd1882cc6cc55\",\"mode\":\"100644\"},{\"path\":\"docs/security/PQ128_LIFETIME_COMPOSITION_V2.md\",\"bytes\":25102,\"sha256\":\"e7a9dc004f1cdf3acf42cd26e958d338d1878f6b10f9705f41c74b91e82ed5d1\",\"git_blob\":\"39d4e18d99bea0c8908c5e0279566a63dbe6f461\",\"mode\":\"100644\"},{\"path\":\"scripts/ci/pq_lifetime_composition.py\",\"bytes\":28724,\"sha256\":\"a61b604e699e91171102490e12b576c8693b64cec96b26eac9c90e6976d54e23\",\"git_blob\":\"595027440b2d1a6ee6da2b7ba4fcf78d9a3aba37\",\"mode\":\"100644\"},{\"path\":\"scripts/ci/pq_lifetime_current_v2.py\",\"bytes\":10522,\"sha256\":\"f8871844501054caf62de14a33330817a517ccefa60d538c0618364761c17401\",\"git_blob\":\"a5b085f9f1f45e1ae3849778ed57479f76ebd427\",\"mode\":\"100644\"},{\"path\":\"trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs\",\"bytes\":438782,\"sha256\":\"0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a\",\"git_blob\":\"b62de39bdba906c9d989498a6299df9a14d900e8\",\"mode\":\"100644\"}]")
frozen=json.loads("{\"config/pon/pq128-lifetime-budget-v1.json\":\"0315e07ca2988b3b209a6fd2980ca6d9aa22a5bb3aa98b5444a041852b2f0afd\",\"config/pon/pq128-source-lock-v1.json\":\"094dcae805f3872ee621d6554ab26a7a3a34c498e21be669740949ada424ccb2\",\"config/pon/pq128-lifetime-composition-v2.json\":\"5b527fbd56885bf7a7cba7516a45f0f911479b0d2867d03ff5361ee3e7a8b052\"}")
receipt={"schema":"trnm-reviewed-policy-prefix-fast-forward-v1","head":head,"tree":tree,"parent":base,"status":"HOLD","steps":h.steps,"errors":[],"remote_mutation":False}
def save():(h.ev/"summary.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.git("rev-parse","HEAD").decode().strip()==base
 assert h.git("symbolic-ref","--short","HEAD").decode().strip()=="fix/chain-audit-final-20261114"
 assert h.run("status-before",["git","status","--porcelain=v1","--untracked-files=all"],timeout=60).stdout==b""
 h.run("preflight-before",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 commit=h.git("cat-file","commit",head)
 assert hashlib.sha1(b"commit "+str(len(commit)).encode()+b"\0"+commit).hexdigest()==head
 headers=commit.split(b"\n\n",1)[0].splitlines();assert [x[7:].decode() for x in headers if x.startswith(b"parent ")]==[base]
 assert h.git("rev-parse",head+"^{tree}").decode().strip()==tree
 paths=h.git("diff-tree","--no-commit-id","--name-only","-r",base,head).decode().splitlines();assert paths==expected and len(paths)==10
 patch=h.run("reviewed-diff",["git","diff","--no-ext-diff","--no-textconv",base,head],timeout=60).stdout
 assert len(patch)==37875 and hashlib.sha256(patch).hexdigest()=="1a4dcea6c65abaa8ecfffec5cebba1e1dd7327608f90f0095527de0b9c4b1356"
 for row in manifest:
  b=h.git("show",head+":"+row["path"]);assert len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"]
  assert hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==row["git_blob"]
 for path,pin in frozen.items():
  b=h.git("show",head+":"+path);assert b==h.git("show",base+":"+path) and hashlib.sha256(b).hexdigest()==pin
 h.run("fast-forward-reviewed-local-commit",["git","merge","--ff-only",head],timeout=120)
 assert h.git("rev-parse","HEAD").decode().strip()==head and h.git("rev-parse","HEAD^{tree}").decode().strip()==tree
 assert h.run("status-after",["git","status","--porcelain=v1","--untracked-files=all"],timeout=60).stdout==b""
 for row in manifest:
  b=(h.src/row["path"]).read_bytes();assert len(b)==row["bytes"] and hashlib.sha256(b).hexdigest()==row["sha256"]
 receipt.update(status="FAST_FORWARDED_REVIEWED_LOCAL_COMMIT",clean=True,changed_paths=paths,all_ten_source_files_verified=True,frozen_files_unchanged=True)
except BaseException as ex:receipt["errors"].append(type(ex).__name__+": "+str(ex))
finally:save()
print(json.dumps({k:v for k,v in receipt.items() if k!="steps"}),flush=True)
raise SystemExit(0 if not receipt["errors"] else 1)
