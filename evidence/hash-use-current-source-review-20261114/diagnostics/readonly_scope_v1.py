import ast, copy, hashlib, json, os, pathlib, re, subprocess, sys
sys.dont_write_bytecode=True
W=pathlib.Path("/private/tmp/chain-hash-use-current-binding-20261114")
E=pathlib.Path("/private/tmp/chain-hash-use-current-binding-evidence-20261114")
D=E/"readonly-pin-audit-v1"; S=E/"readonly-consumer-and-scope-v1";S.mkdir()
HEAD="7d8d4c59fcd01480a12e1c64835b202079091800";LAST="57b069ae1e7ed32ff95e4f2a18a74d5eadcda550"
env=dict(os.environ,PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0")
def sha(b):return hashlib.sha256(b).hexdigest()
def put(name,b):
 p=S/name;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(b)
 return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def dump(n,v):return put(n,(json.dumps(v,indent=2,sort_keys=True)+"\n").encode())
def git(args):
 r=subprocess.run(["/usr/bin/git","-C",str(W),*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 if r.returncode:raise RuntimeError(str(args))
 return r.stdout
before={"head":git(["rev-parse","HEAD"]).decode().strip(),"tree":git(["rev-parse","HEAD^{tree}"]).decode().strip(),"status":git(["status","--porcelain=v1","--untracked-files=all"]).decode()}
assert before["head"]==HEAD and not before["status"]
a=json.loads((D/"all-31-inputs.json").read_bytes())
raw=(W/"config/pon/hash-use-contract-v1.json").read_bytes();m=json.loads(raw)
canon=lambda x:json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
proposed=copy.deepcopy(m["source_files"])
for row in a["rows"]:proposed[row["path"]]={"bytes":row["current_bytes"],"sha256":row["current_sha256"]}
schema={"current_manifest_sha256":sha(raw),"current_source_map_sha256":sha(canon(m["source_files"])),"proposed_current_source_map_sha256":sha(canon(proposed)),"unchanged_semantics_sha256":sha(canon({k:v for k,v in m.items() if k!="source_files"})),"unchanged_review_base_revision":m["review_base_revision"],"uses":len(m["uses"]),"source_paths":len(proposed),"proposed_map_has_exact_same_roster":set(proposed)==set(m["source_files"]),"changed_pin_count":sum(proposed[p]!=m["source_files"][p] for p in proposed),"source_files_currently_modified":False}
originals={}
for name,path in [("manifest.json","config/pon/hash-use-contract-v1.json"),("reader.py","scripts/ci/hash_use_contract.py"),("tests.py","scripts/ci/test_hash_use_contract.py"),("contract.md","docs/security/HASH_USE_CONTRACT_V1.md")]:
 old=git(["show",LAST+":"+path]);current=(W/path).read_bytes()
 originals[path]={"last_mapping_commit":LAST,"historical_blob":git(["rev-parse",LAST+":"+path]).decode().strip(),"current_blob":git(["rev-parse",HEAD+":"+path]).decode().strip(),"whole_raw_same":old==current,"preserved_original":put("originals/"+name,old)}
 assert old==current
roster=[n.name for n in ast.walk(ast.parse((W/"scripts/ci/test_hash_use_contract.py").read_text())) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith("test_")]
assert len(roster)==33
proof_path="config/pon/pq-proof-profile-binding-v1.json"
profile_versions=[]
for commit in [LAST,"ecf8b5cfea66d7451c2ae6910233746bd95fc155","b84568a714e24070d9554008660f1382e2c1b1b5",HEAD]:
 b=git(["show",commit+":"+proof_path]);v=json.loads(b)
 profile_versions.append({"commit":commit,"blob":git(["rev-parse",commit+":"+proof_path]).decode().strip(),"bytes":len(b),"sha256":sha(b),"mapping_contract":v["mapping_contract"],"all_other_profile_fields":{k:x for k,x in v.items() if k!="mapping_contract"}})
assert all(x["all_other_profile_fields"]==profile_versions[0]["all_other_profile_fields"] for x in profile_versions)
r=subprocess.run(["/opt/homebrew/bin/rg","-n","--glob","!evidence/**","--glob","!archive/**","hash_use_contract|hash-use-contract|HASH_USE_CONTRACT|4c52b9ee94afcc67992da56ce88f0705bd4b5c6dd99f29fc56b4b894ed484cbf|50c12b630049933110a400590d64f8bfb764a76bdf8737c71a53a71245a0fc92", "scripts","config","docs",".github","AGENTS.md"],cwd=W,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);assert r.returncode==0
search=put("direct-consumers.stdout",r.stdout);put("direct-consumers.stderr",r.stderr)
excerpts={}
for path,spans in {
 "scripts/ci/ci_job.sh":[(55,72)],
 "scripts/ci/check_ci_contract.py":[(840,860),(1650,1700)],
 "scripts/ci/test_ci_contract.py":[(3180,3220),(3308,3322)],
 "scripts/ci/check_pq_research_integration.py":[(282,307)]
}.items():
 lines=(W/path).read_text().splitlines(keepends=True)
 text="".join("".join(str(i+1)+": "+lines[i] for i in range(lo-1,min(hi,len(lines))))+"\n" for lo,hi in spans)
 excerpts[path]=put(path.replace("/","--")+".excerpt",text.encode())
# Full patches already prove every changed line; these narrow exact spans aid
# review without claiming a Rust parser or a whole-repository refinement proof.
function_checks=[]
def span(data,name):
 lines=data.decode().splitlines(keepends=True)
 found=[i for i,line in enumerate(lines) if re.match(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?fn\s+"+re.escape(name)+r"(?:<|\()",line)]
 if len(found)!=1:raise ValueError("nonunique function "+name)
 i=found[0];indent=re.match(r"^(\s*)",lines[i]).group(1)
 stop=next(j for j in range(i+1,len(lines)) if lines[j].rstrip("\n")==indent+"}")
 return "".join(lines[i:stop+1]).encode()
for path,names in {
 "trillionnium/crates/trnm-pon-node/src/lib.rs":["sequence_root"],
 "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs":["task_id","precheck_proof_statement","verify"]
}.items():
 old=(D/"changed"/(path.replace("/","--")+".before")).read_bytes()
 new=(D/"changed"/(path.replace("/","--")+".current")).read_bytes()
 for name in names:
  ob=span(old,name);nb=span(new,name)
  function_checks.append({"path":path,"function":name,"old_bytes":len(ob),"new_bytes":len(nb),"old_sha256":sha(ob),"new_sha256":sha(nb),"same_raw_span":ob==nb,"current_excerpt":put("function-"+name+".rs",nb)})
p="trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs"
old=(D/"changed"/(p.replace("/","--")+".before")).read_bytes()
new=(D/"changed"/(p.replace("/","--")+".current")).read_bytes()
anchor=b"    let (a, tail) = matrices.split_at(CELLS);"
assert old.count(anchor)==new.count(anchor)==1
body_same=old[old.index(anchor):]==new[new.index(anchor):]
assert body_same
after={"head":git(["rev-parse","HEAD"]).decode().strip(),"tree":git(["rev-parse","HEAD^{tree}"]).decode().strip(),"status":git(["status","--porcelain=v1","--untracked-files=all"]).decode()}
assert before==after
result={"schema":"hash-use-current-provenance-consumer-scope-readonly-v1","source_before":before,"source_after":after,"proposal":schema,"originals":originals,"original_test_roster":roster,"profile_version_provenance":profile_versions,"all_profile_fields_except_mapping_contract_unchanged":True,"direct_consumer_search":search,"direct_consumer_excerpts":excerpts,"exact_declared_function_spans":function_checks,"pon_work_entire_suffix_from_checked_matrices_unchanged":body_same,"no_tests_run":True,"no_source_edits":True,"review_note":"Review-base remains the historical semantic context. A manually reviewed new selected-source map is a new observation of current bytes, not a rewrite of a historical result. No whole-callgraph or cryptographic qualification."}
meta=dump("summary.json",result)
print(json.dumps({"summary":meta,"proposal":schema,"originals_same":all(x["whole_raw_same"] for x in originals.values()),"functions_same":all(x["same_raw_span"] for x in function_checks),"tests_run":False}),flush=True)
