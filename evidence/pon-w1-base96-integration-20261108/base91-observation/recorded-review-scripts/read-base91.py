from pathlib import Path
import hashlib,json,os,subprocess,time
repo=Path("/home/qian-qi/work/chain-w1-base96-integration-20261108-ec265b")
out=Path("/home/qian-qi/work/chain-w1-base91-impact-20261108-ec265b-01")
c7="40a3a45d6b8afc5c4706c5235fec47634f4aabbe"
tree="4b25e3194a0682adff40bb476f2e7c0a395639fe"
base96="96a241bf43f6a46d35dfb3d4ced9594ed8ceca75"
base91="91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c"
out.mkdir()
rows=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
def run(label,argv,ok=(0,),timeout=120):
 p=subprocess.run(argv,cwd=repo,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=timeout)
 (out/(label+".stdout")).write_bytes(p.stdout);(out/(label+".stderr")).write_bytes(p.stderr)
 row={"label":label,"argv":argv,"exit":p.returncode,"stdout_bytes":len(p.stdout),"stdout_sha256":sha(p.stdout),"stderr_bytes":len(p.stderr),"stderr_sha256":sha(p.stderr)}
 rows.append(row);dump(out/"commands.json",rows)
 assert p.returncode in ok,(label,p.returncode,p.stderr.decode(errors="replace")[:3000])
 return p
complete=False
result={}
try:
 assert run("00-c7-head-before",["git","rev-parse","HEAD"]).stdout.decode().strip()==c7
 assert run("01-c7-tree-before",["git","rev-parse","HEAD^{tree}"]).stdout.decode().strip()==tree
 assert run("02-c7-status-before",["git","status","--porcelain","--untracked-files=all"]).stdout==b""
 run("03-fetch-fixed-base91",["git","fetch","--no-tags","--no-write-fetch-head","origin",base91],timeout=180)
 assert run("04-base91-object",["git","cat-file","-t",base91]).stdout.decode().strip()=="commit"
 run("05-base91-parents",["git","show","-s","--format=%H%n%T%n%P%n%s",base91])
 ancestry=run("06-base96-ancestry",["git","merge-base","--is-ancestor",base96,base91],ok=(0,1)).returncode
 run("07-base91-log",["git","log","--reverse","--format=%H %P %s",base96+".."+base91])
 names=run("08-base91-name-status",["git","diff","--name-status",base96,base91]).stdout.decode()
 run("09-base91-stat",["git","diff","--stat",base96,base91])
 run("10-base91-numstat",["git","diff","--numstat",base96,base91])
 run("11-base91-patch",["git","diff","--binary",base96,base91])
 static=run("12-canonical-base91-c7-merge-tree",["git","-c","core.attributesFile=/dev/null","merge-tree","--write-tree","--no-messages",base91,c7],ok=(0,1))
 static_lines=static.stdout.decode().splitlines()
 assert static_lines and len(static_lines[0])==40
 static_tree=static_lines[0]
 run("13-static-vs-c7-name-status",["git","diff","--name-status",tree,static_tree])
 run("14-static-vs-c7-stat",["git","diff","--stat",tree,static_tree])
 assert run("15-c7-head-after",["git","rev-parse","HEAD"]).stdout.decode().strip()==c7
 assert run("16-c7-tree-after",["git","rev-parse","HEAD^{tree}"]).stdout.decode().strip()==tree
 assert run("17-c7-status-after",["git","status","--porcelain","--untracked-files=all"]).stdout==b""
 changed=[line.split("\t")[-1] for line in names.splitlines()]
 result={"source_commit":c7,"source_tree":tree,"reviewed_base96":base96,"reviewed_base91":base91,"base96_is_ancestor":ancestry==0,"changed_paths":changed,"canonical_merge_order":[base91,c7],"static_merge_exit":static.returncode,"static_tree":static_tree,"actual_merge_performed":False,"production_src_candidates":[p for p in changed if p.startswith("trillionnium/crates/") and "/src/" in p],"w1_candidates":[p for p in changed if "w1" in p.lower()],"m12_candidates":[p for p in changed if "native_generation_budget" in p or "async_w1_generation" in p or "service-settlement" in p],"ci_candidates":[p for p in changed if p.startswith((".github/","scripts/ci/","config/"))]}
 complete=True
finally:
 result.update(schema="TRNM-W1-C7-BASE91-READONLY-IMPACT-RAW1",complete=complete,commands=rows,source_worktree_changes=0,new_candidate_branches=0,tests_executed=0,full_proofs=0,new_operations=0,pushes=0)
 dump(out/"raw-review.json",result)
 print(json.dumps({"complete":complete,"out":str(out),"raw_review_sha256":sha((out/"raw-review.json").read_bytes()),"summary":{k:v for k,v in result.items() if k not in ("commands",)}}),flush=True)
