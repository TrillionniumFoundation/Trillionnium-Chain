from pathlib import Path
import ast, hashlib, json, re, subprocess
root=Path("/home/qian-qi/work/chain-w1-base62-integration-20261108-ec265b")
out={"head":subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip(),"sources":[]}
for rel in ("scripts/export_codeql_analysis.py","scripts/test_export_codeql_analysis.py","scripts/ci/test_ci_contract.py","scripts/ci/test_integration_push_source.py","scripts/ci/integration_push_source.py"):
 p=root/rel
 if not p.is_file():
  out["sources"].append({"path":rel,"exists":False});continue
 b=p.read_bytes();s=b.decode();lines=s.splitlines()
 item={"path":rel,"sha256":hashlib.sha256(b).hexdigest(),"bytes":len(b)}
 if "test_" in p.name:
  tree=ast.parse(s)
  functions=[]
  for f in ast.walk(tree):
   if not isinstance(f,(ast.FunctionDef,ast.AsyncFunctionDef)) or not f.name.startswith("test_"):continue
   seg="\n".join(lines[f.lineno-1:f.end_lineno])
   if re.search(r"wrong.*parent|parent.*wrong|wrong.*base|base.*wrong|prospective_merge|source.*context|context.*source|push.*event|event.*push|head.*drift|merge.*drift",f.name):
    functions.append({"name":f.name,"line":f.lineno,"end_line":f.end_lineno,"text":seg[:12000]})
  item["targeted_tests"]=functions
 else:
  pat=r"pull_request|GITHUB_EVENT|GITHUB_SHA|snapshot|parents|base_sha|base\[|base\.|ordered|def .*source|def .*snapshot|event_name|def event_identity"
  item["selected_lines"]=[f"{i+1}:{x}" for i,x in enumerate(lines) if re.search(pat,x)]
 out["sources"].append(item)
for p in sorted((root/".github/workflows").glob("*.yml")):
 s=p.read_text()
 if "export_codeql_analysis.py" not in s:continue
 b=p.read_bytes();out["sources"].append({"path":p.relative_to(root).as_posix(),"sha256":hashlib.sha256(b).hexdigest(),"bytes":len(b),"selected_lines":[f"{i+1}:{x}" for i,x in enumerate(s.splitlines()) if re.search(r"event|sha|SOURCE|BASE|EXPORT|checkout|export_codeql_analysis|test_export",x)]})
print(json.dumps(out,ensure_ascii=False,sort_keys=True))

