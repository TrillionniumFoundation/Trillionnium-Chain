import ast, hashlib, importlib.util, json, os, pathlib, subprocess, sys, traceback
A="43e5c9d6b668276d03e1c7a76f467ec211e1d7dc"
T="beac87c2431d149dbd6d2de4a2e1eaf0617520cc"
R=pathlib.Path("/home/qian-qi/work/chain-daa-resource-competition-20261112-600e")
V1=R.parent/"chain-daa-evidence-final-600e"
D=R.parent/"chain-daa-evidence-comparison-diagnostic-600e"
F=R.parent/"chain-daa-resource-formal-20261112-600e-43e5c9d6b668";C=F/"campaign";P=R.parent/"chain-daa-posthoc-600e"
D.mkdir()
source=subprocess.check_output(["/usr/bin/git","--no-replace-objects","show",A+":formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py"],cwd=R,env={**os.environ,"GIT_OPTIONAL_LOCKS":"0"})
tree=ast.parse(source)
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="canonical")
segment=ast.get_source_segment(source.decode(),fn)
(D/"source-A-canonical.txt").write_text(segment+"\n")
helper=V1/"evidence_formal_validator.py"
if hashlib.sha256(helper.read_bytes()).hexdigest()!="bea23d11321dc44b13f2c7a00483449ce658adb31f8257472fdfe2f8815992de":raise ValueError("v1 helper changed")
spec=importlib.util.spec_from_file_location("v1_formal_diagnostic",helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
failures=[];comparison_seen=False
def differences(a,b,path="$"):
 result=[]
 if type(a) is not type(b):return [{"path":path,"kind":"type","actual":a,"expected":b}]
 if isinstance(a,dict):
  if set(a)!=set(b):result.append({"path":path,"kind":"keys","actual_only":sorted(set(a)-set(b)),"expected_only":sorted(set(b)-set(a))})
  for k in sorted(set(a)&set(b)):result.extend(differences(a[k],b[k],path+"."+k))
 elif isinstance(a,list):
  if len(a)!=len(b):result.append({"path":path,"kind":"length","actual":len(a),"expected":len(b)})
  for i,(x,y) in enumerate(zip(a,b)):result.extend(differences(x,y,path+"["+str(i)+"]"))
 elif a!=b:result.append({"path":path,"kind":"value","actual":a,"expected":b})
 return result
def observe_equal(actual,expected,message):
 global comparison_seen
 diff=differences(actual,expected)
 if diff:
  failures.append({"check":message,"differences":diff})
  if message=="REPORT_COMPARISON":
   comparison_seen=True
   (D/"comparison-actual.json").write_text(json.dumps(actual,sort_keys=True,indent=2)+"\n")
   (D/"comparison-v1-expected.json").write_text(json.dumps(expected,sort_keys=True,indent=2)+"\n")
 # Diagnostic only: continue after equality mismatches to observe later metadata.
 # This process never writes a validation PASS or substitutes for the strict v2.
m.equal=observe_equal
exception=None;reached_end=False
try:
 m.validate_formal_and_posthoc(F,C,P,A,T,R)
 reached_end=True
except BaseException:
 exception=traceback.format_exc()
 (D/"diagnostic-exception.log").write_text(exception)
report=m.strict_json((C/"report.json").read_bytes())
newline_matches=[]
for pair in report["comparison"]["pairs"]:
 honest=m.strict_json((C/(pair["honest"]+".json")).read_bytes())
 premise={k:v for k,v in honest["parameters"].items() if k not in m.ARMS}
 without=m.digest(m.canonical(premise));with_lf=m.digest(m.canonical(premise)+b"\n")
 newline_matches.append({"honest":pair["honest"],"private":pair["private"],"actual_sha256":pair["resource_premises_sha256"],"v1_expected_without_lf":without,"source_A_expected_with_lf":with_lf,"matches_source_A":pair["resource_premises_sha256"]==with_lf})
result={"schema":"trnm-joint-resource-collector-diagnostic-v1","result":"DIAGNOSTIC_ONLY_NOT_QUALIFICATION","source_A":A,"source_A_canonical_function":segment,"source_A_canonical_module_sha256":hashlib.sha256(source).hexdigest(),"v1_helper_sha256":hashlib.sha256(helper.read_bytes()).hexdigest(),"mismatches":failures,"comparison_seen":comparison_seen,"reached_helper_end_with_diagnostic_equality_override":reached_end,"exception":exception,"pair_hash_checks":newline_matches,"all_64_pair_hashes_match_source_A_lf":len(newline_matches)==64 and all(x["matches_source_A"] for x in newline_matches),"new_tests_or_simulator_executions":0,"strict_qualification_performed":False,"original_sources_or_records_modified":False}
(D/"diagnostic.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
manifest={"schema":"trnm-joint-resource-diagnostic-files-v1","files":[{"path":p.name,"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(D.iterdir()) if p.is_file()]}
(D/"manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
small={"result":result["result"],"diagnostic_sha256":hashlib.sha256((D/"diagnostic.json").read_bytes()).hexdigest(),"comparison_seen":comparison_seen,"mismatches":[{"check":x["check"],"count":len(x["differences"]),"first":x["differences"][:2]} for x in failures],"all_64_pair_hashes_match_source_A_lf":result["all_64_pair_hashes_match_source_A_lf"],"reached_helper_end":reached_end,"exception":exception,"diagnostic_directory":str(D),"new_tests_or_simulator_executions":0}
(D/"summary.json").write_text(json.dumps(small,sort_keys=True,indent=2)+"\n")
print(json.dumps(small,sort_keys=True),flush=True)
