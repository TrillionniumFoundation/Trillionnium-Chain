import ast,hashlib,json,os,pathlib,re,subprocess,sys,time
WT=pathlib.Path("/private/tmp/chain-owned-process-control-count-20261114")
BASE=pathlib.Path("/private/tmp/chain-owned-process-control-count-evidence-20261114-v1")
E=BASE/"validation-v1"
if os.path.lexists(E):raise ValueError("create-only validation exists")
E.mkdir()
env=dict(os.environ,PATH="/Users/qianqi/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",PYTHONDONTWRITEBYTECODE="1",PYTHONOPTIMIZE="0",GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0")
PY="/opt/homebrew/bin/python3"
steps=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def put(name,b):
 p=E/name;p.write_bytes(b);return {"path":str(p),"bytes":len(b),"sha256":sha(b)}
def run(label,args,expected=0,timeout=90):
 start=time.monotonic();p=subprocess.run(args,cwd=WT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
 row={"label":label,"argv":args,"exit":p.returncode,"expected_exit":expected,"seconds":time.monotonic()-start,"stdout":put(label+".stdout",p.stdout),"stderr":put(label+".stderr",p.stderr)}
 steps.append(row);(E/"steps.json").write_text(json.dumps(steps,sort_keys=True,indent=2)+"\n")
 if p.returncode!=expected:raise ValueError("unexpected result "+label)
 return p.stdout,p.stderr
sourcepaths=["scripts/ci/ci_job.sh","scripts/ci/check_ci_contract.py","scripts/ci/test_ci_contract.py","scripts/w1_owned_process_collector_v1.py","scripts/test_w1_owned_process_collector_v1.py"]
before={p:sha((WT/p).read_bytes()) for p in sourcepaths}
put("source-before.json",(json.dumps(before,sort_keys=True,indent=2)+"\n").encode())
original=(BASE/"edit-v1/scripts--ci--ci_job.sh.before").read_text()
current=(WT/"scripts/ci/ci_job.sh").read_text()
marker='      python3 - "$w1_contract_out" <<\\'PY\\'\\n'.replace("\\'","'").replace("\\n","\n")
def extract(text):
 if text.count(marker)!=1:raise ValueError("inline parser delimiter changed")
 return text.split(marker,1)[1].split("\nPY\n",1)[0]+"\n"
oldcode,newcode=extract(original),extract(current)
if oldcode.replace('("owned-process-collector", 14))','("owned-process-collector", 16))')!=newcode:raise ValueError("inline semantics changed beyond count")
def expected(code):
 for node in ast.parse(code).body:
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="expected" for t in node.targets):return ast.literal_eval(node.value)
 raise ValueError("expected tuple absent")
old_expected,new_expected=expected(oldcode),expected(newcode)
if len(new_expected)!=12 or [(n,c) for n,c in old_expected if n!="owned-process-collector"]!=[(n,c) for n,c in new_expected if n!="owned-process-collector"]:raise ValueError("other 11 suite counts changed")
put("original-inline-parser.py",oldcode.encode());put("updated-inline-parser.py",newcode.encode())
cases=[
("original-rejects-actual16","original-inline-parser.py",16,"normal",1),
("updated-accepts-exact16","updated-inline-parser.py",16,"normal",0),
("updated-rejects-old14","updated-inline-parser.py",14,"normal",1),
("updated-rejects-incomplete15","updated-inline-parser.py",15,"normal",1),
("updated-rejects-excess17","updated-inline-parser.py",17,"normal",1),
("updated-rejects-zero","updated-inline-parser.py",0,"normal",1),
("updated-rejects-skipped","updated-inline-parser.py",16,"skipped",1),
("updated-rejects-failed","updated-inline-parser.py",16,"failed",1),
("updated-rejects-duplicate-count","updated-inline-parser.py",16,"duplicate",1),
("updated-rejects-missing-log","updated-inline-parser.py",16,"missing",1)]
fixtures=E/"synthetic-count-fixtures";fixtures.mkdir()
for name,parser,count,variant,exitcode in cases:
 folder=fixtures/name;folder.mkdir()
 for suite,expected_count in new_expected:
  observed=count if suite=="owned-process-collector" else expected_count
  body=f"Ran {observed} tests in 0.001s\n\nOK\n"
  if suite=="owned-process-collector":
   if variant=="missing":continue
   if variant=="skipped":body+="skipped=1\n"
   elif variant=="failed":body=body.replace("OK\n","FAILED (failures=1)\n")
   elif variant=="duplicate":body=f"Ran {observed} tests in 0.001s\n"+body
  (folder/(suite+".log")).write_text(body)
 _,err=run(name,[PY,"-B",str(E/parser),str(folder)],exitcode)
 if exitcode==1 and variant!="missing":
  message="all 14 controls must execute without skips" if parser.startswith("original") else "all 16 controls must execute without skips"
  if message.encode() not in err:raise ValueError("required refusal message differs")
run("consumer-search",["/opt/homebrew/bin/rg","-n","--fixed-strings","-e","owned-process-collector","-e","test_w1_owned_process_collector_v1",".github","scripts"])
selectors=[
"W1PostwinLaneTests.test_actual_postwin_lanes_retain_real_controls",
"W1PostwinLaneTests.test_required_postwin_commands_cannot_be_missing_stubbed_or_swallowed",
"W1PostwinLaneTests.test_required_postwin_commands_cannot_change_or_duplicate_lane",
"W1PostwinLaneTests.test_postwin_count_and_original_budget_controls_cannot_be_softened"]
out,err=run("original-ci-postwin-four-controls",[PY,"-B","scripts/ci/test_ci_contract.py","-v"]+selectors,timeout=180)
combined=out+err
if re.findall(rb"^Ran ([0-9]+) tests in ",combined,re.M)!=[b"4"] or not re.search(rb"^OK$",combined,re.M) or b"skipped=" in combined:raise ValueError("exact four CI methods did not execute")
run("actual-ci-contract",[PY,"-B","scripts/ci/check_ci_contract.py"],timeout=180)
after={p:sha((WT/p).read_bytes()) for p in sourcepaths}
put("source-after.json",(json.dumps(after,sort_keys=True,indent=2)+"\n").encode())
if after!=before:raise ValueError("source changed during validation")
summary={"schema":"trnm-owned-collector-exact-count-validation-v1","status":"SELECTED_STATIC_AND_CI_CONTRACT_PASS","base":"08c9becab740ab2c375b970f376a7638f44c9e8e","inline_cases":len(cases),"inline_fixture_scope":"Synthetic count/OK/skip/missing-log fixtures only; no collector process or native workload was executed.","original_inline_16_refusal_preserved":True,"updated_inline_accepts_only_exact16":True,"original_CI_methods_run":selectors,"original_CI_method_count":4,"actual_CI_contract_pass":True,"source_unchanged_during_validation":True,"collector_production_and_test_files_edited":False,"full_Linux_lane_run":False,"Host_run":False,"ROG_accessed":False,"steps":steps}
p=E/"summary.json";p.write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n");raw=p.read_bytes()
print(json.dumps({"summary":str(p),"bytes":len(raw),"sha256":sha(raw),"status":summary["status"],"CI_methods":4,"synthetic_inline_cases":len(cases)},sort_keys=True,indent=2),flush=True)
