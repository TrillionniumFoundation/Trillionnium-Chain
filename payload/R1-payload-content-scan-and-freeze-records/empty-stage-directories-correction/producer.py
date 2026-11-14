import difflib,hashlib,json,os,pathlib,stat,sys
if sys.flags.optimize:raise RuntimeError("optimized execution forbidden")
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");P=R/"execution-receipts-followup-v1"
inp=json.loads(sys.argv[2]);E=R/"R1-empty-stage-directories-correction-v1";E.mkdir(mode=0o700,exist_ok=False)
def save(root,name,data):
 p=root/name
 with p.open("xb")as f:f.write(data);f.flush();os.fsync(f.fileno())
 return {"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def js(v):return(json.dumps(v,indent=2,sort_keys=True)+"\n").encode()
save(E,"producer.py",sys.argv[1].encode());save(E,"inputs.json",js(inp))
for key in ("freeze_args","freeze_run","freeze_terminal","diagnostic1_args","diagnostic1_run","diagnostic1_terminal","diagnostic2_args","diagnostic2_run","diagnostic2_terminal"):save(E,key+".json",js(inp[key]))
fail=R/"frozen-execution-payload-2a8646-content-v1/summary.json";raw=fail.read_bytes()
assert len(raw)==10061 and hashlib.sha256(raw).hexdigest()=="80317ef462ace05fbe2562d00898762468d8f8b9be74f4226205572eb8ab8028"
save(E,"original-freeze-HOLD-summary.json",raw)
targets=["P1-startup-failure-and-final-review/closed-sparse-results/payloads/originals/final-repository-truth-offline-6a8cd5-v1/ci-observations","P1-startup-failure-and-final-review/closed-sparse-results/payloads/originals/final-repository-truth-offline-6a8cd5-v1/tmp"]
def identities():
 out={}
 for root,dirs,names in os.walk(P,followlinks=False):
  for n in dirs:assert not(pathlib.Path(root)/n).is_symlink()
  for n in names:
   q=pathlib.Path(root)/n;s=q.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1
   out[str(q.relative_to(P))]=[s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
 return out
before=identities();assert len(before)==5597 and sum(v[4]for v in before.values())==261120585
save(E,"stage-files-before.json",js(before))
for rel in targets:
 q=P/rel;assert q.resolve(strict=True)==q and q.is_dir()and not list(q.iterdir())
 parent=os.open(q.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.rmdir(q.name,dir_fd=parent)
 finally:os.close(parent)
after=identities();assert after==before
save(E,"stage-files-after.json",js(after))
oldp=R/"R1-payload-scope-static-review-input-v2/prepare_scope_and_scan.py";old=oldp.read_text()
assert len(old.encode())==4994 and hashlib.sha256(old.encode()).hexdigest()=="c9bf8f7d90440f36ec0608f0b714cc4a445b5745b8460cbbce0e47d61b0be012"
new=inp["scope_v3_program"];assert new==old.replace("R1-payload-scope-static-review-input-v2/prepare_scope_and_scan.py","R1-payload-scope-static-review-input-v3/prepare_scope_and_scan.py").replace("frozen-execution-payload-2a8646-content-v1/frozen-execution-payload-manifest-v1.json","frozen-execution-payload-2a8646-content-v2/frozen-execution-payload-manifest-v1.json")
compile(new,"prepare_scope_and_scan.py","exec",optimize=0)
V=R/"R1-payload-scope-static-review-input-v3";V.mkdir(mode=0o700,exist_ok=False)
vp=save(V,"prepare_scope_and_scan.py",new.encode())
save(V,"precise-v2-to-v3.patch","".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=str(oldp),tofile=vp["path"])).encode())
prep={"program":vp,"only_changes":["__file__ fixed V3 producer path","P successful freeze target content-v2; original content-v1 HOLD preserved"],"scope_code_executed":False,"compiled_without_execution":True}
save(V,"preparation.json",js(prep))
summary={"schema":"trnm-owned-stage-empty-directory-correction-v1","status":"CORRECTED","removed_only_empty_owned_stage_directories":targets,"all_5597_file_identities_unchanged":True,"files":5597,"bytes":261120585,"source_and_Git_untouched":True,"original_HOLD_directory_preserved":str(fail.parent),"scope_v3_prepared":vp}
pin=save(E,"summary.json",js(summary));print(json.dumps({"summary":pin,**summary}),flush=True)
