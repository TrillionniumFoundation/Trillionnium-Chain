import hashlib,json,os,pathlib,sys,types
assert sys.flags.optimize==0
root=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");helper=root/"root_merge_helpers.py"
raw=helper.read_bytes();assert hashlib.sha256(raw).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(raw,str(helper),"exec"),h.__dict__)
h.setup("source-bundle-ed0d35-after-2a6206-v1")
(h.ev/"producer.py").write_text(sys.argv[1])
h.env.update(GIT_NO_LAZY_FETCH="1",GIT_NO_REPLACE_OBJECTS="1",GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0",PYTHONOPTIMIZE="0")
head="ed0d35487f2a67239e4d646fd41c2c7acb5cc740";tree="1aa9c21812489080980bdc3c1c2bb43611e88354";base="2a62061177852dc3ebd200fa8d7c66c661a119a1"
record={"schema":"trnm-exact-source-delta-bundle-v1","head":head,"tree":tree,"excluded_base":base,"status":"HOLD","steps":h.steps,"errors":[],"source_or_ref_mutation":False}
def save():(h.ev/"summary.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.git("rev-parse","HEAD").decode().strip()==head and h.git("rev-parse","HEAD^{tree}").decode().strip()==tree
 assert h.run("source-status-before",["git","status","--porcelain","--untracked-files=all"],timeout=60).stdout==b""
 h.run("preflight",["bash","scripts/project-preflight.sh","--audit"],timeout=900)
 h.run("base-is-ancestor",["git","merge-base","--is-ancestor",base,head],timeout=60)
 bundle=h.ev/"concurrent-ed0d3548-after-2a620611.bundle"
 h.run("create-bounded-bundle",["git","bundle","create",str(bundle),"HEAD","^"+base],timeout=300)
 data=bundle.read_bytes();assert 0<len(data)<=64*1024*1024
 header=data.split(b"\n\n",1)[0].decode();(h.ev/"bundle-header.txt").write_text(header+"\n")
 h.run("verify-bundle",["git","bundle","verify",str(bundle)],timeout=120)
 assert h.run("list-heads",["git","bundle","list-heads",str(bundle)],timeout=60).stdout.decode().splitlines()==[head+" HEAD"]
 assert h.git("rev-parse","HEAD").decode().strip()==head and h.git("rev-parse","HEAD^{tree}").decode().strip()==tree
 assert h.run("source-status-after",["git","status","--porcelain","--untracked-files=all"],timeout=60).stdout==b""
 record.update(status="CREATED_AND_VERIFIED",bundle={"path":str(bundle),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},header=header,source_head_tree_status_unchanged=True)
except Exception as e:record["errors"].append(type(e).__name__+": "+str(e))
finally:save()
print(json.dumps(record),flush=True)
raise SystemExit(0 if not record["errors"] else 1)
