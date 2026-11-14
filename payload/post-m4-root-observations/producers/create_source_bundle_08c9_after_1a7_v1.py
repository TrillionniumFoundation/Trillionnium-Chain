import pathlib,hashlib,json,sys
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");assert hashlib.sha256((R/"root_merge_helpers.py").read_bytes()).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
sys.path.insert(0,str(R));import root_merge_helpers as h
h.setup("source-bundle-08c9-after-1a7-v1")
HEAD="08c9becab740ab2c375b970f376a7638f44c9e8e";TREE="036868dfcc953b6f5574c627e0027c3d4e2d3523";BASE="1a7afcdb820b051d1e4bfde3d436f96fc050c487"
assert h.git("rev-parse","HEAD").decode().strip()==HEAD and h.git("rev-parse","HEAD^{tree}").decode().strip()==TREE and not h.git("status","--porcelain","--untracked-files=all").strip()
h.run("preflight",["bash","scripts/project-preflight.sh","--audit"])
bundle=h.ev/"closed-exec-gate-08c9beca-after-1a7afcdb.bundle"
h.run("create-bounded-bundle",["git","bundle","create","--version=2",str(bundle),"HEAD","^"+BASE])
h.run("verify-bundle",["git","bundle","verify",str(bundle)])
b=bundle.read_bytes();assert len(b)<1024*1024 and b.startswith(b"# v2 git bundle\n")
lines=b.split(b"\n\n",1)[0].splitlines()[1:]
prereqs=[x[1:].split(b" ",1)[0].decode() for x in lines if x.startswith(b"-")]
heads=[x.decode().split(" ",1) for x in lines if not x.startswith(b"-")]
assert prereqs==[BASE] and heads==[[HEAD,"HEAD"]]
listed=h.git("bundle","list-heads",str(bundle));(h.ev/"list-heads.log").write_bytes(listed)
assert listed.decode().strip()==HEAD+" HEAD"
assert not h.git("status","--porcelain","--untracked-files=all").strip()
r={"schema":"root-bounded-source-followup-bundle-v1","head":HEAD,"tree":TREE,"prerequisites":prereqs,"advertised_heads":heads,"archive_history_included":False,"source_clean":True,"bundle":{"path":str(bundle),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()},"steps":h.steps}
v=(json.dumps(r,indent=2)+"\n").encode();(h.ev/"summary.json").write_bytes(v);print(json.dumps({"summary":str(h.ev/"summary.json"),"summary_bytes":len(v),"summary_sha256":hashlib.sha256(v).hexdigest(),**r}),flush=True)
