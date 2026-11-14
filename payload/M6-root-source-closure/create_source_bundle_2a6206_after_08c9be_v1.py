import pathlib,hashlib,json,sys
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");assert hashlib.sha256((R/"root_merge_helpers.py").read_bytes()).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
sys.path.insert(0,str(R));import root_merge_helpers as h
h.setup("source-bundle-2a6206-after-08c9be-v1")
HEAD="2a62061177852dc3ebd200fa8d7c66c661a119a1";TREE="f8d170ff75990e879e93888a95e5408f36b36f6c";BASE="08c9becab740ab2c375b970f376a7638f44c9e8e"
assert h.git("rev-parse","HEAD").decode().strip()==HEAD and h.git("rev-parse","HEAD^{tree}").decode().strip()==TREE and not h.git("status","--porcelain","--untracked-files=all").strip()
h.run("preflight",["bash","scripts/project-preflight.sh","--audit"])
bundle=h.ev/"collector-count-2a620611-after-08c9beca.bundle"
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
