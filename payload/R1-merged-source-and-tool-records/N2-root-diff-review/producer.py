import hashlib,json,pathlib,sys,types
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");p=R/"root_merge_helpers.py";b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd";h=types.ModuleType("root_merge_helpers");exec(compile(b,str(p),"exec"),h.__dict__);h.setup("concurrent-head-096c6b-root-diff-review-v1");(h.ev/"producer.py").write_text(sys.argv[1]);h.env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
base="5a4b7fe8de1adce803184f262fd9f704ead1930c";ours="1e54c4ff66a92827c83bea8715f59f6b299e98cf";theirs="096c6b5f9b952c49389fd975515744074ba61317"
assert h.git("rev-parse","HEAD").decode().strip()==ours and not h.git("status","--porcelain=v1","--untracked-files=all")
paths=h.git("diff","--name-only","--no-renames",base,theirs).decode().splitlines();assert len(paths)==7
patch=h.run("N-to-N2-full-diff",["git","diff","--no-ext-diff","--no-textconv","--no-renames",base,theirs]).stdout
rows=[]
for path in paths:
 raw=[h.git("show",c+":"+path)for c in (base,ours,theirs)];rows.append({"path":path,"versions":[{"commit":c,"bytes":len(x),"sha256":hashlib.sha256(x).hexdigest(),"blob":hashlib.sha1(b"blob "+str(len(x)).encode()+b"\0"+x).hexdigest()}for c,x in zip((base,ours,theirs),raw)],"ours_equals_base":raw[0]==raw[1],"ours_equals_theirs":raw[1]==raw[2]})
ours_patch=h.run("N-to-P2-for-seven-diff",["git","diff","--no-ext-diff","--no-textconv","--no-renames",base,ours,"--",*paths]).stdout
assert h.git("rev-parse","HEAD").decode().strip()==ours and not h.git("status","--porcelain=v1","--untracked-files=all")
s={"schema":"trnm-N2-three-way-root-diff-inventory-v1","base":base,"ours":ours,"theirs":theirs,"files":rows,"N_to_N2_diff":{"bytes":len(patch),"sha256":hashlib.sha256(patch).hexdigest()},"N_to_P2_seven_diff":{"bytes":len(ours_patch),"sha256":hashlib.sha256(ours_patch).hexdigest()},"source_unchanged":True}
(h.ev/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n");print(json.dumps(s),flush=True)
