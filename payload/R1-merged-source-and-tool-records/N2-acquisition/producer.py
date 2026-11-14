import hashlib,json,pathlib,sys,types
assert not sys.flags.optimize
R=pathlib.Path("/private/tmp/chain-consolidation-20261114-root");p=R/"root_merge_helpers.py";b=p.read_bytes();assert hashlib.sha256(b).hexdigest()=="036e26a81ce1a41a5440984eeb211707b597bd0a2808488b84b5c8cb609061fd"
h=types.ModuleType("root_merge_helpers");exec(compile(b,str(p),"exec"),h.__dict__);h.setup("concurrent-head-096c6b-acquisition-v1");(h.ev/"producer.py").write_text(sys.argv[1]);h.env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_TERMINAL_PROMPT="0",PYTHONOPTIMIZE="0")
root_head="1e54c4ff66a92827c83bea8715f59f6b299e98cf";root_tree="2c0716f9165f7cbc31ce8eae17f17bf2643d30cb";old="5a4b7fe8de1adce803184f262fd9f704ead1930c";new="096c6b5f9b952c49389fd975515744074ba61317"
s={"schema":"trnm-concurrent-head-096c6b-acquisition-v1","root_head":root_head,"root_tree":root_tree,"previous_remote_head":old,"observed_remote_head":new,"steps":h.steps,"errors":[],"status":"HOLD","source_or_branch_mutation":False,"remote_mutation":False}
def save():(h.ev/"summary.json").write_text(json.dumps(s,indent=2,sort_keys=True)+"\n")
save()
try:
 assert h.git("rev-parse","HEAD").decode().strip()==root_head and h.git("rev-parse","HEAD^{tree}").decode().strip()==root_tree
 assert h.run("status-before",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 h.run("preflight-audit",["bash","scripts/project-preflight.sh","--audit"])
 assert h.git("remote","get-url","origin").decode().strip()=="https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"
 h.run("fetch-exact-observed-object",["git","fetch","--no-tags","--no-recurse-submodules","--no-write-fetch-head","--no-auto-maintenance","origin",new],timeout=300)
 raw=h.run("raw-new-commit",["git","cat-file","commit",new]).stdout;assert hashlib.sha1(b"commit "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==new
 headers=raw.split(b"\n\n",1)[0].splitlines();parents=[x[7:].decode() for x in headers if x.startswith(b"parent ")];tree=[x[5:].decode()for x in headers if x.startswith(b"tree ")];assert len(tree)==1
 ancestors=h.run("old-is-ancestor",["git","merge-base","--is-ancestor",old,new],allowed=(0,1))
 bases=h.run("root-merge-bases",["git","merge-base","--all",root_head,new],allowed=(0,1)).stdout.decode().splitlines()
 commits=h.run("bounded-new-commits",["git","rev-list","--max-count=101",new,"^"+old]).stdout.decode().splitlines();assert len(commits)<=100
 paths=h.run("changed-paths",["git","diff","--name-only","--no-renames",old,new]).stdout.decode().splitlines();assert len(paths)<=200
 h.run("diff-stat",["git","diff","--stat","--no-renames",old,new])
 h.run("diff-numstat",["git","diff","--numstat","--no-renames",old,new])
 assert h.git("rev-parse","HEAD").decode().strip()==root_head and h.git("rev-parse","HEAD^{tree}").decode().strip()==root_tree
 assert h.run("status-after",["git","status","--porcelain=v1","--untracked-files=all"]).stdout==b""
 s.update(status="EXACT_OBSERVED_HEAD_ACQUIRED_FOR_REVIEW",new_tree=tree[0],parents=parents,old_is_ancestor=ancestors.returncode==0,root_merge_bases=bases,new_commits=commits,changed_paths=paths,changed_path_count=len(paths),source_head_tree_status_unchanged=True)
except BaseException as ex:s["errors"].append(type(ex).__name__+": "+str(ex))
finally:save()
print(json.dumps({k:v for k,v in s.items() if k!="steps"}),flush=True);raise SystemExit(0 if not s["errors"] else 1)
