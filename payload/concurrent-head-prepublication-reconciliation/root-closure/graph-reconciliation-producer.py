import datetime,hashlib,json,os,pathlib,subprocess
ROOT=pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
WT=pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
EV=ROOT/"remote-head-drift-5a4b7f-graph-v1";EV.mkdir(mode=0o700,exist_ok=False)
C0="dc42ce4df5cff79cc61c5addbaf01074b56b06ca";M6="2a62061177852dc3ebd200fa8d7c66c661a119a1";N="5a4b7fe8de1adce803184f262fd9f704ead1930c"
env=dict(os.environ);env.update({"PATH":"/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin","GIT_NO_REPLACE_OBJECTS":"1","GIT_NO_LAZY_FETCH":"1","GIT_OPTIONAL_LOCKS":"0","GIT_TERMINAL_PROMPT":"0"})
steps=[];views={}
commands=[
("head-before",["rev-parse","HEAD"]),
("status-before",["status","--porcelain","--untracked-files=all","--ignore-submodules=none"]),
("common-bases",["merge-base","--all",M6,N]),
("new-range-count",["rev-list","--count",C0+".."+N]),
("new-range-commits",["log","--no-show-signature","--format=%H %T %P%n%s",C0+".."+N]),
("new-range-numstat",["diff","--no-ext-diff","--no-textconv","--no-renames","--numstat",C0,N]),
("new-range-raw",["diff","--no-ext-diff","--no-textconv","--no-renames","--raw","--abbrev=40",C0,N]),
("local-refs-at-new",["for-each-ref","--points-at="+N,"--format=%(refname) %(objectname)"]),
("head-after",["rev-parse","HEAD"]),
("status-after",["status","--porcelain","--untracked-files=all","--ignore-submodules=none"])
]
for label,args in commands:
 q=subprocess.run(["git","--no-replace-objects",*args],cwd=WT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 row={"label":label,"argv":["git","--no-replace-objects",*args],"exit":q.returncode}
 for channel in ("stdout","stderr"):
  raw=getattr(q,channel);p=EV/(label+"."+channel);p.write_bytes(raw);row[channel]={"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
 steps.append(row);assert q.returncode==0,label
 if len(q.stdout)<=262144:views[label]=q.stdout.decode("utf-8")
 else:views[label]="retained raw output too large for terminal"
assert views["head-before"].strip()==M6 and views["head-after"]==views["head-before"] and views["status-before"]==views["status-after"]==""
out={"schema":"trnm-remote-head-drift-fixed-graph-v1","observed_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source_unchanged":True,"network_fetch_or_source_mutation":False,"views":views,"steps":steps}
raw=(json.dumps(out,indent=2)+"\n").encode();(EV/"summary.json").write_bytes(raw)
print(json.dumps({"path":str(EV/"summary.json"),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"views":views}),flush=True)
