import hashlib,json,os,pathlib,subprocess
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1");O=E/"kernel-host-contract-v1";O.mkdir(exist_ok=False)
D="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";H="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_PAGER="cat",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0")
idx=[]
for path in ["trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs","trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs"]:
 a=["/usr/bin/git","--git-dir="+D,"-c","protocol.allow=never","cat-file","blob",H+":"+path]
 c=subprocess.run(a,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);assert c.returncode==0
 p=O/(path.replace("/","--")+".raw");p.write_bytes(c.stdout);(O/(p.name+".stderr")).write_bytes(c.stderr)
 idx.append({"path":path,"capture":str(p),"argv":a,"exit":c.returncode,"git_oid":hashlib.sha1(b"blob "+str(len(c.stdout)).encode()+b"\0"+c.stdout).hexdigest(),"bytes":len(c.stdout),"sha256":hashlib.sha256(c.stdout).hexdigest()})
 lines=c.stdout.decode().splitlines()
 if path.endswith("host_kernel_parent.rs"):
  ranges=[(1,620),(1550,len(lines))]
 else:ranges=[(1,len(lines))]
 out="\n\n".join("\n".join(f"{i+1}: {lines[i]}" for i in range(a-1,min(b,len(lines)))) for a,b in ranges)+"\n"
 (O/(path.split("/")[-1]+".excerpt.txt")).write_text(out)
a=["/opt/homebrew/bin/rg","-n","-e","kernel_parent","-e","Host","-e","pub fn serve","-e","check_public","-e","claim_public",str(E/"production-host-entry-v1/public-v3.stdout"),str(O/"trillionnium--crates--trnm-pon-node--src--ingress--history_import.rs.raw")]
c=subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
(O/"public-entry-callsite-locations.stdout").write_bytes(c.stdout);(O/"public-entry-callsite-locations.stderr").write_bytes(c.stderr)
(O/"source-index.json").write_text(json.dumps({"head":H,"files":idx,"rg":{"argv":a,"exit":c.returncode}},indent=2)+"\n")
R=json.loads((E/"host-ownership-and-N-results-v1/N-confirmation-phase-extract.json").read_bytes())
rows=[]
for r in R:
 for p in r["phases"]:
  if p["scalars"]["mode"]!="from-zero-pressure":continue
  reps=[]
  for rp in p["replays"]:
   obs=rp["native_import_observation"]
   d={k:rp[k] for k in ("history_call_index","replay_started_ns","replay_ended_ns","replay_wall_ns","replay_thread_cpu_ns","replay_accepted","replay_error")}
   d["summary_keys"]={k:{"type":type(v).__name__,"length":len(v) if isinstance(v,(list,dict)) else None} for k,v in obs.items()}
   d["phase_top"]=obs.get("phases")
   d["host_checks_top"]=obs.get("host_checks")
   if isinstance(d["host_checks_top"],list):d["host_checks_top"]=d["host_checks_top"][:1]
   d["host_attribution"]=obs.get("host_checkpoint_attribution")
   d["native_attribution"]=obs.get("native_attribution")
   reps.append(d)
  rows.append({"artifact":r["artifact"],"report_sha256":r["report_sha256"],"scalars":p["scalars"],"replays":reps,"initial_meter":p["initial_meter"],"final_meter":p["final_meter"]})
(O/"pressure-import-only.json").write_text(json.dumps(rows,indent=2,sort_keys=True)+"\n")
print(json.dumps({"dir":str(O),"files":idx,"locations":c.stdout.decode(),"pressure_extract_bytes":(O/"pressure-import-only.json").stat().st_size},sort_keys=True))
