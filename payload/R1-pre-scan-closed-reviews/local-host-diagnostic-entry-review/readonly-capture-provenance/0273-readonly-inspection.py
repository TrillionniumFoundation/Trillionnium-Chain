import hashlib,json,os,pathlib,stat,subprocess,zipfile
E=pathlib.Path("/private/tmp/chain-R1-local-host-diagnostic-entry-review-20261114-v1");O=E/"host-ownership-and-N-results-v1";O.mkdir(exist_ok=False)
D="/private/tmp/chain-audit-recovery-records-20261113/full-history-independent-v1/complete.git";H="2a86462a1ab20c68151719ba4635e3c294391e64"
env=os.environ.copy()
for k in list(env):
 if k.startswith("GIT_TRACE") or k=="GIT_CURL_VERBOSE":env.pop(k,None)
env.update(GIT_NO_REPLACE_OBJECTS="1",GIT_NO_LAZY_FETCH="1",GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0",GIT_ALLOW_PROTOCOL="",GIT_PAGER="cat",GIT_TRACE2="0",GIT_TRACE2_EVENT="0",GIT_TRACE2_PERF="0")
argv=["/usr/bin/git","--git-dir="+D,"-c","protocol.allow=never","grep","-n","-e","trnmponpublic.slice","-e","fn host_eligibility","-e","HostEligibility","-e","fn acquire","-e","fn new(","-e","HOST_",H,"--","trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs","trillionnium/crates/trnm-pon-node/src/ingress/host.rs","trillionnium/crates/trnm-pon-node/src/ingress/public_host.rs"]
c=subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
(O/"host-locations.stdout").write_bytes(c.stdout);(O/"host-locations.stderr").write_bytes(c.stderr)
(O/"git-commands.json").write_text(json.dumps([{"argv":argv,"exit":c.returncode,"stdout_sha256":hashlib.sha256(c.stdout).hexdigest()}],indent=2)+"\n")
B=pathlib.Path("/private/tmp/chain-N-protocol-43582713392-readonly-20261114-v1/official-complete-artifacts-v1")
results=[]
for aid in ["14111407094","14111816359"]:
 zp=B/(aid+".zip")
 with os.fdopen(os.open(zp,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb") as stream:
  a=os.fstat(stream.fileno());assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<16*1024*1024
  full=stream.read();assert len(full)==a.st_size
  stream.seek(0)
  with zipfile.ZipFile(stream) as z:
   names=z.namelist();assert len(names)==len(set(names)) and len(names)<=200
   namesel=[n for n in names if n.endswith("from-zero-native/confirmation/report.json")]
   assert len(namesel)==1,namesel
   n=namesel[0];info=z.getinfo(n);assert 0<info.file_size<=32*1024*1024
   raw=z.read(n);assert len(raw)==info.file_size
   doc=json.loads(raw)
   phases=[]
   for ph in doc["phases"]:
    scalar={k:v for k,v in ph.items() if v is None or isinstance(v,(bool,int,float,str))}
    arrays={k:len(v) for k,v in ph.items() if isinstance(v,list)}
    replays=ph.get("independent_history_page_replay",[])
    rows=[]
    for rp in replays:
     item={k:v for k,v in rp.items() if k!="native_import_observation"}
     obs=rp.get("native_import_observation")
     if isinstance(obs,dict):
      item["native_import_observation_keys"]=sorted(obs)
      item["native_import_observation"]=obs
     rows.append(item)
    phases.append({"scalars":scalar,"array_counts":arrays,"verification_errors":ph.get("verification_errors"),"honest_submissions":[{k:v for k,v in row.items() if k not in ("request","response","client_cpu_observation")} for row in ph.get("honest_submissions",[])],"honest_history":[{k:v for k,v in row.items() if k not in ("request","response","client_cpu_observation")} for row in ph.get("honest_history",[])],"replays":rows,"independent_final_confirmation_stage":ph.get("independent_final_confirmation_stage"),"initial_meter":ph.get("initial_meter"),"final_meter":ph.get("final_meter"),"service":ph.get("service")})
   results.append({"artifact":aid,"zip_path":str(zp),"zip_bytes":len(full),"zip_sha256":hashlib.sha256(full).hexdigest(),"report_member":n,"report_bytes":len(raw),"report_sha256":hashlib.sha256(raw).hexdigest(),"report_top_scalars":{k:v for k,v in doc.items() if v is None or isinstance(v,(bool,int,float,str))},"phases":phases})
  b=os.fstat(stream.fileno());assert (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)
out=O/"N-confirmation-phase-extract.json";out.write_text(json.dumps(results,sort_keys=True,indent=2)+"\n")
print(json.dumps({"host_locations":c.stdout.decode(),"summary_path":str(out),"bytes":out.stat().st_size,"sha256":hashlib.sha256(out.read_bytes()).hexdigest(),"results":[{"artifact":r["artifact"],"zip_sha256":r["zip_sha256"],"report_member":r["report_member"],"report_sha256":r["report_sha256"],"phases":[{"mode":p["scalars"].get("mode"),"business_start":p["scalars"].get("business_started_ns"),"confirm":p["scalars"].get("confirmation_ended_ns"),"replays":[{k:v for k,v in x.items() if k!="native_import_observation"} for x in p["replays"]]} for p in r["phases"]]} for r in results]},sort_keys=True))
