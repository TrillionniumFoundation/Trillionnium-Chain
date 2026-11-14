import json,pathlib,zipfile,hashlib,io,os,sys
E=pathlib.Path("/private/tmp/chain-R1-required-queue-diagnosis-20261114-v1")
D=pathlib.Path("/private/tmp/chain-R1-w1-fresh-service-source-review-20261114-v1/artifact-readback-v1")
def H(tag,data):
 h=hashlib.sha256();h.update(b"TRNM-PON1\0");h.update(len(tag).to_bytes(2,"little"));h.update(tag);h.update(len(data).to_bytes(4,"little"));h.update(data);return h.hexdigest()
def encode(obj):return json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()
out=[]
for kind,aid,zsha in [("head",14117751904,"b77dd9120901f5e4d3ccdd21be7f307fecabedabaca28a9d3c3d184d867d6ef8"),("prospective-merge",14117403147,"2f13596450302835bcaf325d3b2364b95d1eeb6abe9f25dbc353a1efc4f2802a")]:
 raw=(E/"R1-W1-complete-artifacts-v1"/(str(aid)+".zip")).read_bytes();assert hashlib.sha256(raw).hexdigest()==zsha
 manifest=json.loads((E/"R1-W1-inner-originals-v1"/str(aid)/"fresh-service"/"manifest.json").read_bytes())
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  for variant in ["original","fresh"]:
   rb=z.read("fresh-service/"+variant+"/report.json");assert hashlib.sha256(rb).hexdigest()==manifest["files"][variant+"/report.json"];d=json.loads(rb)
   for pi,p in enumerate(d["phases"]):
    offset=p["business_receive_clock"]["traffic_epoch_in_observer_ns"];assert type(offset) is int
    expected_first=H(b"public-request-body-v3",encode({"op":"submit","packet":d["signed_honest_packets"][0]}));assert expected_first==p["business_receive_clock"]["first_business_packet_body_digest"]
    rs=p["observations"]["records"];rows=[]
    for cat in ["honest_submissions","honest_history"]:
     for ci,c in enumerate(p[cat]):
      req={"op":"submit","packet":d["signed_honest_packets"][c["packet_index"]]} if cat=="honest_submissions" else {"op":"history","tip":c["request"]["tip"],"after":c["request"]["after"]}
      body=H(b"public-request-body-v3",encode(req))
      matches=[(ri,r) for ri,r in enumerate(rs) if isinstance(r.get("body_digest"),list) and bytes(r["body_digest"]).hex()==body and isinstance(r.get("lifecycle"),dict) and c["started_ns"]+offset<=r["lifecycle"]["accepted_ns"]<=c["ended_ns"]+offset]
      assert len(matches)==1,(kind,variant,pi,cat,ci,len(matches));ri,r=matches[0]
      client={k:v for k,v in c.items() if k not in ["response","request"]}
      rows.append({"category":cat,"call_index":ci,"client_pointer":"/phases/"+str(pi)+"/"+cat+"/"+str(ci),"server_pointer":"/phases/"+str(pi)+"/observations/records/"+str(ri),"wire_body_sha256_domain_digest":body,"client":client,"server":r,"observer_epoch_offset_ns":offset})
    out.append({"kind":kind,"member":"fresh-service/"+variant+"/report.json","report_sha256":hashlib.sha256(rb).hexdigest(),"phase":pi,"mode":p["mode"],"rows":rows})
b=(json.dumps({"schema":"trnm-R1-w1-exact-client-server-request-stage-binding-v1","matching":"Exact production H(public-request-body-v3, serde enum field ordering) + accepted timestamp inside each client interval after original observer epoch mapping; first body digest independently equals original business_receive_clock.","production_hash_source_sha256":"ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b","phases":out},indent=2,sort_keys=True)+"\n").encode();assert len(b)<2*1024*1024
with (D/"client-server-stage-binding.json").open("xb") as f:f.write(b);f.flush();os.fsync(f.fileno())
with (D/"client-server-stage-binding-producer.py").open("x") as f:f.write(sys.argv[1])
print(json.dumps({"path":str(D/"client-server-stage-binding.json"),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}))
for p in out:
 if p["phase"]!=1:continue
 rows=[]
 for r in p["rows"]:
  c,s=r["client"],r["server"];phases={p["phase"]:p for p in s["submit_phases"] if p["started"]}
  ms=lambda x: None if x is None else round(x/1e6,6)
  rows.append({"cat":r["category"],"index":r["call_index"],"start_ms":ms(c["started_ns"]),"end_ms":ms(c["ended_ns"]),"client_cpu_ms":ms(c["client_thread_cpu_ns"]),"client_stages_ms":{k:ms(v) for k,v in c["metrics"].items() if k.endswith("_ns")},"server_connection":s["connection_id"],"server_challenge_ms":ms(s["challenge_wait"]["wall_ns"]),"server_grant_ms":ms(s["grant_wait"]["wall_ns"]),"server_queue_ms":ms(s["paid_task_queue_wait"]["wall_ns"]),"server_dispatch_cpu_ms":ms(s["dispatch_thread_cpu_ns"]),"server_cpu_wait_ms":ms(phases.get("cpu_wait",{}).get("wall_ns")),"server_phases":[{"phase":k,"wall_ms":ms(v["wall_ns"]),"cpu_ms":ms(v["thread_cpu_ns"])} for k,v in phases.items()],"server_io_frames":s["reactor_io"]["frames"]})
 print(json.dumps({"kind":p["kind"],"member":p["member"],"rows":rows},sort_keys=True))
