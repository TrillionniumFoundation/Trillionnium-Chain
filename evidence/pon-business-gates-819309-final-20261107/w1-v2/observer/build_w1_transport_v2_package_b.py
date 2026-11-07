from pathlib import Path
from datetime import datetime,timezone
import gzip,hashlib,io,json
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107");D=R/"w1-components-transport-v2";V=R/"w1-components-metadata-package-v1";P=R/"w1-components-transport-v2-package"
H="819309fd312298e099642e1253b1d4ba07113e98";B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0";M="28df21f965e0348690836c9c854dab645827a03d";T="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
def req(v,m):
 if not v:raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def write(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("x") as f:
  if isinstance(obj,str):f.write(obj)
  else:json.dump(obj,f,indent=2);f.write("\n")
seal=json.loads((V/"SEAL.json").read_bytes());v1=json.loads((V/"W1_CORE.json").read_bytes())
req(sha(V/"SHA256SUMS")==seal["sha256sums_sha256"] and sha(V/"W1_CORE.json")==seal["core_sha256"],"v1 seal reference")
s=json.loads((D/"summary-stage1.json").read_bytes());pure=json.loads((D/"summary-pure-v2.json").read_bytes());plan=json.loads((D/"plan.json").read_bytes())
ids=set(plan["artifact_ids"]);req(ids=={r["artifact_id"] for r in v1["rows"] if r["download_timed_out"]} and len(ids)==6,"original timeout-only IDs")
req({r["artifact_id"] for r in s["results"]}==ids and {r["artifact_id"] for r in pure["rows"]}==ids,"six complete observation denominators")
req(s["identity_unchanged"] is True and s["plan"]==plan and pure["no_native_executed"] is True,"actual identity and pure observer scope")
req(sha(V/"SEAL.json")==plan["v1_seal_sha256"],"predeclared v1 seal unchanged")
v1_file_hashes={line.split("  ",1)[1]:line.split("  ",1)[0] for line in (V/"SHA256SUMS").read_text().splitlines()}
sr={r["artifact_id"]:r for r in s["results"]};pr={r["artifact_id"]:r for r in pure["rows"]}
plans=[]
def add(src,rel):
 src=Path(src);rel=Path(rel);req(src.is_file() and not src.is_symlink(),"regular copy source")
 req(src.stat().st_size<=32*1024**2 and not rel.is_absolute() and ".." not in rel.parts,"bounded copy path")
 plans.append((src,rel))
external=[];new_native_processes=0
for ident in sorted(ids):
 row=sr[ident];d=D/str(ident);a=row["metadata"];dl=row.get("download");z=d/"artifact.zip"
 if dl:
  req(z.is_file() and not z.is_symlink() and z.stat().st_size==dl["bytes"] and sha(z)==dl["sha256"],"v2 retained original/partial bytes unchanged")
 external.append({"artifact_id":ident,"zip_get_attempted":row["zip_get_attempted"],"archive_path":str(z) if dl else None,"actual_bytes":dl["bytes"] if dl else None,"actual_sha256":dl["sha256"] if dl else None,"github_expected_bytes":a["size_in_bytes"],"github_expected_digest":a["digest"],"authenticated_complete":row["archive_authenticated"],"download_timed_out":dl["timed_out"] if dl else None,"download_exit_code":dl["exit_code"] if dl else None,"download_error":dl["error"] if dl else None,"rehashed_at_seal":bool(dl),"included_in_small_package":False})
 for p in sorted(d.iterdir()):
  if p.is_file() and p.name!="artifact.zip":add(p,Path("artifacts")/str(ident)/p.name)
 if row["archive_authenticated"]:
  inv={i["name"]:i for i in row["archive_inventory"]}
  for p in sorted((d/"members").iterdir()):
   if p.is_file():
    req(p.name in inv and sha(p)==inv[p.name]["sha256"],"retained source/control changed")
    add(p,Path("artifacts")/str(ident)/"members"/p.name)
  for m in row.get("manifests",[]):
   p=Path(m["path"]);req(sha(p)==m["manifest_sha256"],"retained original native manifest changed")
   add(p,Path("artifacts")/str(ident)/"members"/m["member"])
 if pr[ident]["status"]=="COMPONENT_READBACK_COMPLETE":
  p=d/"readback-pure-v2.json";r=json.loads(p.read_bytes());new_native_processes+=sum(m["original_total_processes"] for m in r["manifests"])
for name in ("plan.json","summary-stage1.json","summary-pure-v2.json","identity-before.json","identity-before.json.stderr","identity-after.json","identity-after.json.stderr"):
 add(D/name,Path("observation")/name)
for name in ("read_w1_artifacts_transport_v2_819.py","run_w1_pure_transport_v2_819.py","read_w1_pure_records_819_v2.py","build_w1_transport_v2_package.py","build_w1_transport_v2_package_b.py","w1-transport-v2-authoritative-receipts.json"):
 add(R/name,Path("observer")/name)
for name in ("W1_CORE.json","SEAL.json","SHA256SUMS","EXTERNAL_ARCHIVES.json"):
 add(V/name,Path("v1-reference")/name)
rows=[];old_native_processes=0
for old in v1["rows"]:
 ident=old["artifact_id"];new=pr.get(ident);stage=sr.get(ident);selected=bool(new and new["status"]=="COMPONENT_READBACK_COMPLETE")
 status=new["status"] if new else old["pure_reader_status"];known=status=="COMPONENT_READBACK_COMPLETE"
 row={k:old[k] for k in ("artifact_id","job_id","family","arch","source_kind","tested_commit","github_job_conclusion")}
 row.update(v1_independent_status=old["pure_reader_status"],v1_download_timed_out=old["download_timed_out"],transport_v2_attempted=stage["zip_get_attempted"] if stage else False,transport_v2_independent_status=new["status"] if new else "NOT_ELIGIBLE_V1_COMPLETE",transport_v2_download_timed_out=stage.get("download",{}).get("timed_out") if stage else None,final_independent_status=status,selected_evidence_version=("transport-v2" if selected else "v1") if known else "NONE",native_campaigns_verified=new.get("native_campaign_commands",0) if selected else old["native_campaigns_verified"],native_manifests_verified=new.get("native_manifests",0) if selected else old["native_manifests_verified"],unknown=not known)
 row["v1_archive_source_manifest_verified"]=old["archive_source_manifest_verified"]
 row["transport_v2_archive_source_manifest_verified"]=(stage["archive_authenticated"] and stage["source_bound"] and stage["manifest_hashes_complete"] and not stage["errors"]) if stage else None
 rows.append(row)
 if old["pure_reader_status"]=="COMPONENT_READBACK_COMPLETE":
  rel=Path("artifacts")/str(ident)/"readback-pure-v2.json";q=V/rel
  req(sha(q)==v1_file_hashes[rel.as_posix()],"frozen v1 original process readback digest")
  report=json.loads(q.read_bytes());old_native_processes+=sum(m["original_total_processes"] for m in report["manifests"])
core={"schema":"trnm-final819-w1-transport-v2-combined-coverage","qualification":"HOLD","candidate":H,"base":B,"prospective_merge":M,"tree":T,"workflow_run":42402618462,"event":"push","attempt":1,"github_component_jobs_success":20,"full_workflow_jobs":{"total":37,"success":26,"failure":11},"full_native_lanes":{"total":34,"success":24,"failure":10},"v1":{"independent_component_readbacks":14,"unknown":6,"seal_sha256":sha(V/"SEAL.json"),"frozen_unchanged":True},"transport_v2":{"eligible_artifacts":6,"zip_gets_attempted":s["attempted"],"independent_component_readbacks":pure["complete_component_readbacks"],"unknown":pure["unknown"],"non_timeout_error_stop":s["stop_on_non_timeout_error_triggered"],"archive_timeout_seconds":900,"attempts_per_selected_artifact":1,"maximum_parallel_downloads":2},"final_independent_component_readbacks":sum(not r["unknown"] for r in rows),"final_unknown":sum(r["unknown"] for r in rows),"native_campaign_commands_verified":sum(r["native_campaigns_verified"] for r in rows),"native_manifest_count_verified":sum(r["native_manifests_verified"] for r in rows),"original_process_records_verified_including_identity_and_build":old_native_processes+new_native_processes,"rows":rows,"all_original_business_and_hardness_scope_flags_retained":True,"no_ci_or_native_execution":True,"business_gate_conclusion_unchanged":"HOLD","observer_metadata_addendum":"Original pure-driver stage1_status is null because that ancillary field read a nonexistent status key. Actual stage1 coverage_status and archive/source/manifest booleans are retained and govern the coverage shown here; no native result or denominator depended on that null field. Original receipts are unchanged.","missing_historical_artifact_11531476198":"UNKNOWN; no substitute"}
req(len(rows)==20 and core["final_independent_component_readbacks"]+core["final_unknown"]==20,"complete combined artifact denominator")
prepared=[]
for src,rel in plans:
 data=src.read_bytes();orig_hash=hashlib.sha256(data).hexdigest();orig_bytes=len(data);encoding="identity"
 if len(data)>256*1024:
  buf=io.BytesIO()
  with gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=buf,mtime=0) as gz:gz.write(data)
  packed=buf.getvalue();req(gzip.decompress(packed)==data,"lossless metadata gzip");data=packed;encoding="gzip-mtime0-level1";rel=Path(str(rel)+".gz")
 prepared.append((src,rel,data,orig_hash,orig_bytes,encoding))
req(len({p.as_posix() for _,p,_,_,_,_ in prepared})==len(prepared),"no copy collisions")
req(sum(len(b) for _,_,b,_,_,_ in prepared)<=64*1024**2,"small metadata bound")
P.mkdir();files=[]
for src,rel,data,h,n,encoding in prepared:
 p=P/rel;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("xb") as f:f.write(data)
 digest=hashlib.sha256(data).hexdigest();req(sha(p)==digest,"copied bytes")
 files.append({"path":rel.as_posix(),"source":str(src),"source_bytes":n,"source_sha256":h,"encoding":encoding,"bytes":len(data),"sha256":digest})
write(P/"W1_COVERAGE.json",core);write(P/"EXTERNAL_ARCHIVES.json",external);write(P/"FILES.json",files)
write(P/"README.md","""# 819309f W1 — authorized transport-v2 supplement

**Business acceptance remains HOLD.** This is a read-only retrieval supplement to the frozen W1 v1 package. No CI or native work was rerun.

The candidate is `819309fd312298e099642e1253b1d4ba07113e98`, base `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`, ordered merge `28df21f965e0348690836c9c854dab645827a03d`, tree `f9d63abb9e2931fd78e26ccb87e3a7955068f267`. All records belong to original W1 run `42402618462`, real push attempt 1, ProfHepta.

## Complete coverage and preserved failures

[W1_COVERAGE.json](W1_COVERAGE.json) retains all 20 component lanes and distinguishes the original 20/20 GitHub job successes, v1 14 complete / 6 UNKNOWN, each eligible transport-v2 attempt, and final independent artifact/native-record coverage. The original v1 six 240-second transfer failures and partial ZIPs remain unchanged. [v1-reference/](v1-reference/) binds that frozen package.

Only those six exact timeout-affected artifact IDs were eligible for one additional GET each, with a separately declared 900-second observer limit and at most two parallel transfers. The plan was saved before the GETs. Identity was verified as ProfHepta before and after. A non-timeout integrity, identity or transfer failure stops new GETs; already in-flight observations remain retained. There is no retry-until-green policy.

Complete ZIPs must match the original GitHub byte count and SHA256, then pass the same internal manifest, H/M source/context, ELF/binary identity and original native process record checks. The exact same pinned pure-reader wrapper is used; its original reader result must match the retained manifest. Transfer or reader UNKNOWN is never renamed a native failure or a business success.

## Retained evidence

The original pure-driver rows contain an ancillary `stage1_status: null` because the helper read `status` rather than the actual `coverage_status` key. This field was never used for gating: the wrapper required the authenticated archive/source/manifest booleans before importing any original reader. This supplement explicitly records those actual booleans and preserves the original rows unchanged. No native outcome, coverage count or business criterion is changed.

[artifacts/](artifacts/) contains original source receipts, native manifests, logs and independent readbacks. [observation/](observation/) holds the exact transfer plan and full summaries. [observer/](observer/) preserves scripts and authoritative job outcomes. Text above 256 KiB is stored as lossless level-1, zero-timestamp gzip; [FILES.json](FILES.json) records original and packed sizes/hashes and every compression was decompressed and checked.

Original full or partial ZIPs stay in the durable external directory. [EXTERNAL_ARCHIVES.json](EXTERNAL_ARCHIVES.json) records their exact paths, original GitHub identities, observed byte counts and SHA256; each was rehashed at this seal. The original binaries and large native stdout remain inside those original ZIPs, not in this metadata-only supplement.

The separate 14-core package is unchanged: original service/fresh pressure confirmation remains 0/1; History confirmer activation remains genesis; four State lanes pass their own controls. Source or Host success and component record consistency do not satisfy these business gates. The 4-second service window, 30-second import deadline and 1800-second server lifetime are unchanged. No production TPS, hardness, full-system performance or COW claim is established. Historical artifact `11531476198` remains UNKNOWN and is not replaced.

[SHA256SUMS](SHA256SUMS) covers the payload; [SEAL.json](SEAL.json) records this supplement independently from v1. Copy the full directory and retain both sealed versions.
""")
payload=[p for p in sorted(P.rglob("*")) if p.is_file()]
with (P/"SHA256SUMS").open("x") as f:
 for p in payload:f.write(sha(p)+"  "+p.relative_to(P).as_posix()+"\n")
out={"schema":"trnm-final819-w1-transport-v2-package-seal","sealed_utc":datetime.now(timezone.utc).isoformat(),"candidate":H,"payload_files":len(payload),"payload_bytes":sum(p.stat().st_size for p in payload),"sha256sums_sha256":sha(P/"SHA256SUMS"),"coverage_sha256":sha(P/"W1_COVERAGE.json"),"coverage_bytes":(P/"W1_COVERAGE.json").stat().st_size,"v1_seal_sha256":sha(V/"SEAL.json"),"external_archive_count":len(external),"external_observed_bytes":sum(x["actual_bytes"] or 0 for x in external),"final_independent_readbacks":core["final_independent_component_readbacks"],"final_unknown":core["final_unknown"],"native_campaign_commands":core["native_campaign_commands_verified"],"original_total_process_records":core["original_process_records_verified_including_identity_and_build"]}
write(P/"SEAL.json",out)
print(json.dumps({"directory":str(P),"seal":out,"seal_sha256":sha(P/"SEAL.json")}),flush=True)
