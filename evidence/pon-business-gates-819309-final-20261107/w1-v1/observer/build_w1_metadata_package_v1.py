from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,shutil,sys
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107");D=R/"w1-components-read-v1";P=R/"w1-components-metadata-package-v1"
H="819309fd312298e099642e1253b1d4ba07113e98";M="28df21f965e0348690836c9c854dab645827a03d";B="dd6e1c3cbeacbdc532b0679297835b3a0aac78f0";T="f9d63abb9e2931fd78e26ccb87e3a7955068f267"
IDS={13586332713,13586686618,13586462531,13586043542,13586257049,13586660807,13586108382,13586482467,13586616185,13586791050,13585554366,13586253351,13586134600,13586459476,13586509176,13587135201,13586691635,13586536526,13586467463,13586616233}
def req(v,m):
 if not v:raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def write(p,value):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("x") as f:
  if isinstance(value,str):f.write(value)
  else:json.dump(value,f,indent=2);f.write("\n")
s=json.loads((D/"summary-stage1.json").read_bytes());pure=json.loads((D/"summary-pure-v2.json").read_bytes())
req(s["identity_unchanged"] is True and s["attempted"]==20 and len(s["results"])==20 and {x["artifact_id"] for x in s["results"]}==IDS,"all original stage1 attempts and actual identity")
req(len(pure["rows"])==20 and {x["artifact_id"] for x in pure["rows"]}==IDS and pure["no_native_executed"] and pure["no_retry"],"all original pure-reader outcomes")
pr={x["artifact_id"]:x for x in pure["rows"]};plans=[];external=[];rows=[]
def plan(src,rel):
 src=Path(src);req(src.is_file() and not src.is_symlink(),"regular source "+str(src));req(src.stat().st_size<=8*1024**2,"small metadata file bound "+str(src))
 rel=Path(rel);req(not rel.is_absolute() and ".." not in rel.parts,"safe package path")
 plans.append((src,rel))
for row in sorted(s["results"],key=lambda x:x["artifact_id"]):
 ident=row["artifact_id"];d=D/str(ident);a=row["metadata"];dl=row.get("download",{});p=pr[ident];z=d/"artifact.zip"
 req(z.is_file() and not z.is_symlink() and z.stat().st_size==dl["bytes"] and sha(z)==dl["sha256"],"retained original/partial ZIP changed at seal")
 external.append({"artifact_id":ident,"archive_path":str(z),"actual_bytes":dl["bytes"],"actual_sha256":dl["sha256"],"github_expected_bytes":a["size_in_bytes"],"github_expected_digest":a["digest"],"authenticated_complete":row["archive_authenticated"],"download_timed_out":dl["timed_out"],"download_exit_code":dl["exit_code"],"download_error":dl["error"],"rehashed_at_seal":True,"included_in_small_package":False})
 for q in sorted(d.iterdir()):
  if q.is_file() and q.name!="artifact.zip":plan(q,Path("artifacts")/str(ident)/q.name)
 if row["archive_authenticated"]:
  inventory={i["name"]:i for i in row["archive_inventory"]}
  for q in sorted((d/"members").iterdir()):
   if q.is_file():
    name=q.name
    req(name in inventory and sha(q)==inventory[name]["sha256"],"retained source/context changed")
    plan(q,Path("artifacts")/str(ident)/"members"/name)
  for m in row.get("manifests",[]):
   q=Path(m["path"]);req(sha(q)==m["manifest_sha256"],"original native manifest changed")
   plan(q,Path("artifacts")/str(ident)/"members"/m["member"])
 rows.append({"artifact_id":ident,"job_id":row["job"]["id"],"family":row["family"],"arch":row["arch"],"source_kind":row["source_kind"],"tested_commit":row["tested_commit"],"github_job_conclusion":row["job"]["conclusion"],"archive_source_manifest_verified":row["archive_authenticated"] and row["source_bound"] and row["manifest_hashes_complete"] and not row["errors"],"pure_reader_status":p["status"],"native_campaigns_verified":p.get("native_campaign_commands",0) if p["status"]=="COMPONENT_READBACK_COMPLETE" else 0,"native_manifests_verified":p.get("native_manifests",0) if p["status"]=="COMPONENT_READBACK_COMPLETE" else 0,"download_timed_out":dl.get("timed_out"),"unknown":p["status"]!="COMPONENT_READBACK_COMPLETE","stage1_errors":row["errors"],"pure_errors":p["errors"]})
for name in ("summary-stage1.json","summary-pure-v2.json","identity-before.json","identity-before.json.stderr","identity-after.json","identity-after.json.stderr"):
 plan(D/name,Path("observation")/name)
for name in ("read_w1_artifacts_stage1_819_v1.py","read_w1_pure_records_819_v1.py","read_w1_pure_records_819_v2.py","run_w1_pure_readback_once_819_v2.py","build_w1_metadata_package_v1.py"):
 plan(R/name,Path("observer")/name)
for name in ("w1-observer-receipts-before-seal-v1.json",):
 plan(R/name,Path("observer")/name)
S=R/"20261107T194212Z-819309fd3122-7d6a9641"
plan(S/"snapshot.json","metadata/final-snapshot.json");plan(S/"observer-core-v1.json","metadata/final-observer-core.json")
pins=R/"pinned-readers-819309fd-v1"
for q in sorted(pins.rglob("*")):
 if q.is_file() and q.suffix in (".py",".json",".yml",".yaml") and not any(x in (".git","__pycache__") for x in q.relative_to(pins).parts):plan(q,Path("pinned-readers")/q.relative_to(pins))
req(len({rel.as_posix() for _,rel in plans})==len(plans),"no duplicate payload destination")
req(sum(src.stat().st_size for src,_ in plans)<=64*1024**2,"metadata payload total bound")
P.mkdir()
copied=[]
for src,rel in plans:
 target=P/rel;target.parent.mkdir(parents=True,exist_ok=True);data=src.read_bytes()
 with target.open("xb") as f:f.write(data)
 digest=hashlib.sha256(data).hexdigest();req(sha(target)==digest,"copy digest")
 copied.append({"path":rel.as_posix(),"source":str(src),"bytes":len(data),"sha256":digest})
core={"schema":"trnm-final819-w1-components-core-v1","qualification":"HOLD","candidate":H,"base":B,"prospective_merge":M,"tree":T,"workflow_run":42402618462,"event":"push","attempt":1,"actor":"ProfHepta","github_native_component_job_success":20,"artifact_denominator":20,"authenticated_archive_source_manifest":sum(r["archive_source_manifest_verified"] for r in rows),"independent_component_readbacks":sum(not r["unknown"] for r in rows),"unknown":sum(r["unknown"] for r in rows),"native_campaigns_verified":sum(r["native_campaigns_verified"] for r in rows),"native_manifests_verified":sum(r["native_manifests_verified"] for r in rows),"rows":rows,"all_business_qualification_flags_remain_false":True,"no_ci_rerun_or_native_execution":True,"v1_download_limit_seconds":240,"v1_maximum_parallel_downloads":2,"v1_attempts_per_artifact":1,"original_missing_historical_artifact_11531476198":"UNKNOWN; not replaced","core14_package":"core-14-package-v1 (separate, unchanged)","large_archives":"External original and partial ZIPs retained; EXTERNAL_ARCHIVES.json records complete digest/size and observed identities"}
write(P/"W1_CORE.json",core);write(P/"EXTERNAL_ARCHIVES.json",external);write(P/"FILES.json",copied)
text="""# 819309f W1 component evidence — v1 single-attempt readback

**HOLD.** This package preserves the once-only observation of the 20 W1 component lanes from the real integration-branch push. It supplements the separately sealed 14-core business package and does not replace any business gate.

The exact head is `819309fd312298e099642e1253b1d4ba07113e98`; actual base `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`; deterministic ordered merge `28df21f965e0348690836c9c854dab645827a03d`; tested tree `f9d63abb9e2931fd78e26ccb87e3a7955068f267`. GitHub workflow run `42402618462`, event `push`, attempt `1`, actor `ProfHepta`.

## Distinct denominators

- GitHub reports **20/20 component jobs successful**. Full workflow totals remain **37 jobs: 26 success / 11 failure** and **34 native lanes: 24 success / 10 failure**.
- Independent ZIP size/digest, complete internal manifests, original H/M source receipts, actual ELF architecture and binary hashes are checked separately.
- Original pinned pure readers are applied only to authenticated retained native outputs. Their results must equal the original manifest reader values. This observation executes no native work, changes no environment or source, and grants no business or hardness qualification.
- Per-lane coverage, all exceptions, native command denominators and UNKNOWN values are in [W1_CORE.json](W1_CORE.json). Full records are in [artifacts/](artifacts/) and [observation/](observation/).

## Transfer failure preservation

Each v1 ZIP GET is limited to 240 seconds, with at most two concurrent GETs and no retry. A timeout may leave a partial ZIP whose size and digest cannot equal the full GitHub artifact. Such a record remains UNKNOWN; it is **not evidence that the GitHub-produced artifact is corrupt**, and does not change the original native job conclusion.

Original full and partial ZIP bytes remain in the durable external observation directory, with observed SHA256, expected GitHub digest, timeout and exit records in [EXTERNAL_ARCHIVES.json](EXTERNAL_ARCHIVES.json). Every listed ZIP was rehashed at this seal. Large ZIPs, ELF binaries and large campaign stdout are intentionally excluded from this small metadata package. Authenticated ZIP inventories preserve every original member identity.

A separately authorized transport-v2 may later fetch only timeout-affected original artifact IDs once with a distinct 900-second observer bound. It must retain this v1 failure record unchanged and report its own coverage. That changes no 4-second service, 30-second import, 1800-second lifetime, Host or CI execution budget.

## Retained sources and limits

[metadata/](metadata/) contains the terminal full-denominator GitHub snapshot. [pinned-readers/](pinned-readers/) contains exact-head original readers and their source/import pins. [observer/](observer/) preserves this independent observer, preparation records and errors; [FILES.json](FILES.json) maps copies back to original paths.

The false-trace/full-limb, legal-strategy and rank/batch component records retain their original scope flags. Pure reader success is internal record consistency, not a new PNW1 transcript replay, public-service pass, production activation or TPS measurement. Missing historical artifact `11531476198` remains UNKNOWN and is not replaced by any similar source or component artifact.

The 14-core package remains authoritative for the four original service and two fresh lanes (pressure confirmation 0/1), four State lanes, and four History lanes (active confirmer still genesis). Source and Host success do not satisfy those business gates.

## Integrity and copy

Copy this whole directory without modifying files. [SHA256SUMS](SHA256SUMS) covers every payload file and [SEAL.json](SEAL.json) records the package size and manifest digest. No credentials, unrelated operator files, repository mutation, dispatch, rerun or GitHub message is included.
"""
write(P/"README.md",text)
payload=[q for q in sorted(P.rglob("*")) if q.is_file()]
with (P/"SHA256SUMS").open("x") as f:
 for q in payload:f.write(sha(q)+"  "+q.relative_to(P).as_posix()+"\n")
seal={"schema":"trnm-w1-metadata-package-seal-v1","sealed_utc":datetime.now(timezone.utc).isoformat(),"candidate":H,"payload_files":len(payload),"payload_bytes":sum(q.stat().st_size for q in payload),"sha256sums_sha256":sha(P/"SHA256SUMS"),"core_sha256":sha(P/"W1_CORE.json"),"core_bytes":(P/"W1_CORE.json").stat().st_size,"large_archives_external":True,"external_archive_count":len(external),"external_observed_bytes":sum(x["actual_bytes"] for x in external),"independent_component_readbacks":core["independent_component_readbacks"],"unknown":core["unknown"]}
write(P/"SEAL.json",seal)
print(json.dumps({"directory":str(P),"seal":seal,"seal_sha256":sha(P/"SEAL.json"),"readme_bytes":(P/"README.md").stat().st_size,"readme_sha256":sha(P/"README.md")}),flush=True)
