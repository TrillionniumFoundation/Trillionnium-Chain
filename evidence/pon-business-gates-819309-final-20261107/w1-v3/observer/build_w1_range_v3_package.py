from pathlib import Path
from datetime import datetime,timezone
import copy,gzip,hashlib,io,json
R=Path("/home/qian-qi/throughput-final-ci-observation-20261107");O=R/"w1-range-v3";D=O/"13586509176";V=R/"w1-components-transport-v2-package";P=R/"w1-range-v3-package"
def require(v,m):
 if not v:raise ValueError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest()
def save(p,obj):
 p.parent.mkdir(parents=True,exist_ok=True)
 with p.open("x") as f:
  if isinstance(obj,str):f.write(obj)
  else:json.dump(obj,f,indent=2);f.write("\n")
vseal=json.loads((V/"SEAL.json").read_bytes());require(sha(V/"SHA256SUMS")==vseal["sha256sums_sha256"] and sha(V/"W1_COVERAGE.json")==vseal["coverage_sha256"],"v2 frozen")
rec=json.loads((O/"receipt.json").read_bytes());stage=json.loads((D/"readback-stage1.json").read_bytes());out=json.loads((D/"pure-outcome.json").read_bytes())
require(rec["completed"] is True and rec["v2_seal_sha256"]==sha(V/"SEAL.json") and rec["range_get"]["http"]["status"]==206 and rec["range_get"]["body_bytes_retained"]==3208816,"actual exact Range source")
archive=rec["assembled_archive"];require((D/"artifact.zip").stat().st_size==archive["bytes"] and sha(D/"artifact.zip")==archive["sha256"]=="d5e6720c1070b1772107be2d316aea6d27dfdf8dd68535103650730138e9bf38","original complete ZIP identity")
require(stage["archive_authenticated"] and stage["source_bound"] and stage["manifest_hashes_complete"] and not stage["errors"],"same authenticated source/manifest validator")
pure=json.loads((D/"readback-pure-v2.json").read_bytes()) if (D/"readback-pure-v2.json").exists() else {}
complete=out["complete_component_readback"] is True and pure.get("complete_component_readback") is True and not pure.get("errors")
core=json.loads((V/"W1_COVERAGE.json").read_bytes());core["schema"]="trnm-final819-w1-combined-coverage-after-one-range-v3";core["prior_v2_seal_sha256"]=sha(V/"SEAL.json")
for row in core["rows"]:
 if row["artifact_id"]==13586509176:
  row["v2_final_independent_status"]=row["final_independent_status"];row["range_v3_archive_source_manifest_verified"]=True
  row["range_v3_independent_status"]="COMPONENT_READBACK_COMPLETE" if complete else "UNKNOWN"
  if complete:
   row.update(final_independent_status="COMPONENT_READBACK_COMPLETE",selected_evidence_version="range-v3",native_campaigns_verified=pure["native_invocations"],native_manifests_verified=len(pure["manifests"]),unknown=False)
core["range_v3"]={"artifact_id":13586509176,"only_one_range_get":True,"timeout_seconds":120,"max_body_bytes":4194304,"actual_http_status":rec["range_get"]["http"]["status"],"actual_content_range":rec["range_get"]["http"]["headers"]["content-range"],"actual_body_bytes":rec["range_get"]["body_bytes_retained"],"original_prefix_bytes":170967040,"original_prefix_sha256":"7915efca8e574436400a7d9bb5c8e59c8681ba0522f77dd5b119fddafac5dae2","original_prefix_unchanged":archive["original_partial_unchanged"],"assembled_archive_bytes":archive["bytes"],"assembled_archive_sha256":archive["sha256"],"same_original_pure_reader_wrapper_sha256":out["original_wrapper_sha256"],"independent_component_readback_complete":complete,"business_qualification":False}
core["final_independent_component_readbacks"]=sum(not row["unknown"] for row in core["rows"]);core["final_unknown"]=sum(row["unknown"] for row in core["rows"])
core["native_campaign_commands_verified"]=sum(row["native_campaigns_verified"] for row in core["rows"]);core["native_manifest_count_verified"]=sum(row["native_manifests_verified"] for row in core["rows"])
if complete:core["original_process_records_verified_including_identity_and_build"]+=sum(m["original_total_processes"] for m in pure["manifests"])
core["coverage_history"]=[{"phase":"v1","complete":14,"unknown":6},{"phase":"v2_combined","complete":19,"unknown":1},{"phase":"range_v3_combined","complete":core["final_independent_component_readbacks"],"unknown":core["final_unknown"]}]
plans=[]
def add(src,rel):
 src=Path(src);rel=Path(rel);require(src.is_file() and not src.is_symlink() and src.stat().st_size<=32*1024**2,"bounded regular metadata")
 plans.append((src,rel))
for p in sorted(O.iterdir()):
 if p.is_file():add(p,p.name)
for p in sorted(D.iterdir()):
 if p.is_file() and p.name!="artifact.zip":add(p,Path("artifact")/p.name)
inv={x["name"]:x for x in stage["archive_inventory"]}
for p in sorted((D/"members").iterdir()):
 if p.is_file():
  require(sha(p)==inv[p.name]["sha256"],"raw authenticated source/control unchanged");add(p,Path("artifact/members")/p.name)
for m in stage["manifests"]:
 p=Path(m["path"]);require(sha(p)==m["manifest_sha256"],"original native manifest unchanged");add(p,Path("artifact/members")/m["member"])
for p in sorted((R/"range-v3-preparation").iterdir()):
 if p.is_file():add(p,Path("preparation")/p.name)
for name in ("read_w1_range_v3_819.py","read_w1_range_v3_819_b.py","test_range_v3_response_controls.py","test_range_v3_response_controls_b.py","validate_range_v3_original_w1.py","read_w1_pure_records_819_v2.py","build_w1_range_v3_package.py","w1-range-v3-authoritative-receipts.json"):
 add(R/name,Path("observer")/name)
for name in ("W1_COVERAGE.json","SEAL.json","SHA256SUMS","EXTERNAL_ARCHIVES.json"):add(V/name,Path("v2-reference")/name)
prepared=[]
for src,rel in plans:
 data=src.read_bytes();n=len(data);h=hashlib.sha256(data).hexdigest();enc="identity"
 if n>256*1024 and src.name!="tail.bin":
  buf=io.BytesIO()
  with gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=buf,mtime=0) as z:z.write(data)
  b=buf.getvalue();require(gzip.decompress(b)==data,"lossless gzip");data=b;rel=Path(str(rel)+".gz");enc="gzip-mtime0-level1"
 prepared.append((src,rel,data,n,h,enc))
require(len({r.as_posix() for _,r,_,_,_,_ in prepared})==len(prepared),"unique paths")
require(sum(len(b) for _,_,b,_,_,_ in prepared)<=32*1024**2,"small supplement bound")
P.mkdir();files=[]
for src,rel,b,n,h,enc in prepared:
 q=P/rel;q.parent.mkdir(parents=True,exist_ok=True)
 with q.open("xb") as f:f.write(b)
 digest=hashlib.sha256(b).hexdigest();require(sha(q)==digest,"copied bytes")
 files.append({"path":rel.as_posix(),"source":str(src),"source_bytes":n,"source_sha256":h,"encoding":enc,"bytes":len(b),"sha256":digest})
save(P/"W1_FINAL_COVERAGE.json",core);save(P/"FILES.json",files)
save(P/"EXTERNAL_ORIGINAL_ARCHIVE.json",{"artifact_id":13586509176,"archive":archive,"raw_tail_included":"artifact/tail.bin","original_v2_partial_path":"/home/qian-qi/throughput-final-ci-observation-20261107/w1-components-transport-v2/13586509176/artifact.zip","original_v2_partial_sha256":core["range_v3"]["original_prefix_sha256"],"full_zip_included_in_small_package":False,"rehashed_at_seal":True})
save(P/"README.md","""# 819309f W1 — one authorized Range recovery

**Business acceptance remains HOLD.** This small supplement preserves the final authorized read of original artifact `13586509176`, plus full independent coverage across all 20 W1 components. It does not rerun CI, native work, a benchmark or any original business gate.

## Exact original bytes

The source is original run `42402618462`, real integration-branch push attempt 1, head `819309fd312298e099642e1253b1d4ba07113e98`. After v2 was fully terminal and sealed, one local ProfHepta GET requested only bytes `170967040-174175855`. The response was exactly HTTP 206 with `Content-Range: bytes 170967040-174175855/174175856`; only 3,208,816 body bytes were received, within the declared 120-second and 4-MiB bounds.

A new copy combined that tail with the preserved v2 partial. Its complete 174,175,856 bytes have the original GitHub SHA256 `d5e6720c1070b1772107be2d316aea6d27dfdf8dd68535103650730138e9bf38`. The original partial was read only and its before/after SHA256 remained `7915efca8e574436400a7d9bb5c8e59c8681ba0522f77dd5b119fddafac5dae2`.

[receipt.json](receipt.json) and [plan.json](plan.json) retain the actual response, source identity, exact bounds, process outcome and assembly checks. Signed URLs and authorization headers were not retained. [artifact/tail.bin](artifact/tail.bin) preserves the exact response body; the complete original ZIP remains external and is indexed in [EXTERNAL_ORIGINAL_ARCHIVE.json](EXTERNAL_ORIGINAL_ARCHIVE.json).

## Original reader and complete denominator

The restored ZIP passed the same full internal member hash, original native manifest, H/M source/context and ELF/binary checks. The unchanged pinned original pure-reader wrapper was then invoked once. [W1_FINAL_COVERAGE.json](W1_FINAL_COVERAGE.json) is the authoritative final coverage table and records the actual result; the authentic logs and all process/readback records remain under [artifact/](artifact/).

It retains the separate stages: v1 14 complete / 6 transfer UNKNOWN; v2 19 complete / 1 transfer UNKNOWN; and the final Range result. Original failures, partials, timeouts and both earlier seals are unchanged. [v2-reference/](v2-reference/) binds the immediate prior frozen package, which in turn binds v1.

The original 20/20 GitHub W1 component job successes remain separate from independent record verification. Full workflows still have 37 jobs (26 success / 11 failure) and 34 native lanes (24 success / 10 failure). The four service and two fresh pressure confirmations remain 0/1; all four History confirmers remain active genesis; the four State lanes passed their own controls. No service, TPS, hardness, production activation or COW qualification is granted. Missing historical artifact `11531476198` remains UNKNOWN and was not replaced.

## Observer preparation and integrity

[preparation/](preparation/) preserves the local CLI help/version and 12 parser refusal controls; these are observer preparation, not CI/native tests. Two prepared script versions are retained: the final version counts bytes received with a rejected HTTP header and labels truncated stderr hashes precisely before the one live request. No second live Range GET occurred.

[observer/](observer/) preserves code and authoritative job receipts. Large text files are lossless gzip with original/packed sizes and hashes in [FILES.json](FILES.json); every compression was decompressed and compared. [SHA256SUMS](SHA256SUMS) covers payload files; [SEAL.json](SEAL.json) freezes this separate supplement. Copy all three W1 packages, keeping their failures and identity chain.
""")
payload=[p for p in sorted(P.rglob("*")) if p.is_file()]
with (P/"SHA256SUMS").open("x") as f:
 for p in payload:f.write(sha(p)+"  "+p.relative_to(P).as_posix()+"\n")
seal={"schema":"trnm-final819-w1-range-v3-seal","sealed_utc":datetime.now(timezone.utc).isoformat(),"payload_files":len(payload),"payload_bytes":sum(p.stat().st_size for p in payload),"sha256sums_sha256":sha(P/"SHA256SUMS"),"coverage_sha256":sha(P/"W1_FINAL_COVERAGE.json"),"coverage_bytes":(P/"W1_FINAL_COVERAGE.json").stat().st_size,"v2_seal_sha256":sha(V/"SEAL.json"),"final_independent_readbacks":core["final_independent_component_readbacks"],"final_unknown":core["final_unknown"],"original_campaign_commands":core["native_campaign_commands_verified"],"original_native_manifests":core["native_manifest_count_verified"],"original_process_records":core["original_process_records_verified_including_identity_and_build"],"business_gate_unchanged":"HOLD"}
save(P/"SEAL.json",seal)
print(json.dumps({"directory":str(P),"seal":seal,"seal_sha256":sha(P/"SEAL.json")}),flush=True)
