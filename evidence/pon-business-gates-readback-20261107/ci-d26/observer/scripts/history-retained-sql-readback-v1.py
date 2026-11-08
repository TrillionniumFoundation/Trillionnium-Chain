from pathlib import Path
import json,hashlib,sqlite3
R=Path("/home/qian-qi/throughput-ci-observation-20261107/20261107T155220Z-d26e047dedfc-bb63e773/history-artifact-read-v1")
def sha(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
queries={
"blocks":"select count(*) as rows_total, sum(height=0) as genesis_rows, sum(height>0) as non_genesis_rows, min(height) as min_height,max(height) as max_height,sum(packet is not null) as rows_with_packet from blocks",
"active":"select hex(a.tip) as tip_hex,b.height as tip_height,a.generation,a.state_slot from active a left join blocks b on b.id=a.tip where a.singleton=1",
"reorg":"select hex(old_tip) as old_tip_hex,hex(new_tip) as new_tip_hex,generation,cursor,done from reorg where singleton=1",
"steps":"select count(*) as rows_total,min(ordinal) as min_ordinal,max(ordinal) as max_ordinal from steps",
"lifecycle_counts":"select outcome,count(*) as rows_total from reorg_lifecycle_v1 group by outcome order by outcome",
"lifecycle_last":"select operation,hex(old_tip) as old_tip_hex,hex(new_tip) as new_tip_hex,generation,old_slot,outcome,cancelled_cursor,reason from reorg_lifecycle_v1 order by operation desc limit 3",
"snapshots":"select count(*) as rows_total from snapshots",
"slots":"select slot,count(*) as keys from kv group by slot order by slot"
}
results=[]
for d in sorted(x for x in R.iterdir() if x.is_dir()):
 rb=json.loads((d/"readback.json").read_bytes())
 events=[json.loads(x) for x in (d/"history-native/history.log").read_text().splitlines() if x.startswith("{")]
 exit_evidence=next(x for x in events if x.get("schema")=="native-ancestry-independent-sync-exit-evidence-v1")
 entry={"artifact_id":int(d.name),"name":rb["metadata"]["name"],"failure_location":exit_evidence["failure_location"],"databases":[]}
 for owner in ("confirmer","validator"):
  p=d/("history-native/long-history/"+owner+"/native.sqlite");member=str(p.relative_to(d))
  assert not Path(str(p)+"-wal").exists() and not Path(str(p)+"-shm").exists()
  assert not any(i["path"] in (member+"-wal",member+"-shm") for i in rb["inventory"])
  before=sha(p);assert before==rb["files"][member]["sha256"]
  c=sqlite3.connect(p.as_uri()+"?mode=ro&immutable=1",uri=True);c.row_factory=sqlite3.Row;c.execute("PRAGMA query_only=ON")
  rows={key:[dict(x) for x in c.execute(query)] for key,query in queries.items()}
  rows["pinned_target"]=[dict(x) for x in c.execute("select hex(id) as id_hex,height,hex(parent) as parent_hex from blocks where id=?",(bytes.fromhex(exit_evidence["failure_location"]["pinned_tip"]),))]
  c.close();after=sha(p);assert before==after
  entry["databases"].append({"owner":owner,"path":str(p),"bytes":p.stat().st_size,"sha256":before,"after_sha256":after,"read_only":True,"no_wal_or_shm_in_archive":True,"results":rows})
 results.append(entry)
out={"schema":"trnm-d26-history-retained-sql-readback-v1","queries":queries,"scope":"Read-only retained SQLite bytes; no Node open, recovery, activation, replay or native retry; row counts are not validation or successful import-return counts.","results":results,"native_gate_validated":False}
p=R/"retained-sql-readback-v1.json";p.write_text(json.dumps(out,indent=2)+chr(10))
core={"schema":out["schema"],"full_readback":{"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p)},"results":[{"artifact_id":r["artifact_id"],"completed_import_calls":r["failure_location"]["completed_import_calls"],"failure_stage":r["failure_location"]["stage"],"databases":[{"owner":d["owner"],"sha256":d["sha256"],"blocks":d["results"]["blocks"],"active":d["results"]["active"],"reorg":d["results"]["reorg"],"steps":d["results"]["steps"],"lifecycle_last":d["results"]["lifecycle_last"],"pinned_target":d["results"]["pinned_target"]} for d in r["databases"]]} for r in results],"native_gate_validated":False}
cp=R/"retained-sql-core-v1.json";cp.write_text(json.dumps(core,indent=2)+chr(10));print(json.dumps({"path":str(cp),"bytes":cp.stat().st_size,"sha256":sha(cp),"data":core}))
