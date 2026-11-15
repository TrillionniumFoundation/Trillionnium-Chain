from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sqlite3,sys
D=Path(sys.argv[1]);r=json.loads((D/"readback.json").read_bytes())
assert r["readback_complete"] and not r["errors"]
def digest(p):
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def enc(v):
 if isinstance(v,bytes):return {"kind":"blob","bytes":len(v),"hex":v.hex() if len(v)<=256 else None,"sha256":hashlib.sha256(v).hexdigest()}
 return v
schema_result={"schema":"trnm-final819-history-sql-observed-schema-v1","artifact_id":r["artifact_id"],"databases":[]}
core={"schema":"trnm-final819-history-retained-sql-readback-v1","artifact_id":r["artifact_id"],"candidate":"819309fd312298e099642e1253b1d4ba07113e98","source_binding":r["source_binding"],"mode":"SQLite URI mode=ro immutable=1; query_only ON; no Node open or recovery","db_total_denominator":2,"databases":[],"errors":[]}
for item in r["sqlite_files"]:
 p=Path(item["path"]);before=digest(p);assert before==item["sha256"]
 companions=[{"path":str(x),"bytes":x.stat().st_size,"sha256":digest(x)} for x in p.parent.glob(p.name+"-*") if x.is_file()]
 assert all(not x["path"].endswith("-wal") or x["bytes"]==0 for x in companions),"nonempty WAL"
 c=sqlite3.connect(p.as_uri()+"?mode=ro&immutable=1",uri=True)
 c.execute("PRAGMA query_only=ON");c.execute("PRAGMA trusted_schema=OFF")
 ddl=c.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY type,name").fetchall()
 info={}
 for typ,name,_,sql in ddl:
  if typ=="table":
   assert len(info)<128
   q='"'+name.replace('"','""')+'"';info[name]=[list(x) for x in c.execute("PRAGMA table_info("+q+")")]
 for table,cols in {"blocks":["id","parent","height","chainwork","packet","state_root"],"active":["singleton","tip","generation","state_slot"],"metadata":["key","value"],"reorg":["singleton","old_tip","new_tip","generation","cursor","done"],"reorg_lifecycle_v1":["operation","old_tip","new_tip","generation","old_slot","old_root","owner_context","outcome","cancelled_cursor","reason"]}.items():
  assert [x[1] for x in info[table]]==cols,(table,info[table])
 total,packets,lo,hi=c.execute("SELECT COUNT(*),COUNT(packet),MIN(height),MAX(height) FROM blocks").fetchone()
 active=[dict(zip(("singleton","tip_hex","generation","state_slot","height"),row)) for row in c.execute("SELECT a.singleton,lower(hex(a.tip)),a.generation,a.state_slot,b.height FROM active a LEFT JOIN blocks b ON b.id=a.tip")]
 genesis_rows=c.execute("SELECT lower(hex(value)) FROM metadata WHERE key='genesis'").fetchall();assert len(genesis_rows)==1
 genesis=genesis_rows[0][0]
 for a in active:a["is_genesis"]=a["tip_hex"]==genesis
 reorg=[dict(zip(("singleton","old_tip_hex","new_tip_hex","generation","cursor","done"),row)) for row in c.execute("SELECT singleton,lower(hex(old_tip)),lower(hex(new_tip)),generation,cursor,done FROM reorg")]
 life=[dict(zip(("operation","old_tip_hex","new_tip_hex","generation","old_slot","outcome","cancelled_cursor","reason"),row)) for row in c.execute("SELECT operation,lower(hex(old_tip)),lower(hex(new_tip)),generation,old_slot,outcome,cancelled_cursor,reason FROM reorg_lifecycle_v1")]
 misc={name:c.execute('SELECT COUNT(*) FROM "'+name+'"').fetchone()[0] for name in ("steps","events","snapshots","deltas","kv")}
 c.close();after=digest(p);assert after==before
 row={"path":str(p),"role":p.parent.name,"bytes":p.stat().st_size,"sha256_before":before,"sha256_after":after,"companions":companions,"block_rows_including_genesis":total,"non_null_packets":packets,"height_min":lo,"height_max":hi,"genesis_hex":genesis,"active":active,"reorg":reorg,"reorg_lifecycle_v1":life,"other_counts":misc}
 core["databases"].append(row)
 schema_result["databases"].append({"path":str(p),"sha256_before":before,"sqlite_master":[list(x) for x in ddl],"table_info":info})
assert len(core["databases"])==2
raw=(D/"history-native/history.log").read_bytes();core["native_log"]={"path":str(D/"history-native/history.log"),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
records={}
for row in r["structured_native_log_records"]:
 rec=row["record"];records[rec["schema"]]={"line":row["line"],"record":rec}
sync=records.get("native-ancestry-independent-sync-exit-evidence-v1")
server=records.get("native-ancestry-public-server-exit-evidence-v1")
core["native_import_returns"]={"denominator":4105,"failure_location":sync["record"].get("failure_location") if sync else None,"sync_error":sync["record"].get("sync_error") if sync else None,"raw_log_line":sync["line"] if sync else None}
core["server_exit"]=server
core["native_manifest"]={k:r["manifest"].get(k) for k in ("process","passed","failures","source_before_after_equal","binary_before_after_equal","binary_sha256")}
core["host"]=r["host"];core["original_business_passed"]=r["original_business_passed"]
core["finished_utc"]=datetime.now(timezone.utc).isoformat()
for name,value in (("retained-sql-observed-schema-v1.json",schema_result),("retained-sql-readback-v1.json",core)):
 out=D/name
 with out.open("x") as f:json.dump(value,f,indent=2);f.write("\n")
 print(json.dumps({"path":str(out),"bytes":out.stat().st_size,"sha256":digest(out)}))
print(json.dumps({"artifact_id":core["artifact_id"],"native_import_returns":core["native_import_returns"],"server_exit":core["server_exit"],"databases":core["databases"],"native_manifest":core["native_manifest"],"host":core["host"]}))
