import pathlib,sys,json,hashlib,zipfile,datetime
r=json.loads(sys.argv[1]);p=pathlib.Path(r["destination_path"]);b=p.read_bytes()
assert p.resolve(strict=True)==p and len(b)==r["source"]["size"]==r["destination"]["size"] and hashlib.sha256(b).hexdigest()==r["source"]["sha256"]==r["destination"]["sha256"]
at=0
for c in r["chunks"]:
 assert c["offset"]==at and hashlib.sha256(b[at:c["next_offset"]]).hexdigest()==c["chunk_sha256"];at=c["next_offset"]
assert at==len(b)
ib=(p.parent/"EVIDENCE_INDEX.json").read_bytes(); assert hashlib.sha256(ib).hexdigest()=="a9a1526200a71268f4af6fc6bcdedf135ebeb223338c377bbacd0b2c6bb88233";j=json.loads(ib)
with zipfile.ZipFile(p,"r") as z:
 assert len(z.infolist())==42 and z.testzip() is None and z.read("EVIDENCE_INDEX.json")==ib
 for x in j["files"]:
  d=z.read(x["path"]);assert len(d)==x["bytes"] and hashlib.sha256(d).hexdigest()==x["sha256"]
 original=json.loads(z.read("original/summary.json"));before=json.loads(z.read("original/source-before.json"));after=json.loads(z.read("original/source-after.json"))
 assert original["status"]=="failed" and original["source_before_after_verified"] is True and before==after
 assert before["tested_commit"]=="08c9becab740ab2c375b970f376a7638f44c9e8e" and before["tested_tree"]=="036868dfcc953b6f5574c627e0027c3d4e2d3523"
 fail=z.read("original/repository-truth.stderr");assert b"owned-process-collector: all 14 controls must execute without skips" in fail
 assert b"Ran 16 tests in 2.664s\n\nOK" in z.read("original/repository-truth.stdout")
pb=(p.parent/"original-package-summary.json").read_bytes();assert hashlib.sha256(pb).hexdigest()=="91460494bff8c6452c9bf0c1daf11f70b629ac1ba6936b4f045d2ab8319f9ddc"
q=json.loads(pb);assert q["zip"]["sha256"]==hashlib.sha256(b).hexdigest() and q["zip"]["bytes"]==len(b) and q["index"]["sha256"]==hashlib.sha256(ib).hexdigest()
vp=p.parent/"verify_official_copy.py";vb=sys.argv[2].encode()
with vp.open("xb") as f:f.write(vb)
r["verification_producer"]={"path":str(vp),"bytes":len(vb),"sha256":hashlib.sha256(vb).hexdigest()}
r.update(completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),whole_zip_SHA_verified=True,all_42_members_CRC_SHA_verified=True,original_39_execution_files_preserved=True,original_result="failed",source_before_after_equal=True,tests_rerun=False)
d=(json.dumps(r,indent=2,sort_keys=True)+"\n").encode();out=p.parent/"copy-verification.json"
with out.open("xb") as f:f.write(d)
print(json.dumps({"path":str(out),"bytes":len(d),"sha256":hashlib.sha256(d).hexdigest()}))
