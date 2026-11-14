import ast,difflib,hashlib,json,pathlib,sys
assert not sys.flags.optimize
E=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/P1-packagers-root-static-review-v1");E.mkdir(mode=0o700);(E/"producer.py").write_text(sys.argv[1])
old=pathlib.Path("/private/tmp/chain-prci-M8-original-lane-packagers-preparation-20261114-v1")
cases=[("full",old/"package_original_repository_truth_ed0d35_v1.py",28914,"cef78f3610541a8056b297fd5256a2493227d3aa78cd0d964a92c57c687889d8",pathlib.Path("/private/tmp/chain-prci-P1-original-full-v2-packager-preparation-20261114-v1/package_original_repository_truth_6a8cd5_v2.py"),28912,"4ebe16cf283c670b066893d1359b4a4e17abe205eb03c358e83fdb9dd1bf9967","full-M8-to-P1-v2.patch","b5b0d7499f10096dd0cd6f12ca5c9e34ce3bb2a2b688c739aec65e6e9419d195","M8-full-packager.py.original"),("external",old/"package_original_external_evidence_ed0d35_v1.py",14207,"0461689e3f7d576250d26faddb3efd61716cb984469154782088a9fe58d0f10f",pathlib.Path("/private/tmp/chain-prci-P1-original-external-packager-preparation-20261114-v1/package_original_external_evidence_6a8cd5_v1.py"),14207,"fd64736fa3450a7baad12e538556a163a394dd5420e58a2eaecd737250da9811","external-M8-to-P1.patch","f880d789b7bbfdbfffd73a6e4ad2adaabdf99430e522060b546623a72cad5fee","M8-external-packager.py.original")]
rows=[]
for label,a,an,ah,b,bn,bh,pn,ph,fromname in cases:
 x=a.read_bytes();y=b.read_bytes();patch=(b.parent/pn).read_bytes()
 assert len(x)==an and hashlib.sha256(x).hexdigest()==ah and len(y)==bn and hashlib.sha256(y).hexdigest()==bh and hashlib.sha256(patch).hexdigest()==ph
 actual="".join(difflib.unified_diff(x.decode().splitlines(True),y.decode().splitlines(True),fromfile=fromname,tofile=b.name)).encode();assert actual==patch
 compile(ast.parse(y,filename=str(b)),str(b),"exec")
 rows.append({"label":label,"old_path":str(a),"old_sha256":ah,"new_path":str(b),"new_bytes":bn,"new_sha256":bh,"patch_sha256":ph,"actual_diff_equals_independently_reviewed_diff":True,"compiled_without_execution":True})
s={"schema":"trnm-P1-packagers-root-static-review-v1","status":"PASS","cases":rows,"packagers_executed":False,"test_receipts_read":False,"notes":"Full v2 preserves 18 stages and actual P1 start; the original v1 incomplete failure cannot pass the complete-lane packager. External P1 remains prepared-only and will not run because final source is P2."}
b=(json.dumps(s,indent=2,sort_keys=True)+"\n").encode();(E/"summary.json").write_bytes(b);print(json.dumps({"status":"PASS","summary":str(E/"summary.json"),"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}),flush=True)
