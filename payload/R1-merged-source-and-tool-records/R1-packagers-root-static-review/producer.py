import ast,difflib,hashlib,json,pathlib,sys
assert not sys.flags.optimize
E=pathlib.Path("/private/tmp/chain-consolidation-20261114-root/R1-packagers-root-static-review-v1");E.mkdir(mode=0o700);(E/"producer.py").write_text(sys.argv[1])
new=pathlib.Path("/private/tmp/chain-prci-R1-original-lane-packagers-preparation-20261114-v1")
cases=[("full",pathlib.Path("/private/tmp/chain-prci-P1-original-full-v2-packager-preparation-20261114-v1/package_original_repository_truth_6a8cd5_v2.py"),28912,"4ebe16cf283c670b066893d1359b4a4e17abe205eb03c358e83fdb9dd1bf9967",new/"package_original_repository_truth_2a8646_v1.py",28913,"591e2a6539276d4942e74b756ac3ea43c6863da4a8cb5a440d7bd49079d6d8e8","full-P1-v2-to-R1.patch","38e7ae0ae71ebac60980b8ada994d6e6450aa3d9ec809c917625af960b5760fb","P1-full-v2-packager.py.original"),("external",pathlib.Path("/private/tmp/chain-prci-P1-original-external-packager-preparation-20261114-v1/package_original_external_evidence_6a8cd5_v1.py"),14207,"fd64736fa3450a7baad12e538556a163a394dd5420e58a2eaecd737250da9811",new/"package_original_external_evidence_2a8646_v1.py",14191,"8785a7c4ed28c96b4977efc983301278be5bef065188456ab8e405606610f192","external-P1-to-R1.patch","03ddd83a7d9c493e0432084a7497a5d638fee136600cb5cab09c44839dd73282","P1-external-packager.py.original")]
class WithoutConstants(ast.NodeTransformer):
 def visit_Constant(self,node):return ast.copy_location(ast.Constant(value=None),node)
rows=[]
for label,a,an,ah,b,bn,bh,pn,ph,fromname in cases:
 x=a.read_bytes();y=b.read_bytes();patch=(new/pn).read_bytes()
 assert len(x)==an and hashlib.sha256(x).hexdigest()==ah and len(y)==bn and hashlib.sha256(y).hexdigest()==bh and hashlib.sha256(patch).hexdigest()==ph
 actual="".join(difflib.unified_diff(x.decode().splitlines(True),y.decode().splitlines(True),fromfile=fromname,tofile=b.name)).encode();assert actual==patch
 assert ast.dump(WithoutConstants().visit(ast.parse(x)),include_attributes=False)==ast.dump(WithoutConstants().visit(ast.parse(y)),include_attributes=False)
 compile(ast.parse(y,filename=str(b)),str(b),"exec")
 rows.append({"label":label,"old_path":str(a),"old_sha256":ah,"new_path":str(b),"new_bytes":bn,"new_sha256":bh,"patch_sha256":ph,"actual_diff_equals_independently_reviewed_diff":True,"AST_structure_unchanged_except_constants":True,"compiled_without_execution":True})
s={"schema":"trnm-R1-packagers-root-static-review-v1","status":"PASS","cases":rows,"packagers_executed":False,"test_receipts_read":False,"notes":"Exact reviewed identity constants only. Full starts at actual P1 and requires its original 18 steps. External and full are still prepared-only pending each actual R1 terminal."}
raw=(json.dumps(s,indent=2,sort_keys=True)+"\n").encode();(E/"summary.json").write_bytes(raw)
print(json.dumps({"status":"PASS","summary":str(E/"summary.json"),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}),flush=True)
