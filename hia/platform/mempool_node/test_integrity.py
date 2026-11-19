"""Required source or full native-build integrity controls; never skip a group."""
from pathlib import Path
import argparse,copy,json,os,shutil,subprocess,sys,tempfile,unittest
from . import safe,build,node_cases
from .original_graph import include_graph
ROOT=build.ROOT
OPTIONS=None;ARTIFACT=None;WORK=None;COUNTS={"controls":0,"actual_cli":0}
def reject(fn):
 COUNTS["controls"]+=1
 try:fn()
 except (ValueError,AssertionError,OSError,KeyError,TypeError):return
 raise AssertionError("Invalid input was accepted")
def copy_sources(dest):
 dest.mkdir()
 for name in build.source_manifest():
  p=dest/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(safe.read(ROOT,name))
 return dest
class Integrity(unittest.TestCase):
 def test_01_strict_json_and_types(self):
  for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":-Infinity}'):reject(lambda raw=raw:safe.parse(raw))
  for a,b in ((0,False),(1,True),(0,0.0),([0],[False]),({"n":1},{"n":1.0})):
   COUNTS["controls"]+=1;self.assertFalse(safe.same(a,b))
  COUNTS["controls"]+=1;self.assertTrue(safe.same({"x":[1,None,True]},{"x":[1,None,True]}))
  # Shape fixtures come from producer syntax only; they do not claim runtime evidence.
  import ast
  from .evidence import native_report_contract
  records=[]
  def refused(name,value,group):
   reject(lambda:native_report_contract(value,group));records.append({"name":name,"result":"REJECTED"})
  groups=("smoke","boundaries","capacity","node","cross");fixtures={}
  for group in groups:
   tree=ast.parse(safe.read(ROOT,"hia/platform/mempool_node/suite_"+group+".py"))
   nodes=[n.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and
          any(isinstance(t,ast.Name) and t.id=="report" for t in n.targets) and isinstance(n.value,ast.Dict)]
   self.assertEqual(len(nodes),1)
   fields={ast.literal_eval(k):v for k,v in zip(nodes[0].keys,nodes[0].values)}
   value={k:ast.literal_eval(v) if k in ("schema","scope") else None for k,v in fields.items()}
   fixtures[group]=value
   COUNTS["controls"]+=1;self.assertIsNone(native_report_contract(value,group))
   records.append({"name":group+"/producer-shape-only","result":"MATCH"})
  for group,fixture in fixtures.items():
   for label,schema in [("null",None),("bool",True),("number",1),("unknown","unknown")]+[(g,v["schema"]) for g,v in fixtures.items() if g!=group]:
    value=copy.deepcopy(fixture);value["schema"]=schema;refused(group+"/schema-"+label,value,group)
   for field in fixture:
    value=copy.deepcopy(fixture);del value[field];refused(group+"/missing-"+field,value,group)
   for field in ("node_commit","complete_node","production_permit"):
    value=copy.deepcopy(fixture);value[field]=True;refused(group+"/extra-top-"+field,value,group)
   for label,scope in (("null",None),("list",[]),("bool",True),("invented","FULL_NODE")):
    value=copy.deepcopy(fixture);value["scope"]=scope;refused(group+"/scope-"+label,value,group)
   scope=fixture["scope"]
   if type(scope) is dict:
    for field,original in scope.items():
     value=copy.deepcopy(fixture);del value["scope"][field];refused(group+"/scope-missing-"+field,value,group)
     value=copy.deepcopy(fixture);value["scope"][field]=not original if type(original) is bool else "PASS"
     refused(group+"/scope-changed-"+field,value,group)
     if type(original) is bool:
      value=copy.deepcopy(fixture);value["scope"][field]=int(original);refused(group+"/scope-bool-int-"+field,value,group)
    for field in ("node_commit","complete_node","production_permit","extra_authority"):
     value=copy.deepcopy(fixture);value["scope"][field]=True
     if not safe.same(value,fixture):refused(group+"/scope-granted-"+field,value,group)
   else:
    value=copy.deepcopy(fixture);value["scope"]={"complete_node":True,"production_permit":True}
    refused(group+"/scope-object-grant",value,group)
   for label,value in (("null",None),("list",[]),("bool",True)):
    refused(group+"/report-"+label,value,group)
  for group in ("unknown",None,True,1):refused("unknown-group-"+repr(group),fixtures["smoke"],group)
  safe.write_json(WORK/"native-report-contract-controls.json",{
   "schema":"trnm.native-report-contract-controls.v1","scope":"source-contract-only",
   "controls":len(records),"records":records,"native_execution":False,"original_execution":False})
 def test_02_descriptor_relative_reads(self):
  d=WORK/"read";d.mkdir();(d/"data").write_bytes(b"real");(d/"sub").mkdir();(d/"sub/item").write_bytes(b"sub")
  COUNTS["controls"]+=1;self.assertEqual(safe.read(d,"sub/item"),b"sub")
  for name in ("../data","/data","./data","sub/../data","sub//item","data/","bad\\path","bad\0path"):reject(lambda name=name:safe.read(d,name))
  (d/"link").symlink_to(d/"data");reject(lambda:safe.read(d,"link"))
  (d/"ancestor").symlink_to(d/"sub",target_is_directory=True);reject(lambda:safe.read(d/"ancestor","item"))
  os.link(d/"data",d/"hard");reject(lambda:safe.read(d,"hard"))
  (d/"hard").unlink();os.mkfifo(d/"fifo");reject(lambda:safe.read(d,"fifo"))
  reject(lambda:safe.read(d,"data",limit=3))
 def test_03_complete_source_graph(self):
  r=copy_sources(WORK/"source");before=build.source_manifest(r)
  COUNTS["controls"]+=1;self.assertTrue(safe.same(before,build.source_manifest()))
  p=r/"hia/platform/mempool_node/extra.py";p.write_text("x=1\n")
  reject(lambda:safe.need(safe.same(before,build.source_manifest(r)),"Added source"));p.unlink()
  p=r/"hia/src/crypto/ed25519_verify_joint.hepta";raw=p.read_bytes();p.write_bytes(raw+b"\n")
  reject(lambda:safe.need(safe.same(before,build.source_manifest(r)),"Changed source"));p.write_bytes(raw)
  p.unlink();reject(lambda:build.source_manifest(r));p.write_bytes(raw)
  p.unlink();p.symlink_to(ROOT/"hia/src/crypto/ed25519_verify_joint.hepta");reject(lambda:build.source_manifest(r));p.unlink();p.write_bytes(raw)
  dep=r/"hia/platform/mempool_node/dependencies.json";data=dep.read_bytes()
  dep.write_bytes(b'["../escape"]');reject(lambda:build.source_manifest(r));dep.write_bytes(data)
 def test_04_exact_function_composition(self):
  r=copy_sources(WORK/"composition");p=r/"hia/platform/mempool_node/composition.json";original=safe.read_json(r,p.relative_to(r).as_posix())
  plan,sources=build.compose(r);COUNTS["controls"]+=1;self.assertEqual(set(sources),set(build.ORDER)|{"linux_emitter"})
  mutations=(
   lambda v:v["image_order"].pop(),
   lambda v:v["images"]["master"]["entries"].pop(),
   lambda v:v["images"]["master"]["entries"][0].update(function="caller_entry"),
   lambda v:v["images"]["master"]["entries"][1].update(file="../escape"),
   lambda v:v["images"]["master"]["entries"][1].update(prefix_hex=b"external bytes".hex()),
   lambda v:v["images"]["master"].update(suffix_hex=b"external bytes".hex()),
   lambda v:v["images"]["master"]["source"].update(bytes=False),
  )
  for mutation in mutations:
   value=copy.deepcopy(original);mutation(value);safe.write_json(p,value);reject(lambda:build.compose(r))
  safe.write_json(p,original);COUNTS["controls"]+=1;self.assertTrue(safe.same(plan,build.compose(r)[0]))
 def test_05_complete_canonical_corpora(self):
  rows=[safe.parse(l) for l in safe.read(ROOT,"hia/platform/mempool_node/corpus.jsonl").splitlines()]
  COUNTS["controls"]+=1;self.assertEqual((len(rows),sum(len(r["actions"]) for r in rows),sum(a["op"]=="validate" for r in rows for a in r["actions"])),(11,122,58))
  rows=node_cases.histories();COUNTS["controls"]+=1;self.assertEqual((len(rows),sum(len(r["actions"]) for r in rows)),(4,96))
  COUNTS["controls"]+=1;self.assertEqual(safe.read(ROOT,"hia/platform/mempool_node/node_corpus.jsonl"),node_cases.canonical_bytes())
  cross=safe.parse(safe.read(ROOT,"hia/platform/mempool_node/cross_corpus.jsonl"))
  COUNTS["controls"]+=1;self.assertEqual((len(cross["actions"]),sum(a["op"]=="validate" for a in cross["actions"])),(24,5))
  fixture=safe.read_json(ROOT,"hia/platform/mempool_node/capacity_fixture.json")
  COUNTS["controls"]+=1;self.assertEqual(len(fixture["transactions_hex"]),257)
  from .native_contract import fixed_validations
  for group,count in (("smoke",13),("boundaries",41),("capacity",4),("cross",5)):
   COUNTS["controls"]+=1;self.assertEqual(len(fixed_validations(group)),count)
  COUNTS["controls"]+=1;self.assertTrue(safe.same(fixed_validations("smoke")["valid-first"],{"outcome":1,"error":0,"calls":1,"reused":0,"signatures":1}))
 def test_06_public_environment_refusal(self):
  keys=("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","RUSTC","CARGO_BUILD_RUSTC","LD_PRELOAD","LD_LIBRARY_PATH")
  clean=dict(os.environ)
  for k in keys:clean.pop(k,None)
  for index,key in enumerate(keys):
   out=WORK/("override-"+str(index));env=dict(clean);env[key]="not-admitted"
   argv=[sys.executable,"-B","-m","hia.platform.mempool_node.rust_oracle","--group","m05"]
   for name in ("smoke","boundaries","capacity","cross"):argv+=["--"+name,str(WORK/("missing-"+name))]
   argv+=["--cargo-target",str(WORK/"uncreated-cargo"),"--output",str(out)]
   run=subprocess.run(argv,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
   COUNTS["controls"]+=1;COUNTS["actual_cli"]+=1
   evidence=WORK/("override-command-"+str(index));evidence.mkdir()
   (evidence/"stdout.raw").write_bytes(run.stdout);(evidence/"stderr.raw").write_bytes(run.stderr)
   safe.write_json(evidence/"receipt.json",{"argv":argv,"exit_code":run.returncode,"stdout":safe.identity(run.stdout),"stderr":safe.identity(run.stderr),"override":key})
   self.assertEqual(run.returncode,1)
   report=safe.read_json(out,"report.json");self.assertEqual(report["stages"],[])
   self.assertIn(key,report["failure"]["error"])
   self.assertFalse((WORK/"uncreated-cargo").exists())
 def test_07_full_actual_build_positive(self):
  row=build.validate_build(ARTIFACT)
  COUNTS["controls"]+=1;self.assertEqual(len(row["stages"]),26)
  COUNTS["controls"]+=1;self.assertEqual(row["image_order"],list(build.ORDER))
  COUNTS["controls"]+=1;self.assertTrue(safe.same(row["executable"],build.compose()[0]["expected_executable"]))
 def test_08_actual_build_metadata_and_raw_refusal(self):
  d=WORK/"mutant-build";shutil.copytree(ARTIFACT,d)
  source=safe.read(d,"build.json");original=safe.parse(source)
  mutations=(
   lambda v:v.update(source_inputs={},source_set_sha256=safe.identity(safe.canonical({}))["sha256"]),
   lambda v:v["stages"].pop(),
   lambda v:v["image_order"].reverse(),
   lambda v:v.update(executable={"bytes":False,"sha256":v["executable"]["sha256"]}),
   lambda v:v.update(original_sources={}),
   lambda v:v["source_after"].update(errors=[False]),
  )
  for mutation in mutations:
   v=copy.deepcopy(original);mutation(v);safe.write_json(d/"build.json",v);reject(lambda:build.validate_build(d))
  (d/"build.json").write_bytes(source)
  for name in ("owner.elf","prefix.raw","master.flat","master-composed.hepta","compiler/emit-owner/stdin.raw","compiler/compile-ed/stdout.raw"):
   p=d/name;b=p.read_bytes();p.write_bytes(b[:-1]);reject(lambda:build.validate_build(d));p.write_bytes(b)
  COUNTS["controls"]+=1;self.assertTrue(safe.same(build.validate_build(d),original))
 def test_09_public_complete_elf_linkage(self):
  r=copy_sources(WORK/"linkage-source");d=WORK/"linkage-build";shutil.copytree(ARTIFACT,d)
  def cli(name,expect):
   report=WORK/(name+".json");argv=[sys.executable,"-B","-m","hia.platform.mempool_node.build","--verify",str(d),"--report",str(report)]
   run=subprocess.run(argv,cwd=r,env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1"),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
   COUNTS["controls"]+=1;COUNTS["actual_cli"]+=1
   (WORK/(name+".stdout.raw")).write_bytes(run.stdout);(WORK/(name+".stderr.raw")).write_bytes(run.stderr)
   self.assertEqual(run.returncode,expect);self.assertEqual(safe.read_json(report.parent,report.name)["status"],"PASS" if expect==0 else "FAIL")
  cli("linkage-positive",0)
  row=safe.read_json(d,"build.json");plan=safe.read_json(r,"hia/platform/mempool_node/composition.json")
  role="master";p=d/(role+".flat");raw=p.read_bytes();mut=bytes([raw[0]^1])+raw[1:];p.write_bytes(mut)
  (d/("compiler/compile-"+role+"/stdout.raw")).write_bytes(mut)
  sid=next(i for i,x in enumerate(row["stages"]) if x["stage"]=="compile-"+role)
  receipt=row["stages"][sid];receipt["output_bytes"]=len(mut);receipt["output_sha256"]=safe.identity(mut)["sha256"]
  safe.write_json(d/("compiler/compile-"+role+"/receipt.json"),receipt)
  row["images"][role]=safe.identity(mut);plan["expected_images"][role]=safe.identity(mut)
  safe.write_json(r/"hia/platform/mempool_node/composition.json",plan)
  row["source_inputs"]=build.source_manifest(r);row["source_set_sha256"]=safe.identity(safe.canonical(row["source_inputs"]))["sha256"]
  safe.write_json(d/"build.json",row)
  # All claimed flat/compiler/source hashes agree; the unchanged full ELF must still refuse.
  cli("linkage-self-consistent-flat",1)

class RequiredResult(unittest.TextTestResult):
 def __init__(self,*a,**k):super().__init__(*a,**k);self.started=[]
 def startTest(self,test):self.started.append(test._testMethodName);super().startTest(test)
def main(argv=None):
 global OPTIONS,ARTIFACT,WORK,COUNTS
 safe.need(__debug__,"Optimized Python refused")
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("--scope",required=True,choices=("source","build"));p.add_argument("--build",type=Path);p.add_argument("--report",required=True,type=Path);a=p.parse_args(argv);OPTIONS=a
 safe.need((a.scope=="build")==bool(a.build),"Build scope requires actual --build; source scope excludes it")
 safe.need(not a.report.exists() and not a.report.is_symlink() and ROOT not in a.report.absolute().parents,"Fresh separate report")
 ARTIFACT=None if a.build is None else a.build.absolute();WORK=Path(tempfile.mkdtemp(prefix="mempool-node-integrity-",dir=a.report.parent));COUNTS={"controls":0,"actual_cli":0}
 all_names=sorted(n for n in dir(Integrity) if n.startswith("test_"));safe.need(len(all_names)==9,"Exact nine test group definitions")
 selected=all_names if a.scope=="build" else all_names[:6]
 expected=9 if a.scope=="build" else 6
 suite=unittest.TestSuite(Integrity(n) for n in selected);result=unittest.TextTestRunner(verbosity=2,resultclass=RequiredResult).run(suite)
 passed=result.wasSuccessful() and not result.skipped and result.testsRun==expected and result.started==selected
 report={"schema":"trnm.mempool-node-integrity.v1","status":"PASS" if passed else "FAIL","scope":a.scope,"required_groups":expected,
  "executed_groups":result.testsRun,"started":result.started,"skipped":len(result.skipped),"failures":len(result.failures),"errors":len(result.errors),
  **COUNTS,"raw_directory":str(WORK),"native_execution":False,"original_execution":False}
 safe.write_json(a.report,report);print(json.dumps(report,sort_keys=True))
 if not passed:raise SystemExit(1)
if __name__=="__main__":main()
