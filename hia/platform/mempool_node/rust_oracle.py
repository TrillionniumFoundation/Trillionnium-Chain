"""Actual original Node PendingPreview comparison; unchanged production functions."""
from pathlib import Path
import argparse,ast,os,sys,json,time,hashlib,shutil,traceback,subprocess,re,tomllib
from .build import ROOT,source_manifest
from . import observations as observation,node_observations,cross_observations
from . import safe
from .original_graph import include_graph
from hia.platform.execution_state import rust_oracle as utility
HERE=Path(__file__).absolute().parent
R=ROOT
SUITES={};GROUP=None
def current_admission():
 return node_observations.collect(SUITES["node"]) if GROUP=="node" else observation.collect({k:SUITES[k] for k in ("smoke","boundaries","capacity")})
def canonical_bytes():
 cases,_,_=current_admission()
 return b"".join(observation.canonical(c)+b"\n" for c in cases)
need=utility.need;canonical_root=utility.canonical_root;canonical_file=utility.canonical_path
identity=utility.identity;file_identity=utility.file_identity;load_json=utility.load_json;write_json=utility.write_json
SKIP=frozenset((".git","target","__pycache__"))
graph_source=HERE/"original_graph.py"
STORE="trillionnium/crates/trnm-pon-node/src/store/mempool.rs"
HOOK="hia_m05_pending_oracle.rs"
DECL=b'\n#[cfg(test)]\n#[path = "hia_m05_pending_oracle.rs"]\nmod hia_m05_pending_oracle;\n'
TEST="store::mempool::hia_m05_pending_oracle::evaluate"
TESTS=(
 "store::mempool::incremental_prefix_tests::signature_reuse_requires_complete_raw_prefix_and_preserves_first_refusal",
 "store::mempool::incremental_prefix_tests::real_signature_witness_rebinds_parent_state_height_and_complete_config",
 "store::mempool::incremental_prefix_tests::signature_cache_survives_cancellation_and_unwind_without_publishing_suffix",
 "store::init_marker_tests::initialization_marker_preserves_exact_context_errors",
 "store::init_marker_tests::initialization_marker_recovery_and_cold_reopen_preserve_state",
 "store::init_marker_tests::initialization_marker_rejects_special_files_and_post_precheck_substitution",
)
DEFAULTS=(STORE,HOOK,DECL,TEST,TESTS)
def capture_original(repository):
 repository=canonical_root(repository);rows={}
 for dirname in ("trillionnium","config","formal"):
  for path in sorted((repository/dirname).rglob("*")):
   relative=path.relative_to(repository)
   if any(part in SKIP for part in relative.parts):continue
   need(not path.is_symlink(),"Symbolic original input")
   if path.is_dir():continue
   rows[relative.as_posix()]=file_identity(canonical_file(repository,relative.as_posix()))
 graph=include_graph(repository)
 for name in graph["includes"]:rows[name]=file_identity(canonical_file(repository,name))
 need({"trillionnium/Cargo.toml","trillionnium/Cargo.lock",STORE}<=set(rows),"Incomplete original Node")
 return dict(sorted(rows.items())),graph
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def capture_loader_directory(path):
 path=Path(path).absolute()
 need(path==path.resolve(strict=True) and path.is_dir() and not path.is_symlink(),"Compiler loader directory is not canonical")
 st=path.stat()
 return {"path":str(path),"device":st.st_dev,"inode":st.st_ino,"mode":st.st_mode,"uid":st.st_uid,"gid":st.st_gid}
def main(argv=None):
 global SUITES,GROUP,STORE,HOOK,DECL,TEST,TESTS
 need(__debug__,"Optimized Python is not admitted")
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--group",required=True,choices=("m05","node"))
 for group in ("smoke","boundaries","capacity","node","cross"):parser.add_argument("--"+group,type=Path)
 parser.add_argument("--cargo-target",required=True,type=Path)
 parser.add_argument("--output",required=True,type=Path)
 args=parser.parse_args(argv)
 STORE,HOOK,DECL,TEST,TESTS=DEFAULTS
 GROUP=args.group
 required={"node"} if GROUP=="node" else {"smoke","boundaries","capacity","cross"}
 provided={k for k in ("smoke","boundaries","capacity","node","cross") if getattr(args,k) is not None}
 need(provided==required,"Exact required actual native partitions")
 SUITES={k:getattr(args,k).absolute() for k in required}
 if GROUP=="node":
  STORE="trillionnium/crates/trnm-pon-node/src/store.rs";HOOK="hia_node_checked_prefix_oracle.rs"
  DECL=b'\n#[cfg(test)]\n#[path = "hia_node_checked_prefix_oracle.rs"]\nmod hia_node_checked_prefix_oracle;\n'
  TEST="store::hia_node_checked_prefix_oracle::evaluate";TESTS=TESTS[3:]
 output=args.output.absolute();need(output==output.resolve() and not output.exists() and output!=ROOT and ROOT not in output.parents and output not in ROOT.parents,"Fresh separate original evidence")
 output.mkdir(mode=0o700);isolated=output/"isolated-source"
 stages=[];fences=[];controls=[];actual=[];retained=[];failure=None;final_errors=[]
 cross_case=None;cross_native=None;cross_actual=[];cross_controls=[]
 binary=None;binary_identity=None;tools=None;serde=None;serde_capture=None;library=None;loader=None;sqlite=None;sqlite_files={}
 original_map=None;isolated_expected=None;native=None;environment=None;start=time.monotonic_ns()
 captured_native=None;helpers={};bound={}
 def fence(label):
  if captured_native is None:
   row={"label":label,"status":"NOT_CAPTURED","checks":{},"errors":[]}
   fences.append(row);write_json(output/(label+".json"),row);return
  errors=[];checks={}
  def test(name,fn):
   try:checks[name]=fn()
   except BaseException as e:errors.append({"name":name,"error":repr(e)})
  def captured():
   need(utility.same_json(source_manifest(),captured_native),"Complete native source inventory changed")
   for path,row in {**bound,**helpers}.items():need(file_identity(Path(path))==row,"Bound bytes drift "+path)
   return {"status":"MATCH","files":len({**bound,**helpers}),"sha256":identity(canonical({**bound,**helpers}))["sha256"]}
  test("native_runtime_and_actual_raw",captured)
  if original_map is not None:
   def source():
    now,_=capture_original(R);need(now==original_map,"Original source drift")
    return {"status":"MATCH","files":len(now),"sha256":identity(canonical(now))["sha256"]}
   test("actual_original_source",source)
  if isolated_expected is not None:
   def isolated_source():
    now,_=capture_original(isolated);need(now==isolated_expected,"Isolated original or test hook drift")
    need((isolated/STORE).read_bytes()==(R/STORE).read_bytes()+DECL,"Original production prefix changed")
    need((output/"corpus.jsonl").read_bytes()==canonical_bytes(),"Original corpus drift")
    if GROUP=="m05":need((output/"cross-corpus.jsonl").read_bytes()==(HERE/"cross_corpus.jsonl").read_bytes(),"Cross input drift")
    return {"status":"MATCH","files":len(now),"sha256":identity(canonical(now))["sha256"]}
   test("isolated_source_and_original_prefix",isolated_source)
  if tools is not None:
   def actual_tools():
    for name,row in tools.items():need(file_identity(Path(row["path"]))=={k:row[k] for k in ("bytes","sha256")},"Compiler/Cargo drift")
    return {"status":"MATCH","tools":tools}
   test("actual_compilers",actual_tools)
  if serde_capture is not None:
   def actual_serde():
    need(serde_capture()==serde["crate_sources"],"Actual locked serde source drift")
    return {"status":"MATCH","files":len(serde["crate_sources"])}
   test("locked_serde_sources",actual_serde)
  if loader is not None:
   test("derived_normal_compiler_loader",lambda:{"status":"MATCH",**capture_loader_directory(Path(loader["path"]))} if capture_loader_directory(Path(loader["path"]))==loader else (_ for _ in ()).throw(ValueError("Derived compiler loader directory drift")))
  if sqlite is not None:
   def actual_sqlite():
    for path,row in sqlite_files.items():need(file_identity(Path(path))==row,"Actual SQLite qualification artifact/source drift")
    return {"status":"MATCH","files":len(sqlite_files),"build_fence":sqlite["build_fence"]}
   test("actual_sqlite_build_qualification",actual_sqlite)
  if library is not None:
   test("actual_serde_library",lambda:{"status":"MATCH","identity":file_identity(output/"actual-serde-library.rlib")} if file_identity(output/"actual-serde-library.rlib")==library["identity"] else (_ for _ in ()).throw(ValueError("Actual serde library drift")))
  if binary is not None:
   test("actual_independent_binary",lambda:{"status":"MATCH",**file_identity(binary)} if file_identity(binary)==binary_identity else (_ for _ in ()).throw(ValueError("Original binary drift")))
  row={"label":label,"status":"PASS" if not errors else "FAIL","checks":checks,"errors":errors}
  fences.append(row);write_json(output/(label+".json"),row);need(not errors,"Actual source fence failed")
 def run(argv,label,timeout=240,env=None):
  return utility.run_command(argv,isolated,output,label,stages,timeout=timeout,environment=environment if env is None else env)[0]
 try:
  environment=utility.clean_build_environment()
  captured_native=source_manifest()
  helpers={str(ROOT/name):file_identity(ROOT/name) for name in captured_native}
  target=utility.safe_target(args.cargo_target,output,R,SUITES["node" if GROUP=="node" else "smoke"],isolated)
  need(shutil.disk_usage("/tmp").free>1_500_000_000,"Insufficient actual free disk before Node compile")
  cases,native,bound=current_admission()
  if GROUP=="node":need(len(cases)==4 and sum(len(c["actions"]) for c in cases)==96,"Whole four-Settings Node history roster")
  else:need(len(cases)==11 and sum(len(c["actions"]) for c in cases)==122 and sum(a["op"]=="validate" for c in cases for a in c["actions"])==58,"Whole original M05 history roster")
  raw=b"".join(observation.canonical(c)+b"\n" for c in cases)
  need(raw==canonical_bytes()==(HERE/("node_corpus.jsonl" if GROUP=="node" else "corpus.jsonl")).read_bytes(),"Exact actual raw-derived corpus")
  native_path=output/"native-admission.json"
  write_json(native_path,{"status":"ADMITTED_NOT_ORIGINAL_EXECUTED","histories":len(cases),"actions":sum(len(c["actions"]) for c in cases),"validations":sum(a["op"]=="validate" for c in cases for a in c["actions"]),"corpus":identity(raw),"inputs":bound})
  write_json(output/"native-observations.json",native)
  if GROUP=="m05":
   cross_case,cross_native,cross_bound=cross_observations.collect(SUITES["cross"])
   cross_raw=observation.canonical(cross_case)+b"\n"
   need(cross_raw==(HERE/"cross_corpus.jsonl").read_bytes() and len(cross_case["actions"])==24,"Whole canonical cross input")
   for path,row in cross_bound.items():
    if path in bound:need(utility.same_json(bound[path],row),"Native source/input conflict")
    bound[path]=row
   (output/"cross-corpus.jsonl").write_bytes(cross_raw);write_json(output/"cross-native-observations.json",cross_native)
  original_map,graph=capture_original(R)
  write_json(output/"admission.json",{"status":"ADMITTED_NOT_ORIGINAL_EXECUTED","native_report":file_identity(native_path),"bound_native_inputs":bound,"original_sources":original_map,"original_include_graph":graph,"helpers":helpers,"corpus":identity(canonical_bytes())})
  fence("source-before")
  isolated.mkdir(mode=0o700)
  for name,row in original_map.items():
   source=canonical_file(R,name);dest=isolated/name;dest.parent.mkdir(parents=True,exist_ok=True)
   with source.open("rb") as inp,dest.open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
   need(file_identity(dest)==row==file_identity(source),"Original copy drift "+name)
  original_store=(R/STORE).read_bytes();hook=(HERE/("rust_node_reference.rs" if GROUP=="node" else "rust_reference.rs")).read_bytes()
  need(hook.startswith(b"// Private cfg(test)") and DECL.split(b"mod ",1)[1].split(b";",1)[0] not in original_store,"Exact test-only source adapter")
  hook_path=(isolated/STORE).parent/HOOK
  (isolated/STORE).write_bytes(original_store+DECL);hook_path.write_bytes(hook)
  isolated_expected={**original_map,STORE:identity(original_store+DECL),hook_path.relative_to(isolated).as_posix():identity(hook)}
  write_json(output/"isolated-source-preparation.json",{"source_path":str(isolated),"production_prefix_changed":False,"only_append":DECL.decode(),"hook":identity(hook),"expected_sources":isolated_expected,"source_set":identity(canonical(dict(sorted(isolated_expected.items()))))})
  (output/"corpus.jsonl").write_bytes(canonical_bytes());fence("isolated-source-before")
  version=run(["rustc","-Vv"],"rustc-version",15);need(b"host: x86_64-unknown-linux-gnu\n" in version,"Actual Rust target")
  sysroot=Path(run(["rustc","--print","sysroot"],"rustc-sysroot",15).decode().strip()).resolve(strict=True)
  tools={name:{"path":str((sysroot/"bin"/name).resolve(strict=True)),**file_identity((sysroot/"bin"/name).resolve(strict=True))} for name in ("rustc","cargo","rustdoc")}
  need(run([tools["rustc"]["path"],"-Vv"],"rustc-selected-version",15)==version,"Actual selected compiler differs")
  environment.update(RUSTC=tools["rustc"]["path"],RUSTDOC=tools["rustdoc"]["path"],CARGO=tools["cargo"]["path"],RUSTC_WRAPPER="",RUSTC_WORKSPACE_WRAPPER="")
  loader=capture_loader_directory(sysroot/"lib")
  need(not environment.get("LD_LIBRARY_PATH"),"External loader override survived initial refusal")
  environment["LD_LIBRARY_PATH"]=loader["path"]
  write_json(output/"derived-build-environment.json",{"schema":"trnm.actual-node-derived-build-environment.v1","external_override_gate":"clean_build_environment before source admission","actual_tools":tools,"actual_sysroot":str(sysroot),"loader":loader,"derived_ld_library_path":loader["path"],"cargo_config":["build.incremental=false"],"profile_or_feature_overrides":False,"reuse_source":str(isolated)})
  metadata=run([tools["cargo"]["path"],"metadata","--locked","--format-version=1","--filter-platform","x86_64-unknown-linux-gnu","--manifest-path",str(isolated/"trillionnium/Cargo.toml")],"cargo-original-metadata",120)
  metadata_value=load_json(metadata)
  serde,serde_capture=utility.capture_serde_graph(metadata_value,isolated,output)
  built=run([tools["cargo"]["path"],"--config","build.incremental=false","test","--locked","--manifest-path",str(isolated/"trillionnium/Cargo.toml"),"-p","trnm-pon-node","--lib","--no-run","--message-format=json","--target-dir",str(target)],"cargo-original-test-build",900)
  artifacts=[load_json(line) for line in built.splitlines() if line.startswith(b"{")]
  sqlite_packages=[p for p in metadata_value["packages"] if p["name"]=="trnm-sqlite-io-boundary"]
  need(len(sqlite_packages)==1,"Unique actual original SQLite boundary package")
  sqlite_rows=[r for r in artifacts if r.get("reason")=="build-script-executed" and r.get("package_id")==sqlite_packages[0]["id"]]
  need(len(sqlite_rows)==1,"Actual SQLite boundary build-script result absent or duplicated")
  sqlite_row=sqlite_rows[0];sqlite_env=dict(sqlite_row.get("env",[]))
  need(sqlite_row.get("cfgs")==["trnm_sqlite_layout_witness"] and sqlite_env.get("TRNM_SQLITE3_BUILD_FENCE")=="sqlite-3.54.1-normal-native-linux-layout-v4" and sqlite_env.get("TRNM_SQLITE3_AMALGAMATION_SHA256")=="0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52" and "TRNM_SQLITE3_UNQUALIFIED_REASON" not in sqlite_env,"Original unmodified SQLite build qualification did not pass")
  need(b"trnm SQLite I/O boundary UNQUALIFIED" not in (output/"cargo-original-test-build/stderr.raw").read_bytes(),"Original SQLite gate emitted unqualified warning")
  sqlite_out=Path(sqlite_row["out_dir"]).absolute()
  need(sqlite_out==sqlite_out.resolve(strict=True) and target.resolve() in sqlite_out.parents,"Actual SQLite artifact path escaped target")
  sqlite_saved=output/"actual-sqlite-qualification";sqlite_saved.mkdir(mode=0o700)
  for name in ("libtrnm_sqlite_layout_witness.a","trnm-witness-symbols.stdout","trnm-witness-symbols.stderr"):
   source=canonical_file(sqlite_out,name);row=file_identity(source);dest=sqlite_saved/name
   with source.open("rb") as inp,dest.open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
   need(file_identity(dest)==row==file_identity(source),"Actual SQLite witness copy drift")
   sqlite_files[str(source)]=row;sqlite_files[str(dest)]=row
  for name in ("output","stderr"):
   source=canonical_file(sqlite_out.parent,name);row=file_identity(source);dest=sqlite_saved/("build-script-"+name+".raw")
   with source.open("rb") as inp,dest.open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
   need(file_identity(dest)==row==file_identity(source),"Actual SQLite build-script copy drift")
   sqlite_files[str(source)]=row;sqlite_files[str(dest)]=row
  sqlite={"package":sqlite_packages[0],"artifact":sqlite_row,"build_fence":sqlite_env["TRNM_SQLITE3_BUILD_FENCE"],"derived_loader":loader,"files":sqlite_files}
  write_json(output/"actual-sqlite-qualification.json",sqlite)
  serde_rows=[r for r in artifacts if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="serde_json" and r["target"].get("kind")==["lib"]]
  bins=[r for r in artifacts if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="trnm_pon_node" and r["target"].get("kind")==["lib"] and r.get("profile",{}).get("test") is True and r.get("executable")]
  need(len(serde_rows)==len(bins)==1,"Unique actual Node test binary and serde library")
  need(serde_rows[0]["package_id"]==serde["package"]["id"] and set(serde_rows[0]["features"])=={"default","std"},"Actual serde library graph differs")
  libs=[Path(p).absolute() for p in serde_rows[0]["filenames"] if p.endswith(".rlib")]
  need(len(libs)==1 and libs[0]==libs[0].resolve(strict=True) and target.resolve() in libs[0].parents,"Actual serde library escaped target")
  lib=libs[0];libid=file_identity(lib)
  with lib.open("rb") as inp,(output/"actual-serde-library.rlib").open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
  (output/"actual-serde-library.rlib").chmod(0o400);need(file_identity(output/"actual-serde-library.rlib")==libid==file_identity(lib),"Actual serde copy drift")
  library={"artifact":serde_rows[0],"source_path":str(lib),"identity":libid}
  write_json(output/"actual-serde-library-before.json",library)
  compiled=Path(bins[0]["executable"]).absolute();need(compiled==compiled.resolve(strict=True) and target.resolve() in compiled.parents,"Actual binary escaped target")
  binary_identity=file_identity(compiled);binary=output/"original-test-binary"
  with compiled.open("rb") as inp,binary.open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
  binary.chmod(0o500);need(file_identity(binary)==binary_identity==file_identity(compiled),"Independent actual binary differs")
  write_json(output/"original-binary-before.json",{"path":str(binary),"source":str(compiled),"artifact":bins[0],**binary_identity})
  fence("compiled-source-and-binary-before")
  listed=run([str(binary),"--list"],"list-original-tests",30);tests={l.removesuffix(": test") for l in listed.decode().splitlines() if l.endswith(": test")}
  required_tests={TEST,*TESTS}|({"store::mempool::hia_m05_pending_oracle::evaluate_cross"} if GROUP=="m05" else set())
  need(required_tests<=tests,"Actual original methods/tests absent "+repr(required_tests-tests))
  for i,name in enumerate(TESTS):
   result=run([str(binary),"--exact",name,"--nocapture","--test-threads=1"],"retained-original-"+str(i),120)
   utility.assert_test_executed(result,name);retained.append(name)
  extra={"TRNM_HIA_NODE_PREFIX_CORPUS":str(output/"corpus.jsonl"),"TRNM_HIA_NODE_PREFIX_ARTIFACTS":str(output/"actual-node-fixtures")} if GROUP=="node" else {"TRNM_HIA_M05_NODE_CORPUS":str(output/"corpus.jsonl"),"TRNM_HIA_M05_NODE_ARTIFACTS":str(output/"actual-node-fixtures"),"TRNM_HIA_M05_NODE_HISTORY_COUNT":str(len(cases))}
  result=run([str(binary),"--exact",TEST,"--nocapture","--test-threads=1"],"actual-node-corpus",600,dict(environment,**extra))
  utility.assert_test_executed(result,TEST)
  marker=b"NPNODE_ORIGINAL:" if GROUP=="node" else b"M05NODE_ORIGINAL:"
  actual=[load_json(line.split(marker,1)[1]) for line in result.splitlines() if marker in line]
  need(len(actual)==len(cases) and [r["name"] for r in actual]==[r["name"] for r in cases],"Whole actual original histories")
  for case,n,a in zip(cases,native,actual,strict=True):
   differences=[]
   def equal(x,y,label):
    if not utility.same_json(x,y):differences.append(label)
   if GROUP=="node":
    for name in ("actual_original_settings","actual_original_node","actual_checked_parent","actual_checked_prefix","actual_prepared_observation"):equal(a.get(name),True,name)
    equal(a.get("external_state_config_root_or_verdict"),False,"no caller authority")
    for name in ("context","base_hex","base_unchanged","cold_source_equal"):equal(n[name],a.get(name),name)
    equal({k:v for k,v in n["parent"].items() if k not in ("epoch","record_hex")},a.get("parent"),"actual disk parent")
    equal(len(n["actions"]),len(a["actions"]),"complete action count")
    for index,(nr,ar) in enumerate(zip(n["actions"],a["actions"],strict=True)):
     for name in ("index","op","transactions","outcome","error","ready","length","state_hex","root_hex","receipts","metrics","prepared"):equal(nr[name],ar.get(name),str(index)+"."+name)
     equal(ar.get("base_unchanged"),True,str(index)+".actual base unchanged")
   else:
    for name in ("actual_original_settings","actual_original_node","actual_original_pool_parent","actual_original_pending_preview","actual_typed_gate_and_ready","base_unchanged","cold_source_equal"):equal(a.get(name),True,name)
    for name in ("external_state_nonce_signature_or_verdict","continuous_permit","durable_local_pool","node_commit"):equal(a.get(name),False,name)
    for name in ("context","base_hex"):equal(n[name],a.get(name),name)
    equal(len(n["actions"]),len(a["actions"]),"complete action count")
    for nr,ar,request in zip(n["actions"],a["actions"],case["actions"],strict=True):
     index=nr["index"];label=str(index)+"."
     for name in ("index","op","outcome","error","progress"):equal(nr[name],ar.get(name),label+name)
     if nr["op"]=="validate":
      for name in ("main_validations","reused"):equal(nr[name],ar.get(name),label+name)
      equal(ar.get("base_unchanged"),True,label+"actual base unchanged")
      if nr["prefix_observed"]:
       equal(nr["prefix_length"],ar.get("prefix_length"),label+"retained actual optional Prefix length")
       equal(nr["prefix_ready"],ar.get("prefix_length") is not None,label+"retained actual Prefix existence")
      if nr["outcome"]=="ok":equal(nr["ready_count"],ar.get("ready_count"),label+"actual returned Ready count")
      else:equal(ar.get("rollback_length_and_facts"),True,label+"failed preview kept signature facts and length")
      if nr["outcome"]=="cancelled":equal(ar.get("error_full",{}).get("display"),"M05_CALLBACK_TOKEN:"+str(request["cancel"]["token"]),label+"actual cancel token")
      if nr["outcome"]=="panic":equal(ar.get("panic_message"),"M05_CALLBACK_PANIC:"+str(request["cancel"]["token"]),label+"actual panic token")
     elif nr["op"] in ("open","drop"):equal(nr["active"],ar.get("active"),label+"live owner")
     elif nr["op"]=="read":equal(ar.get("base_unchanged"),True,label+"actual full parent reread")
   controls.append({"name":case["name"],"status":"FAIL" if differences else "PASS","differences":differences,"native":n,"original":a})
  write_json(output/"comparison.json",{"controls":controls})
  need(all(r["status"]=="PASS" for r in controls),"Actual original Node PendingPreview differential failed")
  if GROUP=="m05":
   result=run([str(binary),"--exact","store::mempool::hia_m05_pending_oracle::evaluate_cross","--nocapture","--test-threads=1"],"actual-one-node-cross-corpus",240,
    dict(environment,TRNM_HIA_M05_CROSS_CORPUS=str(output/"cross-corpus.jsonl"),TRNM_HIA_M05_CROSS_ARTIFACTS=str(output/"actual-cross-fixtures")))
   utility.assert_test_executed(result,"store::mempool::hia_m05_pending_oracle::evaluate_cross")
   cross_actual=[load_json(line.split(b"M05CROSS_ORIGINAL:",1)[1]) for line in result.splitlines() if b"M05CROSS_ORIGINAL:" in line]
   need(len(cross_actual)==1,"Actual whole one-Node cross history")
   a=cross_actual[0];n=cross_native;differences=[]
   def equal(x,y,label):
    if not utility.same_json(x,y):differences.append(label)
   for field in ("same_actual_node_instance","actual_original_pending_preview","actual_original_checked_prefix","base_unchanged","cold_source_equal"):equal(a.get(field),True,field)
   for field in ("caller_state_root_nonce_or_signature_verdict","continuous_permit","node_commit"):equal(a.get(field),False,field)
   for field in ("name","context","base_hex","parent"):equal(n[field],a.get(field),field)
   equal(len(a["actions"]),24,"whole actual method roster")
   for nr,ar,request in zip(n["actions"],a["actions"],cross_case["actions"],strict=True):
    label=str(nr["index"])+"."
    for field in ("index","op","outcome","error"):equal(nr[field],ar.get(field),label+field)
    op=nr["op"]
    if op in ("node_new","node_execute","node_drop"):
     for field in ("ready","length","state_hex","root_hex","receipts","metrics"):equal(nr[field],ar.get(field),label+field)
    elif op=="canonical_parent":
     for field in ("rows","root_hex"):equal(nr[field],ar.get(field),label+field)
    elif op=="prepared":equal(nr["prepared"],ar.get("prepared"),label+"complete actual Prepared")
    elif op=="record":equal(nr["parent"],ar.get("parent"),label+"actual disk parent")
    elif op=="read":equal(ar.get("base_unchanged"),True,label+"actual shared base")
    elif op in ("open","drop"):equal(nr["active"],ar.get("active"),label+"active");equal(nr["progress"],ar.get("progress"),label+"progress")
    elif op=="validate":
     for field in ("progress","main_validations","reused"):equal(nr[field],ar.get(field),label+field)
     if nr["prefix_observed"]:
      equal(nr["prefix_length"],ar.get("prefix_length"),label+"actual optional Prefix length")
      equal(nr["prefix_ready"],ar.get("prefix_length") is not None,label+"actual Prefix existence")
     equal(ar.get("base_unchanged"),True,label+"actual shared base")
     if nr["outcome"]=="ok":equal(nr["ready_count"],ar.get("ready_count"),label+"Ready count")
     else:equal(ar.get("rollback_length_and_facts"),True,label+"whole retained rollback")
     if nr["outcome"]=="cancelled":equal(ar.get("error_full",{}).get("display"),"M05_CALLBACK_TOKEN:"+str(request["cancel"]["token"]),label+"cancel token")
     if nr["outcome"]=="panic":equal(ar.get("panic_message"),"M05_CALLBACK_PANIC:"+str(request["cancel"]["token"]),label+"panic token")
   cross_controls.append({"name":cross_case["name"],"status":"FAIL" if differences else "PASS","differences":differences,"native":n,"original":a})
   write_json(output/"cross-comparison.json",{"controls":cross_controls})
   need(not differences,"Actual one-Node cross lifecycle differential failed")
 except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
 finally:
  try:fence("source-and-binary-after")
  except BaseException as e:final_errors.append({"fence":repr(e)})
  for stage in stages:
   for stream in ("stdout","stderr"):
    if file_identity(output/stage["stage"]/(stream+".raw"))!=stage[stream]:final_errors.append({"changed_stage_raw":stage["stage"],"stream":stream})
  report={"schema":"trnm.mempool-node-original.v2","group":GROUP,"cross_original_observed":len(cross_actual),"cross_original_methods":sum(len(a["actions"]) for a in cross_actual),"cross_controls":cross_controls,"status":"PASS" if failure is None and not final_errors else "FAIL",
   "failure":failure,"final_errors":final_errors,"stages":stages,"fences":fences,"original_sources":original_map,"native_sources_and_actual_raw":bound,"helpers":helpers,
   "actual_tools":tools,"derived_loader":loader,"actual_sqlite_qualification":sqlite,"actual_serde_source":serde,"actual_serde_library":library,
   "actual_original_binary":None if binary is None else {"path":str(binary),**binary_identity},
   "original_retained":retained,"required_retained":list(TESTS),"original_histories_observed":len(actual),
   "controls":len(controls),"passed":sum(r["status"]=="PASS" for r in controls),"failed":sum(r["status"]!="PASS" for r in controls),
   "elapsed_ns":time.monotonic_ns()-start,"original_production_function_bytes_preserved":True,"node_commit":False,"complete_node":False}
  write_json(output/"report.json",report)
  if actual:write_json(output/"original-observations.json",{"histories":actual})
  print(json.dumps({k:report[k] for k in ("status","failure","original_histories_observed","controls","passed","failed","original_retained","elapsed_ns")}),flush=True)
  if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
