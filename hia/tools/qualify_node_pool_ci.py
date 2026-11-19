"""Exact-source CI observation and transport for the held-disk Node/M05 owner.

This helper reads complete native and original artifacts. It does not execute
consensus methods or grant persistence authority. Trace readback proves capture
start/retirement; it is not an additional syscall-policy oracle.
"""
from __future__ import annotations
import argparse, contextlib, hashlib, io, json, lzma, os, re, shutil, stat, struct, subprocess, tarfile, tempfile, tomllib, traceback
from pathlib import Path, PurePosixPath
from hia.platform.mempool_node import build, safe, evidence, observations as observation
from hia.platform.mempool_node import node_observations, cross_observations, native_contract
from hia.platform.mempool_node import rust_oracle as oracle

REPOSITORY=build.ROOT
need,same,identity=safe.need,safe.same,safe.identity
SCHEMA="trnm.node-pool-ci.v1"
ARCHIVE_SCHEMA="trnm.node-pool-ci-archive.v1"
NATIVE=("smoke","boundaries","capacity","node","cross")
KINDS=(*NATIVE,"original-m05","original-node")
STAGE_FIELDS={"stage","argv","cwd","wall_limit_seconds","cleanup_limit_seconds","started_monotonic_ns","exit_code","timed_out","launch_error","cleanup_error","pid","finished_monotonic_ns","elapsed_ns","stdout","stderr","output_files_closed","status"}
SNAPSHOT="source-capture"
LABELS={"smoke":"runtime-smoke-v3","boundaries":"runtime-boundaries-v3","capacity":"runtime-capacity-v2"}
SCOPE={"complete_node":False,"successor_admission":False,"persistent_commit":False,
       "admission_persistence":False,"continuous_permit":False,
       "service_deadline_qualified":False,"physical_power_loss":False}
def natural(value, label, minimum=0):
    need(type(value) is int and value >= minimum, "Expected exact integer: " + label)
    return value


def absolute(value):
    need(isinstance(value, str), "Absolute path text required")
    path = PurePosixPath(value)
    need(path.is_absolute() and str(path) == value and
         all(part not in (".", "..") for part in path.parts[1:]) and
         "\0" not in value and "\n" not in value and "\r" not in value,
         "Noncanonical absolute path")
    return Path(value)


def relative(value):
    safe.relative(value)
    need("\n" not in value and "\r" not in value, "Line break in artifact path")
    return PurePosixPath(value)


def lineage(environment=None):
    env = os.environ if environment is None else environment
    head, run, attempt = (env.get(key) for key in
                         ("TRNM_EXPECTED_SOURCE_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    need(isinstance(head, str) and re.fullmatch("[0-9a-f]{40}", head),
         "Exact checked out source head is required")
    need(isinstance(run, str) and re.fullmatch("[1-9][0-9]*", run) and
         isinstance(attempt, str) and re.fullmatch("[1-9][0-9]*", attempt),
         "Actual same CI run and attempt are required")
    return {"git_head": head, "run_id": run, "attempt": int(attempt)}


def committed_sources(repository, sources):
    """The same streaming HEAD-blob fence used by the existing CI foundations."""
    need(isinstance(sources, dict) and sources, "Complete committed source map required")
    names = sorted(sources)
    for name in names:
        relative(name)
    with tempfile.TemporaryFile() as requests, tempfile.TemporaryFile() as errors:
        requests.write("".join("HEAD:" + name + "\n" for name in names).encode())
        requests.seek(0)
        child = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repository,
                                 stdin=requests, stdout=subprocess.PIPE, stderr=errors)
        try:
            for name in names:
                header = child.stdout.readline().split()
                need(len(header) == 3 and header[1] == b"blob" and header[2].isdigit(),
                     "Captured source is absent from actual HEAD: " + name)
                total = remaining = int(header[2])
                h = hashlib.sha256()
                while remaining:
                    block = child.stdout.read(min(remaining, 1 << 20))
                    need(block, "Truncated HEAD source blob")
                    remaining -= len(block)
                    h.update(block)
                need(child.stdout.read(1) == b"\n" and
                     same(sources[name], {"bytes": total, "sha256": h.hexdigest()}),
                     "Captured bytes differ from actual HEAD: " + name)
            need(not child.stdout.read() and child.wait(timeout=30) == 0,
                 "Actual HEAD blob reader did not finish")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            child.stdout.close()
    return len(names)


def source_pair(repository, observations, expected):
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repository).decode().strip()
    need(head == expected["git_head"], "Current Git head differs from expected source head")
    result = {}
    for name in ("source-before.json", "source-after.json"):
        source = load(observations, name)
        need(source.get("tested_commit") == source.get("candidate") == head and
             source.get("tested_tree") == tree and source.get("kind") == "head" and
             source.get("tracked_worktree_verified") is True and
             type(source.get("tracked_entries")) is int and source["tracked_entries"] > 0,
             "Full exact-head source observation is missing or changed")
        result[name] = file_identity(observations, name)
    return result


def check_captured_registry(capture_dir, serde):
    raw = safe.read(capture_dir, "serde_json.crate", 16 << 20)
    need(same(identity(raw), {k: serde["registry_archive"][k] for k in ("bytes", "sha256")}),
         "Captured registry archive differs")
    found = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as packed:
        for member in packed:
            parts = relative(member.name).parts
            need(member.isfile() and len(parts) >= 2 and
                 parts[0] == "serde_json-1.0.149" and
                 member.linkname == "" and 0 <= member.size <= 8 << 20,
                 "Unsafe registry archive member")
            name = "/".join(parts[1:])
            need(name not in found and name != ".cargo-ok" and len(found) < 4096,
                 "Duplicate or generated registry member")
            total += member.size
            need(total <= 64 << 20, "Registry source archive exceeds source bound")
            with packed.extractfile(member) as stream:
                data = stream.read(member.size + 1)
            need(len(data) == member.size and
                 safe.read(capture_dir, "serde/" + name) == data,
                 "Actual captured crate differs from lock-bound archive")
            found[name] = identity(data)
    need(same(found, serde["archive_source_files"]) and
         set(found) <= set(serde["crate_sources"]) and
         set(serde["crate_sources"]) - set(found) <= {".cargo-ok"},
         "Complete actual registry source inventory differs")
    generated = {name: serde["crate_sources"][name] for name in
                 set(serde["crate_sources"]) - set(found)}
    need(same(generated, serde["optional_cargo_generated_files"]),
         "Generated Cargo marker inventory differs")
    if generated:
        need(same(load(capture_dir, "serde/.cargo-ok", 1024), {"v": 1}),
             "Generated Cargo readiness marker differs")



def regular_roster(root):
    rows=object_inventory(root)
    need(all(row["type"] in ("file","directory") for row in rows.values()),"Regular unaliased roster required")
    return {name for name,row in rows.items() if row["type"]=="file"}

def digest(value):return identity(safe.canonical(value))["sha256"]
def read(root,name):return safe.read(root,name)
def load(root,name,limit=1<<30):return safe.parse(safe.read(root,name,limit))
def write(path,value):
    path=Path(path)
    need(not path.exists() and not path.is_symlink(),"Fresh result required")
    safe.write_json(path,value)
def sources():
    native=build.source_manifest()
    original,_=oracle.capture_original(REPOSITORY)
    return native,original

def input_fence(inputs):
    for path,row in inputs.items():
        need(same(safe.file_identity(path),row),"Observed artifact changed: "+path)

def native_partition(group,artifact):
    """Replay every predicate for the named complete native partition."""
    need(group in NATIVE,"Known native partition")
    artifact=Path(artifact).absolute()
    captured=build.source_manifest()
    inputs={}
    directory,built,report=evidence.partition(artifact,group,inputs)
    roster=load(REPOSITORY,"hia/platform/mempool_node/case_roster.json")
    if group=="node":
        cases,actual,more=node_observations.collect(artifact)
        counts={"histories":len(cases),"methods":sum(len(c["actions"]) for c in cases),
                "processes":report["real_processes"],"controls":report["controls_total"]}
        need(same(counts,{"histories":4,"methods":96,"processes":8,"controls":4}),"Whole Node roster")
        inputs.update(more)
    elif group=="cross":
        case,actual,more=cross_observations.collect(artifact)
        counts={"histories":1,"methods":len(case["actions"]),"validations":sum(a["op"]=="validate" for a in case["actions"]),
                "processes":report["real_processes"]}
        need(same(counts,{"histories":1,"methods":24,"validations":5,"processes":1}),"Whole same-Node cross roster")
        inputs.update(more)
    else:
        need(type(report["controls_total"]) is int and report["controls_total"]==len(roster[group]["controls"])
             and [r["name"] for r in report["controls"]]==roster[group]["controls"],"Whole native control roster")
        folders=sorted(p.parent for p in directory.glob("*/receipt.json"))
        need(type(report["real_processes"]) is int and report["real_processes"]==roster[group]["processes"]
             and [p.name for p in folders]==roster[group]["process_names"],"Complete actual process roster")
        fixed=native_contract.fixed_validations(group)
        need([r["name"] for r in report["controls"] if r["name"] in fixed]==list(fixed),"Fixed predicate roster")
        cases=[];actual=[]
        for folder in folders:
            case,row=observation.decode_process(folder,LABELS[group],inputs)
            cases.append(case);actual.append(row)
            if group!="capacity":evidence.trace_capture(folder,inputs)
        pending=[a for row in actual for a in row["actions"] if a["op"]=="validate"]
        opens=[(r,a) for r in actual for a in r["actions"] if a["op"]=="open"]
        from hia.platform.mempool_node.suite_smoke import pool_result
        for control in report["controls"]:
            if control["name"] not in fixed:
                native_contract.nonvalidation(group,control)
                if "process" in control:
                    found=[r for r in actual if same(control["process"],r["receipt"])]
                    need(len(found)==1,"Detached process control")
                    expected=[p for a in found[0]["actions"] for p in a["progress_raw"]]
                    observed=[{k:p[k] for k in ("observed_hex","ack_hex","kind","index","height","classification")} for p in control["progress"]]
                    need(same(expected,observed),"Whole process progress differs")
                result=control.get("result",control.get("pool_open"))
                if result is not None:
                    found=False
                    for row,action in opens:
                        if action["output_hex"]!=result.get("raw_hex"):continue
                        raw=bytes.fromhex(action["output_hex"]);h=struct.unpack_from("<8Q",raw)
                        value=pool_result(raw,1,h[2],h[3])
                        if same(result,value) and ("context_hex" not in control or control["context_hex"]==row["context_hex"]) and ("timestamp" not in control or same(control["timestamp"],row["timestamp"])) and ("workers" not in control or same(control["workers"],row["workers"])):
                            found=True;break
                    need(found,"Open/control detached from actual context and response")
                continue
            value=native_contract.validation(control,fixed[control["name"]])
            need(all(same(control.get(k),v) for k,v in value.items()),"Validation metadata differs")
            selected=None
            for i,action in enumerate(pending):
                if action["output_hex"]!=control["raw_hex"]:continue
                request=bytes.fromhex(action["input_hex"]);count=struct.unpack_from("<Q",request,24)[0];at=32;tx=[]
                for _ in range(count):
                    size=struct.unpack_from("<Q",request,at)[0];at+=8;tx.append(request[at:at+size].hex());at+=size
                need(all(type(p.get("action")) is str and p["action"]==control["name"] for p in control["progress"]),"Progress action changed")
                progress=[{k:p[k] for k in ("observed_hex","ack_hex","kind","index","height","classification")} for p in control["progress"]]
                if same(tx,control["input_hex"]) and same(progress,action["progress_raw"]):selected=i;break
            need(selected is not None,"Control detached from whole actual request/response/progress")
            pending.pop(selected)
        need(not pending,"Unreported actual validation")
        expected=[safe.parse(line) for line in read(REPOSITORY,"hia/platform/mempool_node/corpus.jsonl").splitlines()]
        expected=[c for c in expected if c["name"].startswith(LABELS[group]+"/")]
        need(same(cases,expected),"Actual complete canonical partition input differs")
        need(same(report["script"],identity(observation.read(REPOSITORY/("hia/platform/mempool_node/suite_"+group+".py"),inputs))),"Suite source differs")
        counts={"histories":len(cases),"methods":sum(len(c["actions"]) for c in cases),
                "validations":sum(a["op"]=="validate" for c in cases for a in c["actions"]),
                "processes":len(actual),"controls":len(report["controls"])}
    need(same(build.source_manifest(),captured),"Source changed during native readback")
    input_fence(inputs)
    return {"kind":group,"source_inputs":captured,"source_set_sha256":digest(captured),
            "executable":built["executable"],"counts":counts,"build":file_identity(artifact,"build/build.json"),
            "native_report":file_identity(artifact,"native/report.json"),"outer_report":file_identity(artifact,"report.json"),
            "elapsed_ns":report["elapsed_ns"],"trace_scope":"complete capture start and retirement; no additional syscall policy",
            **SCOPE},inputs

def native_admission(group,artifacts):
    counts,inputs=evidence.admit(group,artifacts)
    need(same(counts,{"histories":4,"methods":96,"validations":0,"cross_histories":0,"cross_methods":0}) if group=="node"
         else same(counts,{"histories":11,"methods":122,"validations":58,"cross_histories":1,"cross_methods":24}),"Whole original predecessor input")
    return counts,inputs

def actual_stages(directory,report,group):
    tests=list(oracle.DEFAULTS[4] if group=="m05" else oracle.DEFAULTS[4][3:])
    labels=[("rustc-version",15),("rustc-sysroot",15),("rustc-selected-version",15),("cargo-original-metadata",120),
            ("cargo-original-test-build",900),("list-original-tests",30),
            *(("retained-original-"+str(i),120) for i in range(len(tests))),("actual-node-corpus",600)]
    if group=="m05":labels.append(("actual-one-node-cross-corpus",240))
    rows=report["stages"]
    need(type(rows) is list and [r.get("stage") for r in rows]==[n for n,_ in labels],"Whole actual original stage roster")
    result={};previous=None
    for row,(name,budget) in zip(rows,labels,strict=True):
        need(type(row) is dict and set(row)==STAGE_FIELDS and same(row,load(directory,name+"/receipt.json")),"Exact original stage receipt")
        need(row["status"]=="PASS" and type(row["exit_code"]) is int and row["exit_code"]==0 and row["timed_out"] is False
             and row["launch_error"] is None and row["cleanup_error"] is None and row["output_files_closed"] is True
             and type(row["wall_limit_seconds"]) is int and row["wall_limit_seconds"]==budget
             and type(row["cleanup_limit_seconds"]) is int and row["cleanup_limit_seconds"]==10,"Actual original execution/cleanup budget")
        natural(row["pid"],"actual original pid",1)
        start=natural(row["started_monotonic_ns"],"actual start",1);finish=natural(row["finished_monotonic_ns"],"actual finish",start+1)
        need(natural(row["elapsed_ns"],"actual elapsed",1)==finish-start and (previous is None or start>=previous),"Actual original stage order/time")
        previous=finish;absolute(row["cwd"])
        need(type(row["argv"]) is list and row["argv"] and all(type(v) is str and "\0" not in v for v in row["argv"]),"Exact original argv")
        streams={k:read(directory,name+"/"+k+".raw") for k in ("stdout","stderr")}
        for k,raw in streams.items():need(same(identity(raw),row[k]),"Original complete raw identity")
        result[name]=(row,streams)
    return result,tests

def compare_histories(group,cases,native,actual):
 controls=[]
 for case,n,a in zip(cases,native,actual,strict=True):
  differences=[]
  def equal(x,y,label):
   if not same(x,y):differences.append(label)
  if group=="node":
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
 return controls

def compare_cross(cross_case,cross_native,cross_actual):
 cross_controls=[]
 a=cross_actual[0];n=cross_native;differences=[]
 def equal(x,y,label):
  if not same(x,y):differences.append(label)
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
 return cross_controls


def actual_tools(directory,report,rows,group,tests):
    tools=report["actual_tools"]
    need(type(tools) is dict and set(tools)=={"rustc","cargo","rustdoc"},"Exact Rust tools")
    sysroot=absolute(rows["rustc-sysroot"][1]["stdout"].decode().strip())
    version=rows["rustc-version"][1]["stdout"]
    need(b"host: x86_64-unknown-linux-gnu\n" in version and rows["rustc-selected-version"][1]["stdout"]==version,"Actual selected Rust version/host")
    for name,row in tools.items():
        need(type(row) is dict and set(row)=={"path","bytes","sha256"} and absolute(row["path"])==sysroot/"bin"/name
             and type(row["bytes"]) is int and row["bytes"]>0 and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}",row["sha256"]),"Bound absolute actual tool")
    need(rows["rustc-version"][0]["argv"]==["rustc","-Vv"] and rows["rustc-sysroot"][0]["argv"]==["rustc","--print","sysroot"]
         and rows["rustc-selected-version"][0]["argv"]==[tools["rustc"]["path"],"-Vv"],"Actual compiler argv")
    isolated=absolute(rows["cargo-original-test-build"][0]["cwd"])
    need(isolated.name=="isolated-source" and all(r[0]["cwd"]==str(isolated) for r in rows.values()),"One actual isolated original source")
    manifest=str(isolated/"trillionnium/Cargo.toml")
    need(rows["cargo-original-metadata"][0]["argv"]==[tools["cargo"]["path"],"metadata","--locked","--format-version=1",
         "--filter-platform","x86_64-unknown-linux-gnu","--manifest-path",manifest],"Actual locked metadata argv")
    argv=rows["cargo-original-test-build"][0]["argv"]
    expected=[tools["cargo"]["path"],"--config","build.incremental=false","test","--locked","--manifest-path",manifest,
              "-p","trnm-pon-node","--lib","--no-run","--message-format=json","--target-dir"]
    need(type(argv) is list and len(argv)==len(expected)+1 and argv[:-1]==expected,"Actual original build argv")
    target=absolute(argv[-1]);need(target!=isolated and target not in isolated.parents and isolated not in target.parents,"Target/source disjoint")
    binary=report["actual_original_binary"]
    need(type(binary) is dict and set(binary)=={"path","bytes","sha256"} and absolute(binary["path"])==isolated.parent/"original-test-binary","Independent binary provenance")
    natural(binary["bytes"],"original binary size",1)
    need(same(file_identity(directory,"original-test-binary"),{k:binary[k] for k in ("bytes","sha256")}),"Complete independent actual binary bytes")
    path=binary["path"]
    need(rows["list-original-tests"][0]["argv"]==[path,"--list"],"Actual original discovery")
    for i,name in enumerate(tests):
        need(rows["retained-original-"+str(i)][0]["argv"]==[path,"--exact",name,"--nocapture","--test-threads=1"],"Retained argv changed")
    test="store::hia_node_checked_prefix_oracle::evaluate" if group=="node" else "store::mempool::hia_m05_pending_oracle::evaluate"
    need(rows["actual-node-corpus"][0]["argv"]==[path,"--exact",test,"--nocapture","--test-threads=1"],"Actual corpus argv")
    if group=="m05":
        need(rows["actual-one-node-cross-corpus"][0]["argv"]==[path,"--exact","store::mempool::hia_m05_pending_oracle::evaluate_cross","--nocapture","--test-threads=1"],"Actual same-Node corpus argv")
    events=[safe.parse(line) for line in rows["cargo-original-test-build"][1]["stdout"].splitlines() if line.startswith(b"{")]
    libraries=[r for r in events if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="serde_json" and r["target"].get("kind")==["lib"]]
    binaries=[r for r in events if r.get("reason")=="compiler-artifact" and r.get("target",{}).get("name")=="trnm_pon_node"
              and r["target"].get("kind")==["lib"] and r.get("profile",{}).get("test") is True and r.get("executable")]
    need(len(libraries)==len(binaries)==1,"Unique actual serde lib and original Node test executable")
    artifact=binaries[0];compiled=absolute(artifact["executable"])
    need(target in compiled.parents and artifact["target"]["src_path"]==str(isolated/"trillionnium/crates/trnm-pon-node/src/lib.rs"),"Actual binary source/target path")
    need(same(load(directory,"original-binary-before.json"),{"path":path,"source":str(compiled),"artifact":artifact,**{k:binary[k] for k in ("bytes","sha256")}}),"Actual independent binary capture")
    loader=report["derived_loader"]
    need(type(loader) is dict and set(loader)=={"path","device","inode","mode","uid","gid"} and loader["path"]==str(sysroot/"lib"),"Derived compiler loader path")
    for key in ("device","inode","mode","uid","gid"):natural(loader[key],"derived loader "+key)
    need(loader["inode"]>0 and stat.S_ISDIR(loader["mode"]),"Actual loader directory")
    need(same(load(directory,"derived-build-environment.json"),{
        "schema":"trnm.actual-node-derived-build-environment.v1","external_override_gate":"clean_build_environment before source admission",
        "actual_tools":tools,"actual_sysroot":str(sysroot),"loader":loader,"derived_ld_library_path":loader["path"],
        "cargo_config":["build.incremental=false"],"profile_or_feature_overrides":False,"reuse_source":str(isolated)}),"Actual derived environment differs")
    return tools,isolated,target,events,libraries[0],test

def actual_serde(directory,report,rows,library_row,target):
    serde=report["actual_serde_source"]
    fields={"package","resolve_node","locked_package","crate_directory","crate_sources","crate_source_set_sha256",
            "registry_archive","archive_source_files","archive_source_set_sha256","optional_cargo_generated_files","vendor_checksum_file_required"}
    need(type(serde) is dict and set(serde)==fields and same(load(directory,"serde-json-source-before.json"),serde),"Exact actual serde source")
    metadata=safe.parse(rows["cargo-original-metadata"][1]["stdout"])
    packages=[p for p in metadata["packages"] if p.get("name")=="serde_json"]
    need(same(packages,[serde["package"]]),"Actual unique registry package")
    package=serde["package"];nodes=[n for n in metadata["resolve"]["nodes"] if n.get("id")==package["id"]]
    need(same(nodes,[serde["resolve_node"]]) and {"default","std"}<=set(nodes[0]["features"]),"Actual metadata feature union")
    lock=tomllib.loads(read(REPOSITORY,"trillionnium/Cargo.lock").decode())
    locked=[p for p in lock["package"] if p.get("name")=="serde_json"]
    need(same(locked,[serde["locked_package"]]) and locked[0]["version"]=="1.0.149" and locked[0]["source"]==package["source"]
         and package["source"].startswith("registry+"),"Actual locked registry source")
    crate=absolute(serde["crate_directory"])
    need(package["manifest_path"]==str(crate/"Cargo.toml") and library_row["target"]["src_path"]==str(crate/"src/lib.rs")
         and library_row["package_id"]==package["id"] and library_row["target"]["kind"]==["lib"]
         and set(library_row["features"])=={"default","std"},"Actual library features/source")
    library=report["actual_serde_library"]
    need(type(library) is dict and set(library)=={"artifact","source_path","identity"}
         and same(library,load(directory,"actual-serde-library-before.json")) and same(library["artifact"],library_row),"Exact actual serde artifact copy")
    libpath=absolute(library["source_path"])
    need([p for p in library_row["filenames"] if p.endswith(".rlib")]==[str(libpath)] and target in libpath.parents
         and same(file_identity(directory,"actual-serde-library.rlib"),library["identity"]),"Complete retained serde library")
    need(serde["vendor_checksum_file_required"] is False and serde["crate_source_set_sha256"]==digest(serde["crate_sources"])
         and serde["archive_source_set_sha256"]==digest(serde["archive_source_files"])
         and serde["registry_archive"]["sha256"]==locked[0]["checksum"],"Whole locked registry inventory")
    return serde,library

def adaptation(group,original):
    if group=="node":
        store="trillionnium/crates/trnm-pon-node/src/store.rs";hook="hia_node_checked_prefix_oracle.rs"
        decl=b'\n#[cfg(test)]\n#[path = "hia_node_checked_prefix_oracle.rs"]\nmod hia_node_checked_prefix_oracle;\n'
        hook_source="hia/platform/mempool_node/rust_node_reference.rs"
    else:
        store,hook,decl=oracle.DEFAULTS[:3];hook_source="hia/platform/mempool_node/rust_reference.rs"
    original_bytes=read(REPOSITORY,store)
    need(same(identity(original_bytes),original[store]),"Actual production function bytes")
    hook_name=(PurePosixPath(store).parent/hook).as_posix()
    files={store:original_bytes+decl,hook_name:read(REPOSITORY,hook_source),
           "trillionnium/Cargo.lock":read(REPOSITORY,"trillionnium/Cargo.lock")}
    graph=oracle.include_graph(REPOSITORY)
    for name in graph["includes"]:
        if name not in files:files[name]=read(REPOSITORY,name)
    expected={**original,store:identity(files[store]),hook_name:identity(files[hook_name])}
    return store,hook_name,decl,files,expected

def source_capture(directory,group,original,isolated,serde,capture):
    store,hook,decl,files,expected=adaptation(group,original)
    preparation=load(directory,"isolated-source-preparation.json")
    need(same(preparation,{"source_path":str(isolated),"production_prefix_changed":False,"only_append":decl.decode(),
         "hook":identity(files[hook]),"expected_sources":expected,
         "source_set":identity(oracle.canonical(dict(sorted(expected.items()))))}),"Exact sole test adapter source preparation")
    dest=Path(directory)/SNAPSHOT
    source_map={k:identity(v) for k,v in sorted(files.items())}
    manifest={"schema":"trnm.node-pool-original-source-capture.v1","original_source_set_sha256":digest(original),
              "sole_appended_source":source_map,"serde_archive":{k:serde["registry_archive"][k] for k in ("bytes","sha256")},
              "serde_sources":serde["crate_sources"]}
    if capture and not dest.exists():
        dest.mkdir(mode=0o700)
        for name,raw in files.items():
            actual=read(Path(directory)/"isolated-source",name)
            need(actual==raw,"Actual isolated production prefix/hook/include differs")
            path=dest/"original"/relative(name);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with path.open("xb") as f:f.write(actual)
        archive=absolute(serde["registry_archive"]["path"])
        copy_file(archive.parent,archive.name,dest/"serde_json.crate",manifest["serde_archive"])
        crate=absolute(serde["crate_directory"])
        for name,row in serde["crate_sources"].items():copy_file(crate,name,dest/"serde"/relative(name),row)
        write(dest/"manifest.json",manifest)
    need(same(load(dest,"manifest.json"),manifest),"Actual source capture missing/different")
    expected_files={"manifest.json","serde_json.crate"}
    for name,raw in files.items():
        need(read(dest,"original/"+name)==raw,"Captured actual original prefix/hook/include differs")
        expected_files.add("original/"+name)
    for name,row in serde["crate_sources"].items():
        need(same(file_identity(dest,"serde/"+name),row),"Captured actual registry file differs")
        expected_files.add("serde/"+name)
    need(regular_roster(dest)==expected_files,"Complete source capture roster")
    check_captured_registry(dest,serde)
    return dest,expected

def actual_sqlite(directory,report,rows,events,target,loader):
    sqlite=report["actual_sqlite_qualification"]
    need(type(sqlite) is dict and set(sqlite)=={"package","artifact","build_fence","derived_loader","files"}
         and same(sqlite,load(directory,"actual-sqlite-qualification.json")),"Exact actual SQLite gate")
    metadata=safe.parse(rows["cargo-original-metadata"][1]["stdout"])
    packages=[p for p in metadata["packages"] if p["name"]=="trnm-sqlite-io-boundary"]
    need(same(packages,[sqlite["package"]]),"Actual SQLite package source")
    found=[r for r in events if r.get("reason")=="build-script-executed" and r.get("package_id")==packages[0]["id"]]
    need(same(found,[sqlite["artifact"]]),"Unique actual SQLite build artifact")
    row=found[0];env=dict(row["env"]);out=absolute(row["out_dir"])
    need(row["cfgs"]==["trnm_sqlite_layout_witness"] and env.get("TRNM_SQLITE3_BUILD_FENCE")=="sqlite-3.54.1-normal-native-linux-layout-v4"
         and env.get("TRNM_SQLITE3_AMALGAMATION_SHA256")=="0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52"
         and "TRNM_SQLITE3_UNQUALIFIED_REASON" not in env and b"trnm SQLite I/O boundary UNQUALIFIED" not in rows["cargo-original-test-build"][1]["stderr"]
         and target in out.parents and sqlite["build_fence"]==env["TRNM_SQLITE3_BUILD_FENCE"] and same(sqlite["derived_loader"],loader),"Original unmodified SQLite qualification")
    origin=absolute(report["actual_original_binary"]["path"]).parent
    expected={}
    for name in ("libtrnm_sqlite_layout_witness.a","trnm-witness-symbols.stdout","trnm-witness-symbols.stderr"):
        ident=file_identity(directory,"actual-sqlite-qualification/"+name)
        expected[str(out/name)]=ident;expected[str(origin/"actual-sqlite-qualification"/name)]=ident
    for name in ("output","stderr"):
        ident=file_identity(directory,"actual-sqlite-qualification/build-script-"+name+".raw")
        expected[str(out.parent/name)]=ident;expected[str(origin/"actual-sqlite-qualification"/("build-script-"+name+".raw"))]=ident
    need(same(sqlite["files"],expected),"Whole actual SQLite witness/source bytes")
    return sqlite

def predecessor_inputs(report,artifacts,current_bound,native_sources):
    helpers=report["helpers"];bound=report["native_sources_and_actual_raw"]
    suffix="/hia/platform/mempool_node/rust_oracle.py"
    candidates=[p for p in helpers if p.endswith(suffix)]
    need(len(candidates)==1,"Actual original native source root")
    old_repository=absolute(candidates[0][:-len(suffix)])
    need(same(helpers,{str(old_repository/name):row for name,row in native_sources.items()}),"Complete original helper/source graph")
    roots=[]
    for group,artifact in artifacts.items():
        artifact=Path(artifact).absolute();ident=file_identity(artifact,"report.json")
        candidates=[p for p,row in bound.items() if p.endswith("/report.json") and same(row,ident)]
        need(len(candidates)==1,"Actual native partition identity/provenance is missing or ambiguous")
        roots.append((artifact,absolute(candidates[0]).parent))
    relocated={}
    for name,row in current_bound.items():
        path=absolute(name);options=[]
        if REPOSITORY in path.parents:options.append(old_repository/path.relative_to(REPOSITORY))
        for current,old in roots:
            if current in path.parents:options.append(old/path.relative_to(current))
        need(len(options)==1,"Actual native input has no unique source/partition role")
        relocated[str(options[0])]=row
    need(same(bound,relocated),"Actual original input is not the whole current predecessor set")
    return helpers,bound


def original_result(directory,group,artifacts,capture=False):
    need(group in ("m05","node"),"Known original group")
    directory=Path(directory).absolute()
    native_sources,original=sources()
    counts,current_bound=native_admission(group,artifacts)
    report=load(directory,"report.json")
    fields={"schema","group","cross_original_observed","cross_original_methods","cross_controls","status","failure","final_errors","stages","fences",
            "original_sources","native_sources_and_actual_raw","helpers","actual_tools","derived_loader","actual_sqlite_qualification","actual_serde_source",
            "actual_serde_library","actual_original_binary","original_retained","required_retained","original_histories_observed","controls","passed","failed",
            "elapsed_ns","original_production_function_bytes_preserved","node_commit","complete_node"}
    need(type(report) is dict and set(report)==fields and report["schema"]=="trnm.mempool-node-original.v2" and report["group"]==group
         and report["status"]=="PASS" and report["failure"] is None and same(report["final_errors"],[])
         and report["original_production_function_bytes_preserved"] is True and report["node_commit"] is False and report["complete_node"] is False,"Complete original qualification/schema")
    need(same(report["original_sources"],original),"Complete original source graph differs")
    helpers,bound=predecessor_inputs(report,artifacts,current_bound,native_sources)
    suffix="/hia/platform/mempool_node/rust_oracle.py"
    old_repository=absolute(next(p for p in helpers if p.endswith(suffix))[:-len(suffix)])
    roots=[(REPOSITORY,old_repository)]
    for group_name,artifact in artifacts.items():
        artifact=Path(artifact).absolute();ident=file_identity(artifact,"report.json")
        old=absolute(next(p for p,row in bound.items() if p.endswith("/report.json") and same(row,ident))).parent
        roots.append((artifact,old))
    def rebase(value):
        if type(value) is dict:return {rebase(k):rebase(v) for k,v in value.items()}
        if type(value) is list:return [rebase(v) for v in value]
        if type(value) is str:
            for current,old in roots:
                prefix=str(current)+"/"
                if value.startswith(prefix):return str(old)+value[len(str(current)):]
        return value
    if group=="node":cases,native,before_bound=node_observations.collect(artifacts["node"])
    else:cases,native,before_bound=observation.collect({k:artifacts[k] for k in ("smoke","boundaries","capacity")})
    raw=b"".join(observation.canonical(c)+b"\n" for c in cases)
    need(read(directory,"corpus.jsonl")==raw,"Actual original full corpus bytes/order")
    need(same(load(directory,"native-observations.json"),rebase(native)),"Actual native comparison observation differs")
    need(same(load(directory,"native-admission.json"),{"status":"ADMITTED_NOT_ORIGINAL_EXECUTED","histories":len(cases),
         "actions":sum(len(c["actions"]) for c in cases),"validations":sum(a["op"]=="validate" for c in cases for a in c["actions"]),
         "corpus":identity(raw),"inputs":rebase(before_bound)}),"Actual pre-Cargo native admission differs")
    admission=load(directory,"admission.json")
    graph=oracle.include_graph(REPOSITORY)
    need(set(admission)=={"status","native_report","bound_native_inputs","original_sources","original_include_graph","helpers","corpus"}
         and admission["status"]=="ADMITTED_NOT_ORIGINAL_EXECUTED"
         and same(admission["native_report"],file_identity(directory,"native-admission.json"))
         and same(admission["bound_native_inputs"],bound) and same(admission["original_sources"],original)
         and same(admission["original_include_graph"],graph) and same(admission["helpers"],helpers) and same(admission["corpus"],identity(raw)),
         "Whole actual native/original source admission differs")
    rows,tests=actual_stages(directory,report,group)
    tools,isolated,target,events,library_row,test=actual_tools(directory,report,rows,group,tests)
    serde,library=actual_serde(directory,report,rows,library_row,target)
    sqlite=actual_sqlite(directory,report,rows,events,target,report["derived_loader"])
    captured,isolated_map=source_capture(directory,group,original,isolated,serde,capture)
    need(same(report["required_retained"],tests) and same(report["original_retained"],tests),"Exact actual retained tests")
    listed={line.removesuffix(": test") for line in rows["list-original-tests"][1]["stdout"].decode().splitlines() if line.endswith(": test")}
    required={test,*tests}
    if group=="m05":required.add("store::mempool::hia_m05_pending_oracle::evaluate_cross")
    need(required<=listed,"Actual test discovery incomplete")
    for i,name in enumerate(tests):oracle.utility.assert_test_executed(rows["retained-original-"+str(i)][1]["stdout"],name)
    stdout=rows["actual-node-corpus"][1]["stdout"];oracle.utility.assert_test_executed(stdout,test)
    marker=b"NPNODE_ORIGINAL:" if group=="node" else b"M05NODE_ORIGINAL:"
    actual=[safe.parse(line.split(marker,1)[1]) for line in stdout.splitlines() if marker in line]
    need(len(actual)==len(cases) and [r["name"] for r in actual]==[r["name"] for r in cases],"Whole actual original histories")
    need(same(load(directory,"original-observations.json"),{"histories":actual}),"Original observation summary differs from raw")
    controls=compare_histories(group,cases,rebase(native),actual)
    need(all(r["status"]=="PASS" for r in controls) and same(load(directory,"comparison.json"),{"controls":controls}),"Whole raw differential failed/different")
    for key,expected in (("original_histories_observed",len(actual)),("controls",len(controls)),("passed",len(controls)),("failed",0)):
        need(type(report[key]) is int and report[key]==expected,"Exact actual original count "+key)
    if group=="m05":
        cross_case,cross_native,_=cross_observations.collect(artifacts["cross"])
        need(read(directory,"cross-corpus.jsonl")==observation.canonical(cross_case)+b"\n"
             and same(load(directory,"cross-native-observations.json"),rebase(cross_native)),"Actual same-Node input/native observation")
        stdout=rows["actual-one-node-cross-corpus"][1]["stdout"]
        oracle.utility.assert_test_executed(stdout,"store::mempool::hia_m05_pending_oracle::evaluate_cross")
        actual_cross=[safe.parse(line.split(b"M05CROSS_ORIGINAL:",1)[1]) for line in stdout.splitlines() if b"M05CROSS_ORIGINAL:" in line]
        need(len(actual_cross)==1,"Whole actual same-Node original history")
        cross_controls=compare_cross(cross_case,rebase(cross_native),actual_cross)
        need(all(r["status"]=="PASS" for r in cross_controls)
             and same(load(directory,"cross-comparison.json"),{"controls":cross_controls})
             and same(report["cross_controls"],cross_controls)
             and type(report["cross_original_observed"]) is int and report["cross_original_observed"]==1
             and type(report["cross_original_methods"]) is int and report["cross_original_methods"]==24,"Actual same-Node raw differential")
    else:
        need(type(report["cross_original_observed"]) is int and report["cross_original_observed"]==0
             and type(report["cross_original_methods"]) is int and report["cross_original_methods"]==0
             and same(report["cross_controls"],[]),"Node original cannot claim another history")
    raw_sources={**bound,**helpers}
    common={"native_runtime_and_actual_raw":{"status":"MATCH","files":len(raw_sources),"sha256":identity(oracle.canonical(raw_sources))["sha256"]},
            "actual_original_source":{"status":"MATCH","files":len(original),"sha256":identity(oracle.canonical(original))["sha256"]}}
    copied={"isolated_source_and_original_prefix":{"status":"MATCH","files":len(isolated_map),"sha256":identity(oracle.canonical(isolated_map))["sha256"]}}
    binary={k:report["actual_original_binary"][k] for k in ("bytes","sha256")}
    compiled={"actual_compilers":{"status":"MATCH","tools":tools},
              "locked_serde_sources":{"status":"MATCH","files":len(serde["crate_sources"])},
              "derived_normal_compiler_loader":{"status":"MATCH",**report["derived_loader"]},
              "actual_sqlite_build_qualification":{"status":"MATCH","files":len(sqlite["files"]),"build_fence":sqlite["build_fence"]},
              "actual_serde_library":{"status":"MATCH","identity":library["identity"]},
              "actual_independent_binary":{"status":"MATCH",**binary}}
    expected_fences=[{"label":"source-before","status":"PASS","checks":common,"errors":[]},
                     {"label":"isolated-source-before","status":"PASS","checks":{**common,**copied},"errors":[]},
                     *({"label":label,"status":"PASS","checks":{**common,**copied,**compiled},"errors":[]}
                       for label in ("compiled-source-and-binary-before","source-and-binary-after"))]
    need(same(report["fences"],expected_fences),"Complete actual source/tool/library/binary fences")
    for fence in expected_fences:need(same(load(directory,fence["label"]+".json"),fence),"Actual fence file differs")
    natural(report["elapsed_ns"],"full original interval",1)
    need(report["elapsed_ns"]>=sum(r[0]["elapsed_ns"] for r in rows.values()),"Original interval omits stages")
    now_native,now_original=sources()
    need(same(now_native,native_sources) and same(now_original,original),"Complete source graph changed during original readback")
    input_fence(current_bound)
    return {"kind":"original-"+group,"source_inputs":native_sources,"source_set_sha256":digest(native_sources),
            "original_source_set_sha256":identity(oracle.canonical(original))["sha256"],"counts":counts,
            "actual_original_tests":tests,"actual_stages":len(rows),"actual_compilers":tools,
            "actual_original_binary":binary,"actual_serde_library":library["identity"],
            "actual_sqlite_build_fence":sqlite["build_fence"],"original_report":file_identity(directory,"report.json"),
            "elapsed_ns":report["elapsed_ns"],"source_capture":{name:file_identity(captured,name) for name in sorted(regular_roster(captured))},
            **SCOPE}

def validate(kind,artifacts,original=None,capture=False):
    need(kind in KINDS,"Known CI stage")
    captured_native,captured_original=sources()
    if kind in NATIVE:
        need(set(artifacts)=={kind} and original is None,"One exact native partition")
        result,_=native_partition(kind,artifacts[kind])
        result["original_source_set_sha256"]=identity(oracle.canonical(captured_original))["sha256"]
    else:
        need(original is not None,"Actual original output required")
        result=original_result(original,kind.removeprefix("original-"),artifacts,capture)
    current_native,current_original=sources()
    need(same(captured_native,current_native) and same(captured_original,current_original),"CI reader source drift")
    return result

def bind(kind,observations,artifacts,original=None,parents=()):
    expected=lineage()
    before=source_pair(REPOSITORY,Path(observations),expected)
    actual=validate(kind,artifacts,original,capture=original is not None)
    native,original_map=sources()
    committed_sources(REPOSITORY,{**original_map,**native})
    parent_rows=[]
    if kind.startswith("original-"):
        required={"node"} if kind=="original-node" else {"smoke","boundaries","capacity","cross"}
        need(len(parents)==len(required),"All same-run predecessors required")
        seen=set()
        for path in parents:
            p=load(Path(path).parent,Path(path).name)
            need(p.get("schema")==SCHEMA and p.get("status")=="PASS" and same(p.get("lineage"),expected)
                 and p.get("kind") in required and p["kind"] not in seen and all(p.get(k) is v for k,v in SCOPE.items()),"Actual same-run predecessor kind/scope")
            kind0=p["kind"];seen.add(kind0)
            replay,_=native_partition(kind0,artifacts[kind0])
            replay["original_source_set_sha256"]=identity(oracle.canonical(original_map))["sha256"]
            need(all(same(p.get(k),v) for k,v in replay.items()),"Same-run predecessor actual source/raw changed")
            parent_rows.append({"kind":kind0,"identity":safe.file_identity(path)})
        need(seen==required,"Whole predecessor roster")
    else:need(not parents,"Native partition has no predecessor")
    result={"schema":SCHEMA,"status":"PASS","lineage":expected,"source_observations":before,"parents":parent_rows,**actual}
    write(Path(observations)/"binding.json",result)
    return result

@contextlib.contextmanager
def regular(root, name):
    """Open O_PATH first; no read operation is attempted on special files."""
    parts = safe.relative(name).parts
    parent = safe._directory(root)
    opened = [parent]
    try:
        for part in parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                             os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
            opened.append(parent)
        admitted = os.open(parts[-1], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                           dir_fd=parent)
        opened.append(admitted)
        before = os.fstat(admitted)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             "Regular single-link artifact required")
        fd = os.open("/proc/self/fd/" + str(admitted),
                     os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        opened.append(fd)
        need(_stamp(before) == _stamp(os.fstat(fd)),
             "Artifact changed before descriptor read")
        yield fd, before
        need(_stamp(before) == _stamp(os.fstat(fd)),
             "Artifact changed during descriptor read")
    finally:
        for fd in reversed(opened):
            os.close(fd)



def _stamp(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
def file_identity(root,name):
    h=hashlib.sha256();total=0
    with regular(root,name) as (fd,st):
        while block:=os.read(fd,1<<20):total+=len(block);h.update(block)
        need(total==st.st_size,"Actual regular extent changed")
    return {"bytes":total,"sha256":h.hexdigest()}
def copy_file(root,name,target,expected):
    target=Path(target);target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with regular(root,name) as (fd,st),target.open("xb") as out:
        need(st.st_size==expected["bytes"],"Captured extent changed")
        while block:=os.read(fd,1<<20):out.write(block)
    need(same(file_identity(root,name),expected) and same(file_identity(target.parent,target.name),expected),"Captured bytes differ")
def object_inventory(root, excluded=()):
    """List specials by lstat only. Their contents are never opened."""
    root = Path(root).absolute()
    exclusions = set(excluded)
    for path in exclusions:
        relative(path)
    result = {}
    fd = safe._directory(root)
    def visit(directory, prefix):
        before = os.fstat(directory)
        names = sorted(entry.name for entry in os.scandir(directory))
        for name in names:
            relative(name)
            key = prefix + name
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            row = {"mode": stat.S_IMODE(current.st_mode)}
            if key in exclusions:
                row.update(type="omitted-rebuildable-tree", reason="isolated original Cargo source copy")
            elif stat.S_ISDIR(current.st_mode):
                row["type"] = "directory"
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
                try:
                    actual = os.fstat(child)
                    need((actual.st_dev, actual.st_ino) == (current.st_dev, current.st_ino),
                         "Directory changed during artifact inventory")
                    visit(child, key + "/")
                finally:
                    os.close(child)
            elif stat.S_ISREG(current.st_mode):
                need(current.st_nlink == 1, "Hard-linked evidence is not admitted")
                row.update(type="file", **file_identity(root, key))
            elif stat.S_ISLNK(current.st_mode):
                row.update(type="symlink-metadata", target=os.readlink(name, dir_fd=directory))
            elif stat.S_ISFIFO(current.st_mode):
                row["type"] = "fifo-metadata"
            elif stat.S_ISSOCK(current.st_mode):
                row["type"] = "socket-metadata"
            else:
                row.update(type="special-metadata", file_type=stat.S_IFMT(current.st_mode),
                           device=current.st_rdev)
            result[key] = row
        after = os.fstat(directory)
        need((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
             "Artifact directory changed during inventory")
    try:
        visit(fd, "")
    finally:
        os.close(fd)
    return dict(sorted(result.items()))


class HashSink:
    def __init__(self, destination=None):
        self.destination = destination
        self.bytes = 0
        self.sha = hashlib.sha256()
    def write(self, raw):
        if self.destination is not None:
            self.destination.write(raw)
        self.bytes += len(raw)
        self.sha.update(raw)
        return len(raw)
    def flush(self):
        if self.destination is not None:
            self.destination.flush()
    def tell(self):
        return self.bytes
    def identity(self):
        return {"bytes": self.bytes, "sha256": self.sha.hexdigest()}


class DescriptorReader:
    def __init__(self, fd):
        self.fd = fd
    def read(self, size=-1):
        need(type(size) is int and size >= 0, "Bounded archive read required")
        return os.read(self.fd, size)


def write_canonical_tar(sink, roots, entries):
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.GNU_FORMAT) as archive:
        for name, row in sorted(entries.items()):
            if row["type"] != "file":
                continue
            parts = relative(name).parts
            need(parts[0] in roots and len(parts) > 1, "Unknown regular archive root")
            root, relative_name = roots[parts[0]], "/".join(parts[1:])
            info = tarfile.TarInfo(name)
            info.size = row["bytes"]
            info.mode = 0o600
            info.mtime = 0
            info.uid = info.gid = 0
            with regular(root, relative_name) as (fd, before):
                need(before.st_size == row["bytes"], "Artifact size changed before archive")
                archive.addfile(info, DescriptorReader(fd))
            need(same(file_identity(root, relative_name),
                      {k: row[k] for k in ("bytes", "sha256")}),
                 "Archived artifact changed")
    return sink.identity()



def pack(roots,destination,kind,observations,stage_status):
    need(kind in KINDS and type(roots) is dict and roots,"Exact stage/roots required")
    roots={name:Path(path).absolute() for name,path in roots.items()}
    need(all(re.fullmatch("[a-z][a-z0-9-]*",name) for name in roots),"Exact artifact labels")
    destination=Path(destination).absolute()
    need(not destination.exists() and not destination.is_symlink(),"Fresh artifact output")
    for root in roots.values():need(destination!=root and root not in destination.parents and destination not in root.parents,"Archive overlaps input")
    binding=None
    if stage_status=="success":
        binding=load(observations,"binding.json")
        need(binding["schema"]==SCHEMA and binding["kind"]==kind and binding["status"]=="PASS"
             and same(binding["lineage"],lineage()) and all(binding.get(k) is v for k,v in SCOPE.items()),"Successful actual stage binding required")
    else:need(stage_status in ("failure","cancelled","skipped","unknown"),"Actual stage conclusion")
    def inventory():
        entries={}
        for name,root in roots.items():
            excluded=("isolated-source",) if name=="original" and stage_status=="success" else ()
            if excluded and (root/"isolated-source").exists():need((root/SNAPSHOT/"manifest.json").is_file(),"Actual source prefix/dependencies must be captured before omitting reproducible copy")
            for relative_name,row in object_inventory(root,excluded).items():entries[name+"/"+relative_name]=row
        return entries
    entries=inventory();need(len(entries)<=100000,"Archive roster limit")
    destination.mkdir(mode=0o700)
    with (destination/"evidence.tar.xz").open("xb") as encoded:
        with lzma.LZMAFile(encoded,"w",format=lzma.FORMAT_XZ,preset=3) as compressed:
            tar_identity=write_canonical_tar(HashSink(compressed),roots,entries)
    need(same(entries,inventory()),"Actual artifact changed while archiving")
    result={"schema":ARCHIVE_SCHEMA,"status":"PACKED_COMPLETE","kind":kind,"stage_status":stage_status,
            "lineage":lineage(),"binding":binding,"roots":sorted(roots),"entries":entries,"tar":tar_identity,
            "archive":file_identity(destination,"evidence.tar.xz"),"special_objects_are_metadata_only":True}
    write(destination/"manifest.json",result)
    verify_archive(destination,None)
    return result

def validate_manifest(manifest):
    need(type(manifest) is dict and set(manifest) == {
        "schema", "status", "kind", "stage_status", "lineage", "binding",
        "roots", "entries", "tar", "archive", "special_objects_are_metadata_only"},
        "Complete evidence archive manifest required")
    need(manifest["schema"] == ARCHIVE_SCHEMA and manifest["status"] == "PACKED_COMPLETE" and
         manifest["kind"] in KINDS and manifest["special_objects_are_metadata_only"] is True,
         "Unexpected evidence archive schema/scope")
    need(manifest["stage_status"] in ("success", "failure", "cancelled", "skipped", "unknown"),
         "Actual archive stage conclusion required")
    roots = manifest["roots"]
    need(type(roots) is list and roots == sorted(set(roots)) and roots and
         all(isinstance(x, str) and re.fullmatch("[a-z][a-z0-9-]*", x) for x in roots),
         "Exact archive roots required")
    entries = manifest["entries"]
    need(type(entries) is dict and len(entries) <= 100000, "Bounded archive member map required")
    total = 0
    for name, row in entries.items():
        path = relative(name)
        need(path.parts[0] in roots and len(path.parts) > 1 and type(row) is dict,
             "Escaping archive entry")
        natural(row.get("mode"), "artifact mode")
        need(row["mode"] <= 0o7777, "Invalid artifact mode")
        kind = row.get("type")
        fields = {"mode", "type"}
        if kind == "file":
            fields |= {"bytes", "sha256"}
            total += natural(row.get("bytes"), "artifact size")
            need(row["bytes"] <= 2 << 30 and
                 isinstance(row.get("sha256"), str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
                 "Invalid artifact identity")
        elif kind == "symlink-metadata":
            fields.add("target")
            need(isinstance(row.get("target"), str), "Invalid symlink metadata")
        elif kind == "special-metadata":
            fields |= {"file_type", "device"}
            natural(row.get("file_type"), "special type")
            natural(row.get("device"), "special device")
        elif kind == "omitted-rebuildable-tree":
            fields.add("reason")
            need(name == "original/isolated-source" and
                 row.get("reason") == "isolated original Cargo source copy",
                 "Only the source-bound original copy may be omitted")
        else:
            need(kind in ("directory", "fifo-metadata", "socket-metadata"), "Unknown artifact type")
        need(set(row) == fields, "Unexpected artifact metadata fields")
        for parent in path.parents:
            if str(parent) in (".", path.parts[0]):
                break
            need(str(parent) in entries and entries[str(parent)]["type"] == "directory",
                 "Artifact ancestor is absent or not a directory")
    need(total <= 8 << 30, "Evidence transport byte bound exceeded")
    for key in ("tar", "archive"):
        row = manifest[key]
        need(isinstance(row, dict) and set(row) == {"bytes", "sha256"} and
             type(row["bytes"]) is int and 0 < row["bytes"] <= 8 << 30 and
             isinstance(row["sha256"], str) and re.fullmatch("[0-9a-f]{64}", row["sha256"]),
             "Malformed archive identity")
    if manifest["stage_status"] == "success":
        need(type(manifest["binding"]) is dict and
             manifest["binding"].get("kind") == manifest["kind"] and
             manifest["binding"].get("status") == "PASS" and
             same(manifest["binding"].get("lineage"), manifest["lineage"]),
             "Successful archive lacks an actual matching binding")
    else:
        need(manifest["binding"] is None, "Failed archive cannot carry a success binding")


def decode_xz(artifact, manifest, destination):
    need(same(file_identity(artifact, "evidence.tar.xz"), manifest["archive"]),
         "Compressed evidence archive changed")
    h = hashlib.sha256()
    total = 0
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=32 << 20)
    with regular(artifact, "evidence.tar.xz") as (fd, _):
        while True:
            incoming = os.read(fd, 1 << 20) if decoder.needs_input else b""
            need(incoming or not decoder.needs_input or decoder.eof, "Truncated compressed archive")
            while True:
                block = decoder.decompress(incoming, max_length=min(
                    (1 << 20), manifest["tar"]["bytes"] - total + 1))
                incoming = b""
                total += len(block)
                need(total <= manifest["tar"]["bytes"], "Archive expands beyond exact declared tar")
                destination.write(block)
                h.update(block)
                if decoder.eof:
                    need(decoder.unused_data == b"" and os.read(fd, 1) == b"",
                         "Trailing compressed stream or bytes")
                    break
                if decoder.needs_input:
                    break
            if decoder.eof:
                break
    need(same({"bytes": total, "sha256": h.hexdigest()}, manifest["tar"]),
         "Uncompressed evidence archive differs")
    destination.flush()
    destination.seek(0)


def verify_archive(artifact, destination):
    artifact = Path(artifact).absolute()
    need(regular_roster(artifact) == {"evidence.tar.xz", "manifest.json"},
         "Artifact container must contain exactly archive and manifest")
    manifest = load(artifact, "manifest.json")
    validate_manifest(manifest)
    entries = manifest["entries"]
    regular_entries = {name: row for name, row in entries.items() if row["type"] == "file"}
    if destination is not None:
        destination = Path(destination).absolute()
        need(not destination.exists() and not destination.is_symlink(), "Fresh extraction path required")
        destination.mkdir(mode=0o700)
    with tempfile.TemporaryFile() as decoded:
        decode_xz(artifact, manifest, decoded)
        found = {}
        with tarfile.open(fileobj=decoded, mode="r:") as archive:
            for member in archive:
                relative(member.name)
                need(member.name not in found and member.name in regular_entries and
                     member.isfile() and member.linkname == "" and member.mode == 0o600 and
                     member.uid == member.gid == member.mtime == 0 and
                     member.uname == member.gname == "",
                     "Noncanonical, linked, duplicate or extra tar member")
                row = regular_entries[member.name]
                need(member.size == row["bytes"], "Archived member extent differs")
                total, h = 0, hashlib.sha256()
                target = None
                if destination is not None:
                    target_path = destination / relative(member.name)
                    target_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    target = target_path.open("xb")
                try:
                    with archive.extractfile(member) as source:
                        while block := source.read(1 << 20):
                            total += len(block)
                            need(total <= row["bytes"], "Member exceeds declared extent")
                            h.update(block)
                            if target is not None:
                                target.write(block)
                finally:
                    if target is not None:
                        target.close()
                need(same({"bytes": total, "sha256": h.hexdigest()},
                          {k: row[k] for k in ("bytes", "sha256")}),
                     "Transferred regular bytes differ")
                found[member.name] = row
        need(same(found, regular_entries), "Missing regular evidence archive member")
        # Re-serialize just the admitted members with this canonical writer and
        # compare every tar byte, including headers/padding. Hidden trailing tar
        # records cannot be admitted merely by updating an outer checksum.
        decoded.seek(0)
        with tarfile.open(fileobj=decoded, mode="r:") as source:
            lookup = {m.name: m for m in source.getmembers()}
            sink = HashSink()
            with tarfile.open(fileobj=sink, mode="w|", format=tarfile.GNU_FORMAT) as reconstructed:
                for name, row in sorted(regular_entries.items()):
                    info = tarfile.TarInfo(name)
                    info.size = row["bytes"]
                    info.mode = 0o600
                    info.mtime = 0
                    info.uid = info.gid = 0
                    with source.extractfile(lookup[name]) as stream:
                        reconstructed.addfile(info, stream)
            need(same(sink.identity(), manifest["tar"]),
                 "Noncanonical or trailing uncompressed archive records")
    return manifest


def unpack(artifact,destination,group):
    need(group in NATIVE,"Only an actual native predecessor transfers")
    manifest=verify_archive(artifact,destination);expected=lineage()
    need(manifest["kind"]==group and manifest["stage_status"]=="success" and same(manifest["lineage"],expected),"Exact same-run/head/attempt predecessor")
    binding=manifest["binding"]
    need(binding.get("schema")==SCHEMA and all(binding.get(k) is v for k,v in SCOPE.items()),"Exact finite authority scope")
    actual=validate(group,{group:Path(destination)/"native"})
    need(all(same(binding.get(k),v) for k,v in actual.items()),"Transferred source/build/raw is not the bound predecessor")
    need(same(load(Path(destination)/"observations","binding.json"),binding)
         and same(source_pair(REPOSITORY,Path(destination)/"observations",expected),binding["source_observations"]),"Actual predecessor full source observation")
    native,original=sources();committed_sources(REPOSITORY,{**original,**native})
    write(Path(destination)/"native-binding.json",binding)
    result={"schema":"trnm.node-pool-ci-transfer.v1","status":"VERIFIED_COMPLETE_REGULAR_BYTES_TRANSFERRED","lineage":expected,
            "binding":file_identity(destination,"native-binding.json"),"manifest":file_identity(artifact,"manifest.json"),"archive":manifest["archive"]}
    write(Path(destination)/"transfer-receipt.json",result)
    return result

def main(argv=None):
    need(__debug__,"Optimized Python is not admitted")
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("action",choices=("validate","bind","pack","verify-archive","unpack"))
    p.add_argument("--kind",choices=KINDS)
    for name in NATIVE:p.add_argument("--"+name,type=Path)
    p.add_argument("--original",type=Path);p.add_argument("--capture",action="store_true")
    p.add_argument("--observations",type=Path);p.add_argument("--parent",action="append",default=[],type=Path)
    p.add_argument("--root",action="append",default=[]);p.add_argument("--output",type=Path)
    p.add_argument("--artifact",type=Path);p.add_argument("--stage-status",choices=("success","failure","cancelled","skipped","unknown"))
    p.add_argument("--report",type=Path)
    a=p.parse_args(argv)
    artifacts={n:getattr(a,n) for n in NATIVE if getattr(a,n) is not None}
    result=None;failure=None
    try:
        if a.action=="validate":
            need(a.kind is not None and not a.root and not a.parent and a.observations is None and a.output is None and a.artifact is None and a.stage_status is None,"Exact validate arguments")
            result=validate(a.kind,artifacts,a.original,a.capture)
        elif a.action=="bind":
            need(a.kind is not None and a.observations is not None and not a.root and a.output is None and a.artifact is None and a.stage_status is None and not a.capture,"Exact bind arguments")
            result=bind(a.kind,a.observations,artifacts,a.original,a.parent)
        elif a.action=="pack":
            need(a.kind is not None and a.observations is not None and a.output is not None and a.stage_status is not None and not artifacts and a.original is None and not a.parent and not a.capture and a.artifact is None,"Exact pack arguments")
            roots={}
            for item in a.root:
                name,separator,path=item.partition("=");need(separator and name not in roots,"Unique artifact root");roots[name]=absolute(path)
            result=pack(roots,a.output,a.kind,a.observations,a.stage_status)
        elif a.action=="verify-archive":
            need(a.artifact is not None and a.kind is None and not artifacts and a.original is None and not a.root and not a.parent and a.observations is None and a.stage_status is None and not a.capture,"Exact archive verification arguments")
            result=verify_archive(a.artifact,a.output)
        else:
            need(a.artifact is not None and a.output is not None and a.kind in NATIVE and not artifacts and a.original is None and not a.root and not a.parent and a.observations is None and a.stage_status is None and not a.capture,"Exact transfer arguments")
            result=unpack(a.artifact,a.output,a.kind)
    except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
    receipt={"schema":"trnm.node-pool-ci-command.v1","action":a.action,"kind":a.kind,"status":"PASS" if failure is None else "FAIL","failure":failure,"result":result}
    if a.report is not None:write(a.report,receipt)
    print(json.dumps({"status":receipt["status"],"action":a.action,"kind":a.kind,"failure":failure},sort_keys=True))
    if failure is not None:raise SystemExit(1)
if __name__=="__main__":main()
