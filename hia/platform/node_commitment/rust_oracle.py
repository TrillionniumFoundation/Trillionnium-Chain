"""Recompile unchanged original commitment methods and compare every native field."""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,signal,subprocess,time,traceback
from hia.platform.mempool_node.build import ROOT,validate_build,source_manifest
from hia.platform.mempool_node.original_graph import include_graph
from hia.platform.execution_state import rust_oracle as utility
from hia.platform.mempool_node.safe import new_output
need=utility.need;ident=utility.identity;file_ident=utility.file_identity
STORE="trillionnium/crates/trnm-mvcc-fee/src/pon_commitment.rs"
HOOKS={"some":("rust_some_reference.rs","hia_snapshot_some_reference","NDSOME",82),
       "checked":("rust_checked_reference.rs","hia_checked_snapshot_reference","NDCHECKED",94),
       "delta":("rust_delta_reference.rs","hia_delta_boundary_reference","NDDELTA",2)}
def capture(repository):
    rows={}
    for directory in ("trillionnium","config"):
        for path in sorted((repository/directory).rglob("*")):
            if any(part in ("target","__pycache__") for part in path.relative_to(repository).parts):continue
            if path.is_dir():continue
            name=path.relative_to(repository).as_posix();rows[name]=file_ident(utility.canonical_path(repository,name))
    graph=include_graph(repository)
    for name in graph["includes"]:rows[name]=file_ident(utility.canonical_path(repository,name))
    return dict(sorted(rows.items())),graph

def main(argv=None):
    need(__debug__,"Optimized Python refused")
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("build","some","checked","delta65536","delta65537","cargo-target","output"):
        parser.add_argument("--"+name,required=True,type=Path)
    args=parser.parse_args(argv);out=new_output(args.output,ROOT);isolated=out/"isolated-source"
    stages=[];failure=None;errors=[];comparisons={};bound={};original=None;expected=None;binary=None;serde_capture=None;serde=None
    start=time.monotonic_ns();native_sources=source_manifest()
    def bind(path):
        path=path.absolute();value=file_ident(path);bound[str(path)]=value;return path.read_bytes()
    def bounded_native(directory):
        execution=directory.absolute().with_name(directory.name+"-execution")
        receipt=json.loads(bind(execution/"receipt.json"))
        need(receipt["status"]=="PASS" and receipt["returncode"]==0 and receipt["timed_out"] is False and receipt["cleanup"] is None and receipt["launch_error"] is None,"Actual native child did not complete")
        need(receipt["wall_limit_seconds"]==240 and receipt["cleanup_limit_seconds"]==3,"Original native child bounds changed")
        for stream in ("stdout","stderr"):need(ident(bind(execution/(stream+".raw")))==receipt[stream],"Native child raw stream identity")
    def fence():
        need(source_manifest()==native_sources,"Native source drift");validate_build(args.build)
        for name,value in bound.items():need(file_ident(Path(name))==value,"Bound input/binary drift "+name)
        if original is not None:need(capture(ROOT)[0]==original,"Original production input drift")
        if expected is not None:need(capture(isolated)[0]==expected,"Isolated original or child hook drift")
        if serde_capture is not None:need(serde_capture()==serde["crate_sources"],"Locked serde source drift")
    def run(label,argv,environment,timeout=240):
        directory=out/label;directory.mkdir();started=time.monotonic_ns();timed=False;cleanup=None;launch=None;code=None;process=None
        with (directory/"stdout.raw").open("xb") as stdout,(directory/"stderr.raw").open("xb") as stderr:
            try:
                process=subprocess.Popen(argv,cwd=isolated,env=environment,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
                try:code=process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed=True;cleanup_started=time.monotonic_ns();os.killpg(process.pid,signal.SIGKILL);code=process.wait(timeout=3)
                    cleanup={"signal":"SIGKILL","reaped":True,"elapsed_ns":time.monotonic_ns()-cleanup_started}
            except BaseException as error:
                launch=repr(error)
                if process is not None and process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=3)
        row={"argv":[str(x) for x in argv],"returncode":code,"timeout":timed,"wall_limit_seconds":timeout,"cleanup_limit_seconds":3,"cleanup":cleanup,"launch_error":launch,
             "stdout":file_ident(directory/"stdout.raw"),"stderr":file_ident(directory/"stderr.raw"),"elapsed_ns":time.monotonic_ns()-started}
        (directory/"receipt.json").write_text(json.dumps(row,sort_keys=True,indent=2)+"\n");stages.append({"label":label,**row})
        need(code==0 and not timed and launch is None,"Original process failed; raw stage retained: "+label)
        return (directory/"stdout.raw").read_bytes()
    try:
        environment=utility.clean_build_environment();build=validate_build(args.build);build_id=ident(bind(args.build/"build.json"))
        for name,value in native_sources.items():need(ident(bind(ROOT/name))==value,"Native source admission")
        native={}
        for group,directory,total in (("some",args.some,82),("checked",args.checked,94)):
            bounded_native(directory)
            report=json.loads(bind(directory/"report.json"));history=bind(directory/"semantic-history.jsonl")
            rows=[json.loads(line) for line in history.splitlines()]
            need(report["status"]=="PASS" and report["build"]==build_id and report["semantic_methods"]==len(rows)==total and report["semantic_history"]==rows,"Complete actual native method admission")
            need(report["source_after"]=={"status":"MATCH","errors":[]} and report["failure"] is None,"Native method source/cleanup failure")
            for path,value in report["source_inputs"].items():need(ident(bind(Path(path)))==value,"Native bound method bytes")
            bind(directory/"native-journal.jsonl.xz");native[group]=rows
            (out/(group+"-corpus.jsonl")).write_bytes(history)
        delta=[]
        for index,(directory,count) in enumerate(((args.delta65536,65536),(args.delta65537,65537))):
            bounded_native(directory)
            report=json.loads(bind(directory/"report.json"));observed=json.loads(bind(directory/"observations.json"))
            need(report["status"]=="PASS" and report["failure"] is None and report["errors"]==[] and report["source_after"]=="MATCH" and report["build"]==build_id,"Actual delta admission")
            need(report["before_keys"]==1 and report["after_keys"]==count-1 and report["expected_changes"]==count and report["elapsed_ns"]<=240_000_000_000,"Original actual delta capacity/time bounds")
            for path,value in report["source_inputs"].items():need(ident(bind(Path(path)))==value,"Native bound capacity bytes")
            bind(directory/"native-journal.jsonl")
            for name,blob in report["blobs"].items():need(ident(bind(utility.canonical_path(directory,"blobs/"+name)))==blob["compressed"],"Complete native heap/frame evidence")
            delta.append({"index":index,"before_keys":1,"after_keys":count-1,"observation":observed["prepared"]})
        (out/"delta-corpus.jsonl").write_text("".join(json.dumps({"before_keys":1,"after_keys":n,"before_prefix":"a","after_prefix":"b","value":7},sort_keys=True)+"\n" for n in (65535,65536)))
        original,graph=capture(ROOT);isolated.mkdir()
        for name,value in original.items():
            destination=isolated/name;destination.parent.mkdir(parents=True,exist_ok=True);raw=bind(ROOT/name);need(ident(raw)==value,"Original copy changed");destination.write_bytes(raw)
        declarations=b"";expected=dict(original)
        for _,(file,module,_,_) in HOOKS.items():
            declaration=('\n#[cfg(test)]\n#[path = "'+module+'.rs"]\nmod '+module+';\n').encode();declarations+=declaration
            path=Path(STORE).parent/(module+".rs");raw=bind(ROOT/"hia/platform/node_commitment"/file)
            (isolated/path).write_bytes(raw);expected[path.as_posix()]=ident(raw)
        raw=(ROOT/STORE).read_bytes();need(all(module.encode() not in raw for _,module,_,_ in HOOKS.values()),"Original hook already present")
        (isolated/STORE).write_bytes(raw+declarations);expected[STORE]=ident(raw+declarations)
        target=utility.safe_target(args.cargo_target,out,ROOT,args.build,isolated)
        version=run("rustc-version",["rustc","-Vv"],environment,30);need(version.startswith(b"rustc 1.95.0 ") and b"host: x86_64-unknown-linux-gnu\n" in version,"Exact original Rust 1.95 target")
        sysroot=Path(run("rustc-sysroot",["rustc","--print","sysroot"],environment,30).decode().strip()).resolve(strict=True)
        tools={name:(sysroot/"bin"/name).resolve(strict=True) for name in ("rustc","rustdoc","cargo")}
        for path in tools.values():bind(path)
        environment.update(RUSTC=str(tools["rustc"]),RUSTDOC=str(tools["rustdoc"]),CARGO=str(tools["cargo"]),RUSTC_WRAPPER="",RUSTC_WORKSPACE_WRAPPER="")
        metadata=json.loads(run("cargo-metadata",[str(tools["cargo"]),"metadata","--locked","--offline","--format-version=1","--filter-platform","x86_64-unknown-linux-gnu","--manifest-path",str(isolated/"trillionnium/Cargo.toml")],environment,120))
        serde,serde_capture=utility.capture_serde_graph(metadata,isolated,out)
        built=run("cargo-test-build",[str(tools["cargo"]),"--config","build.incremental=false","test","--locked","--offline","--manifest-path",str(isolated/"trillionnium/Cargo.toml"),"-p","trnm-mvcc-fee","--lib","--no-run","--message-format=json","--target-dir",str(target)],environment,900)
        artifacts=[json.loads(line) for line in built.splitlines() if line.startswith(b"{")];serde_rows,binaries=utility.original_artifacts(artifacts)
        need(len(binaries)==len(serde_rows)==1 and serde_rows[0]["package_id"]==serde["package"]["id"] and set(serde_rows[0]["features"])=={"default","std"},"Actual locked original Cargo graph")
        compiled=Path(binaries[0]["executable"]).resolve(strict=True);need(target.resolve() in compiled.parents,"Original binary escaped target")
        binary=out/"original-test-binary";shutil.copyfile(compiled,binary);binary.chmod(0o500);need(file_ident(binary)==file_ident(compiled),"Original binary copy");bind(binary)
        (out/"original-build.json").write_text(json.dumps({"artifact":binaries[0],"binary":file_ident(binary),"original_sources":original,"include_graph":graph,"isolated_sources":expected,"only_appended_declarations_hex":declarations.hex(),"serde":serde},sort_keys=True,indent=2)+"\n")
        fence()
        for group,(_,module,marker,total) in HOOKS.items():
            test="pon_commitment::"+module+"::evaluate";key={"some":"TRNM_HIA_SOME_CORPUS","checked":"TRNM_HIA_CHECKED_CORPUS","delta":"TRNM_HIA_DELTA_CORPUS"}[group]
            raw=run("original-"+group,[str(binary),"--exact",test,"--nocapture","--test-threads=1"],dict(environment,**{key:str(out/(group+"-corpus.jsonl"))}))
            utility.assert_test_executed(raw,test)
            rows=[json.loads(line.split(marker+"_ORIGINAL:",1)[1]) for line in raw.decode().splitlines() if marker+"_ORIGINAL:" in line]
            final=[json.loads(line.split(marker+"_FINAL:",1)[1]) for line in raw.decode().splitlines() if marker+"_FINAL:" in line]
            need(len(rows)==total and len(final)==1 and final[0]["live_logical_owners"]==0,"Every original method and final Arc retirement")
            wanted=delta if group=="delta" else [{k:row[k] for k in ("index","op","observation")} for row in native[group]]
            need(utility.same_json(rows,wanted),"Full actual original/native observations differ: "+group)
            comparisons[group]={"methods":total,"complete_observations_equal":True,"original_final":final[0]}
        retained=run("retained-original",[str(binary),"pon_commitment::",*[x for _,module,_,_ in HOOKS.values() for x in ("--skip",module+"::")],"--nocapture","--test-threads=1"],environment)
        need(b"36 passed; 0 failed; 6 ignored;" in retained,"Original retained commitment test roster changed")
        comparisons["retained"]={"passed":36,"original_ignored":6,"new_ignored":0}
    except BaseException as error:failure={"error":repr(error),"traceback":traceback.format_exc()}
    finally:
        try:fence()
        except BaseException as error:errors.append(repr(error))
        report={"schema":"trnm.snapshot-original-comparison.v1","status":"PASS" if failure is None and not errors else "FAIL","failure":failure,"errors":errors,
                "native_source_inputs":native_sources,"bound_inputs":bound,"comparisons":comparisons,"stages":stages,"original_runtime_modified":False,"elapsed_ns":time.monotonic_ns()-start}
        (out/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        print(json.dumps({k:report[k] for k in ("status","comparisons","failure","errors","elapsed_ns")}),flush=True)
        if report["status"]!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
