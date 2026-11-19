"""Build the single held-disk Node/M05 owner with the pinned HIA native compiler."""
from pathlib import Path
import argparse,hashlib,json,re,struct,time,traceback
from . import safe
ROOT=Path(__file__).absolute().parents[3]
HERE=ROOT/"hia/platform/mempool_node"
ORDER=("master","worker","settings","pnx","sha","ed","state","root","mandatory_core","mandatory_cleanup","mandatory_expiry","mandatory_epilogue","application_core","application_task","application_model","application_release","application_quota","application_relation","application_claim","json","producer","genesis","prepared","mempool","snapshot","checked","tree")
COMPILER="87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
PATTERN=re.compile(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)")
def source_manifest(repository=ROOT):
    repository=Path(repository).absolute()
    deps=safe.read_json(repository,"hia/platform/mempool_node/dependencies.json")
    safe.need(type(deps) is list and deps==sorted(set(deps)),"Exact explicit source dependency names")
    paths=set(deps)
    for directory in ("hia/platform/mempool_node","hia/platform/node_owner","hia/platform/node_commitment"):
        root=repository/directory
        for p in sorted(root.rglob("*")):
            safe.need(not p.is_symlink(),"Symbolic owned source")
            if p.is_dir():
                safe.need(p.name!="__pycache__","Do not use stale Python bytecode");continue
            safe.need(p.suffix in (".py",".hepta",".json",".jsonl",".md",".rs"),"Unknown owned source type")
            paths.add(p.relative_to(repository).as_posix())
    paths.add("hia/src/crypto/ed25519_verify_joint.hepta")
    return {name:safe.identity(safe.read(repository,name)) for name in sorted(paths)}
def functions(raw):
    result={}
    for match in PATTERN.finditer(raw):
        name=match.group(1).decode();safe.need(name not in result,"Duplicate native function");result[name]=match.group()
    return result
def compose(repository=ROOT):
    plan=safe.read_json(repository,"hia/platform/mempool_node/composition.json")
    safe.need(plan["schema"]=="trnm.production-m05-fixed-composition.v1" and plan["image_order"]==list(ORDER),"Fixed exact image dispatch")
    safe.need(set(plan["images"])==set(ORDER)|{"linux_emitter"},"Complete native image roster")
    cache={};sources={}
    for role in (*ORDER,"linux_emitter"):
        row=plan["images"][role];raw=bytearray();names=set()
        for index,entry in enumerate(row["entries"]):
            name=entry["function"];safe.need(name not in names and (index!=0 or name=="f0"),"Native entry and function uniqueness");names.add(name)
            path=entry["file"];safe.relative(path)
            if path not in cache:cache[path]=functions(safe.read(repository,path))
            safe.need(name in cache[path],"Missing composed source function")
            body=cache[path][name];safe.need(safe.same(safe.identity(body),entry["identity"]),"Source function differs from fixed graph")
            prefix=bytes.fromhex(entry["prefix_hex"])
            safe.need(re.fullmatch(rb"hia-asm\.v1 hepta\.hia\.program\.v8 [A-Za-z_0-9.-]+\n",prefix) if index==0 else not prefix.strip(),"Nonfunction composition payload")
            raw.extend(prefix);raw.extend(body)
        suffix=bytes.fromhex(row["suffix_hex"]);safe.need(not suffix.strip(),"Trailing composed payload");raw.extend(suffix)
        safe.need(safe.same(safe.identity(raw),row["source"]),"Entire native compiler input differs")
        sources[role]=bytes(raw)
    return plan,sources
def build(output,repository=ROOT):
    from hia.platform.build import Build as PinnedBuild,inspect_executable
    output=Path(output);output.mkdir(mode=0o700)
    start=time.monotonic_ns();captured=source_manifest(repository);pinned=None;images={};prefix=None;elf=None;failure=None;after=[]
    try:
        plan,sources=compose(repository)
        for role,raw in sources.items():(output/(role+"-composed.hepta")).write_bytes(raw)
        pinned=PinnedBuild(output/"compiler")
        safe.need(hashlib.sha256(pinned.compiler).hexdigest()==COMPILER,"Fixed native compiler")
        for role in (*ORDER,"linux_emitter"):
            image=pinned.stage(pinned.compiler,sources[role],"compile-"+role)
            safe.need(safe.same(safe.identity(image),plan["expected_images"][role]),"Exact qualified image differs "+role)
            images[role]=image;(output/(role+(".elf" if role=="linux_emitter" else ".flat"))).write_bytes(image)
        payload=struct.pack("<27Q",*(len(images[n]) for n in ORDER))
        prefix=pinned.stage(images["linux_emitter"],payload,"emit-owner")
        safe.need(safe.same(safe.identity(prefix),plan["expected_emitted_prefix"]),"Exact literal prefix differs")
        elf=prefix+b"".join(images[n] for n in ORDER);inspect_executable(elf)
        safe.need(safe.same(safe.identity(elf),plan["expected_executable"]),"Complete machinecode differs")
        (output/"prefix.raw").write_bytes(prefix);(output/"owner.elf").write_bytes(elf)
    except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
    finally:
        try:safe.need(safe.same(source_manifest(repository),captured),"Native source changed")
        except BaseException as e:after.append(repr(e))
        if pinned is not None:
            try:pinned.check_pin()
            except BaseException as e:after.append(repr(e))
        report={"schema":"trnm.mempool-node-build.v1","status":"PASS" if failure is None and not after else "FAIL",
         "source_inputs":captured,"source_set_sha256":safe.identity(safe.canonical(captured))["sha256"],"image_order":list(ORDER),
         "composed_sources":{n:safe.identity(r) for n,r in locals().get("sources",{}).items()},"images":{n:safe.identity(r) for n,r in images.items()},
         "prefix":None if prefix is None else safe.identity(prefix),"executable":None if elf is None else safe.identity(elf),
         "stages":[] if pinned is None else pinned.stages,"compiler_sha256":COMPILER,"toolchain":None if pinned is None else pinned.lock,
         "failure":failure,"source_after":{"status":"MATCH" if not after else "FAIL","errors":after},"elapsed_ns":time.monotonic_ns()-start,
         "runtime":"NOT_RUN","native_runtime_has_python_or_rust":False}
        safe.write_json(output/"build.json",report)
    safe.need(report["status"]=="PASS","Native build failed; complete failure receipt retained")
    return report
def validate_build(directory,repository=ROOT):
    directory=Path(directory);report=safe.read_json(directory,"build.json")
    safe.need(report["schema"]=="trnm.mempool-node-build.v1" and report["status"]=="PASS" and report["failure"] is None and safe.same(report["source_after"],{"status":"MATCH","errors":[]}),"Incomplete native build")
    expected_keys={"schema","status","source_inputs","source_set_sha256","image_order","composed_sources","images","prefix","executable","stages","compiler_sha256","toolchain","failure","source_after","elapsed_ns","runtime","native_runtime_has_python_or_rust"}
    safe.need(set(report)==expected_keys and report["runtime"]=="NOT_RUN" and report["native_runtime_has_python_or_rust"] is False,"Exact build schema; no unbound authority claims")
    manifest=source_manifest(repository)
    safe.need(safe.same(report["source_inputs"],manifest) and report["source_set_sha256"]==safe.identity(safe.canonical(manifest))["sha256"],"Complete actual source closure differs")
    plan,sources=compose(repository)
    safe.need(report["image_order"]==list(ORDER) and safe.same(report["composed_sources"],{n:safe.identity(r) for n,r in sources.items()}),"Complete composed input graph differs")
    safe.need(report["compiler_sha256"]==COMPILER and safe.same(report["toolchain"],safe.read_json(repository,"hia/toolchain.lock.json")),"Locked compiler/toolchain differs")
    stages=report["stages"];labels=["compile-"+n for n in (*ORDER,"linux_emitter")]+["emit-owner"]
    safe.need(type(stages) is list and [r["stage"] for r in stages]==labels,"Whole compiler execution roster")
    images={}
    def stage(row,payload,executable):
        label=row["stage"];rawin=safe.read(directory,"compiler/"+label+"/stdin.raw")
        stdout=safe.read(directory,"compiler/"+label+"/stdout.raw");stderr=safe.read(directory,"compiler/"+label+"/stderr.raw")
        receipt=safe.read_json(directory,"compiler/"+label+"/receipt.json")
        safe.need(safe.same(row,receipt),"Compiler receipt/report differs")
        safe.need(rawin==payload and row["input_sha256"]==safe.identity(rawin)["sha256"] and type(row["input_bytes"]) is int and row["input_bytes"]==len(rawin),"Actual compiler input differs")
        safe.need(type(row["output_bytes"]) is int and row["output_bytes"]==len(stdout) and row["output_sha256"]==safe.identity(stdout)["sha256"],"Actual compiler stdout identity differs")
        safe.need(row["stderr_sha256"]==safe.identity(stderr)["sha256"] and row["stderr_hex"]==stderr.hex(),"Actual compiler stderr identity differs")
        safe.need(type(row["exit_code"]) is int and row["exit_code"]==0 and row["timed_out"] is False and row["cleanup"] is None and not stderr and row["stderr_hex"]=="","Failed compiler/cleanup observation")
        safe.need(type(row["wall_limit_seconds"]) is int and row["wall_limit_seconds"]==30 and type(row["cleanup_limit_seconds"]) is int and row["cleanup_limit_seconds"]==3,"Original compiler budgets differ")
        safe.need(row["executable_sha256"]==executable["sha256"] and type(row["executable_bytes"]) is int and row["executable_bytes"]==executable["bytes"],"Actual compiler executable identity differs")
        return stdout
    binding=safe.read_json(repository,"hia/qualification/compiler-binding.json")
    compiler={"sha256":COMPILER,"bytes":binding.get("compiler_bytes",673903)}
    for role,row in zip((*ORDER,"linux_emitter"),stages[:-1],strict=True):
        image=stage(row,sources[role],compiler)
        safe.need(safe.read(directory,role+"-composed.hepta")==sources[role],"Saved exact compiler input differs")
        safe.need(safe.read(directory,role+(".elf" if role=="linux_emitter" else ".flat"))==image and safe.same(safe.identity(image),plan["expected_images"][role]),"Compiler flat/saved image differs")
        images[role]=image
    safe.need(safe.same(report["images"],{n:safe.identity(raw) for n,raw in images.items()}),"Whole actual image map differs")
    prefix=stage(stages[-1],struct.pack("<27Q",*(len(images[n]) for n in ORDER)),safe.identity(images["linux_emitter"]))
    safe.need(prefix==safe.read(directory,"prefix.raw") and safe.same(safe.identity(prefix),plan["expected_emitted_prefix"]) and safe.same(safe.identity(prefix),report["prefix"]),"Literal prefix input/output differs")
    elf=prefix+b"".join(images[n] for n in ORDER)
    safe.need(elf==safe.read(directory,"owner.elf") and safe.same(safe.identity(elf),report["executable"]) and safe.same(report["executable"],plan["expected_executable"]),"Complete actual ELF linkage differs")
    return report
def main():
    safe.need(__debug__,"Optimized Python disables required checks")
    p=argparse.ArgumentParser(description=__doc__)
    action=p.add_mutually_exclusive_group(required=True)
    action.add_argument("--output",type=Path);action.add_argument("--verify",type=Path)
    p.add_argument("--report",type=Path);a=p.parse_args()
    safe.need((a.verify is not None)==(a.report is not None),"Verification requires its own fresh report")
    if a.report is not None:safe.need(ROOT not in a.report.absolute().parents and a.report.absolute()!=ROOT,"Report overlaps source")
    failure=None;result=None
    try:
        if a.verify is not None:result=validate_build(a.verify)
        else:
            out=safe.new_output(a.output,ROOT);result=build(out/"build");validate_build(out/"build")
    except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
    receipt={"schema":"trnm.mempool-node-public-build-admission.v1","status":"PASS" if failure is None else "FAIL","failure":failure,
             "source_set_sha256":None if result is None else result["source_set_sha256"],"executable":None if result is None else result["executable"]}
    if a.report is not None:
        safe.need(not a.report.exists() and not a.report.is_symlink(),"Fresh verification receipt");safe.write_json(a.report,receipt)
    print(json.dumps(receipt,sort_keys=True))
    if failure is not None:raise SystemExit(1)
if __name__=="__main__":main()
