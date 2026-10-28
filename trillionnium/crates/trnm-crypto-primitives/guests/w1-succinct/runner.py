#!/usr/bin/env python3
"""A finite new transparent recursion window over one actual complete receipt."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
LEGACY = HERE.parent / "w1-risc0"
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(LEGACY))
import prove_segments as scheduler
import segment_frozen_v2 as frozen
from proof_resources import require_runner
from measure_loopback import (_transfer, _closed_success, file_identity, supervise,
                              _OwnedChildCleanupRequired)

def require(ok, message):
    if not ok:
        raise ValueError(message)

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def finite_float(value):
    result = float(value)
    require(math.isfinite(result), "nonfinite JSON number")
    return result

def strict_json(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_float=finite_float,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))

def read_json(path, cap=2*1024**2):
    raw = frozen.checked_bytes(Path(path), cap)
    return strict_json(raw)

def read_single_result(path, schema, operation=None):
    matches = []
    for line in frozen.checked_bytes(Path(path), 16*1024**2).decode("utf-8").splitlines():
        try:
            value = strict_json(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == schema:
            matches.append(value)
    require(len(matches) == 1, "exactly one bounded native result required: " + schema)
    value = matches[0]
    require(operation is None or value.get("operation") == operation, "native operation differs")
    return value

def write(path, value):
    scheduler.write_new(Path(path), value)

def digest(path, cap=128*1024**2):
    raw = frozen.checked_bytes(Path(path), cap)
    return {"bytes":len(raw), "sha256":hashlib.sha256(raw).hexdigest()}

def policy():
    value = read_json(HERE/"policy.json")
    require(value["schema"] == "pon-w1-transparent-succinct-attempt-v1"
            and value["namespace"] == "PWSR0001", "explicit new research namespace")
    require(value["budgets"] == {
        "workers":2,"rayon_threads_per_worker":2,"minimum_available_bytes":8*1024**3,
        "effective_cpus_minimum":4,"each_recursion_stage_seconds":300,
        "complete_new_recursion_work_stop_seconds":3500,"complete_new_recursion_outer_seconds":3600,
        "verify_seconds":900,"audit_seconds":900,"loopback_transfer_seconds":30,
        "loopback_verification_seconds_each":900,"job_timeout_minutes":120,
        "build_phase_seconds":1800,"install_phase_seconds":900,"succinct_receipt_bytes":2*1024**2,
        "succinct_seal_words":256*1024,"one_mib_packet_comparison_bytes":1024**2},
        "reviewed independent budgets changed")
    for field in ("additional_pow","povw_requested","groth16_allowed","dev_mode_allowed",
                  "remote_proving_allowed","existing_packet_codec_changed","complete_from_zero_generation_cost",
                  "pq128_qualified","consensus_authority"):
        require(value[field] is False, "unsupported promotion: "+field)
    require(value["original_backend_manifest_sha256"] == digest(LEGACY/"backend-manifest.json")["sha256"]
            and value["original_cargo_lock_sha256"] == digest(LEGACY/"Cargo.lock")["sha256"],
            "original backend pins changed")
    frozen.load_policy()
    return value

def identity():
    source = os.environ.get("TRNM_EXPECTED_SOURCE_SHA")
    require(isinstance(source,str) and len(source)==40
            and all(c in "0123456789abcdef" for c in source), "actual exact source required")
    result = {"source_sha":source}
    for key in ("GITHUB_RUN_ID","GITHUB_RUN_ATTEMPT"):
        value = os.environ.get(key)
        require(isinstance(value,str) and value.isdigit() and int(value)>0,
                "actual hosted run identity required")
        result[key.lower()] = value
    return result

def check_inputs(directory):
    p = policy()
    for name, expected in p["input_files"].items():
        require(digest(directory/name, expected["bytes"]) == expected, "original material changed: "+name)
    return p

def api_json(path):
    token = os.environ.get("GH_TOKEN")
    require(bool(token), "read-only workflow token required")
    url = "https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/"+path
    req = urllib.request.Request(url,headers={"Authorization":"Bearer "+token,
        "Accept":"application/vnd.github+json","User-Agent":"w1-succinct-research"})
    with urllib.request.urlopen(req,timeout=30) as response:
        raw = response.read(2*1024**2+1)
    require(len(raw)<=2*1024**2,"GitHub JSON byte cap")
    return strict_json(raw)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch_original(out):
    p = policy(); origin=p["origin"]; directory=out/"original"; directory.mkdir()
    result={"schema":"pon-w1-succinct-fetch-v1","accepted":False,"origin":origin}
    started=time.monotonic()
    try:
        run=api_json("actions/runs/"+str(origin["run_id"]))
        artifact=api_json("actions/artifacts/"+str(origin["artifact_id"]))
        require(run["id"]==origin["run_id"] and run["run_attempt"]==origin["run_attempt"]
                and run["head_sha"]==origin["source_sha"] and run["status"]=="completed"
                and run["conclusion"]=="success","original actual successful source/run differs")
        require(artifact["id"]==origin["artifact_id"] and artifact["name"]==origin["artifact_name"]
                and artifact["workflow_run"]["id"]==origin["run_id"]
                and artifact["workflow_run"]["head_sha"]==origin["source_sha"]
                and artifact["expired"] is False and artifact["size_in_bytes"]==origin["artifact_bytes"]
                and artifact["digest"]=="sha256:"+origin["artifact_sha256"],"original artifact identity differs")
        write(out/"origin-run.json",run); write(out/"origin-artifact.json",artifact)
        url="https://api.github.com/repos/TrillionniumFoundation/Trillionnium-Chain/actions/artifacts/"+str(origin["artifact_id"])+"/zip"
        request=urllib.request.Request(url,headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
            "User-Agent":"w1-succinct-research"})
        try:
            urllib.request.build_opener(NoRedirect).open(request,timeout=30)
            raise ValueError("artifact redirect required")
        except urllib.error.HTTPError as error:
            require(error.code in (302,303,307),"artifact redirect status")
            location=error.headers.get("Location","")
        parsed=urllib.parse.urlsplit(location)
        require(parsed.scheme=="https" and parsed.hostname is not None
                and (parsed.hostname.endswith(".blob.core.windows.net")
                     or parsed.hostname.endswith(".githubusercontent.com")),
                "unreviewed artifact download host")
        # The workflow token is never forwarded to the redirected object host.
        h=hashlib.sha256(); size=0; archive=out/"original-assembly.zip"
        with urllib.request.urlopen(location,timeout=120) as response, archive.open("xb") as stream:
            while chunk:=response.read(1024**2):
                size+=len(chunk);require(size<=origin["artifact_bytes"],"original ZIP size cap")
                h.update(chunk);stream.write(chunk)
            stream.flush();os.fsync(stream.fileno())
        require(size==origin["artifact_bytes"] and h.hexdigest()==origin["artifact_sha256"],
                "original ZIP bytes differ")
        with zipfile.ZipFile(archive) as z:
            names=z.namelist()
            require(len(names)==origin["archive_members"] and len(names)==len(set(names)),
                    "original archive member inventory differs")
            for name,expected in p["input_files"].items():
                info=z.getinfo(name);require(info.file_size==expected["bytes"],"member size differs")
                raw=z.read(name)
                require(hashlib.sha256(raw).hexdigest()==expected["sha256"],"member hash differs")
                with (directory/name).open("xb") as f:f.write(raw)
            snapshots=[]
            for name in ("source-before.json","source-after.json","source-final.json"):
                require(z.getinfo(name).file_size<=8192,"source record cap")
                raw=z.read(name);v=strict_json(raw)
                require(v["candidate"]==origin["source_sha"] and v["tested_commit"]==origin["source_sha"]
                        and v["tested_tree"]==origin["source_tree"] and v["tracked_worktree_verified"] is True
                        and v["tests_executed_by_identity_check"] is False,"original source guard differs")
                snapshots.append(v)
                with (directory/name).open("xb") as f:f.write(raw)
            require(snapshots[0]==snapshots[1]==snapshots[2],"original source changed")
        check_inputs(directory)
        result.update(accepted=True,archive_bytes=size,archive_sha256=h.hexdigest(),
                      all_archive_members_extracted=False)
    finally:
        result["wall_seconds"]=time.monotonic()-started
        write(out/"fetch-result.json",result)

def install_tools(destination):
    from install_backend import download
    p=policy();destination.mkdir()
    manifest=read_json(LEGACY/"backend-manifest.json")
    record=download("https://github.com/risc0/risc0/releases/download/v3.0.6/cargo-risczero-x86_64-unknown-linux-gnu.tgz",
        manifest["official_linux_tools_sha256"],destination/"tools",False)
    for name in ("r0vm","cargo-risczero"):
        path=destination/"tools"/name
        require(path.is_file(),"missing pinned tool");path.chmod(0o755)
    print(json.dumps({"schema":"pon-w1-succinct-tools-v1","archive":record,
                     "guest_compiler_used":False,"sdk":p["recursion"]["sdk"]}))

def batches():
    layer=[(i,i+1) for i in range(62)]
    result=[[{"op":"lift","start":a,"split":b,"end":b} for a,b in layer]]
    while len(layer)>1:
        pairs=[];next_layer=[]
        for i in range(0,len(layer),2):
            if i+1==len(layer):
                next_layer.append(layer[i]);continue
            a,m=layer[i];m2,b=layer[i+1]
            require(m==m2,"noncontiguous schedule")
            pairs.append({"op":"join","start":a,"split":m,"end":b});next_layer.append((a,b))
        result.append(pairs);layer=next_layer
    require(layer==[(0,62)] and sum(map(len,result))==123,"complete 62/61 recursion graph")
    return result

def name(task):
    return f'{task["op"]}-{task["start"]}-{task["end"]}'

def terminal(record, expected, timeout=300):
    require(record["schema"]=="pon-w1-segment-worker-process-v1" and record["returncode"]==0
            and record["child_reaped"] is True and record["source_sha"]==expected
            and record["timeout_seconds"]==timeout,"stage terminal/source/budget differs")
    for key in ("wall_seconds","user_cpu_seconds","system_cpu_seconds"):
        value=record[key];require(type(value) in (int,float) and math.isfinite(value) and value>=0,
                                  "unavailable stage cost")
    require(record["wall_seconds"]<=timeout,"stage exceeded declared cap")

def prove(args):
    require(os.getpid()==os.getpgrp(),"owned process-group wrapper required")
    require(os.environ.get("RAYON_NUM_THREADS")=="2" and "RISC0_DEV_MODE" not in os.environ,
            "fixed threads/no development mode")
    ids=identity();p=check_inputs(args.out/"original");d=args.out/"recursion";d.mkdir()
    steps=d/"steps";steps.mkdir();receipts=d/"receipts";receipts.mkdir()
    signal.signal(signal.SIGTERM,scheduler.stopping);signal.signal(signal.SIGINT,scheduler.stopping)
    started=time.monotonic();stages=[]
    outcome={"schema":"pon-w1-succinct-attempt-v1",**ids,"outcome":"failed","completed":[],
             "real_succinct_stark_verified":False,"original_composite_reproved":False,
             "additional_pow":False,"povw_requested":False,"consensus_authority":False,
             "budgets":p["budgets"],"helper":digest(args.helper,64*1024**2)}
    def remaining():
        require(not scheduler.STOP and time.monotonic()-started<3500,"independent recursion work-stop reached")
    def wait(s):
        while s.check() is None:
            remaining();time.sleep(.025)
        terminal(s.record,ids["source_sha"]);remaining()
    try:
        require_runner(d/"resources.json")
        s=scheduler.Stage(steps,"prepare",[str(args.helper),"prepare",str(args.out/"original"),
            str(d/"prepared.json")],300);stages.append(s);wait(s)
        record=read_single_result(steps/"prepare.stdout.log","pon-w1-succinct-prepare-v1")
        require(record["original_composite_verified"] is True and record["native_full_w1_matches"] is True,
                "actual original Composite gate missing")
        for batch in batches():
            pending=list(batch);active={}
            while pending or active:
                remaining()
                while pending and len(active)<2:
                    task=pending.pop(0);n=name(task);a,m,b=task["start"],task["split"],task["end"]
                    left=str(receipts/f"range-{a}-{m}.bin") if task["op"]=="join" else "-"
                    right=str(receipts/f"range-{m}-{b}.bin") if task["op"]=="join" else "-"
                    command=[str(args.helper),"stage",str(args.r0vm),str(args.out/"original/receipt.bin"),
                             str(a),str(m),str(b),left,right,str(receipts/f"range-{a}-{b}.bin")]
                    stage=scheduler.Stage(steps,n,command,300,logs=True);stages.append(stage);active[n]=(task,stage)
                for n,(task,s) in list(active.items()):
                    if s.check() is None:continue
                    terminal(s.record,ids["source_sha"]);remaining()
                    row=read_single_result(steps/f"{n}.stdout.log","pon-w1-succinct-stage-v1")
                    require({k:row[k] for k in ("start","split","end")}=={k:task[k] for k in ("start","split","end")}
                            and row["operation"]==task["op"] and row["real_recursion_stark_verified"] is True
                            and row["complete_w1_proof_verified"] is False and row["additional_pow"] is False
                            and row["povw_requested"] is False and row["dev_mode"] is False,"stage claim/profile differs")
                    require(digest(receipts/f'range-{task["start"]}-{task["end"]}.bin',2*1024**2)
                            =={"bytes":row["receipt_bytes"],"sha256":row["receipt_sha256"]},"stage bytes changed")
                    outcome["completed"].append(n);del active[n]
                    print(json.dumps({"completed_stage":n,"wall_seconds":s.record["wall_seconds"],
                        "user_cpu_seconds":s.record["user_cpu_seconds"],
                        "system_cpu_seconds":s.record["system_cpu_seconds"]}),file=sys.stderr,flush=True)
                time.sleep(.025)
        require(sorted(outcome["completed"])==sorted(name(t) for batch in batches() for t in batch),
                "incomplete recursion graph")
        remaining()
        s=scheduler.Stage(steps,"finish",[str(args.helper),"finish",str(args.out/"original"),
            str(receipts/"range-0-62.bin"),str(args.out/"succinct.bin"),str(args.out/"certificate.bin")],300)
        stages.append(s);wait(s)
        row=read_single_result(steps/"finish.stdout.log","pon-w1-succinct-finish-v1")
        require(row["real_succinct_stark_verified"] is True and row["claim_digest"]==p["claim_digest"],
                "actual complete transparent proof missing")
        outcome.update(outcome="complete",real_succinct_stark_verified=True,finish=row,
                       work_finished_wall_seconds=time.monotonic()-started)
    except BaseException as error:
        outcome["error"]=repr(error);raise
    finally:
        try:
            outcome["direct_children_missing_terminal"]=scheduler.cleanup(stages)
        except BaseException as error:
            outcome["cleanup_error"]=repr(error)
            raise
        finally:
            outcome["wall_seconds"]=time.monotonic()-started
            write(d/"attempt.json",outcome)
    require(not outcome["direct_children_missing_terminal"],"unobserved native child termination")
    print(json.dumps(outcome))

def loopback(args):
    check_inputs(args.out/"original")
    d=args.out/"loopback";d.mkdir()
    paths={"helper":args.helper,"elf":args.out/"original/guest.bin",
           "input":args.out/"original/input.bin","receipt":args.out/"succinct.bin",
           "certificate":args.out/"certificate.bin"}
    before={k:file_identity(v) for k,v in paths.items()}
    expected={k:before["certificate"][k] for k in ("bytes","sha256")}
    report={"schema":"pon-w1-succinct-loopback-v1","outcome":"failed","verification":{},
            "wan_measured":False,"tcp_ip_bytes_measured":False,"public_ingress_qualified":False,
            "binary_build_attested":False,"consensus_authority":False,"material_before":before}
    started=time.monotonic_ns()
    def verify(which,certificate):
        command=[str(args.helper),"verify-certificate",str(paths["elf"]),str(certificate)]
        record={"command":command};report["verification"][which]=record
        try: record["process"]=supervise(command,d/which,{"wall_seconds":900,"rss_bytes":8*1024**3})
        except _OwnedChildCleanupRequired as error:
            record["process"]=error.receipt;raise
        _closed_success(record["process"],8*1024**3)
        row=read_single_result(d/which/"process.log","pon-w1-succinct-certificate-verify-v1")
        require(row["real_succinct_stark_verified"] is True and row["certificate_bytes"]==expected["bytes"]
                and row["certificate_sha256"]==expected["sha256"]
                and row["receipt_sha256"]==before["receipt"]["sha256"]
                and row["public_input_sha256"]==before["input"]["sha256"]
                and row["verification_uses_received_input_and_receipt"] is True,
                "actual received-certificate native verification missing")
        record["result"]=row
    try:
        verify("before",paths["certificate"])
        report["transport"]={}
        received=_transfer(paths["certificate"],expected,d/"transport",report["transport"])
        verify("after",received)
        after={k:file_identity(v) for k,v in paths.items()};report["material_after"]=after
        require(before==after and digest(received)==expected,"loopback material changed")
        report["outcome"]="complete"
    finally:
        report["observed_total_wall_ns"]=time.monotonic_ns()-started
        write(d/"result.json",report)
    print(json.dumps({"schema":report["schema"],"outcome":report["outcome"]}))

PHASE_TIMEOUTS = {"native-toolchain-install":900,"fetch":900,"install":900,
    "original-host-build":1800,"succinct-build":1800,"succinct-tests":1800,
    "succinct-fmt":60,"succinct-clippy":1800,"python-controls":60,
    "native-controls":900,"original-verify":900,"compress":3600,"verify":900,
    "benchmark":900,"audit":900,"loopback":1900}

AUDIT_CASES = frozenset(("composite_kind","groth16_kind","fake_kind","unknown_kind",
    "unbounded_seal_prefix","trailing_byte","truncated_byte","last_seal_tamper",
    "first_seal_tamper","excessive_po2","wrong_control_id","wrong_parameters",
    "wrong_hash_suite","wrong_control_path","empty_seal","wrong_journal","wrong_expected_image"))
CERTIFICATE_CASES = frozenset(("certificate_wrong_magic","certificate_input_length",
    "certificate_receipt_length","certificate_trailing_byte","certificate_truncated_byte",
    "certificate_changed_input","certificate_changed_receipt"))

def checked_audit(audit):
    cases = audit["cases"]
    require(audit["schema"] == "pon-w1-succinct-audit-v1" and audit["all_tested_rejected"] is True
            and audit["global_worst_invalid_proven"] is False and audit["consensus_authority"] is False
            and len(cases) == 17 and {v["case"] for v in cases} == AUDIT_CASES
            and audit["actual_complete_certificate_positive_verified"] is True
            and len(audit["certificate_cases"]) == 7
            and {v["case"] for v in audit["certificate_cases"]} == CERTIFICATE_CASES,
            "actual invalid controls incomplete or promoted")
    combined = cases + audit["certificate_cases"]
    for row in combined:
        require(row["rejected"] is True and type(row["error"]) is str and bool(row["error"])
                and all(type(row[k]) is int and row[k] >= 0 for k in ("wall_ns","process_cpu_ns")),
                "invalid rejection result or measured cost")
    return combined

def closed_phase(out,name,source):
    row=read_json(out/(name+".process.json"))
    require(row["schema"]=="pon-w1-actual-process-v2" and row["source_sha"]==source
            and row["returncode"]==0 and row["timed_out"] is False and row["child_reaped"] is True
            and row["owned_process_group_empty"] is True and not row["cleanup_errors"]
            and row["timeout_seconds"] == PHASE_TIMEOUTS[name],
            "actual phase failed or not closed: "+name)
    for k in ("wall_seconds","user_cpu_seconds","system_cpu_seconds"):
        value=row[k];require(type(value) in (int,float) and math.isfinite(value) and value>=0,"phase cost unavailable")
    for stream in ("stdout","stderr"):
        logged=row["raw_logs"][stream]
        require(logged["path"]==name+"."+stream+".log" and
                digest(out/logged["path"],16*1024**2)=={k:logged[k] for k in ("bytes","sha256")},
                "phase raw log changed")
    return row

def finalize(out):
    # Pure readback after the outer wrapper has settled its exact family. It
    # never launches another stage, retries a failed stage, or extends a budget.
    record={"schema":"pon-w1-succinct-after-cleanup-v1","proof_started":False,
            "complete":False,"known_stage_terminals":[],"missing_stage_terminals":[],
            "retained_files":{},"new_work_started":False}
    phase=out/"compress.process.json"
    if phase.exists():
        record["outer_phase"]=read_json(phase);record["proof_started"]=True
    d=out/"recursion"
    if (d/"attempt.json").exists():record["attempt"]=read_json(d/"attempt.json")
    for started in sorted((d/"steps").glob("*.started.json")):
        terminal_path=started.with_name(started.name.replace(".started.json",".terminal.json"))
        if terminal_path.exists():
            record["known_stage_terminals"].append(read_json(terminal_path))
        else:record["missing_stage_terminals"].append(started.name)
    for directory in (d/"steps",d/"receipts"):
        for path in sorted(directory.glob("*")):
            record["retained_files"][str(path.relative_to(out))]=digest(path,16*1024**2)
    if record["proof_started"]:
        phase=record["outer_phase"]
        record["owned_family_closed"]=phase.get("child_reaped") is True and phase.get("owned_process_group_empty") is True
        record["complete"]=(record["owned_family_closed"] and phase.get("returncode")==0
            and record.get("attempt",{}).get("outcome")=="complete"
            and not record["missing_stage_terminals"])
    write(out/"recursion-after-cleanup.json",record)
    print(json.dumps({"schema":record["schema"],"complete":record["complete"],
        "retained_stage_terminals":len(record["known_stage_terminals"]),"new_work_started":False}))

def report(out):
    ids=identity();p=check_inputs(out/"original")
    source_before=read_json(out/"source-before.json");source_after=read_json(out/"source-after.json")
    require(source_before==source_after and source_before["tested_commit"]==ids["source_sha"]
            and source_before["candidate"]==ids["source_sha"] and source_before["tracked_worktree_verified"] is True,
            "exact new source identity unavailable")
    phases={name:closed_phase(out,name,ids["source_sha"]) for name in PHASE_TIMEOUTS}
    attempt=read_json(out/"recursion/attempt.json")
    tasks=[t for batch in batches() for t in batch]
    require(attempt["source_sha"]==ids["source_sha"] and attempt["outcome"]=="complete"
            and attempt["real_succinct_stark_verified"] is True and not attempt["direct_children_missing_terminal"]
            and sorted(attempt["completed"])==sorted(name(t) for t in tasks)
            and len(attempt["completed"])==123
            and type(attempt["work_finished_wall_seconds"]) in (float,int)
            and 0<=attempt["work_finished_wall_seconds"]<3500,"complete new recursion unavailable")
    settled=read_json(out/"recursion-after-cleanup.json")
    require(settled["complete"] is True and settled["owned_family_closed"] is True
            and settled["attempt"] == attempt and settled["outer_phase"] == phases["compress"]
            and not settled["missing_stage_terminals"],
            "actual recursion cleanup not closed")
    require(attempt["helper"]==digest(out/"native/trnm-w1-succinct-research",64*1024**2),
            "actual native helper bytes changed")
    stage_names = ["prepare", "finish"] + [name(t) for t in tasks]
    retained = {f"recursion/steps/{n}.{suffix}" for n in stage_names
                for suffix in ("started.json","terminal.json","stdout.log","stderr.log")}
    retained |= {f'recursion/receipts/range-{t["start"]}-{t["end"]}.bin' for t in tasks}
    require(set(settled["retained_files"]) == retained, "incomplete or foreign settled file set")
    require(len(settled["known_stage_terminals"]) == 125, "settled terminal inventory incomplete")
    for relative,expected in settled["retained_files"].items():
        require(digest(out/relative,16*1024**2)==expected,"settled stage material changed")
    stage_costs=[]
    for task in tasks:
        n=name(task);directory=out/"recursion/steps"
        term=read_json(directory/(n+".terminal.json"));terminal(term,ids["source_sha"])
        row=read_single_result(directory/(n+".stdout.log"),"pon-w1-succinct-stage-v1")
        require(row["operation"]==task["op"] and all(row[k]==task[k] for k in ("start","split","end"))
                and row["real_recursion_stark_verified"] is True and row["dev_mode"] is False
                and row["additional_pow"] is False and row["povw_requested"] is False,
                "native stage range/profile changed")
        require(digest(out/f'recursion/receipts/range-{task["start"]}-{task["end"]}.bin',2*1024**2)
                =={"bytes":row["receipt_bytes"],"sha256":row["receipt_sha256"]},"verified stage artifact changed")
        stage_costs.append({"name":n,"process":term,"native":row})
    for n in ("prepare","finish"):terminal(read_json(out/f"recursion/steps/{n}.terminal.json"),ids["source_sha"])
    finished=read_single_result(out/"recursion/steps/finish.stdout.log","pon-w1-succinct-finish-v1")
    expected={"bytes":finished["receipt_bytes"],"sha256":finished["receipt_sha256"]}
    require(finished["real_succinct_stark_verified"] is True and digest(out/"succinct.bin",2*1024**2)==expected,
            "final receipt changed")
    require(digest(out/"certificate.bin",3*1024**2)
            =={"bytes":finished["certificate_wire_bytes"],"sha256":finished["certificate_wire_sha256"]},
            "certificate material changed")
    certificate = frozen.checked_bytes(out/"certificate.bin", 3*1024**2)
    receipt = frozen.checked_bytes(out/"succinct.bin", 2*1024**2)
    public_input = frozen.checked_bytes(out/"original/input.bin", 49640)
    require(certificate == b"PWSR0001" + len(public_input).to_bytes(4,"little")
            + len(receipt).to_bytes(4,"little") + public_input + receipt,
            "new certificate framing or full public input binding differs")
    verified=read_single_result(out/"verify.stdout.log","pon-w1-succinct-verify-v1")
    benchmark=read_single_result(out/"benchmark.stdout.log","pon-w1-succinct-benchmark-v1")
    require(all(row["real_succinct_stark_verified"] is True and row["receipt_sha256"]==expected["sha256"]
                and row["receipt_bytes"]==expected["bytes"] for row in (verified,benchmark)),
            "native actual complete verification missing")
    samples=benchmark["samples"];require(len(samples)==31,"bounded verifier sample count")
    for sample in samples:
        require(set(sample)=={"verify_wall_ns","verify_process_cpu_ns"} and
                all(type(v) is int and v>=0 for v in sample.values()),"invalid measured verifier sample")
    audit=read_single_result(out/"audit.stdout.log","pon-w1-succinct-audit-v1")
    cases=checked_audit(audit)
    loop=read_json(out/"loopback/result.json")
    require(loop["outcome"]=="complete" and loop["material_before"]==loop["material_after"]
            and loop["transport"]["outcome"]=="complete","real complete loopback unavailable")
    for which in ("before","after"):
        row=loop["verification"][which]["result"]
        require(row["real_succinct_stark_verified"] is True and row["receipt_sha256"]==expected["sha256"],
                "loopback proof verification not bound")
        require(row["certificate_sha256"]==finished["certificate_wire_sha256"]
                and row["certificate_bytes"]==finished["certificate_wire_bytes"]
                and row["public_input_sha256"]==p["input_files"]["input.bin"]["sha256"]
                and row["verification_uses_received_input_and_receipt"] is True,
                "loopback did not verify the actual received full certificate")
    baseline=read_single_result(out/"original-verify.stdout.log","pon-w1-risc0-research-v1","verify")
    require(baseline["real_composite_stark_verified"] is True and baseline["receipt_bytes"]==15862780,
            "same-host original Composite baseline unavailable")
    median=statistics.median(s["verify_wall_ns"] for s in samples)
    value={"schema":"pon-w1-succinct-costs-v1",**ids,"source":source_before,"origin":p["origin"],
        "complete":True,"original_proof_cost_not_replaced":True,"from_zero_generation_measured":False,
        "new_recursion_phases":123,"recursion_stage_costs":stage_costs,"exclusive_outer_phases":phases,
        "phase_cpu_seconds":sum(v["user_cpu_seconds"]+v["system_cpu_seconds"] for v in phases.values()),
        "phase_wall_seconds_sum":sum(v["wall_seconds"] for v in phases.values()),
        "cpu_accounting":"outer phase totals only; stage costs are included in compress and must not be added again",
        "phase_cost_exclusions":["GitHub checkout and runner provisioning","preflight and source-identity readers",
                                 "record copies and final report writing","artifact upload"],
        "finish":finished,"verification":verified,"benchmark":benchmark,
        "verify_median_wall_ns":median,"same_host_original_verification":baseline,
        "original_verify_over_succinct_median":baseline["verify_wall_ns"]/median if median else None,
        "maximum_tested_rejection":max(cases,key=lambda v:v["wall_ns"]),"global_worst_invalid_proven":False,
        "audit":audit,"loopback":loop,"existing_packet_codec_accepts_succinct":False,
        "additional_pow":False,"povw_requested":False,"groth16_used":False,"pq128_qualified":False,
        "consensus_authority":False}
    write(out/"costs.json",value)
    print(json.dumps({"schema":value["schema"],"complete":True,"receipt":expected,
                      "verify_median_wall_ns":median,"consensus_authority":False}))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("fetch","install","prove","loopback","report","finalize"))
    parser.add_argument("--out",type=Path,required=True);parser.add_argument("--helper",type=Path)
    parser.add_argument("--r0vm",type=Path);parser.add_argument("--dest",type=Path)
    args=parser.parse_args();policy()
    if args.command=="fetch":fetch_original(args.out)
    elif args.command=="install":install_tools(args.dest)
    elif args.command=="prove":prove(args)
    elif args.command=="loopback":loopback(args)
    elif args.command=="finalize":finalize(args.out)
    else:report(args.out)

if __name__=="__main__":
    main()
