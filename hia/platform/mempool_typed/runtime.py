"""Run every declared history as a separate exact sealed native process."""
from __future__ import annotations
import struct,time,traceback
from pathlib import Path
from hia.platform.build import run_native
from .cases import complete
from .contract import need,identity,write_json
from .native_io import parse,commands_wire,original_corpus

CORPUS_ID={"bytes":11057998,"sha256":"07b68d3eed72fe01097cc78cfbac0e20a50cb78b59ede2e2d5b3d970eabda535"}

def run(executable,output,check_sources):
    out=Path(output);out.mkdir(mode=0o700);histories=complete()
    corpus=original_corpus(histories)
    need(identity(corpus)==CORPUS_ID and len(histories)==323,"Declared corpus differs")
    (out/"corpus.bin").write_bytes(corpus)
    report={"schema":"trnm.hia.mempool-typed-native-runtime.v1","status":"FAIL",
        "executable":identity(executable),"corpus":identity(corpus),"histories":[],
        "native_test_traits_only":True,"node_or_persistent_pool_authority":False}
    start=time.monotonic_ns()
    try:
        check_sources()
        for index,history in enumerate(histories):
            commands=history["commands"]
            need(struct.unpack_from("<Q",bytes.fromhex(commands[-1]["input"]),8)[0]==22,
                 "Every history must close all owners")
            payload=commands_wire(history)
            stdout,receipt=run_native(executable,payload,out,f"history-{index:03d}",timeout=30)
            row={"name":history["name"],"index":index,"status":"FAIL","receipt":receipt}
            report["histories"].append(row)
            need(receipt["exit_code"]==0 and not receipt["timed_out"] and receipt["cleanup"] is None
                 and receipt["stderr_hex"]=="","Actual native process failed")
            actual=parse(stdout)
            need(len(actual)==len(commands),"Actual command count differs")
            need([o["op"] for o in actual]==[struct.unpack_from("<Q",bytes.fromhex(c["input"]),8)[0]
                 for c in commands],"Actual operation order differs")
            row.update(status="PASS",actual_commands=len(actual),
                observations=write_json(out/f"history-{index:03d}"/"observations.json",actual),
                close_checked_by_actual_native_owner=True)
        check_sources()
        report.update(status="PASS",actual_processes=len(report["histories"]),
            actual_commands=sum(h["actual_commands"] for h in report["histories"]),
            elapsed_ns=time.monotonic_ns()-start)
        need(report["actual_commands"]==9332,"Incomplete native corpus")
        return report
    except BaseException as error:
        report["failure"]={"error":repr(error),"traceback":traceback.format_exc()};raise
    finally:
        failure=None
        try:check_sources();report["source_after"]="MATCH"
        except BaseException as error:report["source_after"]="FAIL";report["status"]="FAIL";report["source_failure"]=repr(error);failure=error
        write_json(out/"report.json",report)
        if failure is not None:raise failure
