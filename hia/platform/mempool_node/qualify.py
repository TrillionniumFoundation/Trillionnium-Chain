"""Build and execute one complete production-M05 qualification partition."""
from pathlib import Path
import argparse,importlib,json,traceback
from . import safe
from .build import ROOT,build,validate_build,source_manifest
def main():
    safe.need(__debug__,"Optimized Python is not admitted")
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group",required=True,choices=("smoke","boundaries","capacity","node","cross"))
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args();out=safe.new_output(args.output,ROOT)
    captured=None;failure=None;after=[]
    try:
        captured=source_manifest()
        built=build(out/"build")
        module=importlib.import_module("hia.platform.mempool_node.suite_"+args.group)
        module.main(["--build",str(out/"build"),"--output",str(out/"native")])
        validate_build(out/"build")
        actual=safe.read_json(out,"native/report.json")
        safe.need(actual["status"]=="PASS" and actual["failure"] is None and actual["cleanup_errors"]==[] and safe.same(actual["source_after"],{"status":"MATCH","errors":[]}),"Actual native partition failed")
    except BaseException as e:failure={"error":repr(e),"traceback":traceback.format_exc()}
    finally:
        try:
            if captured is not None:safe.need(safe.same(source_manifest(),captured),"Source changed during actual qualification")
        except BaseException as e:after.append(repr(e))
        report={"schema":"trnm.mempool-node-partition.v1","status":"PASS" if failure is None and not after else "FAIL","group":args.group,
         "source_inputs":captured,"source_set_sha256":None if captured is None else safe.identity(safe.canonical(captured))["sha256"],"failure":failure,"source_after":{"status":"NOT_CAPTURED" if captured is None else ("MATCH" if not after else "FAIL"),"errors":after},
         "native_report":None if not (out/"native/report.json").exists() else safe.file_identity(out/"native/report.json"),
         "native_build":None if not (out/"build/build.json").exists() else safe.file_identity(out/"build/build.json")}
        safe.write_json(out/"report.json",report)
    print(json.dumps({"status":report["status"],"group":args.group,"failure":failure},sort_keys=True))
    safe.need(report["status"]=="PASS","Failed partition; actual raw and failure preserved")
if __name__=="__main__":main()
