#!/usr/bin/env python3
"""Actual original-proof admission and native negative controls before recursion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import runner

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--helper",required=True,type=Path);p.add_argument("--original",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path);args=p.parse_args();args.out.mkdir()
    policy=runner.check_inputs(args.original);rows=[]
    cases=[("actual_original","",None),("same_size_input","input.bin",0),
           ("same_size_elf","guest.bin",0),("same_size_receipt","receipt.bin",200),
           ("trailing_receipt","receipt.bin","append"),("short_receipt","receipt.bin","truncate"),
           ("empty_receipt","receipt.bin","empty"),("symlink_input","input.bin","symlink"),
           ("fifo_input","input.bin","fifo"),("existing_output","",None)]
    for case,filename,mutation in cases:
        with tempfile.TemporaryDirectory(prefix="native-control-",dir=args.out) as tmp:
            d=Path(tmp)
            for name in policy["input_files"]:os.link(args.original/name,d/name)
            change=None
            if filename:
                target=d/filename;target.unlink()
                if mutation=="symlink":target.symlink_to(args.original/filename)
                elif mutation=="fifo":os.mkfifo(target)
                else:
                    raw=bytearray((args.original/filename).read_bytes())
                    if type(mutation) is int:raw[mutation]^=1
                    elif mutation=="append":raw.append(0)
                    elif mutation=="truncate":raw=raw[:-1]
                    elif mutation=="empty":raw=bytearray()
                    target.write_bytes(raw)
                    change={"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                            "mutation":mutation,"xor":1 if type(mutation) is int else None}
            manifest=d/"prepared.json"
            if case=="existing_output":manifest.write_bytes(b"original sentinel\n")
            command=[str(args.helper),"prepare",str(d),str(manifest)]
            start=time.monotonic()
            child=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            (args.out/(case+".stdout.log")).write_bytes(child.stdout)
            (args.out/(case+".stderr.log")).write_bytes(child.stderr)
            row={"case":case,"command":command,"returncode":child.returncode,
                 "wall_seconds":time.monotonic()-start,"input_mutation":change,
                 "actual_native_command_executed":True,"proof_generation_requested":False}
            rows.append(row)
            runner.require(child.returncode==(0 if case=="actual_original" else 1),"native gate outcome: "+case)
            if case=="actual_original":
                value=runner.strict_json(child.stdout)
                runner.require(value["original_composite_verified"] is True and value["native_full_w1_matches"] is True,
                               "actual full original proof was not verified")
                runner.write(args.out/"positive-result.json",value)
            if case=="existing_output":
                runner.require(manifest.read_bytes()==b"original sentinel\n","output overwrite")
        runner.check_inputs(args.original)
    runner.write(args.out/"result.json",{"schema":"pon-w1-succinct-native-controls-v1","cases":rows,
        "positive_actual_original_composite":True,"negative_cases":9,"all_expected_results":True,
        "recursion_proofs_generated":0,"temporary_mutant_bytes_removed_after_hash_and_native_terminal":True})
    print(json.dumps({"schema":"pon-w1-succinct-native-controls-v1","passed":len(rows),"skipped":0}))

if __name__=="__main__":
    main()
