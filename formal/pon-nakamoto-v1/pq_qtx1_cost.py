"""Bounded single-host process-inclusive PQN1 validation-cost profile.

NO throughput, consensus, resistance-to-quantum-search, or public admission claim.
The CPU readings are child-process resource deltas, NOT miner security estimates.
"""
from __future__ import annotations
from collections import defaultdict
import json
from pathlib import Path
import platform
import random
import resource
import subprocess
import sys
import tempfile
import time

from pq_envelope import public_key_id
from test_pq_native_qtx1 import body, signed, NET, SENDER

HERE=Path(__file__).resolve().parent
CASES=("valid","invalid_signature","invalid_budget","invalid_magic","valid_max_memo")
SAMPLES=64

def percentile(values, p):
    values=sorted(values)
    return values[(len(values)-1)*p//100]

def run_one(cmd):
    before=resource.getrusage(resource.RUSAGE_CHILDREN)
    begin=time.perf_counter_ns()
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
    elapsed=time.perf_counter_ns()-begin
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu=max(0,round(((after.ru_utime-before.ru_utime)+(after.ru_stime-before.ru_stime))*1e9))
    return result,elapsed,cpu

def main():
    if len(sys.argv)!=2 or sys.argv[1] in ("-h","--help"):
        raise SystemExit("usage: python3 pq_qtx1_cost.py /output/report.json")
    out=Path(sys.argv[1])
    if out.exists():raise SystemExit("refuse overwrite of an existing benchmark report")
    with tempfile.TemporaryDirectory(prefix="trnm-pqn1-cost-") as td:
        root=Path(td)
        native=root/"pq_qtx1_verify"
        subprocess.run(["cc","-std=c11","-O2","-Wall","-Wextra","-Werror","-Wpedantic",
                        str(HERE/"pq_qtx1_verify.c"),"-lcrypto","-o",str(native)],
                       check=True,capture_output=True,timeout=30)
        secret=root/"secret.pem";pub=root/"pub.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ML-DSA-65","-out",str(secret)],
                       check=True,capture_output=True,timeout=15)
        subprocess.run(["openssl","pkey","-in",str(secret),"-pubout","-out",str(pub)],
                       check=True,capture_output=True,timeout=15)
        pem=pub.read_bytes(); kid=public_key_id(pem)
        base=body(); raw=signed(base,pem,secret)
        high=body(bytes(range(256))*2); full=signed(high,pem,secret)
        corrupted=bytearray(raw);corrupted[-1]^=1
        malformed=b"BAD!" + raw[4:]
        blobs={
            "valid":raw,"invalid_signature":bytes(corrupted),
            "invalid_budget":raw,"invalid_magic":malformed,
            "valid_max_memo":full
        }
        for name,blob in blobs.items():(root/(name+".qtx")).write_bytes(blob)
        agenda=[name for name in CASES for _ in range(SAMPLES)]
        random.Random(20261026).shuffle(agenda)
        observations=defaultdict(list)
        for name in agenda:
            cmd=[str(native),str(pub),str(root/(name+".qtx")),NET.hex(),SENDER.hex(),kid.hex(),
                 "2","7","4000","1" if name=="invalid_budget" else "20000",
                 "100","1","1"]
            result,elapsed,cpu=run_one(cmd)
            accepted=name in ("valid","valid_max_memo")
            if (result.returncode==0)!=accepted or ("SIGNATURE_VALID" in result.stdout)!=accepted:
                raise RuntimeError(f"unexpected result {name}: {result.returncode}; {result.stdout}; {result.stderr}")
            observations[name].append((elapsed,cpu))
        summary={}
        for name in CASES:
            arr=observations[name]
            wall=[item[0] for item in arr];cpu=[item[1] for item in arr]
            summary[name]={
                "count":len(arr),"return":"research-only-sig-valid" if name.startswith("valid") else "rejected",
                "wall_p50_ns":percentile(wall,50),"wall_p95_ns":percentile(wall,95),
                "wall_p99_ns":percentile(wall,99),"cpu_p50_ns":percentile(cpu,50),
                "cpu_p95_ns":percentile(cpu,95),"cpu_p99_ns":percentile(cpu,99)
            }
        data={
            "schema":"trnm-pqn1-single-host-process-inclusive-cost-v1",
            "test_profile":"C11/OpenSSL3.5 genuine ML-DSA-65 single-shot offline CLI",
            "samples_per_case":SAMPLES,"random_interleave_seed":20261026,
            "platform":platform.platform(),"python":platform.python_version(),
            "compiler":subprocess.check_output(["cc","--version"],text=True).splitlines()[0],
            "openssl":subprocess.check_output(["openssl","version"],text=True).strip(),
            "normal_signed_bytes":len(raw),"maximum_memo_signed_bytes":len(full),
            "maximum_256_tx_payload_bytes":len(full)*256,"installed_max_block_bytes":1048576,
            "current_legacy_wire_accepts_pq":False,
            "process_start_included":True,"full_chain_throughput_measured":False,
            "independent_security_qualification":False,"production_activation":False,
            "summary":summary}
        out.parent.mkdir(parents=True,exist_ok=True)
        with out.open("x",encoding="utf-8") as f:
            json.dump(data,f,indent=2);f.write("\n")
        print(json.dumps({"cases":list(summary),"observations":sum(v["count"] for v in summary.values()),
                          "max_signed_bytes":len(full),"max_batch_bytes":len(full)*256,
                          "full_chain_tps_measured":False}))
if __name__=="__main__":main()
