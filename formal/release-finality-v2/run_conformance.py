"""Run all local reference tests, export public test vectors and exact-file receipt."""
import argparse
import copy
import hashlib
import json
import platform
from pathlib import Path
import sqlite3
import sys
import time
import unittest
import cryptography
from protocol import canonical, verify_decision
from verify_certificate import verify
from test_protocol import Fixture

parser=argparse.ArgumentParser();parser.add_argument("--out",required=True);args=parser.parse_args()
out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
start=time.monotonic()
suite=unittest.defaultTestLoader.discover(str(Path(__file__).parent),pattern="test_*.py")
with (out/"tests.log").open("w") as log:
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
passed=result.wasSuccessful() and result.testsRun>=54 and not result.skipped
vectors=[]
if passed:
    for n in (4,5):
        fixture=Fixture(n)
        try:
            bundle,_,_=fixture.run()
            dirname=out/f"n{n}";dirname.mkdir()
            for name,value in (("committee",fixture.m),("context",fixture.ctx),("bundle",bundle)):
                (dirname/f"{name}.json").write_bytes(canonical(value))
            a=verify_decision(bundle,fixture.ctx,fixture.m)
            b=verify(canonical(bundle),canonical(fixture.m),canonical(fixture.ctx))
            assert a==b
            vectors.append(dict(n=n,q=fixture.m["quorum"],value=a["value"],accepted=True))
            negative=copy.deepcopy(bundle);negative["commit"]["votes"][0]["signature"]="00"*64
            (dirname/"bad-signature.json").write_bytes(canonical(negative))
            for reader in (lambda:verify_decision(negative,fixture.ctx,fixture.m),lambda:verify(canonical(negative),canonical(fixture.m),canonical(fixture.ctx))):
                try:reader()
                except ValueError:pass
                else:raise AssertionError("negative vector accepted")
        finally:fixture.close()
root=Path(__file__).resolve().parents[2]
files=sorted(Path(__file__).parent.glob("*.py"))+[root/"formal/pon-nakamoto-v1/strict_signature.py"]
receipt=dict(schema="release-finality-local-conformance-v2",passed=passed,tests=result.testsRun,
             failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
             duration_seconds=time.monotonic()-start,python=platform.python_version(),
             cryptography=cryptography.__version__,sqlite=sqlite3.sqlite_version,platform=platform.platform(),
             sources={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
             vectors=vectors,scope="controlled same-author reference and separate-reader tests",
             native_tests_executed=False,full_checkout_verified=False,independent_review=False,
             physical_power_loss=False,real_neural_generations=0,wan_tps_measured=False,activation=False)
(out/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
print(json.dumps(receipt,sort_keys=True))
sys.exit(0 if passed else 1)
