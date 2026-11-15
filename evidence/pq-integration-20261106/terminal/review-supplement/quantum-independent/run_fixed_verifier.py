#!/usr/bin/env python3
import hashlib,json,subprocess,time
from pathlib import Path
B=Path('/workspace/scratch/8a6ecb667c1e')
P=B/'terminal-evidence-curated-final-20261106-v1/publication'
R=Path(__file__).resolve().parent
V=P/'verify_curated_evidence.py'
I=P/'archive-index.json'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert sha(V)=='ad84ee5ccec29a339a54a20a863e964ced941821321c87f10e188de9979174c4'
assert sha(I)=='91ef1453209eb3b72eb0f90066ca05e4e5a93e8d1b1b00f5c87855ddcfe1e8ed'
argv=['python3','-B',str(V),str(I)]
start=time.time_ns()
with (R/'fixed-verifier.stdout.log').open('xb') as out,(R/'fixed-verifier.stderr.log').open('xb') as err:
    process=subprocess.run(argv,cwd=B,stdin=subprocess.DEVNULL,stdout=out,stderr=err,check=False)
receipt={'schema':'trnm-independent-fixed-archive-verifier-execution-v1','argv':argv,'cwd':str(B),'started_unix_ns':start,'finished_unix_ns':time.time_ns(),'exit_code':process.returncode,'verifier_sha256':sha(V),'index_sha256':sha(I),'stdout_sha256':sha(R/'fixed-verifier.stdout.log'),'stderr_sha256':sha(R/'fixed-verifier.stderr.log'),'native_tests_executed':0,'desktop_accessed':False}
with (R/'fixed-verifier.receipt.json').open('x') as f:json.dump(receipt,f,indent=2,sort_keys=True);f.write('\n')
assert process.returncode==0
result=json.loads((R/'fixed-verifier.stdout.log').read_text())
assert result['result']=='PASS_ARCHIVE_CONTENT_ONLY' and result['native_tests_executed']==0 and result['whole_chain_pq_qualified'] is False
assert result['index_sha256']==receipt['index_sha256']=='91ef1453209eb3b72eb0f90066ca05e4e5a93e8d1b1b00f5c87855ddcfe1e8ed'
assert result['verified_parts']==20 and result['verified_members']==5574
assert result['archive_bytes']==30057120 and result['raw_member_bytes']==119411819
assert result['archive_sha256']=='7a57775876306f0eaa0ad720924a48eb1478ab111d6b81eb6ef2d2632cd83794'
print(json.dumps({'receipt':receipt,'result':result},sort_keys=True))
