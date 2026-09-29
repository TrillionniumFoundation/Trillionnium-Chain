"""Explicit native M06 bridge; missing/failed native execution never falls back."""
from __future__ import annotations
import json,os
from bounded_process import run_bounded
from pathlib import Path
from contract_wire import canonical,state_root,unique,NETWORK,PARAMETER_HASH

def execute_native(state,transactions,height,miner,parent,workers=None,binary=None):
    path=Path(binary or os.environ.get('TRNM_NATIVE_EXECUTOR',''))
    try:available=path.is_file()
    except OSError as e:raise ValueError('NATIVE_EXECUTOR_UNAVAILABLE')from e
    if not available:raise ValueError('NATIVE_EXECUTOR_UNAVAILABLE')
    count=int(workers if workers is not None else os.environ.get('TRNM_EXECUTION_WORKERS','1'))
    if count not in {1,2,4,8}:raise ValueError('WORKERS')
    request={'network':NETWORK.hex(),'parameters':PARAMETER_HASH.hex(),'state':state,'transactions':[t.hex()for t in transactions],'height':height,'miner':miner.hex(),'parent':parent.hex(),'workers':count}
    data=canonical(request)
    if len(data)>16*1024*1024:raise ValueError('NATIVE_BRIDGE_LIMIT')
    r=run_bounded([str(path)],data)
    if r.returncode:raise ValueError('NATIVE_'+r.stderr.decode(errors='replace').strip()[:300])
    result=json.loads(r.stdout,object_pairs_hook=unique)
    if set(result)!={'network','parameters','state','receipts','root','metrics','scope'}:raise ValueError('NATIVE_FIELDS')
    if result['network']!=NETWORK.hex()or result['parameters']!=PARAMETER_HASH.hex():raise ValueError('NATIVE_CONTEXT')
    if state_root(result['state']).hex()!=result['root']:raise ValueError('NATIVE_ROOT')
    return result['state'],[bytes.fromhex(x)for x in result['receipts']],result['metrics']
