from pathlib import Path
import sys,json
root=Path(sys.argv[1])
sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
import fixed_probability_contract as c
old=c.load_contract(root/'evidence/pon-fixed-joint-source-binding-20261114/historical/fixed_probability_contract_v1-2bb56596.json')
try:
    c.audit_contract(old,root=root)
except c.ContractError as error:
    assert str(error)=='SOURCE_DIGEST_MISMATCH',str(error)
    print(json.dumps({'schema':'fixed-old-source-mapping-refusal-v1','original_contract_rejected':True,'error':str(error),'qualification_granted':False},sort_keys=True))
else:
    raise AssertionError('old mapping unexpectedly accepted')
