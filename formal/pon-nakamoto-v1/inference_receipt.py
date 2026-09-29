"""Closed consumer-visible receipt, checked before signing a sponsored use.
The receipt is a service observation, not a local capability or a model-quality proof.
"""
from contract_wire import NETWORK,PARAMETER_HASH,H,canonical,fixed,unique
import json
FIELDS={'network','parameters','model','request','input','output','provider','quota','units','provider_nonce'}

def receipt(fields):
    if set(fields)!=FIELDS:raise ValueError('RECEIPT_FIELDS')
    if fields['network']!=NETWORK.hex()or fields['parameters']!=PARAMETER_HASH.hex():raise ValueError('RECEIPT_NETWORK')
    for name in FIELDS-{'units','provider_nonce'}:fixed(fields[name])
    for name in ['units','provider_nonce']:
        if type(fields[name])is not int or not 0<fields[name]<1<<64:raise ValueError('RECEIPT_COUNTER')
    return canonical(fields)

def verify(raw,expected):
    fields=json.loads(raw,object_pairs_hook=unique)
    if receipt(fields)!=raw:raise ValueError('RECEIPT_CANONICAL')
    mandatory={'network','parameters','model','request','input','provider','quota'}
    if not mandatory<=set(expected) or any(k not in FIELDS or fields[k]!=v for k,v in expected.items()):raise ValueError('RECEIPT_BINDING')
    return H('inference-receipt-v2',raw)
