"""Public input fixtures; all comparison answers come from actual original Rust."""
from __future__ import annotations
import hashlib
import json
import struct

U32_MAX, U64_MAX, U128_MAX = (1 << 32)-1, (1 << 64)-1, (1 << 128)-1
I128_MIN, I128_MAX = -(1 << 127), (1 << 127)-1
WHITESPACE = [*range(9,14),32,133,160,5760,*range(8192,8203),8232,8233,8239,8287,12288]


def word(*values):
    return struct.pack('<'+'Q'*len(values), *values)


def string(value):
    value = value.encode() if isinstance(value, str) else value
    return word(len(value)) + value


def frame(operation, payload, profile=0):
    return b'ORAC0001' + word(operation, profile) + payload


def json_frame(kind, direction, payload, profile=0):
    return b'ORJS0001' + word(kind, direction, profile) + payload


def json_decode(kind, raw, profile=0):
    raw = raw.encode() if isinstance(raw, str) else raw
    return json_frame(kind, 0, word(len(raw)) + raw, profile)


def snapshot(*, value=100000, median=100000, mad=2, sources=('a','b'), sample_count=2,
             feed_id='usd', window_start_ms=100, window_end_ms=200, snapshot_ts_ms=200,
             snapshot_hash=None):
    feed = feed_id.encode()
    sources = [source.encode() for source in sources]
    def optional(value, signed):
        return b'\0' if value is None else b'\1' + value.to_bytes(16,'little',signed=signed)
    if snapshot_hash is None:
        preimage = (feed+b'\xff'+value.to_bytes(16,'little',signed=True)+b'\xff'
            +len(sources).to_bytes(4,'little')+b''.join(source+b'\xff' for source in sources)
            +sample_count.to_bytes(4,'little')+b'\xff'+optional(median,True)+optional(mad,False)
            +word(window_start_ms,window_end_ms,snapshot_ts_ms))
        snapshot_hash = hashlib.sha256(preimage).hexdigest()
    hashed = snapshot_hash.encode()
    return (value.to_bytes(16,'little',signed=True)+word(sample_count, median is not None)
        +(median or 0).to_bytes(16,'little',signed=True)+word(mad is not None)
        +(mad or 0).to_bytes(16,'little')+word(window_start_ms,window_end_ms,snapshot_ts_ms,
           len(feed),len(hashed),len(sources))+feed+hashed+b''.join(string(s) for s in sources))


def policy(min_sources=2, max_staleness_ms=5000, max_deviation_bps=500,
           max_update_rate_per_window=60):
    return word(min_sources,max_staleness_ms,max_deviation_bps,max_update_rate_per_window)


def validate(operation, raw=None, *, now=200, limits=None, profile=0):
    return frame(operation,(policy() if limits is None else limits)+word(now)
                 +(snapshot() if raw is None else raw),profile)


def report(*, ok=False, now=200, observation=(1,0,0,0), metrics=(1,0,0,2,0,1), error='stale'):
    return word(ok,now,*observation,*metrics,error is not None)+string(error or '')


def replace_word(raw, at, value):
    return raw[:at]+word(value)+raw[at+8:]


def json_values():
    observation = {'stale_reject_total':U32_MAX,'quorum_reject_total':1,
                   'drift_reject_total':4,'accepted_total':0}
    metrics = {'oracle_stale_reject_total':U32_MAX,'oracle_quorum_reject_total':0,
               'oracle_drift_reject_total':0,'oracle_source_cardinality':0,
               'accepted_total':0,'sample_count':U32_MAX}
    return ['a\0É\u3000"Λ',
        {'feed_id':'Usd','value':I128_MIN,'sources':[' b ','A','a','\0'],
         'sample_count':0,'median':I128_MAX,'mad':U128_MAX,'window_start_ms':0,
         'window_end_ms':U64_MAX,'snapshot_ts_ms':2,'snapshot_hash':''},
        {'min_sources':0,'max_staleness_ms':U64_MAX,'max_deviation_bps':U32_MAX,
         'max_update_rate_per_window':1},observation,metrics,
        {'ok':False,'now_ts_ms':U64_MAX,'observation':observation,'metrics':metrics,
         'error':' snapshot hash mismatch:\0 '}]


def json_roundtrip_cases():
    rows=[]
    for kind, value in enumerate(json_values()):
        for ascii_only in (True,False):
            rows.append(json_decode(kind,json.dumps(value,ensure_ascii=ascii_only)))
        if isinstance(value,dict):
            rows.append(json_decode(kind,json.dumps(list(value.values()))))
            for key in value:
                changed=value.copy();changed.pop(key)
                rows.append(json_decode(kind,json.dumps(changed)))
                rows.append(json_decode(kind,json.dumps(value)[:-1]+','+json.dumps(key)+':null}'))
                for replacement in [None,True,False,0,1,-1,1.0,'',[],{},1<<128,I128_MIN-1]:
                    changed=value.copy();changed[key]=replacement
                    rows.append(json_decode(kind,json.dumps(changed)))
    return rows
