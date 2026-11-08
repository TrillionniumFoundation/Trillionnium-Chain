#!/usr/bin/env python3
"""Reconstructed operation counter using recovered byte-pinned old references.

Original native observations are replayed, never relabeled as new native runs.
"""
from collections import Counter
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import importlib.util
import json
import sys
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('recovered_selected_reference',BASE/'reference/selected_event_reference.py')
ref=importlib.util.module_from_spec(spec);sys.modules[spec.name]=ref;spec.loader.exec_module(ref)
from sha256_prefix import PrefixSHA256,BoundedPrefixSHA256

def encode(tag,*parts):
    if type(tag) is not bytes or len(tag)>=256:raise ValueError('tag')
    if any(type(v) is not bytes or len(v)>=2**32 for v in parts):raise ValueError('part')
    return ref.DOMAIN+bytes([len(tag)])+tag+b''.join(len(v).to_bytes(4,'little')+v for v in parts)

def decode_hash(message):
    if not message.startswith(ref.DOMAIN) or len(message)<=len(ref.DOMAIN):raise ValueError('domain')
    offset=len(ref.DOMAIN);n=message[offset];offset+=1
    if offset+n>len(message):raise ValueError('truncated tag')
    tag=message[offset:offset+n];offset+=n;parts=[]
    while offset<len(message):
        if offset+4>len(message):raise ValueError('truncated length')
        n=int.from_bytes(message[offset:offset+4],'little');offset+=4
        if offset+n>len(message):raise ValueError('truncated part')
        parts.append(message[offset:offset+n]);offset+=n
    return tag,tuple(parts)

def sha_blocks(n):return (n+72)//64

class Recorder:
    def __init__(self):self.messages=[];self.tags=[];self.multiplications=0;self.additions=0
    def h(self,tag,*parts):
        m=encode(tag,*parts);self.messages.append(m);self.tags.append(tag.decode('ascii'))
        return sha256(m).digest()
    @contextmanager
    def active(self):
        old_h,old_mul,old_add=ref.H,ref.block_mul,ref.block_add
        def mul(a,b):
            self.multiplications+=512;self.additions+=448
            return old_mul(a,b)
        def add(a,b):self.additions+=64;return old_add(a,b)
        ref.H=self.h;ref.block_mul=mul;ref.block_add=add
        try:yield self
        finally:ref.H,ref.block_mul,ref.block_add=old_h,old_mul,old_add
    def counts(self):
        return {'sha256_calls':len(self.messages),'sha256_input_bytes':sum(map(len,self.messages)),
                'sha256_compression_blocks':sum(sha_blocks(len(m)) for m in self.messages),
                'scalar_multiplications':self.multiplications,'scalar_additions':self.additions}
    def unique_counts(self,prior=None):
        seen=set() if prior is None else set(prior);fresh=[]
        for message in self.messages:
            if message not in seen:seen.add(message);fresh.append(message)
        return {'distinct_hash_inputs':len(fresh),'unique_hash_input_bytes':sum(map(len,fresh)),
                'full_hash_compressions_after_output_cache':sum(sha_blocks(len(m)) for m in fresh)}

def decode_fixture(expected,witness):
    if len(expected)!=192 or len(witness)!=1419:raise ValueError('fixture length')
    ctx=ref.Expected(*(expected[i:i+32] for i in range(0,192,32)))
    def block(offset):return tuple(int.from_bytes(witness[i:i+4],'little') for i in range(offset,offset+256,4))
    def paths(offset):return tuple(witness[i:i+32] for i in range(offset,offset+192,32))
    w=ref.Witness(int.from_bytes(witness[:8],'little'),*witness[8:11],block(11),block(267),
                  paths(523),paths(715),block(907),block(1163))
    return ctx,w

def decode_task(raw):
    if len(raw)!=16384:raise ValueError('task length')
    return tuple(tuple(int.from_bytes(raw[i+j:i+j+4],'little') for j in range(0,256,4))
                 for i in range(0,len(raw),256))

class Prepared:
    """Explicit native PreparedTask schedule, evaluated with original Python ops."""
    def __init__(self,a,b,cache_useful=False):
        self.a,self.b=a,b;self.ta,self.tb=ref.tree(b'A',a),ref.tree(b'B',b);self.cache=None
        if cache_useful:
            self.cache=tuple(ref.block_mul(a[bi*8+bk],b[bk*8+bj])
                             for bi in range(8) for bk in range(8) for bj in range(8))
    def produce(self,ctx,nonce):
        seed=ref.seed(ctx,nonce);bi,bk,bj=ref.selected_coordinates(seed)
        if (self.ta[-1][0],self.tb[-1][0])!=(ctx.root_a,ctx.root_b):raise ValueError('roots')
        a,b=self.a[bi*8+bk],self.b[bk*8+bj];e,f=ref.noise_blocks(seed,bi,bk,bj)
        noisy=ref.block_mul(ref.block_add(a,e),ref.block_add(b,f))
        useful=ref.block_mul(a,b) if self.cache is None else self.cache[bi*64+bk*8+bj]
        return ref.Witness(nonce,bi,bk,bj,a,b,ref.opening(self.ta,bi*8+bk),
                           ref.opening(self.tb,bk*8+bj),noisy,useful)

def observe_fixtures():
    manifest=json.loads((BASE/'reference/fixture_manifest.json').read_text());result=[]
    for item in manifest['entries']:
        for name,digest in item['file_sha256'].items():
            assert sha256((BASE/'reference'/name).read_bytes()).hexdigest()==digest
        ctx,w=decode_fixture((BASE/'reference'/item['expected_file']).read_bytes(),
                             (BASE/'reference'/item['witness_file']).read_bytes())
        recorder=Recorder()
        with recorder.active():
            try:
                v=ref.verify(ctx,w)
                observed={'status':'ACCEPT_SELECTED_EVENT_ONLY','event_id':v.event_id.hex(),'ticket':v.ticket.hex()}
            except ref.Refusal as e:observed={'status':'REJECT','error':str(e)}
        assert all(item['native_observed_result'][k]==v for k,v in observed.items())
        assert recorder.counts()==item['native_observed_counts']
        prefix=PrefixSHA256()
        for message in recorder.messages:assert prefix.digest(message)==sha256(message).digest()
        result.append({'name':item['name'],'result':observed,'counts':recorder.counts(),
                       'counts_match_retained_native_observation':True,
                       'new_native_measurement':False,
                       'tag_call_counts':dict(sorted(Counter(recorder.tags).items())),
                       'unique_hash_counts':recorder.unique_counts(),
                       'prefix_cached_compressions':prefix.compressions,
                       'prefix_cache_payload':prefix.payload()})
    return result

def producer_campaign(nonces=(24,25,26),cache_useful=False):
    item=json.loads((BASE/'reference/fixture_manifest.json').read_text())['entries'][0]
    ctx,_=decode_fixture((BASE/'reference'/item['expected_file']).read_bytes(),
                         (BASE/'reference'/item['witness_file']).read_bytes())
    a=decode_task((BASE/'reference'/item['producer_check']['a_file']).read_bytes())
    b=decode_task((BASE/'reference'/item['producer_check']['b_file']).read_bytes())
    prep=Recorder()
    with prep.active():task=Prepared(a,b,cache_useful)
    prefix=PrefixSHA256();bounded=BoundedPrefixSHA256()
    for message,tag in zip(prep.messages,prep.tags):
        assert prefix.digest(message)==sha256(message).digest()
        assert bounded.digest(message,tag)==sha256(message).digest()
    seen=set(prep.messages);prep_prefix=prefix.compressions;trials=[]
    for nonce in nonces:
        recorder=Recorder()
        with recorder.active():
            w=task.produce(ctx,nonce);event=ref.statement(ctx,w);ticket=ref.H(b'ticket',event)
        before=prefix.compressions;before_bounded=bounded.compressions
        for message,tag in zip(recorder.messages,recorder.tags):
            assert prefix.digest(message)==sha256(message).digest()
            assert bounded.digest(message,tag)==sha256(message).digest()
        assert w==ref.produce(ctx,nonce,a,b)  # correctness check outside counted schedule
        trials.append({'nonce':nonce,'event_id':event.hex(),'ticket':ticket.hex(),
                       'meets_target':ticket<=ctx.target,'counts':recorder.counts(),
                       'new_hash_inputs_after_lifetime_output_cache':recorder.unique_counts(seen),
                       'prefix_cached_new_compressions':prefix.compressions-before,
                       'bounded_cache_new_compressions':bounded.compressions-before_bounded,
                       'witness_equals_unmodified_reference':True})
        seen.update(recorder.messages)
    return {'algorithm':'prepared_trees_and_all_512_U' if cache_useful else 'prepared_trees_direct_U',
            'sample_nonces':list(nonces),'scope':'exact schedule; not a time measurement or complete mining search',
            'preparation_counts':prep.counts(),'preparation_prefix_cached_compressions':prep_prefix,
            'original_matrix_payload_bytes':32768,'merkle_hash_payload_bytes':8128,
            'useful_product_cache_payload_bytes':131072 if cache_useful else 0,
            'trials':trials,'final_prefix_cache_payload':prefix.payload(),
            'final_bounded_cache_payload':bounded.payload(),'bounded_total_compressions':bounded.compressions}

def hash_length_table():
    profile=len(ref.PROFILE)
    parts={b'leaf':[profile,1,1,256],b'node':[profile,1,1,32,32],b'task':[profile,32,32],
           b'context':[profile]+[32]*5,b'noise-seed':[32,8],b'selected-coordinate':[32],
           b'noise-eight':[32,2,4],b'event':[32,8,3,256,256],b'ticket':[32]}
    return {tag.decode():{'part_lengths':lengths,'input_bytes':len(encode(tag,*(bytes(n) for n in lengths))),
                         'full_sha256_compressions':sha_blocks(len(encode(tag,*(bytes(n) for n in lengths))))}
            for tag,lengths in parts.items()}

def main():
    result={'schema':'selected-composition-exact-operation-model-v2-reconstructed',
            'reconstruction_new_run':True,'new_native_benchmark':False,
            'qualifier':'explicit achieved schedules, not physical lower bounds',
            'domain_hex':ref.DOMAIN.hex(),'domain_bytes':len(ref.DOMAIN),
            'profile_hex':ref.PROFILE.hex(),'profile_bytes':len(ref.PROFILE),
            'hash_length_table':hash_length_table(),'fixture_replays':observe_fixtures(),
            'producer_schedules':[producer_campaign(cache_useful=False),producer_campaign(cache_useful=True)]}
    (BASE/'exact_cost_results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'reconstructed_new_run':True,'fixture_replays':3,'producer_schedules':2,
                      'producer_trials_each':3,'result':'exact_cost_results.json'}))

if __name__=='__main__':main()
