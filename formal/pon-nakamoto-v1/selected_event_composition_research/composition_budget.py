#!/usr/bin/env python3
"""Reconstructed exact classical-ROM budget calculator, not a physical-work bound.

Fresh validation and hashes are required; see RECOVERY.md and THEOREM.md.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass, fields
from decimal import Decimal, localcontext
from fractions import Fraction
from math import comb
from pathlib import Path
import json

Q_FIELD=4294967291
HASH_BITS=256
SIDE=8
TAGS=('leaf','node','task','context','noise-seed','selected-coordinate',
      'noise-eight','event','ticket','other')

def nat(value,name):
    if type(value) is not int or value<0:raise ValueError(f'{name}: nonnegative integer required')
    return value

def fraction_record(value):
    value=Fraction(value)
    with localcontext() as c:
        c.prec=24
        dec=Decimal(value.numerator)/Decimal(value.denominator)
        bits=None if value<=0 else str(-dec.ln()/Decimal(2).ln())
    large=max(value.numerator.bit_length(),value.denominator.bit_length())>12000
    encode=hex if large else str
    return {'numerator':encode(value.numerator),'denominator':encode(value.denominator),
            'integer_encoding':'hex' if large else 'decimal','decimal':str(dec),'negative_log2':bits}

def beta(q=Q_FIELD,n=SIDE):
    if q<2 or n<1:raise ValueError('q>=2,n>=1 required')
    return 1-(1-Fraction(1,q**n))**4

def hash_exception(caps,hash_bits=HASH_BITS):
    if set(caps)-set(TAGS):raise ValueError('unknown domain')
    q={tag:nat(caps.get(tag,0),tag) for tag in TAGS}
    total=sum(q.values());merkle=q['leaf']+q['node']
    terms={
      'output_collisions':comb(total,2),
      'merkle_reverse_pointers':merkle*(2*q['node']+2*q['task']),
      'task_reverse_pointers':q['task']*q['context'],
      'context_reverse_pointers':q['context']*(q['noise-seed']+q['event']),
      'seed_reverse_pointers':q['noise-seed']*(q['selected-coordinate']+q['noise-eight']),
      'event_reverse_pointers':q['event']*q['ticket']}
    return {'total_distinct_query_cap':total,'numerator_terms':terms,
            'probability':Fraction(sum(terms.values()),2**hash_bits)}

def binomial_tail(k,p,hits=1):
    nat(k,'K');nat(hits,'hits');p=Fraction(p)
    if not 0<=p<=1:raise ValueError('p outside [0,1]')
    if hits==0:return Fraction(1)
    if hits>k:return Fraction(0)
    if k>10000:raise ValueError('exact implementation requires K<=10000; use symbolic theorem above this cap')
    if hits==1:return 1-(1-p)**k
    return sum((Fraction(comb(k,j))*p**j*(1-p)**(k-j) for j in range(hits,k+1)),Fraction())

def evaluate(config):
    m=nat(config['candidate_pair_cap_M'],'M')
    r=nat(config['early_event_guesses_per_pair_cap_R'],'R')
    h=nat(config['adversary_distinct_row_access_cap_H'],'H')
    target_hex=config['target_hex']
    if type(target_hex) is not str or len(target_hex)!=64 or any(c not in '0123456789abcdefABCDEF' for c in target_hex):
        raise ValueError('target_hex must be exactly 64 hexadecimal digits')
    target=int(target_hex,16)
    if target==0:raise ValueError('zero target is rejected by the relation')
    p=Fraction(target+1,2**HASH_BITS)
    merged={tag:0 for tag in TAGS}
    for role in ('adversary_query_caps','setup_query_caps','completion_query_caps'):
        caps=config.get(role,{})
        if set(caps)-set(TAGS):raise ValueError(f'unknown domain in {role}')
        for tag,value in caps.items():merged[tag]+=nat(value,f'{role}.{tag}')
    epsilon=hash_exception(merged);k=min(m,h//32)
    delta=32*m*r*beta();tail=binomial_tail(k,p,config.get('required_distinct_events',1))
    return {'schema':'selected-composition-classical-rom-budget-v2-reconstructed',
      'scope':'conditional classical full-message ROM; not SHA instantiation, QROM, physical work or production authority',
      'caps_are_assumed_not_inferred':True,
      'merged_lifetime_query_caps':merged,'total_lifetime_query_cap_Q':epsilon['total_distinct_query_cap'],
      'candidate_pair_cap_M':m,'early_event_guesses_per_pair_cap_R':r,
      'adversary_distinct_row_access_cap_H':h,'paid_first_trial_cap_K':k,
      'target_success_probability_p':fraction_record(p),'single_missing_row_beta':fraction_record(beta()),
      'early_guess_exception_delta':fraction_record(delta),
      'hash_exception_numerator_terms':epsilon['numerator_terms'],
      'hash_exception_epsilon':fraction_record(epsilon['probability']),
      'paid_first_binomial_tail':fraction_record(tail),
      'success_probability_upper_bound':fraction_record(min(Fraction(1),tail+delta+epsilon['probability']))}

def noise_abort_probability(draws=128):
    nat(draws,'draws');n=8*draws;p=Fraction(Q_FIELD,2**32)
    return sum((Fraction(comb(n,j))*p**j*(1-p)**(n-j) for j in range(min(7,n)+1)),Fraction())

@dataclass(frozen=True)
class Resources:
    sha_calls:int=0
    sha_input_bytes:int=0
    sha_compressions:int=0
    field_multiplications:int=0
    field_additions:int=0
    cache_payload_bytes:int=0

    def __add__(self,other):
        return Resources(**{f.name:getattr(self,f.name)+getattr(other,f.name) for f in fields(self)})
    def scale(self,n):
        nat(n,'scale')
        return Resources(**{f.name:getattr(self,f.name)*n for f in fields(self)})
    def priced(self,weights):
        if set(weights)-{f.name for f in fields(self)}:raise ValueError('unknown price component')
        prices={k:Fraction(v) for k,v in weights.items()}
        if any(v<0 for v in prices.values()):raise ValueError('negative price')
        return sum((getattr(self,k)*v for k,v in prices.items()),Fraction())

def product_counts(depth=0):
    if type(depth) is not int or not 0<=depth<=3:raise ValueError('depth 0..3 required')
    leaf=8//2**depth
    mul=7**depth*leaf**3
    add=7**depth*leaf**2*(leaf-1)+sum(18*7**j*(8//2**(j+1))**2 for j in range(depth))
    return Resources(field_multiplications=mul,field_additions=add)

def amortized_arithmetic(trials,depth=0,cache_useful=False):
    nat(trials,'trials');product=product_counts(depth)
    prep=product.scale(512) if cache_useful else Resources()
    trial=product.scale(3 if cache_useful else 4)+Resources(field_additions=128)
    return prep+trial.scale(trials)+Resources(cache_payload_bytes=131072 if cache_useful else 0)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('config',type=Path);p.add_argument('--output',type=Path);args=p.parse_args()
    result=json.dumps(evaluate(json.loads(args.config.read_text())),indent=2)+'\n'
    if args.output:args.output.write_text(result)
    else:print(result,end='')

if __name__=='__main__':main()
