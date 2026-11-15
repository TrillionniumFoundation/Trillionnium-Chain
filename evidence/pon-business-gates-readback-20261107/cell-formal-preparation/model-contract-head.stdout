"""Pure-integer public artifact contract shared by training and physical-host tests.

This is a format/inference boundary, not a Hepta authorization or training owner.
"""
from __future__ import annotations
import json
from pathlib import Path
from contract_wire import H,canonical,unique
from ledger import FAMILY,require
DIM=257;CLASSES=['M00','M04','M10'];SCALE=1024

def load_model(path,expected=None):
    with open(path,'rb')as source:data=source.read(65537)
    return load_model_bytes(data, expected)

def load_model_bytes(data,expected=None):
    require(type(data)is bytes and len(data)<=65536,'ARTIFACT_LIMIT')
    if expected is not None:require(H('artifact',data)==expected,'ARTIFACT_IDENTITY')
    model=json.loads(data,object_pairs_hook=unique)
    require(canonical(model)==data,'ARTIFACT_CANONICAL_BYTES')
    require(set(model)=={'schema','family','scale','source','base','router','deltas','feature','classes'},'ARTIFACT_FIELDS')
    require(model['feature']=='signed-token-hash-256-clipped8-plus-bias-v1'and model['classes']==CLASSES,'FEATURES')
    require(model['schema']=='hepta-source-owner-linear-256-v1'and model['family']==FAMILY.hex()and model['scale']==SCALE,'FAMILY')
    require(isinstance(model['source'],str) and 0<len(model['source'])<=512,'SOURCE')
    def matrix(value):
        require(isinstance(value,list)and len(value)==3,'SHAPE')
        require(all(isinstance(row,list)and len(row)==DIM for row in value),'SHAPE')
        require(all(type(v)is int and -32767<=v<=32767 for row in value for v in row),'NUMERIC')
    for name in ['base','router']:matrix(model[name])
    require(isinstance(model['deltas'],list)and len(model['deltas'])==3,'SHAPE')
    for value in model['deltas']:matrix(value)
    return model

def infer(model,rows):
    require(isinstance(rows,list)and 0<len(rows)<=64,'INFERENCE_BATCH')
    output=[]
    for row in rows:
        require(isinstance(row,list)and len(row)==DIM,'INPUT_SHAPE')
        require(all(type(v)is int and -8<=v<=8 for v in row)and row[-1]==8,'INPUT_RANGE')
        dot=lambda weights:sum(a*b for a,b in zip(row,weights))
        # max's first tied element is the declared lowest class/expert index.
        expert=max(range(3),key=lambda i:dot(model['router'][i]))
        logits=[dot(model['base'][i])+dot(model['deltas'][expert][i])for i in range(3)]
        output.append(max(range(3),key=lambda i:logits[i]))
    return output
