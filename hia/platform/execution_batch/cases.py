"""Strict source fixture shapes and fixed, exhaustive qualification partitions."""
from __future__ import annotations
import re
U64=(1<<64)-1
PREFIX_PARTS=4
def need(c,m):
    if not c:raise ValueError(m)
def uint(value):return type(value) is int and 0<=value<=U64
def hex_bytes(value,size=None):
    need(isinstance(value,str) and len(value)%2==0 and re.fullmatch(r'[0-9a-f]*',value) is not None,'Canonical fixture byte string')
    need(size is None or len(value)==size*2,'Fixture byte extent')
def actions(rows,worker=False):
    need(isinstance(rows,list),'Fixture action list');seen=set()
    for row in rows:
        fields={'sequence','class','token'}|({'worker'} if worker else set())
        need(isinstance(row,dict) and set(row)==fields,'Exact action fields')
        need(uint(row['sequence']) and row['sequence']>0 and type(row['class']) is int and row['class'] in (1,2) and uint(row['token']),'Typed action fields')
        if worker:need(uint(row['worker']) and row['worker']<=8,'Original worker/main index')
        key=(row.get('worker',0),row['sequence']);need(key not in seen,'Repeated observer action');seen.add(key)
def validate(rows,profile):
    need(profile in ('batch','prefix') and isinstance(rows,list),'Known complete corpus')
    need(len(rows)==(102 if profile=='batch' else 186),'Complete original history roster')
    names=set()
    for row in rows:
        need(isinstance(row,dict) and isinstance(row.get('name'),str) and row['name'] and row['name'] not in names,'Unique concrete history name');names.add(row['name'])
        if profile=='batch':
            need(set(row)=={'schema','name','state_hex','transactions','height','workers','miner_hex','parent_id_hex','actions','barrier'} and row['schema']=='trnm.execution-batch-original-input.v1','Exact complete block fixture fields')
            hex_bytes(row['state_hex']);hex_bytes(row['miner_hex'],32);hex_bytes(row['parent_id_hex'],32)
            need(uint(row['height']) and uint(row['workers']) and type(row['barrier']) is bool,'Typed block context')
            need(isinstance(row['transactions'],list),'Actual wire list')
            for wire in row['transactions']:hex_bytes(wire)
            actions(row['actions'],True)
        else:
            need(set(row)=={'schema','name','commands','properties'} and row['schema']=='trnm.transaction-prefix-history.v1','Exact Prefix history fields')
            need(isinstance(row['properties'],list) and all(isinstance(v,str) for v in row['properties']),'Fixture descriptive properties')
            need(isinstance(row['commands'],list) and row['commands'] and row['commands'][0].get('op')==1 and row['commands'][-1].get('op')==4,'Complete retained owner lifecycle')
            for command in row['commands']:
                need(isinstance(command,dict) and type(command.get('op')) is int and command['op'] in (1,2,3,4),'Original method fixture')
                op=command['op'];allowed={'op','requires_ready'}
                if op==1:allowed|={'state_hex','height','timestamp','miner_hex','parent_id_hex','actions'}
                if op==2:allowed|={'transactions','actions'}
                need(set(command)<=allowed,'Unknown fixture method fields')
                if 'requires_ready' in command:need(type(command['requires_ready']) is bool,'Typed ready fixture')
                if op==1:
                    need({'state_hex','height','timestamp','miner_hex','parent_id_hex','actions'}<=set(command),'Complete internal context fixture')
                    need(uint(command['height']) and (command['timestamp'] is None or uint(command['timestamp'])),'Original optional u64 timestamp')
                    hex_bytes(command['state_hex']);hex_bytes(command['miner_hex'],32);hex_bytes(command['parent_id_hex'],32)
                if op==2:
                    need('transactions' in command and isinstance(command['transactions'],list),'Complete raw Prefix list')
                    for wire in command['transactions']:hex_bytes(wire)
                actions(command.get('actions',[]))
    return rows
def selection(profile,part):
    need(type(part) is int,'Typed qualification partition')
    if profile=='batch':
        need(part==0,'Batch has one exhaustive semantic partition');return list(range(102))
    need(profile=='prefix' and 0<=part<PREFIX_PARTS,'One fixed exhaustive Prefix partition')
    return list(range(part,186,PREFIX_PARTS))
