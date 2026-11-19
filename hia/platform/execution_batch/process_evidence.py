"""Decode complete actual method pipes, without granting execution authority."""
from __future__ import annotations
import re,struct
from pathlib import Path
from . import safe_io as safe
from . import batch_observations as batch
from . import prefix_observations as prefix
from .prefix_native_io import parse as parse_prefix
from .build_evidence import check_identity
from .source_graph import need,identity
STREAMS=('stdin','stdout','stderr','progress','replies')
def uint(value):return type(value) is int and 0<=value<(1<<64)
def process_common(row,executable):
    check_identity(row['executable']);need(safe.same(row['executable'],executable),'Actual process uses compiled ELF')
    need(type(row['pid']) is int and row['pid']>0 and type(row['elapsed_ns']) is int and row['elapsed_ns']>0,'Actual process identity/interval')
    need(type(row['exit_code']) is int and row['exit_code']==0,'Actual integer process exit')
    need(type(row['wall_limit_seconds']) is int and row['wall_limit_seconds']==240 and type(row['cleanup_limit_seconds']) is int and row['cleanup_limit_seconds']==3,'Original process and cleanup budgets')
    need(row['status']=='PASS' and row['cleanup_errors']==[],'Complete process lifetime')
def streams(directory,row):
    need(isinstance(row['streams'],dict) and set(row['streams'])==set(STREAMS),'Exact full stream roster')
    result={}
    for name in STREAMS:
        check_identity(row['streams'][name]);result[name]=safe.read(directory,name+'.raw')
        need(safe.same(identity(result[name]),row['streams'][name]),'Actual raw stream identity '+name)
    need(not result['stderr'],'Normal method process emitted diagnostics')
    return result
def prefix_transport(directory,executable,*,schema,allowed,parser,maximum):
    directory=Path(directory);r=safe.load(directory,'report.json')
    need(set(r)=={'schema','status','failure','cleanup_errors','pid','exit_code','elapsed_ns','wall_limit_seconds','cleanup_limit_seconds','executable','commands','streams','events'} and r['schema']==schema,'Exact retained-owner process receipt')
    process_common(r,executable);need(r['failure'] is None,'No unreported retained-owner failure')
    need(isinstance(r['commands'],list) and 0<len(r['commands'])<=maximum,'Full actual method roster')
    files={'report.json',*(name+'.raw' for name in STREAMS),*('command-%04d.json'%(index+1) for index in range(len(r['commands'])))}
    need(safe.roster(directory)==files,'Exact regular retained-owner artifact roster')
    raw=streams(directory,r);cursor={name:0 for name in STREAMS};all_events=[];last_time=0;elapsed_sum=0;frames=[]
    for index,command in enumerate(r['commands']):
        seq=index+1
        need(isinstance(command,dict) and set(command)=={'sequence','opcode','result','events','elapsed_ns','input','output','stream_ranges'},'Exact complete method receipt')
        need(safe.same(safe.load(directory,'command-%04d.json'%seq),command),'Actual individual method receipt differs')
        need(type(command['sequence']) is int and command['sequence']==seq and type(command['opcode']) is int and command['opcode'] in allowed,'Original method identity')
        start=cursor['stdin'];need(start+8<=len(raw['stdin']),'Actual input frame length')
        size=struct.unpack_from('<Q',raw['stdin'],start)[0];end=start+8+size;need(end<=len(raw['stdin']),'Actual complete input extent')
        frame=raw['stdin'][start+8:end];frames.append(frame)
        check_identity(command['input']);need(safe.same(command['input'],identity(raw['stdin'][start:end])),'Actual complete method input identity')
        begin=cursor['stdout'];need(begin+256<=len(raw['stdout']),'Actual response header')
        words=struct.unpack_from('<32Q',raw['stdout'],begin);out_end=begin+256+words[18]+words[16]+words[17]+words[15]
        need(out_end<=len(raw['stdout']),'Actual complete response extent')
        output=raw['stdout'][begin:out_end];check_identity(command['output'])
        need(safe.same(command['output'],identity(output)) and safe.same(command['result'],parser(output,seq,command['opcode'])),'Complete typed response differs from raw')
        next_cursor={**cursor,'stdin':end,'stdout':out_end}
        need(type(command['elapsed_ns']) is int and command['elapsed_ns']>0 and isinstance(command['events'],list),'Actual method interval/events')
        elapsed_sum+=command['elapsed_ns']
        for event_index,event in enumerate(command['events'],1):
            need(isinstance(event,dict) and set(event)=={'sequence','kind','index','height','observed_monotonic_ns','raw_hex','reply_hex','replied_monotonic_ns'},'Exact actual callback observation')
            progress=raw['progress'][next_cursor['progress']:next_cursor['progress']+64]
            reply=raw['replies'][next_cursor['replies']:next_cursor['replies']+48]
            need(len(progress)==64 and len(reply)==48 and event['raw_hex']==progress.hex() and event['reply_hex']==reply.hex(),'Actual callback/reply bytes')
            need(all(uint(event[key]) for key in ('sequence','kind','index','height','observed_monotonic_ns','replied_monotonic_ns')),'Typed callback fields')
            need(last_time<=event['observed_monotonic_ns']<=event['replied_monotonic_ns'],'Actual observation/reply order');last_time=event['replied_monotonic_ns']
            p=struct.unpack('<8Q',progress);ack=struct.unpack('<6Q',reply)
            need(progress[:8]==b'PXPROG01' and p[1:4]==(seq,0,event_index) and p[4] in (1,2,10,11,12,13,14,15,16,17) and p[7]==0,'Actual callback private method/identity')
            need(reply[:8]==b'PXGO0001' and ack[1:4]==(seq,0,event_index) and ack[4] in (0,1,2),'Actual reply identity/classification')
            need(safe.same([event[key] for key in ('sequence','kind','index','height')],list(p[3:7])),'All actual callback fields')
            next_cursor['progress']+=64;next_cursor['replies']+=48;all_events.append(event)
        need(safe.same(command['stream_ranges'],{name:[cursor[name],next_cursor[name]] for name in STREAMS}),'Typed complete contiguous stream ranges')
        cursor=next_cursor
    need(safe.same(cursor,{name:len(value) for name,value in raw.items()}) and safe.same(r['events'],all_events),'Complete pipe/event consumption')
    need(elapsed_sum<=r['elapsed_ns'],'Sequential methods fit actual process interval')
    return r,raw,frames
def prefix_process(directory,case,executable):
    r,raw,frames=prefix_transport(directory,executable,schema='trnm.transaction-prefix-native-process.v1',
        allowed=(1,2,3,4),parser=parse_prefix,maximum=len(case['commands']))
    decoded=prefix.decode_process(directory,case)
    need(len(decoded['commands'])==len(r['commands']),'No omitted decoded method')
    return decoded,{'name':case['name'],'commands':len(r['commands']),'progress_records':len(r['events']),'process':identity(safe.read(directory,'report.json')),'elapsed_ns':r['elapsed_ns'],'skipped':decoded['skipped']}
def batch_process(directory,case,executable):
    directory=Path(directory);r=safe.load(directory,'report.json')
    need(set(r)=={'status','pid','exit_code','elapsed_ns','wall_limit_seconds','cleanup_limit_seconds','input','streams','executable','events','barrier_kernel_tasks','result','primary_error','cleanup_errors'},'Exact complete block process receipt')
    process_common(r,executable);need(r['primary_error'] is None,'No unreported batch failure')
    need(safe.roster(directory)=={'report.json','intended-input.raw',*(name+'.raw' for name in STREAMS)},'Exact regular batch artifact roster')
    raw=streams(directory,r);need(safe.read(directory,'intended-input.raw')==raw['stdin'],'Actual complete write equals intended frame')
    check_identity(r['input']);need(safe.same(r['input'],identity(raw['stdin'])),'Actual complete batch input identity')
    actual,decoded=batch.decode_process(directory,case['name']);need(safe.same(actual,case),'Source-defined complete block request differs')
    need(safe.same(r['result'],decoded['result']),'Typed actual complete block response')
    need(len(raw['progress'])%64==0 and len(raw['replies'])%48==0 and isinstance(r['events'],list) and len(r['events'])==len(raw['progress'])//64,'Complete actual callback roster')
    replies={};sequence=struct.unpack_from('<Q',raw['stdin'],40)[0]
    for at in range(0,len(raw['replies']),48):
        reply=raw['replies'][at:at+48];words=struct.unpack('<6Q',reply);key=(words[2],words[3])
        need(key not in replies,'Repeated callback reply');replies[key]=reply
    count=min(case['workers'],len(case['transactions'])) if case['workers'] in (1,2,4,8) else 0
    for index,event in enumerate(r['events']):
        need(isinstance(event,dict) and set(event)=={'worker','sequence','kind','index','raw_hex','reply_hex'},'Exact block callback record')
        need(all(uint(event[name]) for name in ('worker','sequence','kind','index')),'Typed block callback fields')
        progress=raw['progress'][index*64:index*64+64];words=struct.unpack('<8Q',progress)
        need(event['raw_hex']==progress.hex() and safe.same([event[name] for name in ('worker','sequence','kind','index')],list(words[2:6])),'All block callback bytes/fields')
        need((words[2],words[3]) in replies and event['reply_hex']==replies[(words[2],words[3])].hex(),'Actual block callback reply bytes')
        if words[2]==8:need(words[4] in range(10,18),'Actual canonical callback kind')
        else:need(count>0 and words[2]<count and words[4] in (1,2) and words[5]%count==words[2],'Actual worker stride/kind')
    tasks=r['barrier_kernel_tasks'];need(isinstance(tasks,list),'Actual kernel task observation')
    if case['barrier']:
        need(count>0 and len(tasks)==(count+1 if count>1 else 1),'Actual kernel thread count at complete barrier')
        tids=set()
        for task in tasks:
            need(isinstance(task,dict) and set(task)=={'tid','stat','status','wchan'} and type(task['tid']) is int and task['tid']>0 and task['tid'] not in tids,'Actual distinct task identity')
            tids.add(task['tid']);need(all(isinstance(task[key],str) for key in ('stat','status','wchan')),'Actual task raw observations')
            need(task['stat'].startswith(str(task['tid'])+' ('),'Actual task stat identity')
            need(re.search(r'^Pid:\s*'+str(task['tid'])+r'\s*$',task['status'],re.M) is not None and re.search(r'^Tgid:\s*'+str(r['pid'])+r'\s*$',task['status'],re.M) is not None,'Actual process task lineage')
        need(r['pid'] in tids,'Actual native parent observed at barrier')
    else:need(tasks==[],'Unexpected barrier task assertions')
    return decoded,{'name':case['name'],'commands':1,'progress_records':len(r['events']),'process':identity(safe.read(directory,'report.json')),'elapsed_ns':r['elapsed_ns'],'skipped':[]}
