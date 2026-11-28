"""Replay every physical process receipt and complete raw file/pipe observation."""
from __future__ import annotations
import os,re,stat,struct
from pathlib import Path
from hia.platform.execution_state.cases import map_bytes
from . import safe_io as safe
from .source_graph import REPOSITORY,need,identity,bound_corpus,check_sources
from .build_evidence import validate_build,check_identity
from .bundle import identities
PREFIX_NAMES=('stdin-regular','stdout-regular','stderr-regular','stdout-stderr-alias',
 'stdin-nonblocking','stdout-nonblocking','stderr-nonblocking','gate-write-regular','gate-read-regular',
 'gate-write-wrong-mode','gate-read-wrong-mode','gate-same-pipe','gate-write-stdout-dup','gate-read-stdin-dup',
 'gate-write-nonblocking','gate-read-nonblocking','one-disabled-gate','other-disabled-gate','gate-outside-int',
 'bad-magic','short-header','bad-timestamp-flag','absent-timestamp-nonzero','bad-reserved-context','bad-state-value',
 'header-eof','body-eof','native-mmap-enomem','native-mremap-enomem')
PREFIX_PLANS=tuple((name,64 if i<16 else 78 if i<25 else 70 if i<27 else 79) for i,name in enumerate(PREFIX_NAMES))
U64=(1<<64)-1
def uint(value):return type(value) is int and value>=0
def cap_checks(caps,name):
    need(isinstance(caps,dict) and set(caps)=={'0','1','2','GW','GR'},'Complete actual descriptor observations')
    for key,entry in caps.items():
        unusable=(key=='GW' and name in ('one-disabled-gate','gate-outside-int')) or (key=='GR' and name=='other-disabled-gate') or (key in ('GW','GR') and name.startswith('native-'))
        if unusable:
            wanted=(1<<31) if name=='gate-outside-int' else U64
            need(safe.same(entry,{'unusable_number':wanted}),'Actual refused descriptor number');continue
        need(isinstance(entry,dict) and set(entry)=={'dev','ino','mode','access_flags'} and all(uint(v) for v in entry.values()),'Typed complete fstat/fcntl observation')
        regular=(name=='stdin-regular' and key=='0') or (name=='stdout-regular' and key=='1') or (name=='stderr-regular' and key=='2') or (name=='gate-write-regular' and key=='GW') or (name=='gate-read-regular' and key=='GR')
        need(stat.S_IFMT(entry['mode'])==(stat.S_IFREG if regular else stat.S_IFIFO),'Actual admitted/refused descriptor type')
        access=2 if regular else 0 if key in ('0','GR') else 1
        if name=='gate-write-wrong-mode' and key=='GW':access=0
        if name=='gate-read-wrong-mode' and key=='GR':access=1
        need(entry['access_flags']&os.O_ACCMODE==access and not entry['access_flags']&getattr(os,'O_PATH',0o10000000),'Actual descriptor access class')
        nonblocking=(key,name) in (('0','stdin-nonblocking'),('1','stdout-nonblocking'),('2','stderr-nonblocking'),('GW','gate-write-nonblocking'),('GR','gate-read-nonblocking'))
        need(bool(entry['access_flags']&os.O_NONBLOCK)==nonblocking,'Actual selected blocking-mode control')
    def same_object(a,b):return (caps[a]['dev'],caps[a]['ino'])==(caps[b]['dev'],caps[b]['ino'])
    for a,b,control in [('1','2','stdout-stderr-alias'),('GW','GR','gate-same-pipe'),('GW','1','gate-write-stdout-dup'),('GR','0','gate-read-stdin-dup')]:
        if all('unusable_number' not in caps[k] for k in (a,b)):
            need(same_object(a,b)==(name==control),'Actual selected descriptor alias')
def intended(name,raw,caps):
    state=map_bytes({'model:current':'0'*64,'meta:issued':0})
    if name=='short-header':need(raw==struct.pack('<Q',143),'Actual short body declaration');return
    if name=='header-eof':need(raw==bytes(7),'Actual truncated length word');return
    if name=='body-eof':need(raw==struct.pack('<Q',144),'Actual body EOF');return
    need(len(raw)>=152,'Actual malformed method complete frame')
    gw,gr=struct.unpack_from('<2Q',raw,56)
    for key,fd in (('GW',gw),('GR',gr)):
        if 'unusable_number' in caps[key]:need(fd==caps[key]['unusable_number'],'Actual unusable method descriptor')
        else:need(3<=fd<=2147483647,'Actual diagnostic descriptor number')
    body=bytearray(b'PFXREQ01'+struct.pack('<7Q',1,1,10,0,0,gw,gr)+bytes([1])*32+bytes([2])*32+struct.pack('<2Q',len(state),0)+state)
    if name=='bad-magic':body[0]^=1
    if name=='bad-timestamp-flag':struct.pack_into('<Q',body,32,2)
    if name=='absent-timestamp-nonzero':struct.pack_into('<Q',body,40,1)
    if name=='bad-reserved-context':struct.pack_into('<Q',body,136,1)
    if name=='bad-state-value':body[-1]=255
    need(raw==struct.pack('<Q',len(body))+body,'Exact source-defined physical method input')
def prefix_control(directory,name,wanted,executable):
    r=safe.load(directory,'report.json')
    fields={'name','status','expected_exit','actual_exit','caps_before','files_before','files_after','cleanup_errors','elapsed_ns','streams','intended_input','argv','pid','wall_limit_seconds','cleanup_limit_seconds'}
    need(isinstance(r,dict) and set(r)==fields and r['name']==name and r['status']=='PASS','Complete physical process receipt')
    need(type(r['expected_exit']) is int and type(r['actual_exit']) is int and r['expected_exit']==r['actual_exit']==wanted,'Actual selected process refusal')
    need(type(r['pid']) is int and r['pid']>0 and type(r['elapsed_ns']) is int and r['elapsed_ns']>0,'Actual physical process identity/interval')
    need(type(r['wall_limit_seconds']) is int and r['wall_limit_seconds']==240 and type(r['cleanup_limit_seconds']) is int and r['cleanup_limit_seconds']==3 and r['cleanup_errors']==[],'Physical process budget and cleanup')
    need(isinstance(r['streams'],dict) and set(r['streams'])=={'stdin','stdout','stderr','progress'},'Full physical stream roster')
    streams={}
    for key,row in r['streams'].items():
        check_identity(row);streams[key]=safe.read(directory,key+'.raw');need(safe.same(identity(streams[key]),row),'Actual physical raw stream identity')
    need(not streams['stdout'] and not streams['stderr'] and not streams['progress'],'Refused process publishes no observation or progress')
    raw=safe.read(directory,'intended-input.raw');check_identity(r['intended_input']);need(safe.same(identity(raw),r['intended_input']),'Actual intended input bytes')
    cap_checks(r['caps_before'],name);intended(name,raw,r['caps_before'])
    if name=='stdin-regular':need(not streams['stdin'],'Regular input is not a pipe write')
    else:need(raw.startswith(streams['stdin']),'Actual partial pipe write is an exact prefix')
    files={'report.json','intended-input.raw','stdin.raw','stdout.raw','stderr.raw','progress.raw'}
    fixtures={'stdio.fixture'} if name in ('stdin-regular','stdout-regular','stderr-regular') else {'gate.fixture'} if name in ('gate-write-regular','gate-read-regular') else set()
    need(isinstance(r['files_before'],dict) and isinstance(r['files_after'],dict) and safe.same(r['files_before'],r['files_after']),'Failed descriptor admission left every passed file unchanged')
    need(len(r['files_before'])==len(fixtures),'Complete regular fixture roster')
    actual_names=set()
    for path,row in r['files_before'].items():
        p=Path(path);need(p.is_absolute() and p.parent.name==name and p.name in fixtures and p.name not in actual_names,'Actual fixture namespace')
        actual_names.add(p.name);check_identity(row)
        before=safe.read(directory,'sentinels-before/'+p.name);after=safe.read(directory,p.name)
        need(before==after and safe.same(identity(after),row),'Complete sentinel bytes are unchanged')
        need(before==(raw if name=='stdin-regular' else b'unchanged-native-capability-sentinel'),'Source-defined exact passed-file sentinel')
        files.update((p.name,'sentinels-before/'+p.name))
    argv=r['argv'];need(isinstance(argv,list) and argv and all(isinstance(v,str) for v in argv),'Actual physical argv')
    sealed=argv[-1];need(re.fullmatch(r'/proc/self/fd/[0-9]+',sealed) is not None and int(sealed.rsplit('/',1)[1])>=3,'Actual sealed native process image')
    if name.startswith('native-'):
        syscall='mmap' if name=='native-mmap-enomem' else 'mremap'
        need(len(argv)==10 and Path(argv[0]).is_absolute() and Path(argv[0]).name=='strace','Actual syscall observer executable')
        need(argv[1:3]==['-qq','-o'] and Path(argv[3]).parent.name==name and Path(argv[3]).name=='syscalls.raw','Actual raw syscall capture path')
        need(argv[4:9]==['-e','trace=mmap,mremap,exit_group','-e','inject='+syscall+':error=ENOMEM:when=1','--'],'Exact selected real kernel refusal')
        trace=safe.read(directory,'syscalls.raw').decode();matches=[line for line in trace.splitlines() if re.search(r'\b'+syscall+r'\(.*\)\s+= -1 ENOMEM.*\(INJECTED\)',line)]
        need(len(matches)==1 and 'exit_group(79)' in trace,'Actual injected syscall failure and terminal')
        files.add('syscalls.raw')
    else:need(argv==[sealed],'No hosted runtime process or extra native argv')
    need(safe.roster(directory)==files,'Complete physical artifacts including exact special-free fixtures')
    return r
def wrong_ack(directory,case,executable):
    r=safe.load(directory,'report.json')
    fields={'status','pid','exit_code','elapsed_ns','wall_limit_seconds','cleanup_limit_seconds','input','streams','executable','events','barrier_kernel_tasks','result','primary_error','cleanup_errors'}
    need(set(r)==fields and r['status']=='PASS' and r['primary_error'] is None and r['cleanup_errors']==[] and r['result'] is None and r['barrier_kernel_tasks']==[],'Complete actual worker-protocol refusal')
    need(type(r['exit_code']) is int and r['exit_code']==78 and type(r['pid']) is int and r['pid']>0 and type(r['elapsed_ns']) is int and r['elapsed_ns']>0,'Actual native protocol terminal')
    need(type(r['wall_limit_seconds']) is int and r['wall_limit_seconds']==240 and type(r['cleanup_limit_seconds']) is int and r['cleanup_limit_seconds']==3,'Actual worker-control budgets')
    need(safe.same(r['executable'],executable),'Actual whole-block image identity')
    names={'stdin','stdout','stderr','progress','replies'};need(set(r['streams'])==names,'Complete worker pipe roster')
    streams={}
    for name,row in r['streams'].items():
        check_identity(row);streams[name]=safe.read(directory,name+'.raw');need(safe.same(identity(streams[name]),row),'Actual worker raw pipe identity')
    raw=safe.read(directory,'intended-input.raw');need(raw==streams['stdin'] and len(raw)>=136 and safe.same(r['input'],identity(raw)),'Actual complete malformed-ACK workload')
    frame=raw[8:];need(struct.unpack_from('<Q',raw)[0]==len(frame) and frame[:8]==b'BPEXEC01','Actual worker workload frame')
    height,workers,count,sequence,gw,gr,sn=struct.unpack_from('<7Q',frame,8)
    state=bytes.fromhex(case['state_hex']);tx=[bytes.fromhex(value) for value in case['transactions']]
    need((height,workers,count,sequence,sn)==(case['height'],case['workers'],len(tx),91,len(state)) and 3<=gw<=2147483647 and 3<=gr<=2147483647 and gw!=gr,'Actual original worker context')
    expected=b'BPEXEC01'+struct.pack('<7Q',height,workers,count,sequence,gw,gr,sn)+bytes.fromhex(case['miner_hex'])+bytes.fromhex(case['parent_id_hex'])+state+b''.join(struct.pack('<Q',len(value))+value for value in tx)
    need(frame==expected and not streams['stdout'] and not streams['stderr'],'Complete source-defined workload and no successor/diagnostic')
    need(isinstance(r['events'],list) and len(streams['progress'])==64*len(r['events']) and len(streams['replies'])==48*len(r['events']),'All actual worker protocol observations')
    replies={};seen={};changed=0
    for at in range(0,len(streams['replies']),48):
        raw_reply=streams['replies'][at:at+48];ack=struct.unpack('<6Q',raw_reply)
        need(raw_reply[:8]==b'BPGO0001' and ack[1]==sequence and ack[4:6]==(0,0),'Actual source-defined refused ACK')
        key=(ack[2],ack[3]);need(key not in replies,'No repeated actual reply');replies[key]=raw_reply
    for index,event in enumerate(r['events']):
        need(set(event)=={'worker','sequence','kind','index','raw_hex','reply_hex'} and all(uint(event[name]) for name in ('worker','sequence','kind','index')),'Typed actual worker callback metadata')
        progress=streams['progress'][64*index:64*index+64];p=struct.unpack('<8Q',progress)
        need(progress[:8]==b'BPPROG01' and p[1]==sequence and p[6:8]==(height,0) and event['raw_hex']==progress.hex(),'Actual raw worker callback')
        need(safe.same([event[k] for k in ('worker','sequence','kind','index')],list(p[2:6])) and p[3]==seen.get(p[2],0)+1,'Exact per-worker callback fields/order')
        seen[p[2]]=p[3];delta=1 if p[2]==0 else 0;key=(p[2],p[3]+delta)
        need(key in replies and event['reply_hex']==replies.pop(key).hex(),'Actual wrong worker sequence supplied')
        changed+=delta
    need(not replies and changed>=1,'At least one actual wrong ACK and no omitted replies')
    need(safe.roster(directory)=={'report.json','intended-input.raw',*(name+'.raw' for name in names)},'Complete refused worker artifacts')
    return {'name':'batch-wrong-worker-ack','status':'PASS','expected_exit':78,'actual_exit':78,'process':identity(safe.read(directory,'report.json'))}
def validate_physical(repository,output):
    output=Path(output);before=identities(output);r=safe.load(output,'report.json')
    fields={'schema','status','builds','controls','planned','failure','source_after','elapsed_ns','actual_trace_required','runtime_host_proxy','persistent_commit','original_rust_executed'}
    need(set(r)==fields and r['schema']=='trnm.execution-batch-physical.v1' and r['status']=='PASS','Complete physical qualification report')
    need(r['failure'] is None and safe.same(r['source_after'],{'status':'PASS','errors':[]}) and r['actual_trace_required'] is True and r['runtime_host_proxy'] is False and r['persistent_commit'] is False and r['original_rust_executed'] is False,'Actual physical scope/source closure')
    need(type(r['planned']) is int and r['planned']==30 and isinstance(r['controls'],list) and len(r['controls'])==30,'Every physical control is present')
    need(type(r['elapsed_ns']) is int and r['elapsed_ns']>0 and set(r['builds'])=={'prefix','batch'},'Actual physical build/time roster')
    builds={};files={'report.json'}
    for profile in ('prefix','batch'):
        build,elf,roster=validate_build(output/('native-'+profile),profile,repository)
        need(safe.same(r['builds'][profile],build),'Physical actual source/ELF lineage')
        builds[profile]=build;files.update('native-'+profile+'/'+name for name in roster)
    need(safe.same(builds['prefix']['source_inputs'],builds['batch']['source_inputs']) and safe.same(builds['prefix']['original_sources'],builds['batch']['original_sources']),'One complete physical source closure')
    controls=[];elapsed=0
    for name,wanted in PREFIX_PLANS:
        directory=output/'prefix'/name;controls.append(prefix_control(directory,name,wanted,builds['prefix']['executable']))
        files.update('prefix/'+name+'/'+path for path in safe.roster(directory));elapsed+=controls[-1]['elapsed_ns']
    _,cases=bound_corpus(repository,'batch');matches=[case for case in cases if case['name']=='cancel-all-joins-before-first-handle-error'];need(len(matches)==1,'Actual source-bound worker control fixture')
    directory=output/'batch-wrong-worker-ack';controls.append(wrong_ack(directory,matches[0],builds['batch']['executable']))
    files.update('batch-wrong-worker-ack/'+name for name in safe.roster(directory));elapsed+=safe.load(directory,'report.json')['elapsed_ns']
    need(safe.same(r['controls'],controls) and elapsed<=r['elapsed_ns'],'All controls are derived from complete actual artifacts')
    need(set(before)==files and identities(output)==before,'Complete unchanged physical regular evidence')
    check_sources(builds['prefix']['source_inputs'],builds['prefix']['original_sources'],repository)
    return r
