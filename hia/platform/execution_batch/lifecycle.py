"""Actual scoped Prefix clone, journal rollback and drop over one native heap."""
from __future__ import annotations
import argparse,json,struct,time,traceback
from pathlib import Path
from . import safe_io as safe
from .source_graph import REPOSITORY,complete_sources,original_manifest,check_sources,bound_corpus,canonical,identity,need
from .build import Build
from .build_evidence import validate_build
from .process_evidence import prefix_transport
from .scoped_native_io import Session,parse
from .bundle import identities
NAMES=('success-multiple-private-scopes','constructor-cancel-panic-base-survival',
 'append-error-cancel-panic-journal-survival','application-indexmut-panic-scoped-drop',
 'constructor-error-whole-input-count-before-state','constructor-error-whole-input-reward-credit-overflow')
SCHEMA='trnm.execution-batch-scoped-lifecycle.v1'
def plans(repository=REPOSITORY):
    _,rows=bound_corpus(repository,'prefix');by_name={row['name']:row for row in rows}
    first=by_name['append-repeat-error-retry-binding'];base=first['commands'][0]['state_hex']
    good=first['commands'][9]['transactions'];bad=first['commands'][4]['transactions']
    need(len(good)==3 and len(bad)==2,'Exact retained signed lifecycle fixtures')
    result=[]
    def case(name,state):
        steps=[];result.append({'name':name,'base_hex':state,'steps':steps});return steps
    def add(steps,label,opcode,*,outcome=1,ready=None,args=None,checks=None):
        steps.append({'label':label,'opcode':opcode,'outcome':outcome,'ready':ready,'args':args or {},'checks':checks or {}})
    def base_at(s,label,*,count=None,baseline=None):
        checks={'base':True}
        if count is not None:checks['objects']=count
        if baseline is not None:checks['baseline']=baseline
        add(s,label,6,checks=checks)
    def close(s):add(s,'close-root',7,ready=0,checks={'zero_heap':True})
    def action(kind,classification,index=None):
        return {'kind':kind,'class':classification,'index':index,'token':900000+kind*10+classification}
    s=case(NAMES[0],base)
    add(s,'new',1,ready=1,args={'state_hex':base});base_at(s,'base-with-scope',count=2)
    add(s,'append-one',2,ready=1,args={'transactions':good[:1]});base_at(s,'base-after-append')
    add(s,'drop-first',4,ready=0);base_at(s,'baseline',count=1)
    add(s,'drop-again',4,ready=0);base_at(s,'base-after-double-drop',baseline='baseline')
    add(s,'new-again',5,ready=1)
    add(s,'empty-again',2,ready=1,checks={'header':{'8':0,'11':0}})
    base_at(s,'base-after-new')
    add(s,'drop-final',4,ready=0);base_at(s,'base-final',baseline='baseline');close(s)
    s=case(NAMES[1],base)
    add(s,'cancel-new',1,outcome=3,ready=0,args={'state_hex':base,'action':action(10,1)})
    base_at(s,'baseline',count=1);add(s,'drop-cancel',4,ready=0);base_at(s,'base-after-cancel',baseline='baseline')
    add(s,'panic-new',5,outcome=4,ready=0,args={'action':action(11,2)})
    base_at(s,'base-after-panic',baseline='baseline');add(s,'drop-panic',4,ready=0)
    base_at(s,'base-after-panic-drop',baseline='baseline')
    add(s,'new-success',5,ready=1);add(s,'drop-success',4,ready=0)
    base_at(s,'base-final',baseline='baseline');close(s)
    s=case(NAMES[2],base)
    add(s,'new',1,ready=1,args={'state_hex':base})
    add(s,'accepted-one',2,ready=1,args={'transactions':good[:1]})
    add(s,'bad-suffix',2,outcome=2,ready=1,args={'transactions':bad},checks={'restore':'accepted-one'})
    base_at(s,'base-after-error')
    for index,(kind,classification) in enumerate(((13,1),(16,2),(17,1))):
        add(s,'interrupted-'+str(index),2,outcome=3 if classification==1 else 4,ready=1,
            args={'transactions':good[:2],'action':action(kind,classification,1 if kind==13 else None)},checks={'restore':'accepted-one'})
        base_at(s,'base-after-interruption-'+str(index))
    add(s,'retry',2,ready=1,args={'transactions':good[:2]},checks={'header':{'8':2,'11':1}})
    base_at(s,'base-after-retry');add(s,'drop',4,ready=0);base_at(s,'baseline',count=1)
    add(s,'new-again',5,ready=1);base_at(s,'base-with-second-scope')
    add(s,'drop-again',4,ready=0);base_at(s,'base-final',baseline='baseline');close(s)
    item=by_name['application-write-domain-evaluate-votes-2'];initial=item['commands'][0]
    s=case(NAMES[3],initial['state_hex'])
    add(s,'new',1,ready=1,args={'state_hex':initial['state_hex'],'height':initial['height']})
    add(s,'before-panic',3,ready=1)
    add(s,'actual-indexmut-panic',2,outcome=4,ready=1,args={'transactions':item['commands'][1]['transactions']},checks={'restore':'before-panic'})
    base_at(s,'base-after-panic');add(s,'drop-panic',4,ready=0);base_at(s,'baseline',count=1)
    add(s,'new-again',5,ready=1,args={'height':initial['height']});add(s,'drop-again',4,ready=0)
    base_at(s,'base-final',baseline='baseline');close(s)
    for name in ('whole-input-count-before-state','whole-input-reward-credit-overflow'):
        initial=by_name[name]['commands'][0];s=case('constructor-error-'+name,initial['state_hex'])
        add(s,'new-refusal',1,outcome=2,ready=0,args={'state_hex':initial['state_hex'],'height':initial['height']})
        base_at(s,'baseline',count=1);add(s,'drop-refusal',4,ready=0)
        add(s,'new-refusal-again',5,outcome=2,ready=0,args={'height':initial['height']})
        base_at(s,'base-after-repeat',baseline='baseline')
        add(s,'drop-final',4,ready=0);close(s)
    need(tuple(row['name'] for row in result)==NAMES,'Complete lifecycle roster')
    for case_row in result:
        labels=[step['label'] for step in case_row['steps']]
        need(len(labels)==len(set(labels)),'Unique lifecycle method labels')
    return result
def response_checks(plan,observed):
    need(len(observed)==len(plan['steps']),'Every scoped method executed')
    previous={};base_reads=0
    for step,row in zip(plan['steps'],observed,strict=True):
        h=row['header'];need(type(h[3]) is int and h[3]==step['outcome'],'Actual scoped result class: '+step['label'])
        if step['ready'] is not None:need(type(h[25]) is int and h[25]==step['ready'],'Actual scoped readiness')
        check=step['checks']
        if check.get('base'):
            need(row['held_state_hex']==plan['base_hex'] and type(h[27]) is int and h[27]==1,'Whole owner base remains identical and genuinely held')
            base_reads+=1
        if 'objects' in check:need(type(h[28]) is int and h[28]==check['objects'],'Exact real live State object count')
        if 'baseline' in check:need(safe.same(h[28:30],previous[check['baseline']]['header'][28:30]),'Scope returns all allocator/State objects')
        if 'restore' in check:
            old=previous[check['restore']]
            need(safe.same([row['held_state_hex'],row['receipts'],h[8:10]],[old['held_state_hex'],old['receipts'],old['header'][8:10]]),'Error/panic/cancel restores exact private State, receipt vector and fees')
        if check.get('zero_heap'):need(safe.same(h[27:30],[0,0,0]),'Root close retires all real State objects and allocations')
        for index,value in check.get('header',{}).items():need(type(h[int(index)]) is int and h[int(index)]==value,'Exact lifecycle header counter')
        previous[step['label']]=row
    return base_reads
def callback(step,event):
    action=step['args'].get('action')
    if action and event['kind']==action['kind'] and (action['index'] is None or event['index']==action['index']):
        return action['class'],action['token'],0
    return 0,0,0
def validate_process(directory,plan,executable):
    r,raw,frames=prefix_transport(directory,executable,schema='trnm.scoped-prefix-bridge-native-process.v1',
        allowed=(1,2,3,4,5,6,7),parser=parse,maximum=len(plan['steps']))
    need(len(frames)==len(plan['steps']),'Complete scoped method roster')
    fds=None;observations=[]
    for seq,(step,command,frame) in enumerate(zip(plan['steps'],r['commands'],frames,strict=True),1):
        need(len(frame)>=144 and frame[:8]==b'BRGREQ01','Actual scoped method input magic/extent')
        h=struct.unpack('<18Q',frame[:144]);op=step['opcode'];args=step['args']
        need(h[1:3]==(op,seq) and command['opcode']==op,'Actual source-defined private method')
        actual_fds=h[6:8];need(all(3<=fd<=2147483647 for fd in actual_fds) and actual_fds[0]!=actual_fds[1],'Actual distinct diagnostic pipe descriptors')
        if fds is None:fds=actual_fds
        need(fds==actual_fds,'Same real process capability lifetime')
        if op in (1,5):
            timestamp=args.get('timestamp');state=bytes.fromhex(args.get('state_hex',''))
            need(h[3:6]==(args.get('height',10),int(timestamp is not None),0 if timestamp is None else timestamp),'Actual private constructor context')
            need(frame[64:96]==bytes.fromhex(args.get('miner_hex','01'*32)) and frame[96:128]==bytes.fromhex(args.get('parent_id_hex','02'*32)),'Actual miner/parent bytes')
            need(h[16:18]==(len(state),0) and frame[144:]==state,'Actual base comes from this retained fixture import')
        else:
            wires=[bytes.fromhex(value) for value in args.get('transactions',[])] if op==2 else []
            payload=b''.join(struct.pack('<Q',len(wire))+wire for wire in wires)
            need(h[3:6]==(0,0,0) and frame[64:128]==bytes(64) and h[16:18]==(0,len(wires)) and frame[144:]==payload,'Complete actual source method bytes')
        for event in command['events']:
            expected=callback(step,event);ack=struct.unpack('<6Q',bytes.fromhex(event['reply_hex']))
            need(ack[4:6]==expected[:2],'Exact source-defined actual callback action')
        observations.append(command['result'])
    base_reads=response_checks(plan,observations)
    return {'name':plan['name'],'status':'PASS','commands':len(frames),'progress_records':len(r['events']),
        'full_base_reads':base_reads,'process':identity(safe.read(directory,'report.json')),'elapsed_ns':r['elapsed_ns']}
def validate_report(repository,output):
    output=Path(output);before=identities(output);r=safe.load(output,'report.json')
    expected={'schema','status','build','inputs','controls','processes','commands','progress_records','full_base_reads','elapsed_ns','verification','scope'}
    need(set(r)==expected and r['schema']==SCHEMA and r['status']=='PASS','Complete scoped report')
    build,elf,files=validate_build(output/'native-build','scoped',repository)
    need(safe.same(r['build'],build),'Actual scoped build lineage')
    native=build['source_inputs'];original=build['original_sources'];plan=plans(repository)
    raw=canonical(plan)+b'\n';need(safe.read(output,'inputs.json')==raw and safe.same(r['inputs'],identity(raw)),'Source-defined complete private lifecycle inputs')
    controls=[validate_process(output/('cases/%04d'%index),case,build['executable']) for index,case in enumerate(plan)]
    need(safe.same(r['controls'],controls),'Complete lifecycle actual observations')
    for key,value in [('processes',len(plan)),('commands',sum(row['commands'] for row in controls)),
      ('progress_records',sum(row['progress_records'] for row in controls)),('full_base_reads',sum(row['full_base_reads'] for row in controls))]:
        need(type(r[key]) is int and r[key]==value,'Exact scoped aggregate '+key)
    need(type(r['elapsed_ns']) is int and r['elapsed_ns']>=sum(row['elapsed_ns'] for row in controls),'Actual complete lifecycle interval')
    need(safe.same(r['verification'],{'primary_error':None,'cleanup_errors':[],'source_after':{'status':'PASS','errors':[]}}),'Closed scoped source/cleanup verification')
    need(safe.same(r['scope'],{'same_actual_heap':True,'base_is_test_fixture':True,'actual_node_source':False,'full_node':False,'persistent_commit':False,'original_rust':'NOT_RUN'}),'Exact scoped lifecycle authority boundary')
    expected_files={'report.json','inputs.json',*('native-build/'+name for name in files)}
    for index in range(len(plan)):expected_files.update('cases/%04d/'%index+name for name in safe.roster(output/('cases/%04d'%index)))
    need(set(before)==expected_files and identities(output)==before,'Complete regular source-bound scoped artifact roster')
    check_sources(native,original,repository);return r
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--validate-only',action='store_true')
    args=parser.parse_args();need(__debug__,'Optimized Python is not admitted')
    if args.validate_only:
        r=validate_report(REPOSITORY,args.output);print(json.dumps({'status':'PASS','processes':r['processes'],'commands':r['commands']}));return
    output=args.output.absolute();output.mkdir(mode=0o700);(output/'cases').mkdir()
    native=None;original=None;builder=None;elf=None;build=None;active=None;controls=[];primary=None;cleanup=[];source_after={'status':'NOT_RUN','errors':[]};start=time.monotonic_ns()
    try:
        native,_=complete_sources();original=original_manifest()
        builder=Build(output/'native-build',profile='scoped');build=builder.build();elf=builder.executable
        validate_build(output/'native-build','scoped',REPOSITORY)
        plan=plans();inputs=canonical(plan)+b'\n';(output/'inputs.json').write_bytes(inputs)
        for index,item in enumerate(plan):
            active=Session.__new__(Session)
            active.__init__(output/('cases/%04d'%index),elf)
            observed=[]
            for step in item['steps']:
                kw={};a=step['args']
                for name in ('height','timestamp'):
                    if name in a:kw[name]=a[name]
                if 'state_hex' in a:kw['state']=bytes.fromhex(a['state_hex'])
                if 'transactions' in a:kw['transactions']=[bytes.fromhex(value) for value in a['transactions']]
                if 'miner_hex' in a:kw['miner']=bytes.fromhex(a['miner_hex'])
                if 'parent_id_hex' in a:kw['parent_id']=bytes.fromhex(a['parent_id_hex'])
                observed.append(active.request(step['opcode'],gate=lambda event,current=step:callback(current,event),**kw))
            response_checks(item,observed)
            process=active.finish();active=None;need(process['status']=='PASS','Actual scoped process terminal')
            controls.append(validate_process(output/('cases/%04d'%index),item,build['executable']))
            print(json.dumps(controls[-1]),flush=True)
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        if active is not None:
            try:active.finish(RuntimeError('qualification interrupted'))
            except BaseException as error:cleanup.append({'process':repr(error)})
        if native is not None and original is not None:
            try:check_sources(native,original);source_after={'status':'PASS','errors':[]}
            except BaseException as error:source_after={'status':'FAIL','errors':[repr(error)]}
        if builder is not None:
            try:
                if builder.pinned is not None:builder.pinned.check_pin()
            except BaseException as error:cleanup.append({'builder':repr(error)})
        okay=primary is None and not cleanup and source_after['status']=='PASS' and len(controls)==len(NAMES)
        r={'schema':SCHEMA,'status':'PASS' if okay else 'FAIL','build':build,
           'inputs':identity((output/'inputs.json').read_bytes()) if (output/'inputs.json').exists() else None,
           'controls':controls,'processes':len(controls),'commands':sum(row['commands'] for row in controls),
           'progress_records':sum(row['progress_records'] for row in controls),'full_base_reads':sum(row['full_base_reads'] for row in controls),
           'elapsed_ns':time.monotonic_ns()-start,'verification':{'primary_error':primary,'cleanup_errors':cleanup,'source_after':source_after},
           'scope':{'same_actual_heap':True,'base_is_test_fixture':True,'actual_node_source':False,'full_node':False,'persistent_commit':False,'original_rust':'NOT_RUN'}}
        safe.write_json(output/'report.json',r)
    if r['status']=='PASS':validate_report(REPOSITORY,output)
    print(json.dumps({'status':r['status'],'processes':r['processes'],'commands':r['commands'],'verification':r['verification']}),flush=True)
    raise SystemExit(0 if r['status']=='PASS' else 1)
if __name__=='__main__':main()
