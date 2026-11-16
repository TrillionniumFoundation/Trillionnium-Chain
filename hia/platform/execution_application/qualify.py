"""Actual default application histories with complete native pipe evidence."""
from __future__ import annotations
import argparse,json,lzma,os,shutil,time,traceback
from pathlib import Path
from .build import Build
from .source_graph import REPOSITORY,IMAGE_ORDER,bound_corpus,check_sources,identity,need
from .native_io import Session

ERRORS={1:'RANGE',2:'STATE',3:'NONCE',4:'FEE',5:'FUNDS',6:'EXPIRED',7:'LIMIT',8:'RESOURCE_ID',9:'DUPLICATE',10:'AUTHORITY',11:'EVIDENCE',12:'SUBMISSION_ROUND',13:'ROOT',14:'CANDIDATE_WINDOW_FULL',15:'NONCANONICAL',16:'SIGNATURE',17:'LENGTH',18:'ENCODING',19:'VERSION',20:'EVALUATION_POLICY',253:'ACCOUNT_ACCESS',254:'PANIC',255:'PRIVATE_INVARIANT'}
PREP_ERRORS={1:'ENCODING',2:'SERVICE_CONTRACT_PROFILE',3:'WORK_TASK_PROFILE',4:'PUBLIC_EVAL_PROFILE',5:'FACTOR_PROFILE',6:'EVOLUTION_PROFILE',7:'NETWORK',8:'EXPIRED',9:'SIGNATURE'}
ROOT_ERRORS={69:'LIMIT',70:'RANGE',71:'NONCANONICAL'}
BATCH_SIZE=40
NATIVE_SECONDS=240


class Observer:
    def __init__(self,session):self.session=session;self.state_commands=0
    def state(self,op,a=0,b=0,arg=0,key=b'',data=b''):
        row=self.session.state(op,a,b,arg,key,data);self.state_commands+=1
        need(row['status']==0,'Actual State primitive refused: '+repr((op,row)))
        return row
    def put(self,handle,key,data):
        if data is None:old=self.state(10,handle,key=key)['result']
        else:
            value=self.state(1,data=data)['result'];old=self.state(8,handle,value,key=key)['result']
        if old:self.state(4,old)
    def history(self,case):
        handle=self.state(5)['result']
        for row in case['base']:self.put(handle,bytes.fromhex(row['key_hex']),bytes.fromhex(row['value_hex']))
        before=self.state(11,handle)['data_hex'];steps=[]
        for transaction in case['transactions']:
            base_before=self.state(11,handle)['data_hex']
            actual=self.session.application(handle,bytes.fromhex(transaction['wire_hex']),transaction['height'],transaction['callback'],transaction['cancel_at'])
            if actual['kind']=='preparation':
                result={'kind':'preparation','outcome':'error','error':PREP_ERRORS[actual['fields'][1]],'callbacks':actual['callbacks'],'patch_hex':None,'fee':None,'receipt_hex':None,'current_before':None,'current_after':None}
            else:
                error=None if actual['error']==0 else ERRORS[actual['error']]
                if actual['error'] not in (0,253,254,255):need(bytes.fromhex(actual['error_hex']).decode()==error,'Native error code/text disagreement')
                outcome={1:'ok',2:'error',3:'panic',4:'cancelled',5:'private_failure'}[actual['outcome']]
                result={'kind':'application','outcome':outcome,'error':error,'callbacks':actual['callbacks'],'patch_hex':None,'fee':None,'receipt_hex':None,'current_before':None,'current_after':None}
                need(outcome!='private_failure','Native private invariant failed')
            result['base_unchanged']=self.state(11,handle)['data_hex']==base_before
            need(result['base_unchanged'],'Application changed the borrowed State before Patch::apply')
            if result['outcome']=='ok':
                patch=actual['patch'];result.update(patch_hex=self.state(23,patch)['data_hex'],fee=actual['fee'],receipt_hex=actual['receipt_hex'],current_before=bool(self.state(20,patch,handle)['result']))
                for mutation in transaction['current_mutations']:self.put(handle,bytes.fromhex(mutation['key_hex']),None if mutation['value_hex'] is None else bytes.fromhex(mutation['value_hex']))
                result['current_after']=bool(self.state(20,patch,handle)['result'])
                self.state(21,patch,handle) if transaction['commit'] else self.state(22,patch)
            else:need(actual.get('patch',0)==0,'Rejected application transferred a Patch')
            result['after_hex']=self.state(11,handle)['data_hex'];result['root']=None
            if transaction['root']:
                root=self.session.state(24,handle);self.state_commands+=1
                result['root']={'hash_hex':root['data_hex'] if root['status']==0 else None,'error':None if root['status']==0 else ROOT_ERRORS[root['status']]}
            expected=transaction.get('expect')
            need(expected is None or ('OK' if result['outcome']=='ok' else result['error'])==expected,'Source-defined semantic expectation differs: '+case['name'])
            steps.append(result)
        self.state(7,handle);stats=self.state(0)
        need(stats['live_objects']==0 and stats['live_blocks']==0,'Application history leaked private State objects or allocations')
        return {'name':case['name'],'before_hex':before,'observations':steps}


def qualify(output):
    output=output.absolute();need(output.resolve()==output and not output.exists() and REPOSITORY not in output.parents,'Fresh output outside repository required')
    output.mkdir(mode=0o700);bundle=output/'bundle';bundle.mkdir();builder=None;session=None;primary=None;cleanup=[];source_errors=[];results=[];processes=[];controls=[];state_commands=0;start=time.monotonic_ns();corpus=None
    try:
        builder=Build(output/'build');built=builder.build();raw,inputs,configuration=bound_corpus()
        compressed=lzma.compress(raw);(bundle/'corpus.jsonl').write_bytes(raw);(bundle/'corpus.jsonl.xz').write_bytes(compressed)
        corpus={'path':'corpus.jsonl.xz','raw':identity(raw),'compressed':identity(compressed)}
        images=bundle/'native-build';images.mkdir()
        for name in (*IMAGE_ORDER,'linux_emitter'):
            file=name+('.elf' if name=='linux_emitter' else '.flat');shutil.copyfile(builder.output/file,images/file)
        for file in ('elf-prefix.raw','owner.elf'):shutil.copyfile(builder.output/file,images/file)
        for begin in range(0,len(inputs),BATCH_SIZE):
            directory='processes/%03d'%(begin//BATCH_SIZE);(bundle/'processes').mkdir(exist_ok=True)
            session=Session(builder.executable,bundle/directory,seconds=NATIVE_SECONDS);observer=Observer(session)
            for name in ('network','parameters','family','plan'):need(session.context_fields[name]==configuration[name].hex(),'Actual native Config differs from source fixtures')
            need(session.context_fields['params']==configuration['params'],'Actual native Config params differ')
            process_names=[]
            for case in inputs[begin:begin+BATCH_SIZE]:
                row=observer.history(case);results.append(row);process_names.append(case['name']);controls.append({'name':case['name'],'status':'PASS','transactions':len(row['observations'])})
                if len(results)%10==0 or len(results)==len(inputs):print(json.dumps({'histories_done':len(results),'total':len(inputs),'last':case['name']}),flush=True)
            observer.state(26);receipt=session.finish();processes.append({'directory':directory,'histories':process_names,'state_commands':observer.state_commands,'context':session.context_fields,'receipt':receipt});state_commands+=observer.state_commands;session=None
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        if session is not None:
            try:processes.append({'partial_process':session.finish(allow_failure=True)})
            except BaseException as error:cleanup.append({'error':repr(error),'traceback':traceback.format_exc()})
        if builder is not None:
            for label,call in [('complete_sources',lambda:check_sources(builder.inputs,builder.original)),('compiler',lambda:builder.pinned.check_pin() if builder.pinned is not None else None)]:
                try:call()
                except BaseException as error:source_errors.append({'stage':label,'error':repr(error)})
        status='PASS' if primary is None and not cleanup and not source_errors else 'FAIL'
        comparison={'schema':'trnm.execution-application-comparison.v1','status':status,'build':None if builder is None else builder.report,'corpus':corpus,'cases':results,'processes':processes}
        comparison_raw=(json.dumps(comparison,sort_keys=True,indent=2)+'\n').encode();(bundle/'native-comparison.json').write_bytes(comparison_raw)
        report={'schema':'trnm.execution-application-qualification.v1','status':status,'build':comparison['build'],'corpus':corpus,'comparison':identity(comparison_raw),'controls':controls,
          'histories_total':len(results),'transactions':sum(len(x['observations']) for x in results),'state_commands':state_commands,'actual_processes':len(processes),'batch_size':BATCH_SIZE,
          'verification':{'primary_error':primary,'cleanup_errors':cleanup,'source_after':{'status':'PASS' if not source_errors else 'FAIL','errors':source_errors}},
          'scope':{'actual_private_prepared':True,'actual_private_state_view_patch':True,'runtime_host_proxy':False,'default_commands':list(range(1,13)),'complete_node':False,'admission_persistence':False,'original_rust':'NOT_RUN'},'elapsed_ns':time.monotonic_ns()-start}
        data=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();(output/'report.json').write_bytes(data);(bundle/'native-report.json').write_bytes(data)
        print(json.dumps({k:report[k] for k in ('status','histories_total','transactions','state_commands','actual_processes','elapsed_ns','verification')}),flush=True)
    return report

def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();return int(qualify(a.output)['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
