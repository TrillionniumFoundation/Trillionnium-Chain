"""Run one fixed exhaustive batch/Prefix partition in real native processes."""
from __future__ import annotations
import argparse,json,lzma,os,time,traceback
from pathlib import Path
from .source_graph import REPOSITORY,complete_sources,original_manifest,check_sources,bound_corpus,identity,need
from .build import Build
from .cases import selection
from . import safe_io as safe
from . import batch_native_io as batch_io
from . import prefix_native_io as prefix_io
from .process_evidence import batch_process,prefix_process
from .build_evidence import validate_build,file_names
from .bundle import partition,SCOPE,copy_files,validate_bundle
def run(output,profile,part):
    output=Path(output).absolute();need(output.resolve()==output and not output.exists() and REPOSITORY not in output.parents,'Fresh qualification output outside the repository')
    output.mkdir(mode=0o700);start=time.monotonic_ns();builder=None;inputs=None;original=None;build=None;elf=None;corpus=None;rows=[];selected=[]
    primary=None;cleanup=[];after=[];observed=[];controls=[];session=None;declaration=None
    try:
        inputs,_=complete_sources(REPOSITORY);original=original_manifest(REPOSITORY)
        corpus,rows=bound_corpus(REPOSITORY,profile);selected=selection(profile,part)
        archived=lzma.compress(corpus,format=lzma.FORMAT_XZ,preset=3)
        (output/'corpus.jsonl').write_bytes(corpus);(output/'corpus.jsonl.xz').write_bytes(archived)
        declaration={'raw':identity(corpus),'compressed':identity(archived),'path':'corpus.jsonl.xz'}
        builder=Build.__new__(Build);Build.__init__(builder,output/'native-build',profile);build=builder.build();elf=builder.executable
        need(build['source_inputs']==inputs and build['original_sources']==original,'Actual build source binding changed')
        validate_build(output/'native-build',profile,REPOSITORY)
        (output/'cases').mkdir(mode=0o700)
        for index in selected:
            row=rows[index];directory=output/'cases'/('%04d'%index)
            if profile=='batch':
                actions={(item['worker'],item['sequence']):item for item in row['actions']}
                def gate(event):
                    action=actions.get((event['worker'],event['sequence']))
                    return (0,0,0) if action is None else (action['class'],action['token'],0)
                record=batch_io.execute(directory,elf,bytes.fromhex(row['state_hex']),[bytes.fromhex(value) for value in row['transactions']],
                 workers=row['workers'],height=row['height'],miner=bytes.fromhex(row['miner_hex']),parent_id=bytes.fromhex(row['parent_id_hex']),gate=gate,barrier=row['barrier'])
                need(record['status']=='PASS' and record['exit_code']==0,'Actual complete batch Result failed')
                decoded,summary=batch_process(directory,row,build['executable'])
            else:
                session=prefix_io.Session.__new__(prefix_io.Session);prefix_io.Session.__init__(session,directory,elf);ready=False
                for command in row['commands']:
                    if command.get('requires_ready',False) and not ready:continue
                    actions={item['sequence']:item for item in command.get('actions',[])}
                    def gate(event):
                        action=actions.get(event['sequence'])
                        return (0,0,0) if action is None else (action['class'],action['token'],0)
                    if command['op']==1:
                        result=session.request(1,state=bytes.fromhex(command['state_hex']),height=command['height'],timestamp=command['timestamp'],
                         miner=bytes.fromhex(command['miner_hex']),parent_id=bytes.fromhex(command['parent_id_hex']),gate=gate)
                    else:result=session.request(command['op'],transactions=[bytes.fromhex(value) for value in command.get('transactions',[])],gate=gate)
                    ready=result['header'][25]==1
                record=session.finish();session=None;need(record['status']=='PASS','Actual retained Prefix process failed')
                decoded,summary=prefix_process(directory,row,build['executable'])
            observed.append({'index':index,'observation':decoded});controls.append({'index':index,'status':'PASS',**summary})
            print(json.dumps({'index':index,'name':row['name'],'status':'PASS','commands':summary['commands'],'progress_records':summary['progress_records'],'elapsed_ns':summary['elapsed_ns']},sort_keys=True),flush=True)
    except BaseException as error:primary={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        if session is not None and hasattr(session,'streams') and not session.finished:
            try:
                record=session.finish(primary)
                if record['cleanup_errors']:cleanup.extend(record['cleanup_errors'])
            except BaseException as error:cleanup.append({'error':repr(error),'traceback':traceback.format_exc()})
        if inputs is not None and original is not None:
            try:check_sources(inputs,original,REPOSITORY)
            except BaseException as error:after.append({'error':repr(error),'traceback':traceback.format_exc()})
        if builder is not None and getattr(builder,'pinned',None) is not None:
            try:builder.pinned.check_pin()
            except BaseException as error:after.append({'compiler':repr(error)})
        status='PASS' if primary is None and not cleanup and not after and len(observed)==len(selected) and build is not None else 'FAIL'
        if build is None and builder is not None:build=getattr(builder,'report',None)
        comparison={'schema':'trnm.execution-batch-native-comparison.v1','status':status,'profile':profile,'partition':partition(profile,part),'build':build,'corpus':declaration,'cases':observed}
        safe.write_json(output/'native-comparison.json',comparison)
        planned=sum(len(rows[index]['commands']) if profile=='prefix' else 1 for index in selected)
        report={'schema':'trnm.execution-batch-native-qualification.v1','status':status,'profile':profile,'partition':partition(profile,part),'build':build,'corpus':declaration,
         'comparison':identity(safe.read(output,'native-comparison.json')),'histories_total':len(rows),'histories_executed':len(observed),'commands_planned':planned,
         'commands_actual':sum(row['commands'] for row in controls),'progress_records':sum(row['progress_records'] for row in controls),'skipped_commands':sum(len(row['skipped']) for row in controls),
         'controls':controls,'elapsed_ns':time.monotonic_ns()-start,'verification':{'primary_error':primary,'cleanup_errors':cleanup,'source_after':{'status':'PASS' if not after else 'FAIL','errors':after}},'scope':SCOPE}
        safe.write_json(output/'native-report.json',report)
    if report['status']=='PASS':
        names={'native-comparison.json','native-report.json','corpus.jsonl','corpus.jsonl.xz'}
        names.update('native-build/'+name for name in file_names(build))
        for index in selected:names.update('cases/%04d/'%index+name for name in safe.roster(output/'cases'/('%04d'%index)))
        try:
            copy_files(output,output/'bundle',names);validated=validate_bundle(REPOSITORY,output/'bundle',profile)
            check_sources(inputs,original,REPOSITORY)
            safe.write_json(output/'bundle-admission.json',{'status':'PASS','files':len(validated['bundle_artifacts']),'histories':len(selected),'source_set_sha256':build['source_set_sha256'],'executable':build['executable']})
        except BaseException as error:
            safe.write_json(output/'bundle-admission.json',{'status':'FAIL','error':repr(error),'traceback':traceback.format_exc()})
            raise
    need(report['status']=='PASS','Actual qualification failed; complete failure/raw output retained')
    return report
def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--profile',choices=('batch','prefix'),required=True);parser.add_argument('--part',type=int,default=0);args=parser.parse_args()
    selection(args.profile,args.part);result=run(args.output,args.profile,args.part)
    print(json.dumps({key:result[key] for key in ('status','profile','partition','histories_executed','commands_actual','progress_records','elapsed_ns')},sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
