"""Run the actual private owner histories; original Rust is a separate gate."""
from __future__ import annotations
import argparse,json,lzma,time,traceback,shutil
from pathlib import Path
from .build import Build,check_sources,identity
from .cases import histories,canonical_bytes
from .native_io import Session,execute


def qualify(output:Path)->dict:
    output=output.absolute();output.mkdir(mode=0o700);start=time.monotonic_ns();build=None;builder=None;rows=[];primary=None;cleanup_errors=[];source_errors=[];corpus=canonical_bytes();bundle=output/'bundle';bundle.mkdir(mode=0o700)
    (bundle/'corpus.jsonl').write_bytes(corpus);compressed=lzma.compress(corpus);(bundle/'corpus.jsonl.xz').write_bytes(compressed)
    try:
        builder=Build(output/'build');build=builder.build()
        (bundle/'native-build').mkdir(mode=0o700)
        for name in ('owner.flat','root.flat','linux_emitter.elf','owner.elf'):
            shutil.copyfile(builder.output/name,bundle/'native-build'/name)
        (bundle/'processes').mkdir(mode=0o700)
        for index,case in enumerate(histories()):
            session=None;observations=None;error=None;process=None
            try:
                session=Session(builder.executable,output/('history-%03d'%index))
                observations=execute(session,case['commands'])
            except BaseException as failure:
                error={'error':repr(failure)[:4096],'traceback':traceback.format_exc()}
            finally:
                if session is not None:
                    try:process=session.finish(allow_failure=error is not None)
                    except BaseException as failure:
                        cleanup_errors.append({'history':case['name'],'error':repr(failure)})
                        process=getattr(session,'receipt',None)
                    target=bundle/'processes'/('%03d'%index);target.mkdir(mode=0o700)
                    for name in ('stdin.raw','stdout.raw','stderr.raw','receipt.json'):
                        shutil.copyfile(session.output/name,target/name)
                    all_actual=[record['actual'] for record in session.commands]
                    (session.output/'observations.json').write_text(json.dumps(all_actual,sort_keys=True,indent=2)+'\n')
            row={'name':case['name'],'status':'PASS' if error is None and process is not None and process['exit_code']==0 else 'FAIL','observations':observations,'process':process,'process_directory':'processes/%03d'%index,'failure':error};rows.append(row)
            if row['status']!='PASS':raise RuntimeError('Actual native history failed: '+case['name'])
            if (index+1)%16==0:print(json.dumps({'actual_native_histories':index+1,'status':'PROGRESS'}),flush=True)
    except BaseException as failure:
        primary={'error':repr(failure),'traceback':traceback.format_exc()}
    finally:
        if builder is not None:
            for label,check in (('pinned_compiler',builder.pinned.check_pin),('sources',lambda:check_sources(builder.inputs,builder.original))):
                try:check()
                except BaseException as failure:source_errors.append({'stage':label,'error':repr(failure)})
        source_after={'status':'PASS' if builder is not None and not source_errors else 'FAIL','errors':source_errors}
        status='PASS' if primary is None and not cleanup_errors and source_after['status']=='PASS' and len(rows)==len(histories()) and all(r['status']=='PASS' for r in rows) else 'FAIL'
        if build is None and builder is not None:build=getattr(builder,'report',None)
        corpus_binding={'raw':identity(corpus),'compressed':identity(compressed),'path':'corpus.jsonl.xz'}
        comparison={'schema':'trnm.execution-state-native-comparison.v1','status':status,'build':build,'corpus':corpus_binding,'histories':rows}
        raw=json.dumps(comparison,sort_keys=True,separators=(',',':')).encode()+b'\n';(bundle/'native-comparison.json').write_bytes(raw)
        report={'schema':'trnm.execution-state-qualification.v1','status':status,'build':build,'corpus':corpus_binding,'comparison':identity(raw),'histories_total':len(rows),'histories_expected':len(histories()),'native_commands':sum(len(r['observations'] or []) for r in rows),'actual_processes':len(rows),'elapsed_ns':time.monotonic_ns()-start,'controls':[{'name':r['name'],'status':r['status'],'commands':len(r['observations'] or []),'failure':r['failure']} for r in rows],'verification':{'primary_error':primary,'cleanup_errors':cleanup_errors,'source_after':source_after},'scope':{'actual_private_state_view_patch_owner':True,'canonical_hia_state_root':True,'runtime_host_proxy':False,'complete_node':False,'admission_persistence':False,'original_rust':'NOT_RUN'}}
        (bundle/'native-report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');(output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps({k:report[k] for k in ('status','histories_total','native_commands','elapsed_ns','verification')},sort_keys=True),flush=True)
    return report


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();return int(qualify(a.output)['status']!='PASS')
if __name__=='__main__':raise SystemExit(main())
