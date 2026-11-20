"""Actual native descriptor refusal, syscall failure and thread protocol controls."""
from __future__ import annotations
from pathlib import Path
import argparse,fcntl,json,os,re,shutil,signal,stat,struct,subprocess,time,traceback
from hia.platform.execution_state.cases import map_bytes
from .source_graph import REPOSITORY,complete_sources,original_manifest,check_sources,bound_corpus,identity,need
from .build import Build
from .build_evidence import validate_build
from . import batch_native_io
from . import safe_io as safe
from .physical_evidence import PREFIX_PLANS,validate_physical
save=safe.write_json
def prefix_controls(out,elf):
    state=map_bytes({'model:current':'0'*64,'meta:issued':0})
    plans=PREFIX_PLANS
    controls=[];primary=None
    for name,wanted in plans:
        directory=out/name;directory.mkdir(mode=0o700)
        fds=[];files=[];child=None;failure=None;cleanup=[];raw_streams={'stdin':b'','stdout':b'','stderr':b'','progress':b''};caps={};started=time.monotonic_ns();payload=b'';command=None;before={};after={}
        def pipe():
            pair=os.pipe();fds.extend(pair);return pair
        def regular(label,content=b'unchanged-native-capability-sentinel'):
            path=directory/(label+'.fixture');path.write_bytes(content)
            fd=os.open(path,os.O_RDWR|os.O_CLOEXEC);fds.append(fd);files.append(path);return fd
        def meta(fd):
            value=os.fstat(fd)
            return {'dev':value.st_dev,'ino':value.st_ino,'mode':value.st_mode,'access_flags':fcntl.fcntl(fd,fcntl.F_GETFL)}
        try:
            image=os.memfd_create('hia-prefix-physical',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);fds.append(image)
            at=0
            while at<len(elf):at+=os.write(image,elf[at:])
            os.fchmod(image,0o500);fcntl.fcntl(image,getattr(fcntl,'F_ADD_SEALS',1033),15)
            ir,iw=pipe();orr,ow=pipe();er,ew=pipe();pr,pw=pipe();ar,aw=pipe()
            standard=[ir,ow,ew];gw,gr=pw,ar
            if name in ('stdin-regular','stdout-regular','stderr-regular'):
                at=('stdin-regular','stdout-regular','stderr-regular').index(name);standard[at]=regular('stdio')
            if name=='stdout-stderr-alias':standard[2]=standard[1]
            if name in ('stdin-nonblocking','stdout-nonblocking','stderr-nonblocking'):
                at=('stdin-nonblocking','stdout-nonblocking','stderr-nonblocking').index(name)
                fcntl.fcntl(standard[at],fcntl.F_SETFL,fcntl.fcntl(standard[at],fcntl.F_GETFL)|os.O_NONBLOCK)
            if name=='gate-write-regular':gw=regular('gate')
            if name=='gate-read-regular':gr=regular('gate')
            if name=='gate-write-wrong-mode':gw=pr
            if name=='gate-read-wrong-mode':gr=aw
            if name=='gate-same-pipe':gr=pr
            if name=='gate-write-stdout-dup':gw=os.dup(ow);fds.append(gw)
            if name=='gate-read-stdin-dup':gr=os.dup(ir);fds.append(gr)
            if name=='gate-write-nonblocking':fcntl.fcntl(gw,fcntl.F_SETFL,fcntl.fcntl(gw,fcntl.F_GETFL)|os.O_NONBLOCK)
            if name=='gate-read-nonblocking':fcntl.fcntl(gr,fcntl.F_SETFL,fcntl.fcntl(gr,fcntl.F_GETFL)|os.O_NONBLOCK)
            if name=='one-disabled-gate':gw=(1<<64)-1
            if name=='other-disabled-gate':gr=(1<<64)-1
            if name=='gate-outside-int':gw=1<<31
            if name.startswith('native-'):gw=gr=(1<<64)-1
            body=bytearray(b'PFXREQ01'+struct.pack('<7Q',1,1,10,0,0,gw,gr)+bytes([1])*32+bytes([2])*32+struct.pack('<2Q',len(state),0)+state)
            if name=='bad-magic':body[0]^=1
            if name=='bad-timestamp-flag':struct.pack_into('<Q',body,32,2)
            if name=='absent-timestamp-nonzero':struct.pack_into('<Q',body,40,1)
            if name=='bad-reserved-context':struct.pack_into('<Q',body,136,1)
            if name=='bad-state-value':body[-1]=255
            payload=struct.pack('<Q',len(body))+body
            if name=='short-header':payload=struct.pack('<Q',143)
            if name=='header-eof':payload=b'\0'*7
            if name=='body-eof':payload=struct.pack('<Q',144)
            if name=='stdin-regular':
                os.ftruncate(standard[0],0);os.write(standard[0],payload);os.lseek(standard[0],0,os.SEEK_SET)
            before={str(path):identity(path.read_bytes()) for path in files}
            (directory/'intended-input.raw').write_bytes(payload)
            if files:
                (directory/'sentinels-before').mkdir(mode=0o700)
                for path in files:(directory/'sentinels-before'/path.name).write_bytes(path.read_bytes())
            caps={str(index):meta(fd) for index,fd in enumerate(standard)}
            for label,fd in (('GW',gw),('GR',gr)):
                if fd in fds:caps[label]=meta(fd)
                else:caps[label]={'unusable_number':fd}
            passed=tuple(sorted({image,*[fd for fd in (gw,gr) if fd in fds]}))
            command=['/proc/self/fd/'+str(image)]
            if name.startswith('native-'):
                syscall='mmap' if name=='native-mmap-enomem' else 'mremap'
                tracer=shutil.which('strace');need(tracer is not None,'real strace required')
                command=[tracer,'-qq','-o',str(directory/'syscalls.raw'),'-e','trace=mmap,mremap,exit_group','-e','inject='+syscall+':error=ENOMEM:when=1','--',*command]
            child=subprocess.Popen(command,stdin=standard[0],stdout=standard[1],stderr=standard[2],pass_fds=passed,close_fds=True,env={'PATH':''},start_new_session=True)
            keep={iw,orr,er,pr}
            for fd in tuple(fds):
                if fd not in keep:os.close(fd);fds.remove(fd)
            if name!='stdin-regular':
                at=0
                while at<len(payload):
                    try:n=os.write(iw,payload[at:])
                    except BrokenPipeError:break
                    need(n>0,'physical actual input write');raw_streams['stdin']+=payload[at:at+n];at+=n
            os.close(iw);fds.remove(iw)
            child.wait(timeout=240)
            for label,fd in (('stdout',orr),('stderr',er),('progress',pr)):
                os.set_blocking(fd,False)
                while True:
                    try:raw=os.read(fd,65536)
                    except BlockingIOError:break
                    if not raw:break
                    raw_streams[label]+=raw
            after={str(path):identity(path.read_bytes()) for path in files}
            need(child.returncode==wanted,'real exit '+str(child.returncode)+' expected '+str(wanted))
            need(before==after,'failed ABI wrote to a passed regular file')
            need(not any(raw_streams[n] for n in ('stdout','stderr','progress')),'failed ABI published output/progress')
            if name.startswith('native-'):
                trace=(directory/'syscalls.raw').read_text()
                matches=[line for line in trace.splitlines() if re.search(r'\b'+syscall+r'\(.*\)\s+= -1 ENOMEM.*\(INJECTED\)',line)]
                need(len(matches)==1 and 'exit_group(79)' in trace,'actual selected kernel resource error/exit was not observed')
            row={'name':name,'status':'PASS','expected_exit':wanted,'actual_exit':child.returncode,'caps_before':caps,'files_before':before,'files_after':after}
        except BaseException as error:
            failure={'error':repr(error),'traceback':traceback.format_exc()}
            row={'name':name,'status':'FAIL','failure':failure,'caps_before':caps,'expected_exit':wanted,'actual_exit':None if child is None else child.poll()}
            if child is not None and child.poll() is None:
                try:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=3)
                except BaseException as error:cleanup.append(repr(error))
        finally:
            for fd in fds:
                try:os.close(fd)
                except BaseException as error:cleanup.append(repr(error))
            for n,raw in raw_streams.items():(directory/(n+'.raw')).write_bytes(raw)
            row.update(cleanup_errors=cleanup,elapsed_ns=time.monotonic_ns()-started,streams={n:identity(raw) for n,raw in raw_streams.items()},intended_input=identity(payload),argv=command,pid=None if child is None else child.pid,wall_limit_seconds=240,cleanup_limit_seconds=3)
            if cleanup:row['status']='FAIL'
            save(directory/'report.json',row);controls.append(row)
            print(json.dumps({k:row[k] for k in ('name','status','actual_exit','elapsed_ns')},sort_keys=True),flush=True)
        if row['status']!='PASS':primary=failure or {'error':'cleanup failed'};break

    need(primary is None and len(controls)==len(plans),'Actual Prefix physical control failed: '+repr(primary))
    return controls
def run(output):
    output=Path(output).absolute();need(output.resolve()==output and not output.exists() and REPOSITORY not in output.parents,'Fresh output outside the source repository')
    output.mkdir(mode=0o700);start=time.monotonic_ns();inputs=None;original=None;builds={};controls=[];failure=None;errors=[];builders=[]
    try:
        inputs,_=complete_sources(REPOSITORY);original=original_manifest(REPOSITORY)
        for profile in ('prefix','batch'):
            builder=Build.__new__(Build);builders.append(builder);Build.__init__(builder,output/('native-'+profile),profile);builds[profile]=builder.build()
            validate_build(output/('native-'+profile),profile,REPOSITORY)
        (output/'prefix').mkdir(mode=0o700)
        controls=prefix_controls(output/'prefix',(output/'native-prefix/owner.elf').read_bytes())
        _,cases=bound_corpus(REPOSITORY,'batch')
        selected=[row for row in cases if row['name']=='cancel-all-joins-before-first-handle-error'];need(len(selected)==1,'Bound actual multiworker fixture')
        case=selected[0]
        def gate(event):return (0,0,1) if event['worker']==0 else (0,0,0)
        record=batch_native_io.execute(output/'batch-wrong-worker-ack',(output/'native-batch/owner.elf').read_bytes(),
          bytes.fromhex(case['state_hex']),[bytes.fromhex(value) for value in case['transactions']],workers=case['workers'],height=case['height'],
          miner=bytes.fromhex(case['miner_hex']),parent_id=bytes.fromhex(case['parent_id_hex']),gate=gate,barrier=False)
        need(record['status']=='PASS' and record['exit_code']==78 and record['result'] is None and not safe.read(output/'batch-wrong-worker-ack','stdout.raw') and not safe.read(output/'batch-wrong-worker-ack','stderr.raw'),'Malformed actual worker ACK must refuse without successor')
        controls.append({'name':'batch-wrong-worker-ack','status':'PASS','expected_exit':78,'actual_exit':78,'process':identity(safe.read(output/'batch-wrong-worker-ack','report.json'))})
    except BaseException as error:failure={'error':repr(error),'traceback':traceback.format_exc()}
    finally:
        if inputs is not None and original is not None:
            try:check_sources(inputs,original,REPOSITORY)
            except BaseException as error:errors.append({'source':repr(error)})
        for builder in builders:
            if getattr(builder,'pinned',None) is not None:
                try:builder.pinned.check_pin()
                except BaseException as error:errors.append({'compiler':repr(error)})
        report={'schema':'trnm.execution-batch-physical.v1','status':'PASS' if failure is None and not errors and len(controls)==30 else 'FAIL',
         'builds':builds,'controls':controls,'planned':30,'failure':failure,'source_after':{'status':'PASS' if not errors else 'FAIL','errors':errors},
         'elapsed_ns':time.monotonic_ns()-start,'actual_trace_required':True,'runtime_host_proxy':False,'persistent_commit':False,'original_rust_executed':False}
        save(output/'report.json',report)
    need(report['status']=='PASS','Physical qualification failed; all raw process artifacts retained')
    validate_physical(REPOSITORY,output)
    return report
def main():
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);parser.add_argument('--validate-only',action='store_true');args=parser.parse_args();report=validate_physical(REPOSITORY,args.output) if args.validate_only else run(args.output)
    print(json.dumps({'status':report['status'],'controls':len(report['controls']),'elapsed_ns':report['elapsed_ns']}));return 0
if __name__=='__main__':raise SystemExit(main())
