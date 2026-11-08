#!/usr/bin/env python3
"""One exact 23-request/4s Node-adapter research campaign in an owned resource-limited unit.

The outside observer forks gated children, moves each blocked child to its own
unit's cgroup, confirms membership, then releases it to exec the pinned verifier.
All verifier descendants inherit that cgroup. The observer retains wait4 status
and rusage even when the whole workload cgroup is SIGKILLed at the deadline.
No cgroup/resource fallback, sudo, production Node claim, or timeout-as-rejection.

The 7 legitimate requests repeat ONE proved Node fixture in independent fresh
processes/stores. The 16 malicious requests repeat four typed, shape-valid
negative proofs. This is not a single Node queue or seven production submissions.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import subprocess
import sys
import time
import uuid

LIMITS={'cpu_quota_percent':25,'memory_max_bytes':2147483648,'memory_swap_max_bytes':0,
        'tasks_max':256,'deadline_seconds':4,'requests':23,'rayon_num_threads':8}
PROPERTIES=('Id','InvocationID','ActiveState','SubState','Result','MainPID','ControlGroup',
            'CPUQuotaPerSecUSec','CPUQuotaPeriodUSec','MemoryMax','MemorySwapMax','TasksMax',
            'CPUUsageNSec','MemoryCurrent','MemoryPeak','TasksCurrent','TasksPeak',
            'KillMode','Delegate','RuntimeMaxUSec','ExecMainCode','ExecMainStatus')
CG_FILES=('cpu.max','cpu.max.burst','cpu.stat','memory.max','memory.current','memory.peak','memory.swap.max',
          'memory.swap.current','memory.events','pids.max','pids.current','pids.peak','pids.events',
          'cgroup.procs','cgroup.events')


def now():return time.monotonic_ns()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')

def proc(pid):
    base=Path('/proc')/str(pid)
    try:
        raw=(base/'stat').read_text();tail=raw[raw.rfind(')')+2:].split()
        status={}
        for line in (base/'status').read_text().splitlines():
            key,_,value=line.partition(':')
            if key in ('State','VmRSS','VmHWM','Threads'):status[key]=value.strip()
        try:exe=os.readlink(base/'exe')
        except OSError:exe=None
        return {'pid':pid,'starttime_ticks':int(tail[19]),'state':tail[0],
                'utime_ticks':int(tail[11]),'stime_ticks':int(tail[12]),
                'status':status,'cgroup':(base/'cgroup').read_text().strip(),'exe':exe}
    except (FileNotFoundError,ProcessLookupError):return None


def cgroup_snapshot(path):
    observed={'monotonic_ns':now(),'path':str(path),'exists':path.exists(),'files':{}}
    for name in CG_FILES:
        try:observed['files'][name]=(path/name).read_text().strip()
        except OSError as e:observed['files'][name]={'error':str(e)}
    return observed


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--coordination-cleared',required=True,
                        help='Explicit retained root/backend completion signal text, not a safety override')
    args=parser.parse_args()
    inputs=args.inputs.resolve(strict=True);out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    journal=(out/'events.jsonl').open('x',buffering=1)
    def event(kind,**fields):
        value={'event':kind,'monotonic_ns':now(),**fields}
        journal.write(json.dumps(value)+'\n');journal.flush()
        return value
    commands=[]
    def command(argv,timeout=5):
        started=now()
        try:
            completed=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
            value={'argv':argv,'started_ns':started,'finished_ns':now(),'exit_code':completed.returncode,
                   'stdout':completed.stdout,'stderr':completed.stderr}
        except subprocess.TimeoutExpired as error:
            value={'argv':argv,'started_ns':started,'finished_ns':now(),'exit_code':None,'timeout':True,
                   'stdout':str(error.stdout or ''),'stderr':str(error.stderr or '')}
        commands.append(value);event('controller_command',**value)
        return value
    def show(unit):
        value=command(['systemctl','--user','show',unit,*['--property='+p for p in PROPERTIES]])
        return {line.split('=',1)[0]:line.split('=',1)[1] for line in value['stdout'].splitlines() if '=' in line}
    manifest=json.loads((inputs/'manifest.json').read_text())
    unit='w1-node-pressure-f16ac5-'+uuid.uuid4().hex[:12]+'.service'
    result={'schema':'w1-node-pressure-23x4s-observation-v1','started_utc':datetime.now(timezone.utc).isoformat(),
            'limits_requested':LIMITS,'coordination_cleared':args.coordination_cleared,
            'input_manifest_sha256':sha(inputs/'manifest.json'),'unit':unit,
            'production_node':False,'single_node_service':False,'actual_node_api_adapter':True,
            'seven_independent_production_submissions':False,'legitimate_distinct_fixtures':1,
            'global_rejection_cost_bound':False,'qualification':'HOLD_NO_GO',
            'observer_outside_workload_cgroup':True,
            'deadline_scope':'from first attempted fork through all23 fresh-process verifications; setup/pinning outside',
            'observer_cost_excluded_from_quota':True,
            'cache_state':'not flushed; pinning read all inputs before the campaign',
            'machine':platform.uname()._asdict(),'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),
            'inherited_cpu_affinity':sorted(os.sched_getaffinity(0)),
            'new_complete_proofs':0,'preflight_exercises_excluded_from_this_campaign':5,
            'initial_limit_readback_enforced':True,'continuous_limit_drift_abort_implemented':False,
            'requests':[{'ordinal':i,'case':name,'spawned':False,'status':'not_started','pid':None,
                         'kind':next(c['kind'] for c in manifest['cases'] if c['name']==name),
                         'exit_code':None,'wait_status':None,'rusage':None} for i,name in enumerate(manifest['case_schedule'])],
            'fatal_error':None}
    cgroup=None;created=False;kill_fd=None;children={};gates={};t0=None;deadline=None
    exited={};case_map={c['name']:c for c in manifest['cases']}
    def reap():
        for pid,index in list(children.items()):
            observed,status,usage=os.wait4(pid,os.WNOHANG)
            if not observed:continue
            finished=now();row=result['requests'][index]
            row.update({'wait_observed_ns':finished,'exit_code':os.waitstatus_to_exitcode(status),
                        'wait_status':status,'completed_observed_by_deadline':deadline is not None and finished<=deadline,
                        'rusage':{key:getattr(usage,key) for key in ('ru_utime','ru_stime','ru_maxrss','ru_minflt',
                              'ru_majflt','ru_inblock','ru_oublock','ru_nvcsw','ru_nivcsw')},
                        'rusage_maxrss_unit':'KiB on Linux'})
            exited[pid]=row;del children[pid]
            event('request_wait4',ordinal=index,pid=pid,exit_code=row['exit_code'],wait_status=status,
                  completed_observed_by_deadline=row['completed_observed_by_deadline'],rusage=row['rusage'])
    def kill_owned(reason):
        if not created or cgroup is None:return
        if cgroup.name!=unit or not re.fullmatch(r'w1-node-pressure-f16ac5-[0-9a-f]{12}\.service',unit):
            raise RuntimeError('OWNERSHIP_PATH_REFUSAL')
        event('owned_cgroup_kill_requested',reason=reason,cgroup=str(cgroup))
        result.setdefault('kill_events',[]).append({'reason':reason,'requested_ns':now()})
        if kill_fd is not None:
            try:
                os.write(kill_fd,b'1');result['kill_events'][-1]['method']='cgroup.kill'
                result['kill_events'][-1]['returned_ns']=now();return
            except OSError as error:
                result['kill_events'][-1]['cgroup_kill_error']=str(error)
        reply=command(['systemctl','--user','kill','--kill-whom=all','--signal=SIGKILL',unit])
        result['kill_events'][-1].update({'method':'systemctl kill owned unit','exit_code':reply['exit_code'],
                                        'returned_ns':now()})
    try:
        if platform.system()!='Linux' or len(result['requests'])!=23:raise RuntimeError('DOMAIN')
        for name,record in manifest['files'].items():
            if sha(inputs/name)!=record['sha256']:raise RuntimeError('PIN_CHANGED:'+name)
        if manifest['original_generation_rayon_num_threads']!='8':raise RuntimeError('THREAD_PROFILE_CHANGED')
        # No fallback if the requested controller settings are refused.
        argv=['systemd-run','--user','--unit='+unit,'--property=Type=exec',
              '--property=CPUQuota=25%','--property=MemoryMax=2147483648','--property=MemorySwapMax=0',
              '--property=TasksMax=256','--property=CPUAccounting=yes','--property=MemoryAccounting=yes',
              '--property=TasksAccounting=yes','--property=Delegate=yes','--property=KillMode=control-group',
              '--property=TimeoutStopSec=1s','--property=SendSIGKILL=yes','--property=RuntimeMaxSec=20s',
              '/usr/bin/sleep','infinity']
        launch=command(argv)
        if launch['exit_code']!=0:raise RuntimeError('REQUESTED_UNIT_LIMITS_UNAVAILABLE')
        created=True
        properties=show(unit);result['unit_before']=properties
        relative=properties.get('ControlGroup','')
        if not relative.startswith('/') or Path(relative).name!=unit:raise RuntimeError('UNEXPECTED_OWN_CGROUP')
        cgroup=Path('/sys/fs/cgroup')/relative.lstrip('/')
        result['cgroup_before']=cgroup_snapshot(cgroup)
        f=result['cgroup_before']['files']
        quota,period=map(int,f['cpu.max'].split())
        if quota*4!=period or f['memory.max']!='2147483648' or f['memory.swap.max']!='0' or f['pids.max']!='256':
            raise RuntimeError('ACTUAL_KERNEL_LIMITS_MISMATCH')
        if any(properties.get(k)!=v for k,v in {'MemoryMax':'2147483648','MemorySwapMax':'0','TasksMax':'256'}.items()):
            raise RuntimeError('SYSTEMD_LIMIT_READBACK_MISMATCH')
        ancestors=[]
        for path in cgroup.parents:
            if path==Path('/sys/fs/cgroup').parent:break
            ancestors.append({'path':str(path),'limits':{n:(path/n).read_text().strip() for n in
                             ('cpu.max','memory.max','memory.swap.max','pids.max') if (path/n).is_file()}})
        result['ancestor_limits']=ancestors
        if not os.access(cgroup/'cgroup.procs',os.W_OK):raise RuntimeError('OWN_CGROUP_MIGRATION_UNAVAILABLE')
        try:kill_fd=os.open(cgroup/'cgroup.kill',os.O_WRONLY)
        except OSError as error:result['direct_cgroup_kill_open_error']=str(error)
        result['actual_kernel_limits_confirmed']=True
        result['harness_sha256']=sha(Path(__file__))
        result['controller_before']=proc(os.getpid())
        result['sentinel_before']=proc(int(properties['MainPID']))
        if sum(r['kind']=='legitimate' for r in result['requests'])!=7 or sum(r['kind']=='malicious' for r in result['requests'])!=16:
            raise RuntimeError('REQUEST_ROLE_COUNTS')
        (out/'node-requests').mkdir()
        output_fds=[]
        for row in result['requests']:
            stdout=out/(f"request-{row['ordinal']:02d}.stdout.log")
            stderr=out/(f"request-{row['ordinal']:02d}.stderr.log")
            row['stdout_file']=stdout.name;row['stderr_file']=stderr.name
            output_fds.append((os.open(stdout,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),
                               os.open(stderr,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)))
        environment=os.environ.copy();environment['RAYON_NUM_THREADS']='8'
        result['child_environment_explicit']={'RAYON_NUM_THREADS':'8'}
        result['cgroup_campaign_start']=cgroup_snapshot(cgroup)
        t0=now();deadline=t0+4000000000
        result.update({'campaign_started_ns':t0,'deadline_ns':deadline})
        event('campaign_started',deadline_ns=deadline,requests=23)
        for index,row in enumerate(result['requests']):
            row['spawn_attempt_ns']=now()
            if row['spawn_attempt_ns']>=deadline:
                row['status']='not_spawned_deadline';continue
            read_gate,write_gate=os.pipe2(os.O_CLOEXEC)
            request_output=out/'node-requests'/f"request-{index:02d}"
            if request_output.exists():raise RuntimeError('OUTPUT_MUST_BE_NEW')
            row['request_output']=str(request_output)
            row['receiver_node_path']=str(request_output/'receiver-node')
            row['receiver_node_existed_before_spawn']=False
            command_args=[str(inputs/'node-adapter'),'exercise',str(inputs/'fixture'),
                          str(inputs/'cases'/row['case']),str(request_output),'none']
            row['command']=command_args
            pid=os.fork()
            if pid==0:
                try:
                    os.close(write_gate)
                    permission=os.read(read_gate,1)
                    if permission!=b'1':os._exit(126)
                    os.close(read_gate)
                    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                    os.setsid()
                    nullfd=os.open('/dev/null',os.O_RDONLY);os.dup2(nullfd,0)
                    os.dup2(output_fds[index][0],1);os.dup2(output_fds[index][1],2)
                    for fd in list(map(int,os.listdir('/proc/self/fd'))):
                        if fd>2:
                            try:os.close(fd)
                            except OSError:pass
                    os.write(2,(json.dumps({'event':'harness_exec_attempt','monotonic_ns':now(),
                        'pid':os.getpid(),'cpu_affinity':sorted(os.sched_getaffinity(0)),
                        'executable':command_args[0]})+'\n').encode())
                    os.execve(command_args[0],command_args,environment)
                except BaseException as error:
                    try:os.write(2,(json.dumps({'harness_exec_error':repr(error)})+'\n').encode())
                    finally:os._exit(127)
            os.close(read_gate);gates[pid]=write_gate;children[pid]=index
            row.update({'pid':pid,'spawned':True,'fork_return_ns':now(),'status':'gated'})
            event('request_forked',ordinal=index,pid=pid)
            (cgroup/'cgroup.procs').write_text(str(pid))
            membership=proc(pid)
            if not membership or membership['cgroup']!='0::'+relative:raise RuntimeError('CHILD_NOT_IN_OWN_LIMITED_CGROUP')
            row['membership_before_release']=membership;row['moved_to_cgroup_ns']=now()
            os.write(write_gate,b'1');os.close(write_gate);del gates[pid]
            row.update({'released_ns':now(),'status':'running'})
            event('request_released',ordinal=index,pid=pid,cgroup=membership['cgroup'])
            for fd in output_fds[index]:os.close(fd)
        next_snapshot=t0
        while children:
            observed=now()
            if observed>=deadline:break
            reap()
            if observed>=next_snapshot:
                snap=cgroup_snapshot(cgroup)
                samples=[]
                for pid,index in children.items():
                    entry=proc(pid)
                    if entry:
                        samples.append(entry)
                        row=result['requests'][index]
                        row['last_proc_observation']=entry
                        if entry.get('exe')==str(inputs/'node-adapter'):
                            row.setdefault('adapter_exec_observed_ns',now())
                event('resource_sample',cgroup=snap,processes=samples)
                next_snapshot=observed+50000000
            time.sleep(min(0.005,max(0,(deadline-now())/1000000000)))
        result['decision_ns']=now()
        result['deadline_expired']=result['decision_ns']>=deadline and bool(children)
        result['unreaped_at_deadline_or_completion']=[{'pid':pid,'ordinal':index} for pid,index in children.items()]
        result['cgroup_at_decision_before_kill']=cgroup_snapshot(cgroup)
        if result['deadline_expired']:
            kill_owned('four_second_deadline')
        else:
            result['cgroup_completed_before_cleanup']=cgroup_snapshot(cgroup)
            kill_owned('all_request_processes_finished')
        end_reap=now()+5000000000
        while children and now()<end_reap:
            reap()
            if children:time.sleep(0.005)
        result['all_spawned_children_reaped']=not children
        result['unit_after_kill']=show(unit)
        result['cgroup_after_kill']=cgroup_snapshot(cgroup)
        result['cleanup_before_stop_ns']=now()
        # Query and retain failed-unit accounting first, then remove our transient unit.
        command(['systemctl','--user','stop',unit])
        command(['systemctl','--user','reset-failed',unit])
        result['unit_after_cleanup']=show(unit)
        result['cgroup_after_cleanup']=cgroup_snapshot(cgroup)
        remaining=[]
        known=[r for r in result['requests'] if r['spawned']]
        for row in known:
            live=proc(row['pid'])
            before=row.get('membership_before_release')
            if live and before and live['starttime_ticks']==before['starttime_ticks']:remaining.append(live)
        result['known_pid_identities_remaining']=remaining
        final_cg=result['cgroup_after_cleanup']
        final_events=final_cg['files'].get('cgroup.events','')
        empty=(not final_cg['exists']) or (final_cg['files'].get('cgroup.procs')=='' and
              isinstance(final_events,str) and 'populated 0' in final_events.splitlines())
        result['cleanup_confirmed']=empty and not remaining and not children
    except BaseException as error:
        result['fatal_error']=repr(error);event('fatal_error',error=repr(error))
    finally:
        for pid,gate in list(gates.items()):
            try:os.close(gate)
            except OSError:pass
        if children:
            if created and cgroup is not None:kill_owned('exception_or_incomplete_cleanup')
            # Only unreaped direct children of this observer; a failed move cannot
            # leave a gated own child outside the unit. No arbitrary PID cleanup.
            for pid in list(children):
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
            until=now()+3000000000
            while children and now()<until:
                reap()
                if children:time.sleep(0.01)
        if created and not result.get('cleanup_confirmed'):
            if cgroup is not None:kill_owned('final_unit_cleanup')
            command(['systemctl','--user','stop',unit])
            result['unit_failure_cleanup']=show(unit)
            command(['systemctl','--user','reset-failed',unit])
            if cgroup is not None:result['cgroup_failure_cleanup']=cgroup_snapshot(cgroup)
        if kill_fd is not None:os.close(kill_fd)
        for row in result['requests']:
            if not row['spawned']:continue
            log=out/row['stdout_file'];error_log=out/row['stderr_file']
            objects=[]
            for line in log.read_text(errors='replace').splitlines():
                try:
                    value=json.loads(line)
                    if isinstance(value,dict):objects.append(value)
                except ValueError:pass
            row['checkpoints']=[o for o in objects if o.get('event')=='checkpoint']
            error_objects=[]
            for line in error_log.read_text(errors='replace').splitlines():
                try:
                    value=json.loads(line)
                    if isinstance(value,dict):error_objects.append(value)
                except ValueError:pass
            row['child_exec_attempts']=[o for o in error_objects if o.get('event')=='harness_exec_attempt']
            row['exec_success_evidence_observed']=('adapter_exec_observed_ns' in row or bool(row['checkpoints']))
            outer=next((o for o in reversed(objects) if isinstance(o.get('result'),dict)),None)
            final=outer.get('result') if outer else None
            row['final_adapter_object']=final
            row['stdout_sha256']=sha(log);row['stderr_sha256']=sha(error_log)
            receiver=Path(row['receiver_node_path'])
            row['receiver_node_exists_after_exit']=receiver.exists()
            row['receiver_node_is_directory_after_exit']=receiver.is_dir()
            row['receiver_node_files_after_exit']=[{'path':str(p.relative_to(receiver)),'bytes':p.stat().st_size}
                for p in sorted(receiver.rglob('*')) if p.is_file()] if receiver.is_dir() else []
            receipt=Path(row['request_output'])/'exercise.json'
            row['exercise_receipt_exists']=receipt.is_file()
            row['exercise_receipt_sha256']=sha(receipt) if receipt.is_file() else None
            row['node_opened_reported']=final.get('node_opened') if final else None
            stages={o.get('stage') for o in row['checkpoints']}
            row['proof_verified_checkpoint_observed']='ProofVerified' in stages
            kind=row['kind'];expected=case_map[row['case']]
            exact_error=expected.get('expected_error')
            required=expected.get('required_checkpoint')
            controlled=(kind=='malicious' and row['exit_code']==0 and final is not None
                and final.get('schema')=='trnm-w1-node-adapter-exercise-v1'
                and final.get('error')==exact_error and required in stages
                and 'ProofVerified' not in stages and final.get('node_opened') is False
                and not receiver.exists())
            outcome=final.get('outcome') if final else None
            admitted=(kind=='legitimate' and row['exit_code']==0 and final is not None
                and final.get('error') is None and final.get('node_opened') is True
                and isinstance(outcome,dict) and outcome.get('native_admitted') is True
                and outcome.get('both_real_proofs_verified') is True
                and 'ProofVerified' in stages and 'NodeCommitted' in stages and receiver.is_dir())
            row['expected_exact_rejection_error']=exact_error
            row['expected_rejection_checkpoint']=required
            row['controlled_late_rejection']=controlled
            row['native_admission_completed']=admitted
            row['rejection_observed_by_deadline']=controlled and row.get('completed_observed_by_deadline',False)
            row['admission_observed_by_deadline']=admitted and row.get('completed_observed_by_deadline',False)
            row['malicious_receiver_created']=kind=='malicious' and receiver.exists()
            if row['rejection_observed_by_deadline']:row['status']='controlled_rejection_observed_before_deadline'
            elif row['admission_observed_by_deadline']:row['status']='native_admission_observed_before_deadline'
            elif controlled:row['status']='controlled_rejection_observed_after_deadline'
            elif admitted:row['status']='native_admission_observed_after_deadline'
            elif row['exit_code']==-signal.SIGKILL:row['status']='sigkill_incomplete_not_rejection'
            elif row['exit_code'] is None:row['status']='exit_unobserved_not_rejection'
            elif row['exit_code'] in (126,127):row['status']='exec_or_gate_failure_not_rejection'
            elif final and isinstance(final.get('error'),str) and final['error'].startswith('REQUEST_CANCELLED:'):
                row['status']='cancelled_not_cryptographic_rejection'
            else:row['status']='other_exit_not_validated_outcome'
        result['input_files_unchanged_after']={name:sha(inputs/name)==record['sha256'] for name,record in manifest['files'].items()}
        result['input_manifest_unchanged_after']=sha(inputs/'manifest.json')==result['input_manifest_sha256']
        result['summary']={'requested':23,'malicious_requested':16,'legitimate_requested':7,
                           'legitimate_distinct_fixtures':1,'single_node_service':False,
                           'spawned':sum(r['spawned'] for r in result['requests']),
                           'adapter_exec_observed':sum('adapter_exec_observed_ns' in r for r in result['requests']),
                           'exec_success_evidence_observed':sum(r.get('exec_success_evidence_observed',False) for r in result['requests']),
                           'rejection_observed_by_deadline':sum(r.get('rejection_observed_by_deadline',False) for r in result['requests']),
                           'admission_observed_by_deadline':sum(r.get('admission_observed_by_deadline',False) for r in result['requests']),
                           'controlled_rejection_observed_after_deadline':sum(r.get('controlled_late_rejection',False) and not r.get('completed_observed_by_deadline',False) for r in result['requests']),
                           'native_admission_observed_after_deadline':sum(r.get('native_admission_completed',False) and not r.get('completed_observed_by_deadline',False) for r in result['requests']),
                           'sigkill_incomplete':sum(r['exit_code']==-signal.SIGKILL for r in result['requests']),
                           'receiver_node_created':sum(r.get('receiver_node_exists_after_exit',False) for r in result['requests']),
                           'malicious_receiver_created':sum(r.get('malicious_receiver_created',False) for r in result['requests']),
                           'unobserved_exit':sum(r['spawned'] and r['exit_code'] is None for r in result['requests']),
                           'sum_worker_user_cpu_seconds':sum((r.get('rusage') or {}).get('ru_utime',0) for r in result['requests']),
                           'sum_worker_system_cpu_seconds':sum((r.get('rusage') or {}).get('ru_stime',0) for r in result['requests']),
                           'input_files_unchanged':all(result['input_files_unchanged_after'].values()) and result['input_manifest_unchanged_after'],
                           'cleanup_confirmed':result.get('cleanup_confirmed',False),
                           'fatal_error':result['fatal_error'],'qualification':'HOLD_NO_GO'}
        result['summary']['status_counts']={s:sum(r['status']==s for r in result['requests']) for s in sorted({r['status'] for r in result['requests']})}
        result['controller_commands']=commands
        result['finished_utc']=datetime.now(timezone.utc).isoformat()
        if t0 is not None:result['observer_total_since_campaign_seconds']=(now()-t0)/1000000000
        save(out/'result.json',result);event('result_written',summary=result['summary'])
        journal.close()
        print(json.dumps(result['summary'],indent=2),flush=True)
    return 0 if result['fatal_error'] is None and result.get('cleanup_confirmed') and result['summary']['input_files_unchanged'] and not result['summary']['malicious_receiver_created'] else 2

if __name__=='__main__':raise SystemExit(main())
