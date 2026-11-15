#!/usr/bin/env python3
"""One exact 16-request/4s research campaign in an owned resource-limited unit.

The outside observer forks gated children, moves each blocked child to its own
unit's cgroup, confirms membership, then releases it to exec the pinned verifier.
All verifier descendants inherit that cgroup. The observer retains wait4 status
and rusage even when the whole workload cgroup is SIGKILLed at the deadline.
No cgroup/resource fallback, sudo, Node integration, or timeout-as-rejection.
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
        'tasks_max':256,'deadline_seconds':4,'requests':16,'rayon_num_threads':8}
PROPERTIES=('Id','InvocationID','ActiveState','SubState','Result','MainPID','ControlGroup',
            'CPUQuotaPerSecUSec','CPUQuotaPeriodUSec','MemoryMax','MemorySwapMax','TasksMax',
            'CPUUsageNSec','MemoryCurrent','MemoryPeak','TasksCurrent','TasksPeak',
            'KillMode','Delegate','RuntimeMaxUSec','ExecMainCode','ExecMainStatus')
CG_FILES=('cpu.max','cpu.stat','memory.max','memory.current','memory.peak','memory.swap.max',
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
    unit='w1-pressure-f16ac5-'+uuid.uuid4().hex[:12]+'.service'
    result={'schema':'w1-pressure-16x4s-observation-v1','started_utc':datetime.now(timezone.utc).isoformat(),
            'limits_requested':LIMITS,'coordination_cleared':args.coordination_cleared,
            'input_manifest_sha256':sha(inputs/'manifest.json'),'unit':unit,
            'production_node':False,'global_rejection_cost_bound':False,'qualification':'HOLD_NO_GO',
            'observer_outside_workload_cgroup':True,
            'deadline_scope':'from first attempted fork through all16 fresh-process verifications; setup/pinning outside',
            'observer_cost_excluded_from_quota':True,
            'cache_state':'not flushed; pinning read all inputs before the campaign',
            'machine':platform.uname()._asdict(),'clock_ticks_per_second':os.sysconf('SC_CLK_TCK'),
            'requests':[{'ordinal':i,'case':name,'spawned':False,'status':'not_started','pid':None,
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
        if cgroup.name!=unit or not re.fullmatch(r'w1-pressure-f16ac5-[0-9a-f]{12}\.service',unit):
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
        if platform.system()!='Linux' or len(result['requests'])!=16:raise RuntimeError('DOMAIN')
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
        event('campaign_started',deadline_ns=deadline,requests=16)
        for index,row in enumerate(result['requests']):
            row['spawn_attempt_ns']=now()
            if row['spawn_attempt_ns']>=deadline:
                row['status']='not_spawned_deadline';continue
            read_gate,write_gate=os.pipe2(os.O_CLOEXEC)
            command_args=[str(inputs/'verifier'),'verify',str(inputs/'cases'/row['case']/'statement.bin'),
                          str(inputs/'expected-header.bin'),str(inputs/'expected-artifacts.bin'),
                          str(inputs/'cases'/row['case'])]
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
                        if entry.get('exe')==str(inputs/'verifier'):
                            row.setdefault('verifier_exec_observed_ns',now())
                event('resource_sample',cgroup=snap,processes=samples)
                next_snapshot=observed+50000000
            time.sleep(min(0.005,max(0,(deadline-now())/1000000000)))
        result['decision_ns']=now()
        result['deadline_expired']=result['decision_ns']>=deadline and bool(children)
        result['unreaped_at_deadline_or_completion']=[{'pid':pid,'ordinal':index} for pid,index in children.items()]
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
            row['phase_events']=[o for o in objects if 'phase' in o]
            row['final_verifier_object']=next((o for o in reversed(objects) if 'qualification' in o),None)
            row['stdout_sha256']=sha(log);row['stderr_sha256']=sha(error_log)
            final=row['final_verifier_object'] or {}
            expected_error=case_map[row['case']]['historical_expected_rejection'].get('error')
            phase_names={o['phase'] for o in row['phase_events']}
            required_phase='sha_stark_verify' if row['case'].startswith('sha-') else 'arith_stark_verify'
            controlled=(row['exit_code']==1 and final.get('status')=='REJECTED_OR_FAILED' and
                        final.get('error')==expected_error and required_phase in phase_names)
            row['expected_exact_rejection_error']=expected_error
            row['expected_rejection_phase']=required_phase
            row['controlled_late_rejection']=controlled
            row['rejection_completed_by_deadline']=controlled and row.get('completed_observed_by_deadline',False)
            if row['rejection_completed_by_deadline']:row['status']='controlled_rejection_before_deadline'
            elif controlled:row['status']='controlled_rejection_after_deadline_not_success'
            elif row['exit_code']==-signal.SIGKILL:row['status']='killed_incomplete_not_rejection'
            elif row['exit_code'] is None:row['status']='exit_unobserved_not_rejection'
            else:row['status']='other_exit_not_validated_rejection'
        result['summary']={'requested':16,'spawned':sum(r['spawned'] for r in result['requests']),
                           'verifier_exec_observed':sum('verifier_exec_observed_ns' in r for r in result['requests']),
                           'rejection_completed_by_deadline':sum(r.get('rejection_completed_by_deadline',False) for r in result['requests']),
                           'controlled_rejection_after_deadline':sum(r.get('controlled_late_rejection',False) and not r.get('completed_observed_by_deadline',False) for r in result['requests']),
                           'killed_incomplete':sum(r['exit_code']==-signal.SIGKILL for r in result['requests']),
                           'unobserved_exit':sum(r['spawned'] and r['exit_code'] is None for r in result['requests']),
                           'sum_worker_user_cpu_seconds':sum((r.get('rusage') or {}).get('ru_utime',0) for r in result['requests']),
                           'sum_worker_system_cpu_seconds':sum((r.get('rusage') or {}).get('ru_stime',0) for r in result['requests']),
                           'cleanup_confirmed':result.get('cleanup_confirmed',False),
                           'fatal_error':result['fatal_error'],'qualification':'HOLD_NO_GO'}
        result['controller_commands']=commands
        result['finished_utc']=datetime.now(timezone.utc).isoformat()
        if t0 is not None:result['observer_total_since_campaign_seconds']=(now()-t0)/1000000000
        save(out/'result.json',result);event('result_written',summary=result['summary'])
        journal.close()
        print(json.dumps(result['summary'],indent=2),flush=True)
    return 0 if result['fatal_error'] is None and result.get('cleanup_confirmed') else 2

if __name__=='__main__':raise SystemExit(main())
