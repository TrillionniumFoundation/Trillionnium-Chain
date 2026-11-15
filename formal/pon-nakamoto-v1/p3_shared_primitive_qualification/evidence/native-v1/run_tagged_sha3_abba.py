#!/usr/bin/env python3
"""Complete fresh W1 prepare/prove/independent-receive ABBA experiment.

A is the unchanged original packed-carry runner; B is the tagged SHA3 profile.
Fixtures are preconstructed inputs: mining/search is outside the measured scope.
All planned runs, failures, stdout/stderr, resource reports and source hashes stay.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import time


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def source_snapshot(repo, crate, bins, fixtures):
    sources = sorted(p for name in ['src','examples','tests'] for p in (crate/name).rglob('*') if p.is_file() and p.suffix in ['.rs','.json'])
    sources += [crate/'Cargo.toml',crate/'Cargo.lock']
    return {
        'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
        'tracked_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD','--binary'],cwd=repo)).hexdigest(),
        'source_files':{str(p.relative_to(crate)):sha(p) for p in sources},
        'binaries':{k:{'path':str(p),'sha256':sha(p)} for k,p in bins.items()},
        'fixtures':{k:{n:{'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size} for n,p in v.items()} for k,v in fixtures.items()},
        'driver_sha256':sha(Path(__file__)),
    }


def system_snapshot():
    cgroup = Path('/proc/self/cgroup').read_text()
    rel = next(line.split(':',2)[2] for line in cgroup.splitlines() if line.startswith('0::'))
    group = Path('/sys/fs/cgroup')/rel.lstrip('/')
    return {
        'monotonic_ns':time.monotonic_ns(),'utc_unix_ns':time.time_ns(),
        'loadavg':Path('/proc/loadavg').read_text().strip(),
        'cpu_pressure':Path('/proc/pressure/cpu').read_text().strip(),
        'memory_pressure':Path('/proc/pressure/memory').read_text().strip(),
        'cgroup':cgroup,
        'cgroup_values':{n:(group/n).read_text().strip() for n in ['cpu.max','cpu.stat','memory.max','memory.current','memory.peak','memory.events'] if (group/n).exists()},
    }


def stage(argv,dest,crate,env,timeout):
    dest.mkdir(parents=True,exist_ok=False)
    usage=dest/'resource.txt';before=system_snapshot();start=time.monotonic_ns();expired=False
    with (dest/'stdout.jsonl').open('wb') as so,(dest/'stderr.txt').open('wb') as se:
        process=subprocess.Popen(['/usr/bin/time','-v','-o',str(usage),*map(str,argv)],cwd=crate,env=env,stdout=so,stderr=se,start_new_session=True)
        try:
            code=process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired=True
            os.killpg(process.pid,signal.SIGTERM)
            try:code=process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);code=process.wait()
    events=[]
    for line in (dest/'stdout.jsonl').read_text().splitlines():
        try:events.append(json.loads(line))
        except json.JSONDecodeError:pass
    resource=usage.read_text() if usage.exists() else ''
    rss=re.search(r'Maximum resident set size \(kbytes\): (\d+)',resource)
    report={'argv':list(map(str,argv)),'exit_code':code,'timeout':expired,'outer_wall_s':(time.monotonic_ns()-start)/1e9,
        'peak_rss_kib':int(rss.group(1)) if rss else None,'report':events[-1] if events else None,
        'before':before,'after':system_snapshot()}
    write(dest/'stage.json',report)
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo',required=True,type=Path)
    ap.add_argument('--target',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--fixtures',required=True,type=Path)
    ap.add_argument('--timeout',type=float,default=1800)
    a=ap.parse_args();repo=a.repo.resolve();crate=repo/'formal/pon-nakamoto-v1/w1_public_stark_research'
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    bins={'A':a.target/'release/examples/packed_carry_backend','B':a.target/'release/examples/tagged_sha3_backend'}
    fixtures={case:{name:a.fixtures/f'{case}.{name}.bin' for name in ['input','prefix','expected-header','artifacts']} for case in ['retained','dense']}
    cpus=sorted(os.sched_getaffinity(0))[:8];assert len(cpus)==8
    os.sched_setaffinity(0,cpus);env=dict(os.environ,RAYON_NUM_THREADS='8')
    order=[{'case':case,'variant':variant} for case in fixtures for variant in 'ABBA']
    m={'schema':'w1-tagged-sha3-fresh-complete-abba-v1','qualification':'HOLD_NO_GO',
       'comparison':'B tagged SHA3-512 profile SHA1 + packed4 arithmetic versus A unchanged original Poseidon2 profile SHA1 + packed4 arithmetic',
       'scope':'Fresh full prepare/prove/independent-verifier process chain on preconstructed raw/prefix fixtures; excludes mining/search, production Node, global runtime bounds and all cryptographic security qualification',
       'fresh_full_proofs_planned':8,'distinct_input_tasks':2,'small_test_proofs_counted':False,
       'shared_parameters':'Goldilocks, quadratic extension, original SHA AIR, packed carry AIR, log blowup2, queries64, binary FRI, cap0, no grinding, no ZK',
       'changed_parameters':'Commitment digest raw512bits; framed SHA3 leaf/branch/transcript; typed statement context; separate proof magic; profile metadata',
       'concrete_security_bits':None,'complete_qrom_security_bits':None,'lifecycle_security_bits':None,
       'source_before':source_snapshot(repo,crate,bins,fixtures),'platform':platform.platform(),
       'cpu_affinity':cpus,'rayon_threads':8,'per_stage_timeout_s':a.timeout,'host_exclusive':False,
       'initial_system':system_snapshot(),'planned_order':order,'runs':[]}
    write(out/'manifest.json',m)
    for i,planned in enumerate(order):
        case=planned['case'];variant=planned['variant'];f=fixtures[case];binary=bins[variant]
        run=out/f'{i:02d}-{case}-{variant}';run.mkdir();prepared=run/'prepared';proof=run/'proof';stages={}
        stages['prepare']=stage([binary,'prepare',f['input'],f['prefix'],f['expected-header'],f['artifacts'],prepared],run/'prepare_stage',crate,env,a.timeout)
        if stages['prepare']['exit_code']==0:
            stages['prove']=stage([binary,'prove',prepared/'statement.bin',f['expected-header'],f['artifacts'],proof],run/'prove_stage',crate,env,a.timeout)
        if stages.get('prove',{}).get('exit_code')==0:
            stages['verify']=stage([binary,'verify',prepared/'statement.bin',f['expected-header'],f['artifacts'],proof],run/'verify_stage',crate,env,a.timeout)
        final=stages.get('verify',{}).get('report') or {}
        good=len(stages)==3 and all(x['exit_code']==0 and not x['timeout'] for x in stages.values()) and final.get('status')=='VERIFIED_COMPLETE_W1_RESEARCH_ONLY' and final.get('qualification')=='HOLD_NO_GO'
        payload={str(p.relative_to(run)):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in [prepared/'statement.bin',proof/'sha.proof.bin',proof/'arith.proof.bin'] if p.exists()}
        row={**planned,'index':i,'full_fresh_proof_verified':good,'stages':stages,'files':payload,
            'pipeline_outer_s':sum(x['outer_wall_s'] for x in stages.values()),
            'pipeline_peak_rss_kib':max((x['peak_rss_kib'] or 0) for x in stages.values()),
            'transmitted_bytes':sum(x['bytes'] for x in payload.values()) if good else None}
        m['runs'].append(row);write(out/'manifest.json',m)
        print(json.dumps({'index':i,**planned,'ok':good,'pipeline_s':row['pipeline_outer_s'],'verify_s':stages.get('verify',{}).get('outer_wall_s'),'rss_kib':row['pipeline_peak_rss_kib'],'payload_bytes':row['transmitted_bytes']}),flush=True)
    m['source_after']=source_snapshot(repo,crate,bins,fixtures)
    m['source_binaries_and_inputs_unchanged']=m['source_before']==m['source_after']
    m['completed_full_proofs']=sum(r['full_fresh_proof_verified'] for r in m['runs'])
    m['all_planned_runs_finished']=len(m['runs'])==len(order)
    summaries={}
    for case in ['all',*fixtures]:
        summaries[case]={}
        for variant in bins:
            rows=[r for r in m['runs'] if r['variant']==variant and (case=='all' or r['case']==case) and r['full_fresh_proof_verified']]
            summaries[case][variant]={'count':len(rows)}
            for field in ['pipeline_outer_s','pipeline_peak_rss_kib','transmitted_bytes']:
                summaries[case][variant][field]=statistics.median(r[field] for r in rows) if rows else None
            for phase in ['prepare','prove','verify']:
                summaries[case][variant][phase+'_outer_s']=statistics.median(r['stages'][phase]['outer_wall_s'] for r in rows) if rows else None
    m['observed_medians']=summaries;m['final_system']=system_snapshot()
    m['result']='PASS' if m['completed_full_proofs']==8 and m['source_binaries_and_inputs_unchanged'] else 'FAIL'
    write(out/'manifest.json',m)
    write(out/'summary.json',{k:m[k] for k in ['schema','qualification','scope','result','completed_full_proofs','distinct_input_tasks','source_binaries_and_inputs_unchanged','observed_medians']})
    print(json.dumps({'result':m['result'],'medians':summaries}),flush=True)
    return 0 if m['result']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
