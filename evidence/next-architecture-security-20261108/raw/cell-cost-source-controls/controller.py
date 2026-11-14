from pathlib import Path
import datetime,hashlib,json,os,signal,subprocess,time
r=Path('/home/qian-qi/work/chain-next-architecture-security-20261108-8720')
v=Path(str(r)+'-validation');d=Path(str(r)+'-delivery');head='a93024cfdd4f4a4dfede03507f3b3289385bfc49'
end=time.monotonic()+1200
while not (v/'attempt-4/summary.json').exists():
    if time.monotonic()>=end:raise SystemExit('complete campaign receipt not available within controller wait')
    time.sleep(5)
summary=json.loads((v/'attempt-4/summary.json').read_text())
assert summary['source_commit']==head and summary['source_before_after_identical'] is True and summary['all_planned_commands_completed'] is True
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()==head
assert hashlib.sha256((d/'measure_next_cells.py').read_bytes()).hexdigest()=='c901b20f750e7decb65c254349b23960f158ba6e500307b6e4f722406b8bc9fe'
out=v/'cell-cost-source-controls';out.mkdir(exist_ok=False)
(out/'controller.py').write_bytes(Path(__file__).read_bytes())
(out/'measure_next_cells.py').write_bytes((d/'measure_next_cells.py').read_bytes())
rows=[]
def run(label,args,timeout):
    start=time.monotonic_ns();timed_out=False
    with (out/(label+'.stdout')).open('xb') as so,(out/(label+'.stderr')).open('xb') as se:
        p=subprocess.Popen(args,cwd=r,stdout=so,stderr=se,start_new_session=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        try:code=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(p.pid,signal.SIGTERM)
            try:code=p.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);code=p.wait(timeout=30)
    row={'label':label,'args':args,'source_commit':head,'exit_code':code,'timeout':timed_out,'elapsed_wall_ns':time.monotonic_ns()-start}
    for name in ('stdout','stderr'):
        raw=(out/(label+'.'+name)).read_bytes();row[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    rows.append(row);(out/'commands.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n');print(json.dumps(row,sort_keys=True),flush=True)
    return code==0 and not timed_out
common=['python3','-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',head,'--output']
pre=run('source-before',common+[str(out/'source-before.json')],600)
measured=False
if pre:
    (out/'environment-before.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'io_pressure':Path('/proc/pressure/io').read_text(),'loadavg':Path('/proc/loadavg').read_text(),'scope':'shared desktop, not original Host qualification'},indent=2,sort_keys=True)+'\n')
    measured=run('measurement',['python3','-B',str(d/'measure_next_cells.py'),'--repo',str(r),'--target-dir',str(r)+'-target','--output-dir',str(v/'cell-cost-observation')],1250)
post=run('source-after',common+[str(out/'source-after.json')],600)
equal=pre and post and (out/'source-before.json').read_bytes()==(out/'source-after.json').read_bytes()
result={'source_commit':head,'source_before_after_identical':equal,'measurement_passed':measured,'qualification':'HOLD_NO_GO','original_host_contract_executed':False,'real_models_loaded':False,'economic_sustainability_qualified':False}
(out/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True),flush=True)
raise SystemExit(0 if pre and measured and post and equal else 1)
