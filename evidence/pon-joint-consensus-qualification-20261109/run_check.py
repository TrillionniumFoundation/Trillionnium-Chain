from pathlib import Path
import datetime, json, subprocess, sys, time
name, expected, *command = sys.argv[1:]
root = Path(__file__).resolve().parent
repo = Path('/workspace/scratch/b6ec4f0afca8/chain-joint-daa')
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
commit = subprocess.check_output(['git','rev-parse','HEAD'], cwd=repo,text=True).strip()
tree = subprocess.check_output(['git','rev-parse','HEAD^{tree}'], cwd=repo,text=True).strip()
start = time.monotonic()
with (root/(name+'.log')).open('wb') as log:
    result = subprocess.run(command,cwd=repo,stdout=log,stderr=subprocess.STDOUT)
record = {'name':name,'command':command,'cwd_scope':'repository root','started_utc':started,'duration_seconds':round(time.monotonic()-start,3),'source_commit':commit,'source_tree':tree,'exit_code':result.returncode,'expected_exit_code':int(expected),'expectation_met':result.returncode==int(expected),'log':name+'.log'}
(root/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
if not record['expectation_met']:
    print((root/(name+'.log')).read_text()[-12000:])
sys.exit(0 if record['expectation_met'] else 1)
