import hashlib,json,os,pathlib
p=pathlib.Path("/home/qq/chain-system-security-native-receipts-20261112-306929/sqlite-fixed-bac6b765.launch-input.json")
body=p.read_bytes()
assert len(body)==2741 and hashlib.sha256(body).hexdigest()=="2de84ffe0d960f4b6d0f20604090f86fa173bac3e4ebf0f7626875214bf7f63a",'launch input changed'
c=json.loads(body)
assert c['source']=='bac6b7659bd7e2d633e25c2da0add60f6a10c7fb'
checks=[(c['args'][0],c['driver_sha256']),(c['args'][c['args'].index('--plan')+1],c['plan_sha256']),(c['provider_env_path'],c['provider_env_sha256'])]
for name,pin in checks:
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==pin,'fixed input changed: '+name
provider={}
for line in pathlib.Path(c['provider_env_path']).read_text().splitlines():
    key,value=line.split('=',1);provider[key]=value
assert len(provider)==7 and all(c['env'].get(k)==v for k,v in provider.items()),'provider launch mismatch'
env=os.environ.copy()
env.update(c['env'])
os.chdir(c['cwd'])
print(json.dumps({'event':'immutable_launch_inputs_verified','source':c['source'],'launch_input_sha256':hashlib.sha256(body).hexdigest(),'provider_env_sha256':c['provider_env_sha256']}),flush=True)
os.execve(c['executable'],[c['executable'],*c['args']],env)
