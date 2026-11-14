import os,sys,hashlib,pathlib
source=sys.argv[1];D=pathlib.Path('/private/tmp/chain-prci-H5DF-service-model-original-logs-20261114-v1')
assert sys.flags.optimize==0
compile(source,str(D/'producer.py'),'exec',optimize=0)
D.mkdir(mode=0o700)
with (D/'producer.py').open('xb')as f:f.write(source.encode())
with (D/'launcher.py').open('xb')as f:f.write(sys.argv[2].encode())
env=dict(os.environ);env.pop('GH_DEBUG',None);env['GH_HOST']='github.com';env['PYTHONDONTWRITEBYTECODE']='1';env['PYTHONOPTIMIZE']='0'
print('FIXED_PRODUCER '+str(D/'producer.py')+' '+hashlib.sha256(source.encode()).hexdigest(),flush=True)
os.execve('/opt/homebrew/bin/python3',['/opt/homebrew/bin/python3','-B',str(D/'producer.py')],env)
