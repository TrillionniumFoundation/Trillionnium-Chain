import pathlib,subprocess,os,json,hashlib,time
r=pathlib.Path('/home/qian-qi/chain-hepta-review-340e')
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()
assert head=='9891218ac5f8df50e545dcac36bd10399c95195e';assert not subprocess.check_output(['git','status','--porcelain'],cwd=r)
facts={p:{'free_bytes':os.statvfs(p).f_bavail*os.statvfs(p).f_frsize,'free_inodes':os.statvfs(p).f_favail,'device':os.stat(p).st_dev} for p in ['/tmp','/home/qian-qi']}
print(json.dumps({'source':head,'filesystem':facts}),flush=True)
assert facts['/home/qian-qi']['free_bytes']>=12*1024**3,'insufficient private-home capacity'
assert facts['/home/qian-qi']['free_inodes']>=100000,'insufficient private-home inodes'
tmp=pathlib.Path('/home/qian-qi/chain-hepta-review-340e-tmp-05');assert not tmp.exists();tmp.mkdir(mode=0o700)
out=pathlib.Path('/home/qian-qi/chain-hepta-review-340e-validation-05');assert not out.exists()
target=pathlib.Path('/home/qian-qi/chain-hepta-review-340e-native-target-01');assert not target.exists(),'unknown existing target must be reconciled'
p=pathlib.Path('/home/qian-qi/chain-hepta-validate-review-340e-v3.py');raw=p.read_bytes();s=raw.decode()
assert s.count('chain-hepta-review-340e-validation-03')==1
s=s.replace('chain-hepta-review-340e-validation-03','chain-hepta-review-340e-validation-05')
assert s.count("env=os.environ.copy();")==1
s=s.replace("env=os.environ.copy();","env=os.environ.copy();env['TMPDIR']="+repr(str(tmp))+";")
s=s.replace("'native_execution_performed':False","'native_business_campaign_performed':False,'native_tests_performed':False,'native_compile_lint_requested':True")
v=pathlib.Path('/home/qian-qi/chain-hepta-validate-review-340e-v5.py');compile(s,str(v),'exec');v.open('x').write(s)
record=pathlib.Path('/home/qian-qi/chain-hepta-review-340e-validation-05-input.json');record.open('x').write(json.dumps({'head':head,'filesystem_before':facts,'tmpdir':str(tmp),'recipe_before_sha256':hashlib.sha256(raw).hexdigest(),'recipe_sha256':hashlib.sha256(s.encode()).hexdigest(),'time_unix':time.time()},indent=2)+'\n')
q=subprocess.run(['/usr/bin/python3',str(v)],cwd=r)
print('VALIDATION_V4_EXIT',q.returncode,flush=True)
raise SystemExit(q.returncode)
