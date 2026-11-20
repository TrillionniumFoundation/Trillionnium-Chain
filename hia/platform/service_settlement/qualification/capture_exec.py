from pathlib import Path
import hashlib,json,os,resource,stat,sys
request=json.loads(Path(sys.argv[1]).read_bytes())
root=Path(request['output']);assert root.is_dir() and not root.is_symlink()
exe=Path(request['argv'][0]);fd=os.open(exe,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
s=os.fstat(fd);assert stat.S_ISREG(s.st_mode)
with os.fdopen(os.dup(fd),'rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
assert {'bytes':s.st_size,'sha256':digest}==request['executable']
assert request['argv']==[str(exe),'generate'] and request['source_report_status']=='FRESH_ORIGINAL_FULL_ROSTER_NESTED_PHASES_CLIPPY_FMT_AND_ADAPTER_BUILD_PASS_GENERATOR_PENDING'
stdout=os.open(root/'original.stdout.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
stderr=os.open(root/'original.stderr.raw',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
assert resource.getrlimit(resource.RLIMIT_FSIZE)[1] in (-1,resource.RLIM_INFINITY) or resource.getrlimit(resource.RLIMIT_FSIZE)[1]>=67108864
resource.setrlimit(resource.RLIMIT_FSIZE,(67108864,67108864))
intent={'argv':request['argv'],'cwd':os.getcwd(),'actual_executable':request['executable'],'exec_by_open_verified_fd':True,'stdout':str(root/'original.stdout.raw'),'stderr':str(root/'original.stderr.raw'),'stdout_max_bytes':67108864,'stdin_sha256':hashlib.sha256(b'').hexdigest()}
(root/'actual-exec-intent.json').write_text(json.dumps(intent,sort_keys=True,indent=2)+'\n')
os.dup2(stdout,1);os.dup2(stderr,2);os.close(stdout);os.close(stderr)
os.execve(fd,request['argv'],dict(os.environ))
