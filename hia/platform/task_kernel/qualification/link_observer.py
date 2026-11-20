"""Actual provider vs actual Rust std::fs::hard_link, including empty paths."""
from pathlib import Path
import ctypes, hashlib, json, os, struct, subprocess, sys, time, traceback

build, original, output = map(Path, sys.argv[1:])
output.mkdir(mode=0o700)
report={'started':True,'finalized':False,'status':'FAIL','cases':[]}
def identity(p):
    b=Path(p).read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def write(): (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
write()
try:
    report['inputs']={'provider':identity(build/'provider.so'),'original':identity(original),'observer_source':identity(__file__)}
    lib=ctypes.CDLL(str(build/'provider.so'))
    lib.trnm_task_provider_new.restype=ctypes.c_void_p
    lib.trnm_task_provider_free.argtypes=[ctypes.c_void_p]
    f=lib.trnm_task_provider;f.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64];f.restype=ctypes.c_uint64
    owner=lib.trnm_task_provider_new();assert owner
    source=output/'source';source.write_bytes(b'actual hard-link bytes\x00\xff')
    scenarios=[('empty-target',os.fsencode(source),b''),('empty-source',b'',os.fsencode(output/'not-created')),('both-empty',b'',b''),('ordinary-target',os.fsencode(source),os.fsencode(output/'ordinary'))]
    try:
        for index,(name,left,right) in enumerate(scenarios):
            rust_right=right+(b'-rust' if right else b'')
            argv=[os.fsencode(original),left,rust_right]
            row={'name':name,'original_argv_hex':[a.hex() for a in argv],'started':True,'completed':False}
            report['cases'].append(row);write()
            (output/f'{index}.stdin.raw').write_bytes(b'')
            try: p=subprocess.run(argv,input=b'',capture_output=True,timeout=30)
            except subprocess.TimeoutExpired as e:
                (output/f'{index}.stdout.raw').write_bytes(e.stdout or b'');(output/f'{index}.stderr.raw').write_bytes(e.stderr or b'');row['error']='TimeoutExpired';write();raise
            except OSError as e:
                (output/f'{index}.stdout.raw').write_bytes(b'');(output/f'{index}.stderr.raw').write_bytes(b'');row['error']=repr(e);write();raise
            (output/f'{index}.stdout.raw').write_bytes(p.stdout);(output/f'{index}.stderr.raw').write_bytes(p.stderr)
            row.update(completed=True,exit=p.returncode);write();p.check_returncode()
            request=struct.pack('<QQQ',0,0,len(left))+left+right
            inp=ctypes.create_string_buffer(request);out=ctypes.create_string_buffer(24)
            result=int(f(owner,20,inp,len(request),out,24))
            expected=json.loads(p.stdout);actual=struct.unpack('<QQQ',out.raw)
            row.update(original=expected,provider_request_hex=request.hex(),provider_return=result,provider_output_hex=out.raw.hex(),equal=result==24 and actual==(expected['errno'],0,0))
            if expected['errno']==0:
                assert Path(os.fsdecode(right)).read_bytes()==source.read_bytes()
                assert os.stat(right).st_ino==source.stat().st_ino==os.stat(rust_right).st_ino
            write()
        report.update(finalized=True,status='PASS' if all(r['equal'] for r in report['cases']) else 'FAIL')
        write()
    finally: lib.trnm_task_provider_free(owner)
    if report['status']!='PASS': raise AssertionError('Actual provider differs from actual Rust hard_link')
except BaseException as e:
    report.update(status='FAIL',failure=repr(e));write();(output/'failure.traceback').write_text(traceback.format_exc());raise
print(json.dumps({'status':'PASS','actual_original_provider_pairs':len(report['cases'])}))
