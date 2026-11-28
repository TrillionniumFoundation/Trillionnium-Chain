"""Fresh finite SettlementEngine gate. Every process and original observation is retained."""
from pathlib import Path
import argparse,contextlib,hashlib,json,os,re,runpy,shutil,sys,time,traceback
from .contract import ROOT,HERE,SCHEMA,COUNTS,LIMITS,FALSE_SCOPES,canonical,document,digest,file_identity,source_inputs,repository,output_directory
from .process import run,collector
from .qualification.evidence import capture,Evidence
def save(path,value):path.write_bytes(canonical(value)+b'\n')
FORBIDDEN=('PYTHONOPTIMIZE','PYTHONHOME','PYTHONPATH','LD_PRELOAD','LD_LIBRARY_PATH','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_RUSTC','CARGO_TARGET_DIR','CC','CFLAGS','CPPFLAGS','LDFLAGS')
def qualify(output,rust_bin):
 assert __debug__ and not any(os.environ.get(k) for k in FORBIDDEN), 'Unadmitted tool/environment override'
 output=output_directory(output);output.mkdir(mode=0o700)
 start=time.monotonic_ns();deadline=start+1200*10**9
 python=Path(sys.executable).resolve(strict=True);rust_bin=rust_bin.resolve(strict=True)
 home=Path(os.environ['HOME']).resolve(strict=True);cargo_home=Path(os.environ.get('CARGO_HOME',str(home/'.cargo'))).resolve(strict=True)
 report={'schema':SCHEMA,'status':'INCOMPLETE','finalized':False,**FALSE_SCOPES,'prior_execution_reused':False,'source_inputs_stable':False,'limits':LIMITS}
 save(output/'report.json',report);external={}
 def actual(path):
  path=Path(path).resolve(strict=True);value=file_identity(path);old=external.setdefault(str(path),value);assert old==value
  return {'path':str(path),**value}
 runtime_env={'PATH':'/usr/bin:/bin','HOME':str(home),'PYTHONDONTWRITEBYTECODE':'1'}
 build_env=dict(runtime_env)
 for key in ['HIA_TOOLCHAIN_ROOT','HIA_NATIVE_COMPILER','HIA_NATIVE_COMPILER_SHA256']:
  assert os.environ.get(key),key
  build_env[key]=os.environ[key]
 session={'schema':'trnm.hia.service-settlement-engine.execution.v1','output_root':str(output),'source_root':str(ROOT),'start_monotonic_ns':start,'deadline_monotonic_ns':deadline,'boot_id':collector().boot_id(),'python':actual(python),'rust_bin':str(rust_bin),'home':str(home),'cargo_home':str(cargo_home),'limits':LIMITS,'runtime_environment':runtime_env,'build_environment':build_env,'argv':[str(python),*sys.argv],'repository':repository(),'source_inputs':source_inputs()}
 save(output/'session.json',session);save(output/'source-before.json',session['source_inputs'])
 capture(output,session['source_inputs'],external)
 (output/'stages').mkdir()
 def time_left():assert time.monotonic_ns()<deadline,'Global 1200 second qualification deadline exhausted'
 def stage(name,argv,seconds=240,env=None):
  time_left();assert deadline-time.monotonic_ns()>=seconds*10**9,'Not enough original qualification time left for a complete stage'
  row=run(output/'stages'/name,argv,cwd=ROOT,environment=runtime_env if env is None else env,seconds=seconds)
  actual(row['argv'][0] if str(row['argv'][0]).startswith('/') else shutil.which(row['argv'][0],path=(runtime_env if env is None else env)['PATH']))
  time_left();assert row['status']=='PASS',(name,row.get('exception'))
  return row
 def inline(name,module,argv):
  time_left();save(output/(name+'-invocation.json'),{'module':module,'argv':argv,'python':session['python'],'cwd':str(ROOT),'deadline_monotonic_ns':deadline,'source':actual(HERE/(module.split('.')[-1]+'.py')) if name=='original' else actual(HERE/'qualification/generator.py')})
  prior=sys.argv;sys.argv=[module,*argv];then=time.monotonic_ns();code=None
  try:
   with (output/(name+'-launcher.stdout.raw')).open('x') as stdout,(output/(name+'-launcher.stderr.raw')).open('x') as stderr,contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
    try:runpy.run_module(module,run_name='__main__');code=0
    except SystemExit as error:code=error.code
  finally:
   sys.argv=prior
   save(output/(name+'-invocation-result.json'),{'exit_code':code,'started_monotonic_ns':then,'completed_monotonic_ns':time.monotonic_ns(),'stdout':file_identity(output/(name+'-launcher.stdout.raw')),'stderr':file_identity(output/(name+'-launcher.stderr.raw'))})
  assert type(code) is int and code==0,(name,code)
  time_left()
 try:
  stage('preflight',[str(Path('/usr/bin/bash').resolve()),'scripts/project-preflight.sh']+(['--audit'] if session['repository']['branch']=='HEAD' else []),30)
  inline('original','hia.platform.service_settlement.original',['--output',str(output/'original'),'--rust-bin',str(rust_bin),'--head',session['repository']['head'],'--tree',session['repository']['tree'],'--deadline-monotonic-ns',str(deadline)])
  inline('generator','hia.platform.service_settlement.qualification.generator',['--output',str(output/'generator'),'--original',str(output/'original'),'--rust-bin',str(rust_bin),'--head',session['repository']['head'],'--tree',session['repository']['tree']])
  stage('build',[str(python),'-B','-m','hia.platform.service_settlement.build','--output',str(output/'build')],env=build_env)
  original=document((output/'original/qualification/report.json').read_bytes())
  def loader(name,images):
   stage(name,['/usr/bin/bash','/usr/bin/ldd',*map(str,images)],30)
   raw=(output/'stages'/name/'stdout.raw').read_bytes();assert b'not found' not in raw
   for path in re.findall(r'(/[A-Za-z0-9_./+:-]+)',raw.decode()):
    p=Path(path.rstrip(':'))
    if p.is_file():actual(p)
  loader('runtime-loader',[python,output/'build/public/settlement-engine.so',output/'build/units/arithmetic/module.so',Path(original['original_adapter_binary']['path'])])
  stage('native',[str(python),'-B','-m','hia.platform.service_settlement.qualification.native','--build',str(output/'build/public'),'--fee-build',str(output/'build/units/arithmetic'),'--output',str(output/'native')])
  stage('allocator-build',[str(python),'-B','-m','hia.platform.service_settlement.qualification.build_allocator','--build',str(output/'build/public'),'--output',str(output/'allocator-build')])
  loader('allocator-loader',[output/'allocator-build/engine-observed.so'])
  stage('allocator',[str(python),'-B','-m','hia.platform.service_settlement.qualification.allocator','--build',str(output/'build/public'),'--observer',str(output/'allocator-build'),'--output',str(output/'allocator')])
  for path in ['original/qualification/dependency-source-before.json','generator/qualification/source-before.json']:
   for name,value in document((output/path).read_bytes()).items():assert actual(name)=={'path':name,**value}
  for row in document((output/'original/qualification/actual-toolchains.json').read_bytes()).values():assert actual(row['path'])==row
  build=document((output/'build/build.json').read_bytes())
  for row in build['tools_before'].values():assert actual(row['resolved_path'])=={'path':row['resolved_path'],**{k:row[k] for k in ['bytes','sha256']}}
  toolchain=Path(build_env['HIA_TOOLCHAIN_ROOT']).resolve(strict=True)
  for name,row in build['toolchain_sources_before'].items():assert actual(toolchain/name)=={'path':str(toolchain/name),**{k:row[k] for k in ['bytes','sha256']}}
  runtime_tools={k:actual(p) for k,p in [('bash','/usr/bin/bash'),('git','/usr/bin/git'),('ldd','/usr/bin/ldd'),('readelf','/usr/bin/readelf'),('nm','/usr/bin/nm')]}
  allocator=document((output/'allocator-build/build.json').read_bytes())
  for row in allocator['tools'].values():assert actual(row['path'])==row
  save(output/'runtime-tools.json',runtime_tools)
  save(output/'source-after.json',source_inputs());save(output/'repository-after.json',repository())
  assert document((output/'source-after.json').read_bytes())==session['source_inputs'] and document((output/'repository-after.json').read_bytes())==session['repository']
  capture(output,session['source_inputs'],external)
  stage('integrity',[str(python),'-B','-m','hia.platform.service_settlement.qualification.integrity','--input',str(output),'--output',str(output/'integrity')])
  assert source_inputs()==session['source_inputs'] and repository()==session['repository']
  capture(output,session['source_inputs'],external)
  from .qualification.assessment import assessment,verify_controls,summary
  evidence=Evidence(output);actual_report=assessment(evidence);controls=verify_controls(evidence);evidence.final();time_left()
  report.update(actual_report,status='PASS',finalized=True,source_inputs_stable=True,prior_execution_reused=False,integrity_controls=controls,elapsed_ns=time.monotonic_ns()-start,**FALSE_SCOPES)
  summary(report,actual_report,controls)
 except BaseException:report.update(status='FAIL',finalized=True,exception=traceback.format_exc(),elapsed_ns=time.monotonic_ns()-start)
 finally:
  try:
   now=source_inputs();save(output/'source-after.json',now);save(output/'repository-after.json',repository())
   if now!=session['source_inputs'] or repository()!=session['repository']:report.update(status='FAIL',source_inputs_stable=False,final_fence='FAIL')
   else:report['final_fence']='PASS'
  except BaseException:report.update(status='FAIL',source_inputs_stable=False,final_fence='FAIL',final_fence_exception=traceback.format_exc())
  # Failed attempts retain every file and a final manifest without becoming PASS.
  try:capture(output,session['source_inputs'],external)
  except BaseException:report.update(status='FAIL',capture_exception=traceback.format_exc())
  report['completed_monotonic_ns']=time.monotonic_ns()
  report['elapsed_ns']=report['completed_monotonic_ns']-start
  if report['completed_monotonic_ns']>deadline:report.update(status='FAIL',qualification_deadline_exceeded=True)
  save(output/'report.json',report)
  if time.monotonic_ns()>deadline:
   report.update(status='FAIL',qualification_deadline_exceeded=True,elapsed_ns=time.monotonic_ns()-start)
   save(output/'report.json',report)
 print(json.dumps({'status':report['status'],'report':str(output/'report.json'),'report_identity':file_identity(output/'report.json'),'counts':report.get('counts'),'elapsed_ns':report['elapsed_ns'],'exception':report.get('exception')},sort_keys=True),flush=True)
 return 0 if report['status']=='PASS' else 1
def main():
 parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='command',required=True);p=sub.add_parser('run')
 p.add_argument('--output',type=Path,required=True);p.add_argument('--rust-bin',type=Path,required=True)
 args=parser.parse_args();return qualify(args.output,args.rust_bin)
if __name__=='__main__':raise SystemExit(main())
