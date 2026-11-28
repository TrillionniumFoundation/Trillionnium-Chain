"""Independently reconstruct the eight source selections and all actual build receipts."""
from pathlib import Path,PurePosixPath
import hashlib,importlib,re,struct,sys,tomllib
from ..contract import UNITS,EXPORTS,COMPILER_SHA256,identity,document,digest
REVISION='f33d8da316de8fdf27b504371f1a5310997ff548'
BUDGET={'functions':128,'instructions':8192,'blocks':1536,'blocks_per_function':256,'values_per_function':2048,'parameters_per_block':16}
ROLES=('control','trust','receipt','rollup','settle','values')
FIXED=('AGENTS.md','PROJECT_ID','PROJECT_BOUNDARY.json','scripts/project-preflight.sh','scripts/ci/project_boundary.py','config/portability-inventory-v1.json','config/hia-migration-v1.json','docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md','trillionnium/Cargo.toml','trillionnium/Cargo.lock','hia/tools/toolchain.py','hia/toolchain.lock.json','hia/components.json','hia/qualification/compiler-binding.json','hia/platform/service_settlement/build.py','hia/platform/service_settlement/engine_owned_exports.json','hia/platform/service_settlement/engine_owned.map','hia/platform/service_settlement/engine_owned.h')
def functions(raw):
 matches=list(re.finditer(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)',raw))
 result={m[1].decode():m[0] for m in matches}
 assert len(result)==len(matches)==len(re.findall(rb'(?m)^fn ',raw))
 return result
def section(raw,name):
 assert raw[:6]==b'\x7fELF\x02\x01'
 off=struct.unpack_from('<Q',raw,40)[0];width,count,names=struct.unpack_from('<3H',raw,58)
 assert width==64 and names<count and off+width*count<=len(raw)
 rows=[struct.unpack_from('<IIQQQQIIQQ',raw,off+width*i) for i in range(count)]
 entry=rows[names];strings=raw[entry[4]:entry[4]+entry[5]]
 found=[r for r in rows if strings[r[0]:].split(b'\0',1)[0]==name.encode()];assert len(found)==1
 r=found[0];assert r[4]+r[5]<=len(raw);return raw[r[4]:r[4]+r[5]]
def verify(store):
 top=store.doc('build/build.json');origin=store.origin+'/build';source=store.source_root
 assert top['schema']=='trnm.hia.service-settlement-engine-build.v1' and top['status']=='EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED' and top['finalized'] is True
 assert top['source_unchanged'] is True and top['changed_inputs']==[] and top['compiler_fallback_used'] is False and top['authored_reference_used'] is False and top['actual_hia_ownership_emitter_executed'] is True
 assert top['declared_budget']==BUDGET and top['unit_roster']==UNITS and set(top['units'])==set(UNITS)
 registry=store.doc('source/hia/components.json')['includes'];selections={};admissions={};wanted=set(FIXED)
 cargo=tomllib.loads(store.read('source/trillionnium/Cargo.toml').decode())
 wanted.update('trillionnium/'+m+'/Cargo.toml' for m in cargo['workspace']['members'])
 binding=store.doc('source/hia/qualification/compiler-binding.json')
 assert binding['compiler_sha256']==COMPILER_SHA256 and binding['toolchain_revision']==REVISION and top['compiler_qualification_binding']==binding
 for field,key in [('outer_report','outer_sha256'),('nested_report','compressed_sha256')]:
  name='hia/qualification/'+binding[field];wanted.add(name);assert store.source(name)['sha256']==binding[key]
 assert store.doc('source/hia/qualification/'+binding['outer_report'])['status']=='COLD_SELFHOST_REPLAY_PASS'
 pin=store.doc('source/hia/toolchain.lock.json')
 assert pin['revision']==REVISION and pin['language_schema']=='hepta.hia.program.v8' and pin['target']=='x86_64-linux-gnu' and top['toolchain']==pin
 def visit(name,stack=()):
  assert name not in stack;entry='hia/'+name;raw=store.read('source/'+entry)
  paths={entry,'hia/components.json'};selected={n:{'path':entry,**identity(data)} for n,data in functions(raw).items()}
  for row in registry.get(name,[]):
   assert set(row)=={'source','functions'} and row['functions']
   dep='hia/'+row['source'];paths.update(visit(row['source'],stack+(name,))[0]);available=functions(store.read('source/'+dep))
   for n in row['functions']:assert n not in selected and n in available;selected[n]={'path':dep,**identity(available[n])}
  return paths,selected
 for role,entry in UNITS.items():
  paths,selected=visit(entry.removeprefix('hia/'));admissions[role]=paths;selections[role]=selected;wanted.update(paths)
 assert top['source_inputs']==top['source_before']==top['source_after']=={n:store.source(n) for n in sorted(wanted)}
 assert top['source_digest']==digest(top['source_inputs'])
 for name in wanted:assert store.read('build/source/'+name)==store.read('source/'+name)
 assert top['source_graph']['global_registry_key_presence']==sorted(registry)
 for name in registry:store.source('hia/'+name)
 assert top['source_graph']['units']=={r:{'entry':UNITS[r],'admission_sources':sorted(admissions[r]),'function_sources':selections[r]} for r in UNITS}
 tools=top['tools_before'];assert set(tools)==set(top['tools_after'])=={'python','ld','objcopy','bash','git','compiler'}
 resolved={}
 for name,row in tools.items():
  actual={k:row[k] for k in ['bytes','sha256']};resolved[name]=row['resolved_path']
  assert store.identity('build/'+row['snapshot'])==actual==store.actual(row['resolved_path'])
  assert top['tools_after'][name]=={'resolved_path':row['resolved_path'],**actual}
 assert tools['compiler']['sha256']==COMPILER_SHA256
 chain=top['toolchain_sources_before'];assert set(chain)==set(top['toolchain_sources_after'])
 tree=store.read('build/stages/toolchain-input-tree/stdout.raw');seen={}
 for item in tree.split(b'\0'):
  if not item:continue
  meta,name=item.split(b'\t',1);mode,kind,blob=meta.decode().split();name=name.decode()
  assert mode in ['100644','100755'] and kind=='blob' and name not in seen
  raw=store.read('build/tools/toolchain/'+name);assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blob
  seen[name]={'git_blob':blob,**identity(raw)}
 assert chain==seen and top['toolchain_sources_after']=={n:{k:v[k] for k in ['bytes','sha256']} for n,v in chain.items()}
 chain_dir=store.root/'build/tools/toolchain';sys.path.insert(0,str(chain_dir))
 try:
  from hepta.hia_agent_assembly import assemble_program,render_assembly
  from hepta.object_symbols import inspect_object_symbols
  from hepta.elf_shared_abi import inspect_owned_shared_elf
  import hepta
  assert Path(hepta.__file__).resolve().parent==chain_dir/'hepta'
  specs={};env={'PATH':str(PurePosixPath(resolved['python']).parent)+':/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1','PYTHONPYCACHEPREFIX':origin+'/python-cache','GIT_NO_LAZY_FETCH':'1','LC_ALL':'C'}
  toolroot=top['invocation']['relevant_environment']['HIA_TOOLCHAIN_ROOT']
  for suffix in ['', '-after']:
   specs['stages/toolchain-head'+suffix]=([resolved['git'],'-C',toolroot,'rev-parse','HEAD'],30,env,b'')
   specs['stages/toolchain-status'+suffix]=([resolved['git'],'-C',toolroot,'status','--porcelain=v1','--untracked-files=no'],30,env,b'')
   assert store.read('build/stages/toolchain-head'+suffix+'/stdout.raw').decode().strip()==REVISION and store.read('build/stages/toolchain-status'+suffix+'/stdout.raw')==b''
  specs['stages/toolchain-input-tree']=([resolved['git'],'-C',toolroot,'ls-tree','-rz','--full-tree',REVISION,'--','hepta','pyproject.toml'],30,env,b'')
  for suffix in ['before','after']:specs['stages/preflight-'+suffix]=([resolved['bash'],'scripts/project-preflight.sh','--audit'],30,env,b'')
  for role,entry in UNITS.items():
   directory='build/units/'+role;row=store.doc(directory+'/build.json');u=top['units'][role]
   assert u['directory']=='units/'+role and u['build']==store.identity(directory+'/build.json')
   assert row['status']=='NATIVE_EMITTED_NOT_EXECUTED' and row['role']==role and row['entry']==entry and row['compiler_fallback_used'] is False
   assert row['source_inputs']=={n:store.source(n) for n in sorted(admissions[role])}
   for name in admissions[role]:assert store.read(directory+'/source/'+name)==store.read('source/'+name)
   composed=store.read(directory+'/composed.hepta');selected=functions(composed)
   assert {n:identity(v) for n,v in selected.items()}=={n:{k:v[k] for k in ['bytes','sha256']} for n,v in selections[role].items()}
   core=assemble_program(composed).as_dict()
   core['module']='selfhost_elf';assert store.doc(directory+'/core.json')==core
   wire=render_assembly(core).encode();assert wire==store.read(directory+'/native-compile/stdin.raw')
   wire_fn=functions(wire)
   assert row['function_sources']=={n:{**v,'compiler_function':identity(wire_fn[n])} for n,v in selections[role].items()}
   blocks=[b for f in core['functions'] for b in f['blocks']]
   shape={'functions':len(core['functions']),'ops':sum(len(b['ops']) for b in blocks),'blocks':len(blocks),'max_blocks_per_function':max(len(f['blocks']) for f in core['functions']),'max_block_parameters':max(len(b['params']) for b in blocks)}
   assert shape==row['shape']==u['shape']
   assert 0<shape['functions']<=128 and 0<shape['ops']<=8192 and shape['blocks']<=1536 and shape['max_blocks_per_function']<=256 and shape['max_block_parameters']<=16 and row['declared_budget']==BUDGET
   assert row['compiler_sha256']==COMPILER_SHA256 and row['compiler_wire_sha256']==identity(wire)['sha256'] and row['toolchain']==pin
   obj=store.read(directory+'/module.o');image=store.read(directory+'/module.so')
   assert identity(obj)==row['object']==u['object']==store.identity(directory+'/native-compile/stdout.raw')
   assert identity(image)==row['artifact']==u['artifact'] and store.read(directory+'/native-compile/stderr.raw')==b''
   symbols=inspect_object_symbols(obj,'ELF64',62);assert symbols['defined']==frozenset({'f0'}) and symbols['undefined']<={'calloc','free'}
   assert inspect_owned_shared_elf(image,('f0',))==row['dynamic_abi']
   compile_request=store.doc(directory+'/native-compile/request.json');fds=compile_request['pass_fds']
   assert len(fds)==1 and type(fds[0]) is int and fds[0]>=3
   specs['units/'+role+'/native-compile']=(['/proc/self/fd/'+str(fds[0])],30,{'PATH':''},wire)
   specs['units/'+role+'/link']=([resolved['ld'],'-m','elf_x86_64','-shared','-z','defs','-z','noexecstack','-z','relro','-z','now','--build-id=none','--hash-style=both',origin+'/units/'+role+'/module.o','-lc','-o',origin+'/units/'+role+'/module.so'],30,env,b'')
   assert row['stages']==[store.doc(directory+'/'+x+'/receipt.json') for x in ['native-compile','link']]
  public=store.doc('build/public/build.json')
  assert public['status']=='PUBLIC_NATIVE_LINKED_NOT_QUALIFIED' and sorted(public['exports'])==EXPORTS and public['all_business_decisions_in_canonical_hia'] is True
  assert top['public']=={'directory':'public','status':public['status'],'build':store.identity('build/public/build.json')}
  public_stages=['execute-emitter',*['rename-'+r for r in ROLES],'link']
  assert public['stages']==[store.doc('build/public/'+name+'/receipt.json') for name in public_stages]
  er='build/public/emitter-execution';e=store.doc(er+'/report.json');obj=store.read(er+'/engine-owned.o')
  assert e['status']=='PASS' and e['return_code']==0 and e['object']==identity(obj) and len(obj)==9760
  assert e['actual_compiled_hia_execution'] is True and e['authored_reference_used'] is False and e['image']==top['units']['emitter']['artifact']
  assert e['input']==identity(b'SSOWN001') and type(e['elapsed_ns']) is int and 0<e['elapsed_ns']<=60*10**9
  assert set(e['checks'])=={'return_zero','input_unchanged','empty_workspace_unchanged','output_guards_unchanged','exact_length'} and all(v is True for v in e['checks'].values())
  before=[store.read(er+'/before-'+str(i)+'.raw') for i in range(3)];after=[store.read(er+'/after-'+str(i)+'.raw') for i in range(3)]
  assert before==[b'\xa7'*32+b'SSOWN001'+b'\xa7'*32,b'\x5c'*(9768+64),b'\x96'*64]
  assert e['before']==[identity(x) for x in before] and e['after']==[identity(x) for x in after]
  assert before[0]==after[0] and before[2]==after[2] and after[1]==b'\x5c'*32+struct.pack('<Q',9760)+obj+b'\x5c'*32
  assert store.read('build/public/engine-owned.o')==obj
  assert public['emitter_execution']['object']==identity(obj) and public['emitter_execution']['authored_reference_used'] is False and public['emitter_execution']['observation']==store.identity(er+'/report.json')
  symbols=inspect_object_symbols(obj,'ELF64',62);assert symbols['defined']==frozenset(EXPORTS) and symbols['undefined']==frozenset({'calloc','free','memcpy'}|{'_trnm_settlement_'+r for r in ROLES})
  specs['public/execute-emitter']=([resolved['python'],'-B',source+'/hia/platform/service_settlement/build.py','--execute-emitter','--emitter-image',origin+'/units/emitter/module.so','--emitter-sha256',top['units']['emitter']['artifact']['sha256'],'--emitter-output',origin+'/public/emitter-execution'],60,env,b'')
  assert set(public['modules'])=={'emitter',*ROLES}
  pub_sources=set()
  for role in ('emitter',*ROLES):
   row=public['modules'][role];unit=top['units'][role]
   assert row['directory']==origin+'/units/'+role and row['build']==unit['build'] and row['object']==unit['object'] and row['image']==unit['artifact']
   pub_sources.update(admissions[role])
   if role=='emitter':continue
   converted=store.read('build/public/'+role+'.o');original=store.read('build/units/'+role+'/module.o')
   assert identity(converted)==row['renamed'] and section(original,'.text')==section(converted,'.text') and row['machine_code']==identity(section(converted,'.text'))
   names=inspect_object_symbols(converted,'ELF64',62);assert names['defined']==frozenset({'_trnm_settlement_'+role}) and names['undefined']<={'calloc','free'}
   specs['public/rename-'+role]=([resolved['objcopy'],'--redefine-sym','f0=_trnm_settlement_'+role,origin+'/units/'+role+'/module.o',origin+'/public/'+role+'.o'],60,env,b'')
  pub_sources.update('hia/platform/service_settlement/'+n for n in ['engine_owned_exports.json','engine_owned.map','engine_owned.h','build.py'])
  assert public['source_inputs']=={n:store.source(n) for n in sorted(pub_sources)}
  for n in pub_sources:assert store.read('build/public/source/'+n)==store.read('source/'+n)
  specs['public/link']=([resolved['ld'],'-m','elf_x86_64','-shared','-z','defs','-z','noexecstack','-z','relro','-z','now','--build-id=none','--hash-style=both','--version-script='+source+'/hia/platform/service_settlement/engine_owned.map',origin+'/public/engine-owned.o',*[origin+'/public/'+r+'.o' for r in ROLES],'-lc','-o',origin+'/public/settlement-engine.so'],60,env,b'')
  image=store.read('build/public/settlement-engine.so');assert identity(image)==top['artifact']==public['artifact'] and inspect_owned_shared_elf(image,tuple(EXPORTS))==public['dynamic_abi']
  order=['stages/toolchain-head','stages/toolchain-status','stages/toolchain-input-tree','stages/preflight-before']+[p for role in UNITS for p in ['units/'+role+'/native-compile','units/'+role+'/link']]+['public/execute-emitter']+['public/rename-'+r for r in ROLES]+['public/link','stages/preflight-after','stages/toolchain-head-after','stages/toolchain-status-after']
  assert [r['path'] for r in top['stages']]==order and len(specs)==31
  for item in top['stages']:
   name=item['path'];row=store.doc('build/'+name+'/receipt.json');req=store.doc('build/'+name+'/request.json')
   assert {k:v for k,v in item.items() if k!='path'}==row and set(req)<=set(row)
   assert all(row[k]==v for k,v in req.items())
   argv,seconds,environment,stdin=specs[name]
   assert req['argv']==argv and req['cwd']==source and req['environment']==environment and req['timeout_seconds']==seconds and req['cleanup_seconds']==3
   if not name.endswith('/native-compile'):assert req['pass_fds']==[]
   assert req['stdin']==identity(stdin)==store.identity('build/'+name+'/stdin.raw')
   assert type(row['exit_code']) is int and row['exit_code']==0 and row['timed_out'] is False and row['exception'] is None and row['cleanup'] is None
   assert type(row['elapsed_ns']) is int and 0<row['elapsed_ns']<seconds*10**9
   for stream in ['stdout','stderr']:assert row[stream]==store.identity('build/'+name+'/'+stream+'.raw')
  return {'artifact':top['artifact'],'units':8,'stages':31,'source_digest':top['source_digest']}
 finally:
  sys.path.remove(str(chain_dir))
