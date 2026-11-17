"""Complete native function composition and source-bound ordinary M06 fixtures."""
from __future__ import annotations
import ast,builtins,json,re,types
from pathlib import Path
from hia.platform.execution_application import source_graph as application
from hia.platform.execution_state import rust_oracle as utility
REPOSITORY=Path(__file__).absolute().parents[3]
OWNED='hia/platform/execution_batch'
IMAGE_ORDER=('master','worker','settings','pnx','sha','ed','state','root',
 'mandatory_core','mandatory_cleanup','mandatory_expiry','mandatory_epilogue',
 'application_core','application_task','application_model','application_release',
 'application_quota','application_relation','application_claim')
PROFILES=('batch','prefix','scoped')
REQUIRED=frozenset({'README.md','abi.json','images.json','source_graph.py','build.py','safe_io.py',
 'cases.py','batch_cases.json','prefix_cases.py','mandatory_cases.py',
 'batch_native_io.py','prefix_native_io.py','batch_observations.py','prefix_observations.py',
 'qualification.py','physical.py','lifecycle.py','rust_oracle.py','test_integrity.py',
 'rust_batch_reference.rs','rust_prefix_reference.rs','build_evidence.py','process_evidence.py','bundle.py','scoped_native_io.py','physical_evidence.py'})
need=utility.need;identity=utility.identity;canonical_path=utility.canonical_path
canonical=utility.canonical_json
digest=lambda value:utility.digest(canonical(value))
declarations=application.declarations
def complete_sources(repository=REPOSITORY):
    need(__debug__,'Optimized Python is not admitted')
    repository=utility.canonical_root(repository);dependency,app=application.complete_sources(repository)
    captured=dict(dependency);raws={}
    def capture(name):
        raw=canonical_path(repository,name).read_bytes()
        need(name not in captured or captured[name]==identity(raw),'Changed dependency source')
        need(name not in raws or raws[name]==raw,'Source changed during capture')
        raws[name]=raw;captured[name]=identity(raw);return raw
    for name,row in dependency.items():need(identity(capture(name))==row,'Dependency capture drift')
    owned=canonical_path(repository,OWNED,directory=True);names=set()
    for path in sorted(owned.rglob('*')):
        need(not path.is_symlink() and path.name!='__pycache__' and path.suffix!='.pyc','Symbolic source or stale bytecode')
        if path.is_dir():continue
        need(path.suffix in utility.SOURCE_SUFFIXES,'Unexpected owned artifact')
        name=path.relative_to(repository).as_posix();capture(name)
        if path.parent==owned:names.add(path.name)
    need(REQUIRED<=names,'Incomplete execution owner source inventory: '+repr(sorted(REQUIRED-names)))
    graph=utility.load_json(capture(OWNED+'/images.json'))
    need(set(graph)=={'schema','image_order','profiles','dependency_images','fragments'} and graph['schema']=='trnm.execution-batch-image-composition.v1','Invalid image graph')
    need(graph['image_order']==list(IMAGE_ORDER) and set(graph['profiles'])==set(PROFILES),'Complete profile/image order differs')
    expected_dependency={'settings':'settings','pnx':'pnx','sha':'sha','ed':'ed','state':'state','root':'root',
     **{'application_'+name:name for name in ('core','task','model','release','quota','relation','claim')}}
    need(graph['dependency_images']==expected_dependency,'Existing native dependency selection differs')
    fragments=graph['fragments'];need(isinstance(fragments,dict) and fragments,'Missing own image fragments')
    parsed={};used=set();pieces={}
    def functions(name):
        need(name in captured and name.endswith('.hepta'),'Unbound function source')
        if name not in parsed:parsed[name]=declarations(capture(name))
        return parsed[name]
    for name,entry in fragments.items():
        need(isinstance(name,str) and re.fullmatch(r'[a-z][a-z_0-9]*',name) is not None,'Invalid image name')
        need(isinstance(entry,dict) and set(entry)=={'header_source','functions'},'Invalid fragment selection')
        header_source=entry['header_source']
        need(isinstance(header_source,str) and header_source.startswith(OWNED+'/') and header_source in captured,'Foreign module header')
        own=functions(header_source);raw=raws[header_source];header=raw[:raw.index(b'fn ')]
        need(isinstance(entry['functions'],list) and entry['functions'],'Empty image function roster')
        selected={};order=[]
        for row in entry['functions']:
            need(isinstance(row,dict) and set(row)=={'source','function'},'Malformed original function selection')
            source,fn=row['source'],row['function']
            need(isinstance(source,str) and isinstance(fn,str),'Invalid function reference type')
            available=functions(source)
            need(fn in available and fn not in selected,'Missing or repeated function in image')
            selected[fn]=available[fn].rstrip()+b'\n';order.append(fn);used.add((source,fn))
        need(order[0]=='f0','Actual image entry is not first')
        combined=header+b''.join(selected[fn] for fn in order)
        calls={m.decode() for m in re.findall(rb'"function"\s*:\s*"([A-Za-z_][A-Za-z_0-9]*)"',combined)}
        need(calls<=set(selected),'Unclosed native image call graph: '+name)
        pieces[name]=combined
    own_functions={(name,fn) for name in captured if name.startswith(OWNED+'/') and name.endswith('.hepta') for fn in functions(name)}
    need(own_functions<=(used),'Unused owned native body or unbound source version')
    profiles={}
    for profile,selection in graph['profiles'].items():
        need(isinstance(selection,dict) and set(selection)=={'master','worker','mandatory_core','mandatory_cleanup','mandatory_expiry','mandatory_epilogue','emitter'},'Incomplete profile-specific native entries')
        need(all(isinstance(value,str) and value in pieces for value in selection.values()),'Unknown native entry fragment')
        actual={}
        for name in IMAGE_ORDER:
            actual[name]=app[expected_dependency[name]] if name in expected_dependency else pieces[selection[name]]
        actual['emitter']=pieces[selection['emitter']]
        profiles[profile]=actual
    need(set(pieces)=={name for selection in graph['profiles'].values() for name in selection.values()},'Unused image fragment/version')
    for name,raw in raws.items():need(canonical_path(repository,name).read_bytes()==raw,'Source changed during capture')
    return dict(sorted(captured.items())),profiles
def original_manifest(repository=REPOSITORY):return application.original_manifest(repository)
def check_sources(native,original,repository=REPOSITORY):
    observed,_=complete_sources(repository)
    need(observed==native,'Complete native source closure changed')
    need(original_manifest(repository)==original,'Complete original Cargo/include source closure changed')
def bound_corpus(repository=REPOSITORY,profile='prefix'):
    repository=utility.canonical_root(repository);need(profile in ('batch','prefix'),'No original corpus for this lifecycle profile')
    modules={};captured={}
    paths={'hia.platform.execution_prepare.cases':'hia/platform/execution_prepare/cases.py',
     'hia.platform.execution_state.cases':'hia/platform/execution_state/cases.py',
     'hia.platform.execution_application.cases':'hia/platform/execution_application/cases.py',
     'hia.platform.execution_batch.mandatory_cases':OWNED+'/mandatory_cases.py',
     'hia.platform.execution_batch.prefix_cases':OWNED+'/prefix_cases.py',
     'hia.platform.execution_batch.cases':OWNED+'/cases.py'}
    standard={'__future__','functools','pathlib','copy','hashlib','json','struct','re'}
    def source_import(name,globals=None,locals=None,fromlist=(),level=0):
        need(level==0 and name in standard|set(paths),'Unbound fixture import: '+name)
        return load(name) if name in paths else builtins.__import__(name,globals,locals,fromlist,level)
    def load(name):
        if name in modules:return modules[name]
        path=canonical_path(repository,paths[name]);raw=path.read_bytes();captured[paths[name]]=raw
        tree=ast.parse(raw,filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):need(all(alias.name in standard for alias in node.names),'Unbound fixture import')
            if isinstance(node,ast.ImportFrom):need(node.level==0 and node.module in standard|set(paths),'Unbound fixture import')
        module=types.ModuleType(name);module.__file__=str(path);modules[name]=module
        module.__dict__['__builtins__']={**vars(builtins),'__import__':source_import}
        exec(compile(tree,str(path),'exec',dont_inherit=True),module.__dict__)
        return module
    # The JSON contains only the exact source-defined input requests, never outputs.
    batch_source=canonical_path(repository,OWNED+'/batch_cases.json').read_bytes();captured[OWNED+'/batch_cases.json']=batch_source
    cases=load('hia.platform.execution_batch.cases')
    rows=utility.load_json(batch_source) if profile=='batch' else load('hia.platform.execution_batch.prefix_cases').histories()
    cases.validate(rows,profile)
    raw=b''.join(canonical(row)+b'\n' for row in rows)
    for name,source in captured.items():need(canonical_path(repository,name).read_bytes()==source,'Source fixture changed')
    return raw,rows
