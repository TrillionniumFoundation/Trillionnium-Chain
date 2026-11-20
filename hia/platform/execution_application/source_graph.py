"""Complete source composition without a compiler, Rust tool, or cached bytecode.

The native builder and the public evidence gate use the same declared source
graph.  It selects existing HIA bodies only; no application algorithm runs here.
"""
from __future__ import annotations
import ast,builtins,re,types
from pathlib import Path
from hia.platform.execution_state import rust_oracle as state
from hia.platform.execution_prepare import rust_oracle as prepare

REPOSITORY=Path(__file__).absolute().parents[3]
OWNED='hia/platform/execution_application'
REQUIRED=frozenset({'README.md','abi.json','includes.json','build.py','source_graph.py',
 'cases.py','native_io.py','qualify.py','rust_oracle.py','rust_reference.rs','physical.py','test_integrity.py',
 'core.hepta','task.hepta','model.hepta','release.hepta','quota.hepta','relation.hepta',
 'claim.hepta','support.hepta','prepare_bridge.hepta','linux_emitter.hepta'})
APP_IMAGES=('prepare_bridge','core','task','model','release','quota','relation','claim')
IMAGE_ORDER=('state','root','settings','pnx','sha','ed',*APP_IMAGES)
EXPLICIT=('hia/platform/build.py','hia/tools/toolchain.py','hia/components.json',
 'hia/toolchain.lock.json','hia/qualification/compiler-binding.json',
 'hia/qualification/compiler-cold.json','hia/qualification/compiler-cold-full.json.xz')
CONFIGURATION=('config/pon/devnet-v1.json','config/pon/ledger-v1.json',
 'config/pon/model-family-v1.json','config/pon/work-profile-v1.json')
CANONICAL={'settings':'src/node/settings_development.hepta','pnx':'src/protocol/pnx1.hepta',
 'sha':'src/crypto/sha256.hepta','ed':'src/crypto/ed25519_verify.hepta'}
need=state.need;identity=state.identity;canonical_path=state.canonical_path
digest=lambda rows:state.digest(state.canonical_json(rows))


def declarations(raw):
    state.source_functions(raw)
    return {m.group(1).decode():m.group(0) for m in re.finditer(
        rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)',raw)}


def complete_sources(repository=REPOSITORY):
    need(__debug__,'Optimized Python is not admitted')
    repository=state.canonical_root(repository);captured={};raw_sources={}
    def capture(name):
        raw=canonical_path(repository,name).read_bytes()
        need(name not in raw_sources or raw_sources[name]==raw,'Source changed during capture')
        raw_sources[name]=raw;captured[name]=identity(raw);return raw
    # Include the complete real State and Prepare owners, their source gates,
    # observers, canonical dependencies, and the four actual Settings inputs.
    state_sources,state_composed=state.complete_sources(repository)
    prepare_sources=prepare.complete_source_manifest(repository)
    for table in (state_sources,prepare_sources):
        for name,row in table.items():need(identity(capture(name))==row,'Dependency source capture changed')
    directory=canonical_path(repository,OWNED,directory=True);owned=set()
    for path in sorted(directory.rglob('*')):
        need(not path.is_symlink() and path.name!='__pycache__' and path.suffix!='.pyc','Symbolic owned source or stale bytecode')
        if path.is_dir():continue
        need(path.suffix in state.SOURCE_SUFFIXES,'Unexpected owned artifact')
        name=path.relative_to(repository).as_posix();capture(name)
        if path.parent==directory:owned.add(path.name)
    need(REQUIRED<=owned,'Incomplete application owner inventory: '+repr(sorted(REQUIRED-owned)))
    for name in (*EXPLICIT,*CONFIGURATION):capture(name)
    pinned=state.literal_assignment(capture('hia/platform/build.py'),'INPUTS')
    need(isinstance(pinned,(tuple,list)) and pinned and len(pinned)==len(set(pinned)),'Invalid pinned build inputs')
    for name in pinned:capture('hia/'+name)
    common=state.load_json(capture('hia/components.json'))
    local=state.load_json(capture(OWNED+'/includes.json'))
    need(set(common)=={'schema','includes'} and common['schema']=='trnm.hia.component-includes.v1','Invalid canonical includes')
    need(set(local)=={'schema','includes'} and local['schema']=='trnm.hia.execution-application-includes.v1','Invalid application includes')
    need(isinstance(common['includes'],dict) and isinstance(local['includes'],dict),'Invalid include maps')
    expected={name[4:] for name in captured if name.startswith(OWNED+'/') and name.endswith('.hepta')}
    need(set(local['includes'])==expected,'Incomplete application HIA declaration inventory')
    def component_path(name):
        need(isinstance(name,str) and name.startswith(('src/','platform/','storage/')) and name.endswith('.hepta'),'Invalid HIA dependency')
        return canonical_path(repository,'hia/'+name)
    # The reused dependency gates also validate the presence and nonsymbolic
    # identity of every canonical component key. Bind those inspected files,
    # even when this executable selects no function from them.
    for name in common['includes']:
        component_path(name);capture('hia/'+name)
    done={}
    def visit(name,ancestry=()):
        component_path(name);need(name not in ancestry,'Cyclic HIA dependency')
        if name in done:return done[name]
        raw=capture('hia/'+name);own=declarations(raw);selected=dict(own)
        rows=local['includes'][name] if name in local['includes'] else common['includes'].get(name,[])
        need(isinstance(rows,list),'Malformed includes list')
        pieces=[raw.rstrip()+b'\n']
        for row in rows:
            need(isinstance(row,dict) and set(row)=={'source','functions'} and isinstance(row['functions'],list) and row['functions'],'Malformed include selection')
            _,available=visit(row['source'],(*ancestry,name))
            for fn in row['functions']:
                need(isinstance(fn,str) and fn in available and fn not in selected,'Missing, duplicate or re-exported HIA function')
                selected[fn]=available[fn];pieces.append(available[fn].rstrip()+b'\n')
        combined=b''.join(pieces)
        if name.startswith('platform/execution_application/') and name!='platform/execution_application/prepare_bridge.hepta':
            # Match the already checked development modules: f0 first, then
            # lexicographically selected original bodies. This is byte linking.
            header=raw[:raw.index(b'fn ')]
            order=(['f0'] if 'f0' in selected else [])+sorted(set(selected)-{'f0'})
            combined=header+b''.join(selected[fn].rstrip()+b'\n' for fn in order)
        done[name]=(combined,own);return done[name]
    composed={'state':state_composed['owner'],'root':state_composed['root']}
    composed.update({name:visit(path)[0] for name,path in CANONICAL.items()})
    composed.update({name:visit('platform/execution_application/'+name+'.hepta')[0] for name in (*APP_IMAGES,'linux_emitter')})
    need(tuple(composed)==(*IMAGE_ORDER,'linux_emitter'),'Native image inventory/order differs')
    # A library fragment may call a helper explicitly selected by its final
    # image. Every executable image, rather than each non-executable fragment,
    # must close the complete callee set.
    for name,raw in composed.items():
        functions=declarations(raw)
        calls={m.decode() for m in re.findall(rb'"function"\s*:\s*"([A-Za-z_][A-Za-z_0-9]*)"',raw)}
        need(calls<=set(functions),'Undeclared native HIA callee in '+name+': '+repr(sorted(calls-set(functions))))
    for name,raw in raw_sources.items():need(canonical_path(repository,name).read_bytes()==raw,'Source changed during complete capture')
    return dict(sorted(captured.items())),composed


def original_manifest(repository=REPOSITORY):
    return state.original_manifest(repository)


def check_sources(native,original,repository=REPOSITORY):
    observed,_=complete_sources(repository)
    need(observed==native,'Complete native source closure changed')
    need(original_manifest(repository)==original,'Original source closure changed')


def bound_corpus(repository=REPOSITORY):
    """Compile bound fixture sources directly; never import their bytecode cache."""
    repository=state.canonical_root(repository);modules={};captured={}
    paths={'hia.platform.execution_prepare.cases':'hia/platform/execution_prepare/cases.py',
           'hia.platform.execution_state.cases':'hia/platform/execution_state/cases.py',
           'hia.platform.execution_application.cases':OWNED+'/cases.py'}
    standard={'__future__','functools','pathlib','copy','hashlib','json','struct'}
    def source_import(name,globals=None,locals=None,fromlist=(),level=0):
        need(level==0 and (name in paths or name in standard),'Unbound fixture import: '+name)
        return load(name) if name in paths else builtins.__import__(name,globals,locals,fromlist,level)
    def load(name):
        if name in modules:return modules[name]
        path=canonical_path(repository,paths[name]);raw=path.read_bytes();captured[paths[name]]=raw
        tree=ast.parse(raw,filename=str(path))
        for item in ast.walk(tree):
            if isinstance(item,ast.Import):need(all(alias.name in standard for alias in item.names),'Unbound fixture import')
            if isinstance(item,ast.ImportFrom):need(item.level==0 and item.module in standard|set(paths),'Unbound fixture import')
        module=types.ModuleType(name);module.__file__=str(path);modules[name]=module
        module.__dict__['__builtins__']={**vars(builtins),'__import__':source_import}
        exec(compile(tree,str(path),'exec',dont_inherit=True),module.__dict__)
        return module
    module=load('hia.platform.execution_application.cases');raw=module.canonical_bytes();rows=module.histories()
    need(type(raw) is bytes and raw.endswith(b'\n') and state.same_json([state.load_json(x) for x in raw.splitlines()],rows),'Canonical source corpus differs')
    names=set()
    for row in rows:
        need(set(row)=={'schema','name','base','transactions'} and row['schema']=='trnm.execution-application-history.v1' and isinstance(row['name'],str) and row['name'] not in names,'Invalid or repeated history')
        names.add(row['name']);need(isinstance(row['base'],list) and isinstance(row['transactions'],list) and row['transactions'],'Invalid history inputs')
    for name,source in captured.items():need(canonical_path(repository,name).read_bytes()==source,'Fixture source drift')
    return raw,rows,module.config()
