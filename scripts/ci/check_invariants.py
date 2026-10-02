#!/usr/bin/env python3
"""Exact invariant-to-test/source binding. Does not run tests or grant readiness."""
from pathlib import Path
import ast,json,re
from functools import lru_cache
FIELDS={'module','id','claim','scope','atomic','cuts','tests','source','limit','threat','remaining'}
def require(ok,message):
    if not ok:raise ValueError(message)
@lru_cache(maxsize=32)
def functions(text):
    found=set()
    def walk(nodes,prefix=''):
        for node in nodes:
            if isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
                name=prefix+node.name
                if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):found.add(name)
                walk(node.body,name+'.')
    walk(ast.parse(text).body);return frozenset(found)
def validate(root):
    root=Path(root).resolve()
    data=json.loads((root/'config/pon/invariants-v2.json').read_text())
    require(data['schema']=='pon-invariants-v2'and data['binding_is_execution']is False and data['independent_accepted']is False,'binding may not grant execution/acceptance')
    params=json.loads((root/'config/pon/devnet-v1.json').read_text())
    require(type(data.get('genesis_revision'))is int and data['genesis_revision']==params['consensus_revision'],'invariant contract revision does not match installed consensus')
    contracts=json.loads((root/'config/pon/module-contracts-v1.json').read_text())['modules']
    specs={c['id']:c['specification']for c in contracts};seen=set();owners=set();tests=set()
    for row in data['invariants']:
        require(set(row)==FIELDS,'invariant schema')
        identity=row['module']+'.'+row['id'];require(identity not in seen,'duplicate invariant');seen.add(identity)
        require(row['module']in specs,'unknown owner');owners.add(row['module'])
        for field in ['claim','scope','atomic','limit','threat','remaining']:
            require(isinstance(row[field],str)and row[field].strip()and row[field].strip().lower()not in {'tbd','todo','none'},'missing semantic boundary '+field)
        require(row['cuts']and all(isinstance(s,str)and s.strip()for s in row['cuts']),'missing failure schedule')
        require(row['tests']and row['source'],'missing concrete test/source binding')
        doc=(root/specs[row['module']]).read_text()
        require(identity in doc,'missing invariant reference '+identity)
        for source in row['source']:
            path=(root/source).resolve();require(path.is_relative_to(root)and path.is_file(),'missing source '+source)
        for selector in row['tests']:
            path,symbol=selector.split('::',1);file=(root/path).resolve()
            require(file.is_relative_to(root)and file.is_file(),'missing test file')
            text=file.read_text()
            if file.suffix=='.py':require(symbol in functions(text)and symbol.split('.')[-1].startswith('test_'),'missing exact Python test '+selector)
            elif file.suffix=='.rs':require(re.search(r'#\[test\]\s*fn\s+'+re.escape(symbol)+r'\s*\(',text)is not None,'missing exact native test '+selector)
            else:raise ValueError('unsupported test selector')
            require(selector in doc,'module omits exact regression '+selector);tests.add(selector)
    require(owners==set(specs),'module invariant coverage incomplete')
    critical={'M03.RevokeEntryLinearization','M07.OwnedInitialization','M10.PendingNotHistory','M02.RecoveredBestChain'}
    require(critical<=seen,'known counterexample obligation omitted')
    return {'invariants':len(seen),'specific_tests':len(tests),'binding_consistent':True,'tests_executed_by_this_checker':False,'independent_accepted':False}
if __name__=='__main__':print(json.dumps(validate(Path(__file__).resolve().parents[2]),sort_keys=True))
