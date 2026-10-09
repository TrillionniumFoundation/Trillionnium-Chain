#!/usr/bin/env python3
"""Read-only portable-source integrity. Does not certify a runnable consensus."""
from __future__ import annotations
import hashlib,json,pathlib,re,subprocess,sys,tomllib
from urllib.parse import unquote,urlsplit
ROOT=pathlib.Path(__file__).resolve().parents[2]
MODULES={f'M{i:02d}' for i in range(18)}
FORBIDDEN_NAME=re.compile(r'poco|tendermint|cometbft|hotstuff|consensus-(?:core|types|crypto|safety|signer|sim)|order-finality|core-restart',re.I)
FORBIDDEN_SYMBOL=re.compile(r'PoCO|poco|QuorumCertificate|TimeoutVote|VotingPower|CanonicalSignIntent|ValidatorSetV[0-9]|locked_qc|high_qc|three_chain_finality')
CLAIMS=('production_candidate','production_consensus_activation','public_testnet_ready','release_ready','runtime_implemented','work_profile_qualified')
class Invalid(ValueError):pass
def require(ok,msg):
    if not ok:raise Invalid(msg)
def unique(pairs):
    d={}
    for k,v in pairs:
        require(k not in d,'duplicate key '+k);d[k]=v
    return d
def load(path):return json.loads(path.read_text(),object_pairs_hook=unique)
def no_promotion(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if key in CLAIMS:require(item is False,'unsupported activation '+key)
            no_promotion(item)
    elif isinstance(value,list):
        for item in value:no_promotion(item)
def contained(root,relative):
    path=pathlib.Path(relative)
    require(not path.is_absolute() and '..' not in path.parts,'noncanonical inventory path')
    p=(root/path).resolve()
    require(p.is_relative_to(root.resolve()) and p.is_file(),'missing/escaping file '+relative)
    return p
def graph_acyclic(graph):
    visiting=set();done=set()
    def visit(node):
        require(node not in visiting,'package cycle '+node)
        if node in done:return
        visiting.add(node)
        for dep in graph[node]:
            require(dep in graph,'undeclared dependency '+dep);visit(dep)
        visiting.remove(node);done.add(node)
    for node in graph:visit(node)
def all_files(root):
    return sorted(p for p in root.rglob('*') if p.is_file() and not any(s in {'.git','target','__pycache__','.pytest_cache','node_modules'} for s in p.relative_to(root).parts))
def check(root=ROOT):
    inventory=load(root/'config/portability-inventory-v1.json')
    rows=inventory['packages'];names=[r['package'] for r in rows]
    require(len(names)==len(set(names)) and bool(names),'duplicate/empty package inventory')
    require(inventory['runtime_implemented'] is False and inventory['old_protocol_compatibility'] is False,'inventory false claim')
    cargo=tomllib.loads((root/'trillionnium/Cargo.toml').read_text())
    require(set(cargo['workspace']['members'])=={'crates/'+n for n in names},'workspace differs from inventory')
    require(set(p.name for p in (root/'trillionnium/crates').iterdir() if p.is_dir())==set(names),'undeclared crate directory')
    graph={};normal_graph={};source_count=0
    for row in rows:
        name=row['package'];require(row['module'] in MODULES,'unknown module')
        require(row['path']=='trillionnium/crates/'+name,'wrong source binding')
        require(row['consensus_authority'] is False and row['production_activation'] is False,'source grants authority')
        require(not FORBIDDEN_NAME.search(name),'retired package restored')
        manifest=contained(root,row['path']+'/Cargo.toml');data=tomllib.loads(manifest.read_text())
        require(data['package']['name']==name,'package name drift');deps=set();normal=set()
        tables=[(key,data.get(key,{})) for key in ['dependencies','build-dependencies','dev-dependencies']]
        for cfg in data.get('target',{}).values():tables.extend((k,cfg.get(k,{})) for k in ['dependencies','build-dependencies','dev-dependencies'])
        for category,table in tables:
            for alias,dep in table.items():
                actual=dep.get('package',alias) if isinstance(dep,dict) else alias
                require(not FORBIDDEN_NAME.search(actual),'retired dependency '+actual)
                if isinstance(dep,dict) and 'path' in dep:
                    target=(manifest.parent/dep['path']).resolve()
                    require(target.parent==(root/'trillionnium/crates').resolve() and target.name in names,'external/absent path dependency')
                    require(actual==target.name,'path dependency alias mismatch')
                    deps.add(actual)
                    if category!='dev-dependencies':normal.add(actual)
        graph[name]=deps;normal_graph[name]=normal
        for p in manifest.parent.rglob('*.rs'):
            source_count+=1
            require(not FORBIDDEN_SYMBOL.search(p.read_text()),'retired code symbol in '+str(p.relative_to(root)))
    # Normal dependency cycles are forbidden; dev edges are still inventoried and checked.
    graph_acyclic(normal_graph)
    locks=tomllib.loads((root/'trillionnium/Cargo.lock').read_text())
    for package in locks['package']:require(not FORBIDDEN_NAME.search(package['name']),'retired lock package')
    truth=load(root/'config/consensus-mainline.json')
    require(set(CLAIMS) <= set(truth), 'missing explicit runtime/readiness claim')
    no_promotion(truth)
    require(truth['active_consensus_implementation'] is None and truth['historical_consensus_sources_present'] is False,'active runtime claim')
    pon=load(root/'config/pon-nakamoto-v1.json');no_promotion(pon)
    require(pon['selected_development_target']=='pon-nakamoto-v1','selected target drift')
    require(pon['fork_choice']=='maximum-fully-validated-cumulative-required-work','wrong fork choice')
    for key in ['validator_voting','quality_weighted_chainwork','automatic_bft_fallback','automatic_hash_only_fallback']:require(pon[key] is False,'forbidden authority/fallback')
    require(pon['work_profile']['status']=='implemented-experimental-not-security-qualified' and pon['work_profile']['concrete_profile_id']=='pon-matmul-transcript-64-v1' and pon['work_profile']['canonical_codec_frozen'] is True and pon['work_profile']['codec_scope']=='experimental-genesis-only','experimental work identity or qualification drift')
    for key in ['cost_hardness_accepted','independent_verifier','quality_is_work','historical_training_is_fresh_work']:require(pon['work_profile'][key] is False,'work security claim')
    required_axes={'runtime_implemented','work_profile_qualified','public_model_efficacy_measured','public_model_product_loop_accepted','reorg_external_effects_qualified','independent_security_accepted','independent_economics_accepted'}
    require(set(pon['implementation']) == required_axes, 'incomplete or unknown implementation axes')
    require(all(v is False for v in pon['implementation'].values()),'implementation acceptance fabricated')
    require(pon['retirement']['history_only'] is True and pon['retirement']['old_protocol_decoders_present'] is False,'old source compatibility restored')
    specs=pon['module_targets'];require({r['id'] for r in specs}==MODULES and len(specs)==18,'module contract coverage')
    for row in specs:
        text=contained(root,row['technical_spec']).read_text()
        require('## Retired PoCO implementation reference' not in text,'legacy appendix restored')
    # Every current Markdown link, not just selected navigation, must resolve locally.
    links=0;files=all_files(root)
    for p in files:
        relative=str(p.relative_to(root))
        if relative.startswith(('config/portability-inventory','scripts/ci/check_repository','scripts/ci/test_repository')):continue
        require(not FORBIDDEN_NAME.search(p.name),'retired filename '+relative)
        if p.suffix=='.json':load(p)
        if p.suffix=='.toml':tomllib.loads(p.read_text())
        if p.suffix=='.md':
            text=re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '',p.read_text(),flags=re.M|re.S)
            for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)',text):
                u=urlsplit(target.strip('<>'))
                if u.scheme or u.netloc or not u.path:continue
                resolved=(p.parent/unquote(u.path)).resolve()
                require(resolved.is_relative_to(root.resolve()) and resolved.exists(),'broken link '+relative+' -> '+target);links+=1
    require(not any(p.is_dir() and p.name.startswith('poco') for p in (root/'docs/protocol').iterdir()),'old protocol tree restored')
    wf=root/'.github/workflows/trnm-required-baseline.yml';text=wf.read_text()
    for name in load(root/'config/repository-policy-v1.json')['required_check_names']:require('  '+name+':' in text,'missing required job '+name)
    require('self-hosted' not in text and 'contents: write' not in text,'privileged PR execution')
    require('persist-credentials: false' in text,'checkout credentials retained')
    require(not re.search(r'(?ms)^    env:\n(?:(?:^      [^\n]*\n)|(?:^\s*\n))*?^      [^\n]*\$\{\{\s*runner\.', text), 'runner context is unavailable in job-level env')
    # The five required head checks and separate prospective-merge matrix all
    # receive isolated paths after allocation. Check each actual job, not a
    # fixed count that would accidentally prohibit a merge-verification lane.
    from check_ci_contract import validate as ci_validate
    ci_validate(root)
    require('RUST_TEST_THREADS: "1"' in text,'fault-test harness isolation missing')
    for row in specs:
        prose=contained(root,row['technical_spec']).read_text()
        require('VerifyHistoricalPoCO' not in prose and 'decoders in explicit legacy dispatch' not in prose,'old decoder requirement restored')
    require('pull_request_target' not in text,'privileged pull request event')
    from check_detailed_contracts import validate as detailed_validate
    detailed_validate(root)
    from check_applicability import validate as applicability_validate
    applicability_validate(root)
    from check_invariants import validate as invariant_validate
    invariant_validate(root)
    from report_current_implementation import validate as current_validate
    current_validate(root)
    return {'result':'PASS','workspace_packages':len(names),'rust_files':source_count,'local_links':links,'runtime_implemented':False,'activation':False,'normal_dependency_edges':sum(map(len,normal_graph.values()))}
if __name__=='__main__':
    try:
        report=check();report['head']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        report['tree']=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip()
        report['source_state']='dirty-candidate' if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip() else 'committed-clean'
        print(json.dumps(report,sort_keys=True))
    except (Invalid,KeyError,ValueError,OSError) as e:
        print('Repository check failed: '+str(e),file=sys.stderr);sys.exit(2)
