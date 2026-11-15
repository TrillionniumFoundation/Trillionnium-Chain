#!/usr/bin/python3
"""Isolated, source-bound CI guard repair and A2 validation."""
from __future__ import annotations
import ast, collections, datetime, hashlib, importlib.util, json, os
from pathlib import Path
import re, shutil, stat, subprocess, sys, tempfile, traceback

A='43e5c9d6b668276d03e1c7a76f467ec211e1d7dc'
ROOT=Path('/home/qian-qi/work/chain-daa-resource-ci-guard-20261112-600e')
CANONICAL=Path('/home/qian-qi/work/chain-daa-resource-competition-20261112-600e')
BASE=Path('/home/qian-qi/work/chain-daa-ci-gates-600e')
OUT=BASE/'ci-guard-repair-and-freeze-v1'
HELPER=BASE/'controller-v1.py'
HELPER_SHA='c7e211a71620ce161ce53a29f468a3b9796eb58ef18714192ee31ffcd9a0612c'
CHECKER='scripts/ci/check_ci_contract.py'
CORPUS='config/pon/pq-cross-branch-corpus-v1.json'
TEST='scripts/ci/test_ci_contract.py'
OLD_BLOB='8c84ca65e93b8cccdbd0311a3c35dd70b366b5fd'
SCOPE={CHECKER,CORPUS}
MIN_FREE=14*1024**3
ENV={**os.environ,'PATH':'/usr/bin:/bin:/usr/local/bin',
     'PYTHONDONTWRITEBYTECODE':'1','PYTHONUNBUFFERED':'1'}
PY='/usr/bin/python3'
sys.dont_write_bytecode=True

def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def blob(raw): return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def ensure(value,message):
    if not value: raise RuntimeError(message)

ensure(HELPER.is_file() and digest(HELPER)==HELPER_SHA,'HELPER_IDENTITY')
spec=importlib.util.spec_from_file_location('ci_record_helpers',HELPER)
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.ROOT=ROOT
OUT.mkdir(exist_ok=False)
OPS=OUT/'operations';OPS.mkdir()
DEV=OUT/'development';DEV.mkdir()
VALID=OUT/'validation';VALID.mkdir()
started=stamp()
commands=[]
development=[]
validation=[]
freeze=None
failure=None
common_before=None
common_path=None
preconditions={}
canonical_after=None
def save(path,data): helper.write_json(path,data)

def command(name,argv,*,cwd=ROOT,input_bytes=None,timeout=600):
    directory=OPS/name;directory.mkdir()
    row={'name':name,'argv':argv,'cwd':str(cwd),'started_utc':stamp(),
         'ended_utc':None,'exit_code':None,'state':'starting',
         'environment_overrides':helper.OVERRIDES}
    if input_bytes is not None:
        p=directory/'stdin.raw'
        with p.open('xb') as handle:
            handle.write(input_bytes);handle.flush();os.fsync(handle.fileno())
        row['stdin']={'bytes':len(input_bytes),'sha256':digest(p)}
    save(directory/'record.json',row)
    with (directory/'stdout.raw').open('xb') as stdout,(directory/'stderr.raw').open('xb') as stderr:
        try:
            result=subprocess.run(argv,cwd=cwd,env=ENV,input=input_bytes,
                                  stdout=stdout,stderr=stderr,timeout=timeout)
            row.update(state='completed',exit_code=result.returncode)
        except Exception as error:
            row.update(state='controller-error',exception={'type':type(error).__name__,'message':str(error)})
        finally:
            stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
    row['ended_utc']=stamp()
    for stream in ('stdout','stderr'):
        path=directory/(stream+'.raw')
        row[stream]={'file':path.name,'bytes':path.stat().st_size,'sha256':digest(path)}
    save(directory/'record.json',row)
    commands.append({'name':name,'record':str((directory/'record.json').relative_to(OUT)),
                     'exit_code':row['exit_code'],'state':row['state']})
    ensure(row['state']=='completed' and row['exit_code']==0,name+' did not complete successfully')
    return (directory/'stdout.raw').read_bytes()

def observe_dev(name,argv,*,tests=None,check=None,expected=0):
    specification=helper.gate(name,argv,600,tests=tests,check=check,expected_exit=expected)
    row=helper.observe(specification,DEV,A,ENV)
    development.append(row)
    ensure(row['expectation_met'],'development check failed: '+name)
    return row

def index_snapshot(label):
    raw=command(label+'-index',['git','ls-files','-v','-z'])
    flags=dict(collections.Counter(row[:1].decode() for row in raw.split(b'\0') if row))
    tree=command(label+'-tree',['git','ls-tree','-r','-z','--full-tree',A])
    entries=[row for row in tree.split(b'\0') if row]
    missing=[]
    for row in entries:
        rel=row.split(b'\t',1)[1].decode()
        path=ROOT/rel
        if not path.is_file() and not path.is_symlink(): missing.append(rel)
    return {'tracked_entries':len(entries),'index_flags':flags,'missing_count':len(missing),
            'missing_first':missing[:10]},b'\0'.join(row.split(b'\t',1)[1] for row in entries)+b'\0'

def replace_file(path,raw):
    mode=stat.S_IMODE(path.stat().st_mode)
    with tempfile.NamedTemporaryFile(dir=path.parent,prefix='.daa-ci-repair-',delete=False) as temporary:
        temporary.write(raw);temporary.flush();os.fsync(temporary.fileno());pending=Path(temporary.name)
    try:
        pending.chmod(mode);os.replace(pending,path)
    finally:
        pending.unlink(missing_ok=True)

validation_specs=[]
save(OUT/'plan.json',{'schema':'trnm-daa-ci-guard-repair-plan-v1','source_A':A,
     'repair_root':str(ROOT),'canonical_root':str(CANONICAL),'controller':str(Path(__file__).resolve()),
     'controller_sha256':digest(Path(__file__)),'helper_sha256':HELPER_SHA,
     'started_utc':started,'allowed_source_delta':sorted(SCOPE),
     'existing_tests_are_unchanged':True,'minimum_free_bytes_before_full_materialization':MIN_FREE,
     'development_controls':['focused-new-negative-method-1','actual-ci','current-corpus-915'],
     'A2_validation_gates':['source-before','preflight-audit','ci-contract-negatives',
         'ci-contract-current','pq-corpus-current','repository-and-markdown-links','source-after'],
     'native_or_formal_execution_source':'A only; this controller performs no native or scientific campaign',
     'production_activation':False})
try:
    ensure(ROOT.is_dir() and not ROOT.is_symlink() and ROOT.resolve()==ROOT,'REPAIR_ROOT')
    ensure(command('canonical-head-before',['git','rev-parse','HEAD'],cwd=CANONICAL).decode().strip()==A,'CANONICAL_NOT_A')
    ensure(command('repair-head-before',['git','rev-parse','HEAD']).decode().strip()==A,'REPAIR_NOT_A')
    ensure(command('repair-branch-before',['git','branch','--show-current']).decode().strip()
           =='fix/chain-daa-resource-ci-guard-20261112-600e','REPAIR_BRANCH')
    ensure(not command('repair-status-before',['git','status','--porcelain']).strip(),'DIRTY_REPAIR')
    common=Path(command('common-directory',['git','rev-parse','--path-format=absolute','--git-common-dir']).decode().strip())
    common_path=common/'config'
    common_before=digest(common_path)
    preconditions={'source_A':A,'common_config_sha256_before':common_before,
                   'common_config_span':'this repair routine after worktree add; no pre-add attestation',
                   'free_bytes_before':shutil.disk_usage(ROOT.parent).free}
    observe_dev('preflight-before-edits',['/bin/bash','scripts/project-preflight.sh','--audit'],check='preflight')
    snapshot,paths=index_snapshot('initial')
    preconditions['initial_index']=snapshot
    if snapshot!={'tracked_entries':26711,'index_flags':{'H':26711},'missing_count':0,'missing_first':[]}:
        free=shutil.disk_usage(ROOT.parent).free
        preconditions['free_before_full_materialization']=free
        ensure(free>=MIN_FREE,'LOW_DISK_FULL_MATERIALIZATION_REFUSED')
        ensure(command('worktree-config-enabled',['git','config','--bool','extensions.worktreeConfig']).decode().strip()=='true',
               'WORKTREE_CONFIG_NOT_ENABLED')
        command('disable-sparse-worktree',['git','config','--worktree','core.sparseCheckout','false'])
        command('disable-sparse-cone-worktree',['git','config','--worktree','core.sparseCheckoutCone','false'])
        command('clear-skip-flags',['git','update-index','--no-skip-worktree','-z','--stdin'],input_bytes=paths)
        command('clear-assume-flags',['git','update-index','--no-assume-unchanged','-z','--stdin'],input_bytes=paths)
        command('materialize-index',['git','checkout-index','--all','--force'],timeout=900)
        snapshot,_=index_snapshot('materialized')
        preconditions['materialized_index']=snapshot
    ensure(snapshot=={'tracked_entries':26711,'index_flags':{'H':26711},'missing_count':0,'missing_first':[]},
           'INCOMPLETE_ISOLATED_SOURCE')
    ensure(digest(common_path)==common_before,'COMMON_CONFIG_CHANGED_DURING_INITIALIZATION')
    observe_dev('source-before-repair',[PY,'-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',A],check='source')
    preconditions['all_26711_H_physical_and_raw_A_verified']=True
    save(OUT/'preconditions.json',preconditions)
    old=(ROOT/CHECKER).read_bytes()
    ensure(blob(old)==OLD_BLOB,'CHECKER_BASE_BLOB')
    old_corpus=(ROOT/CORPUS).read_bytes()
    corpus=json.loads(old_corpus)
    ensure(corpus['pinned_blobs'][CHECKER]==OLD_BLOB,'CHECKER_BASE_CORPUS_PIN')
    ensure(len(corpus['pinned_blobs'])==915,'CORPUS_DENOMINATOR')
    test_before=digest(ROOT/TEST)
    ensure(command('unchanged-test-before',['git','show',A+':'+TEST])==(ROOT/TEST).read_bytes(),'TEST_ALREADY_CHANGED')
    constant_anchor="""JOINT_CONSENSUS_QUALIFICATION_COMMANDS = (
    'python3 formal/pon-nakamoto-v1/joint_consensus_qualification.py --check',
    'python3 formal/pon-nakamoto-v1/test_joint_consensus_qualification.py',
    'python3 formal/pon-nakamoto-v1/test_dynamic_participation_v1.py',
    'python3 formal/pon-nakamoto-v1/test_joint_production_tail_v1.py',
)"""
    addition="""JOINT_RESOURCE_COMPETITION_COMMANDS = (
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_quantum_probability_sampling.py' -v",
    "python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_joint_resource_competition_campaign.py' -v",
)"""
    loop_anchor="""    for command in JOINT_CONSENSUS_QUALIFICATION_COMMANDS:
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'joint consensus qualification controls must execute exactly once in repository-truth')
"""
    loop_addition="""    for command in JOINT_RESOURCE_COMPETITION_COMMANDS:
        require(code_lines(lanes['repository-truth']).count(command) == 1
                and code_lines(script).count(command) == 1,
                'joint resource competition controls must execute exactly once in repository-truth')
"""
    text=old.decode()
    ensure(text.count(constant_anchor)==1 and text.count(loop_anchor)==1,'UNIQUE_APPROVED_ANCHORS')
    ensure('JOINT_RESOURCE_COMPETITION_COMMANDS' not in text,'FAMILY_ALREADY_PRESENT')
    changed=text.replace(constant_anchor,constant_anchor+'\n\n'+addition,1).replace(loop_anchor,loop_anchor+loop_addition,1)
    ast.parse(changed)
    new=changed.encode()
    new_blob=blob(new)
    old_pin='"'+CHECKER+'": "'+OLD_BLOB+'"'
    new_pin='"'+CHECKER+'": "'+new_blob+'"'
    ensure(old_corpus.decode().count(old_pin)==1,'UNIQUE_CURRENT_CORPUS_PIN')
    new_corpus=old_corpus.decode().replace(old_pin,new_pin,1).encode()
    parsed=json.loads(new_corpus)
    expected=json.loads(old_corpus)
    expected['pinned_blobs'][CHECKER]=new_blob
    ensure(parsed==expected,'CORPUS_OTHER_CONTENT_CHANGED')
    replace_file(ROOT/CHECKER,new)
    replace_file(ROOT/CORPUS,new_corpus)
    ensure(digest(ROOT/TEST)==test_before,'NEGATIVE_TEST_CHANGED')
    changed_paths=set(command('approved-diff-paths',['git','diff','--name-only']).decode().splitlines())
    ensure(changed_paths==SCOPE,'UNAPPROVED_SOURCE_DELTA')
    command('approved-diff',['git','diff','--',CHECKER,CORPUS])
    command('unchanged-other-ci',['git','diff','--exit-code',A,'--',TEST,'scripts/ci/ci_job.sh'])
    command('diff-whitespace',['git','diff','--check'])
    observe_dev('focused-new-negative-method',[PY,'-B',TEST,
        'MergedQualificationLaneTests.test_joint_resource_commands_cannot_be_omitted_moved_or_skipped','-v'],tests=1)
    observe_dev('actual-ci',[PY,'-B',CHECKER],check='ci')
    observe_dev('current-corpus',[PY,'-B','scripts/ci/check_pq_research_integration.py'],check='pq')
    ensure(digest(common_path)==common_before,'COMMON_CONFIG_CHANGED_BEFORE_COMMIT')
    ensure(command('canonical-head-before-commit',['git','rev-parse','HEAD'],cwd=CANONICAL).decode().strip()==A,'CANONICAL_MOVED')
    command('stage-approved-delta',['git','add','--',CHECKER,CORPUS])
    ensure(set(command('staged-paths',['git','diff','--cached','--name-only']).decode().splitlines())==SCOPE,'STAGED_SCOPE')
    staged=json.loads(command('staged-preflight',['/bin/bash','scripts/project-preflight.sh','--staged']).decode())
    ensure(staged.get('result')=='PASS' and staged.get('mode')=='--staged','STAGED_PREFLIGHT')
    command('freeze-a2',['git','commit','-m','ci: enforce one lane for quantum resource controls'],timeout=600)
    a2=command('a2-head',['git','rev-parse','HEAD']).decode().strip()
    tree=command('a2-tree',['git','rev-parse','HEAD^{tree}']).decode().strip()
    ensure(re.fullmatch('[0-9a-f]{40}',a2) and a2!=A,'A2_IDENTITY')
    ensure(command('a2-parent',['git','rev-parse','HEAD^']).decode().strip()==A,'A2_NOT_DIRECT_CHILD')
    delta=set(command('a2-delta',['git','diff-tree','--no-commit-id','--name-only','-r','HEAD']).decode().splitlines())
    ensure(delta==SCOPE,'A2_SCOPE')
    ensure(not command('a2-clean',['git','status','--porcelain']).strip(),'A2_DIRTY')
    ensure(digest(ROOT/TEST)==test_before,'TEST_CHANGED_AT_FREEZE')
    ensure(digest(common_path)==common_before,'COMMON_CONFIG_CHANGED_AT_FREEZE')
    freeze={'schema':'trnm-daa-ci-guard-repair-freeze-v1','source_A':A,'commit':a2,'tree':tree,
        'parent':A,'scope_only_two_files':True,'changed_files':sorted(delta),
        'checker_before_blob':OLD_BLOB,'checker_after_blob':new_blob,
        'checker_before_sha256':hashlib.sha256(old).hexdigest(),'checker_after_sha256':hashlib.sha256(new).hexdigest(),
        'corpus_before_sha256':hashlib.sha256(old_corpus).hexdigest(),'corpus_after_sha256':hashlib.sha256(new_corpus).hexdigest(),
        'negative_test_sha256_before':test_before,'negative_test_sha256_after':digest(ROOT/TEST),
        'existing_169_tests_unchanged':True,'development_controls_passed':all(row['expectation_met'] for row in development),
        'common_config_sha256_before':common_before,'common_config_sha256_after':digest(common_path),
        'common_config_span':'routine only; pre-worktree-add identity was not recorded',
        'canonical_head_at_freeze':A,'canonical_source_writes_performed':False,
        'native_or_formal_execution_source':A,'frozen_utc':stamp(),'production_activation':False}
    save(OUT/'freeze.json',freeze)
    source=[PY,'-B','scripts/ci/verify_ci_source.py','--kind','head','--expected-head',a2]
    validation_specs=[
        helper.gate('source-before',source,check='source'),
        helper.gate('preflight-audit',['/bin/bash','scripts/project-preflight.sh','--audit'],check='preflight'),
        helper.gate('ci-contract-negatives',[PY,'-B',TEST,'-v'],1800,tests=169),
        helper.gate('ci-contract-current',[PY,'-B',CHECKER],check='ci'),
        helper.gate('pq-corpus-current',[PY,'-B','scripts/ci/check_pq_research_integration.py'],check='pq'),
        helper.gate('repository-and-markdown-links',[PY,'-B','scripts/ci/check_repository.py'],check='repository'),
        helper.gate('source-after',source,check='source')]
    save(VALID/'plan.json',{'schema':'trnm-daa-ci-guard-A2-validation-plan-v1','expected_head':a2,
                          'gates':validation_specs,'controller_sha256':digest(Path(__file__))})
    try:
        validation.append(helper.observe(validation_specs[0],VALID,a2,ENV))
        ensure(validation[0]['expectation_met'],'A2_SOURCE_BEFORE_FAILED')
        free=shutil.disk_usage(ROOT.parent).free
        save(VALID/'disk-before-suite.json',{'free_bytes':free,'minimum_free_bytes':MIN_FREE,
              'purpose':'protect concurrent native work before full-suite temporary source copies','observed_utc':stamp()})
        ensure(free>=MIN_FREE,'LOW_DISK_FULL_SUITE_REFUSED')
        for specification in validation_specs[1:-1]:
            validation.append(helper.observe(specification,VALID,a2,ENV))
    finally:
        validation.append(helper.observe(validation_specs[-1],VALID,a2,ENV))
    ensure(len(validation)==7 and all(row['expectation_met'] for row in validation),'A2_VALIDATION_FAILED')
except BaseException as error:
    failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()}
finally:
    try:
        canonical_after=command('canonical-head-final',['git','rev-parse','HEAD'],cwd=CANONICAL).decode().strip()
    except BaseException as error:
        if failure is None: failure={'type':type(error).__name__,'message':str(error),'stage':'canonical-final'}
    common_after=digest(common_path) if common_path is not None and common_path.is_file() else None
    passed=(failure is None and freeze is not None and len(validation)==7
            and all(row['expectation_met'] for row in validation)
            and canonical_after==A and common_before==common_after)
    summary={'schema':'trnm-daa-ci-guard-repair-summary-v1','source_A':A,
        'A2':freeze['commit'] if freeze else None,'started_utc':started,'ended_utc':stamp(),
        'status':'PASS' if passed else 'FAIL','all_expected_outcomes_observed':passed,
        'controller_error':failure,'scope_only_two_files':freeze is not None and freeze['scope_only_two_files'],
        'existing_169_tests_unchanged':freeze is not None and freeze['existing_169_tests_unchanged'],
        'canonical_head_after':canonical_after,'canonical_head_unchanged':canonical_after==A,
        'common_config_sha256_before':common_before,'common_config_sha256_after':common_after,
        'common_config_unchanged_during_routine':common_before is not None and common_before==common_after,
        'common_config_before_add_attested':False,
        'development_controls':[{'name':row['name'],'expectation_met':row['expectation_met']} for row in development],
        'validation_planned':len(validation_specs),'validation_observed':len(validation),
        'validation_complete':len(validation_specs)==7 and len(validation)==7,
        'validation_records':[str(Path('validation')/row['name']/'record.json') for row in validation],
        'operation_records':commands,'qualification':'HOLD_NO_GO','release_ready':False,
        'native_or_formal_execution_source':A,'canonical_source_writes_performed':False}
    save(OUT/'summary.json',summary)
    files={str(path.relative_to(OUT)):{'bytes':path.stat().st_size,'sha256':digest(path)}
           for path in sorted(OUT.rglob('*')) if path.is_file()}
    save(OUT/'manifest.json',{'schema':'trnm-daa-ci-guard-repair-manifest-v1',
                             'source_A':A,'A2':summary['A2'],'files':files})
    print(json.dumps(summary,sort_keys=True),flush=True)
raise SystemExit(0 if passed else 1)
