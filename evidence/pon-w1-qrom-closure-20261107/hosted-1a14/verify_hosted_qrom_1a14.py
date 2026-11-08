#!/usr/bin/env python3
"""Read back retained GitHub observations; this is not a cryptographic verifier."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

HEAD = '1a14f7d4826363daefac9ec10131c66d7e70ece7'
TREE = 'e08b5dcd9ae2e90d0a36cb5d85e6ce1def387e85'
BASE = 'cb114b13bf848a77634e40a08b31b30c7c758e7b'
MERGE = 'f14298a2728b22fda625267e2e4844b70f829b37'
QUALIFICATION = {
    'post_quantum_soundness_qualified': False,
    'complete_w1_soundness_qualified': False,
    'quantum_work_qualified': False,
    'pq_signature_qualification_inferred': False,
    'production_qualified': False,
    'consensus_admission': False,
    'unconditional_project_security_bits': None,
}
PROFILES = {
    'closure': {'run':42379162582, 'tests':105,
        'roster':'config/pon/w1-qrom-closure-required-tests-v1.json',
        'roster_sha256':'ee2b11492a362bd4be2f2df4e7ad691f4dd8a78cd9df884979cb3409e117745f',
        'named':'named-controls.json', 'named_schema':'TRNM-W1-QROM-CLOSURE-CONTROLS1',
        'status_schema':'TRNM-W1-QROM-CLOSURE-CI1',
        'required_stages':['observations','checkout','source_before','preflight','named_controls','reproduce','source_after']},
    'implementation': {'run':42379162380, 'tests':81,
        'roster':'config/pon/w1-qrom-required-tests-v1.json',
        'roster_sha256':'ca685b61914435e0be6defdaa0bc4f2368f7430060663315cd96f226adab5bd8',
        'named':'named-tests.json', 'named_schema':'TRNM-W1-QROM-NAMED-TEST-OBSERVATION1',
        'status_schema':'TRNM-W1-QROM-CI-OBSERVATION1',
        'required_stages':['observations','checkout','source_before','preflight','named_tests','implementation','budget_unknown','budget_hypothetical','report_scopes','source_after']},
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value

def refuse_constant(value):
    raise ValueError('nonfinite JSON: ' + value)

def strict(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=refuse_constant)

def load(path):
    return strict(path.read_bytes())

def check_scope(value):
    for key, expected in QUALIFICATION.items():
        require(key in value and value[key] is expected, 'security scope differs: ' + key)

def git(root, *args):
    return subprocess.check_output(['git','--no-replace-objects','-C',str(root),*args])

def check_named(value, profile, roster):
    require(value['schema'] == profile['named_schema'], 'named schema')
    require(value['roster_sha256'] == profile['roster_sha256'], 'named roster pin')
    require(type(value['required_tests']) is int and value['required_tests'] == profile['tests'], 'named count')
    require(type(value['suites']) is list and len(value['suites']) == len(roster['suites']), 'suite count')
    if profile is PROFILES['closure']:
        require(set(value) == {'schema','roster_sha256','required_tests','suites','qualification'}, 'closure completion shape')
        check_scope(value['qualification'])
    else:
        require(set(value) == {'schema','roster_sha256','required_tests','suites','all_named_controls_passed','post_quantum_soundness_qualified','unconditional_project_security_bits'}, 'implementation completion shape')
        require(value['all_named_controls_passed'] is True and value['post_quantum_soundness_qualified'] is False and value['unconditional_project_security_bits'] is None, 'implementation completion scope')
    names = []
    suites = []
    for actual, expected in zip(value['suites'], roster['suites']):
        fields = {'module','registered_ids','started_ids','success_ids','tests_run','loader_errors','skipped','failures','errors','expected_failures','unexpected_successes'}
        fields |= {'exception'} if profile is PROFILES['closure'] else {'expected_ids','passed'}
        require(set(actual) == fields, 'completion suite shape')
        require(actual['module'] == expected['module'], 'suite order')
        count = len(expected['tests']) if profile is PROFILES['closure'] else expected['expected_tests']
        require(type(count) is int and count > 0 and type(actual['tests_run']) is int and actual['tests_run'] == count, 'suite typed count')
        wanted = expected['tests']
        require(type(wanted) is list and all(type(x) is str for x in wanted) and len(set(wanted)) == len(wanted) == count, 'roster suite IDs')
        for field in ['registered_ids','started_ids','success_ids'] + ([] if profile is PROFILES['closure'] else ['expected_ids']):
            require(type(actual[field]) is list and all(type(x) is str for x in actual[field]) and Counter(actual[field]) == Counter(wanted), 'named identities: ' + field)
        for field in ['loader_errors','skipped','failures','errors','expected_failures','unexpected_successes']:
            require(type(actual[field]) is list and actual[field] == [], 'non-success named outcome: ' + field)
        if profile is PROFILES['closure']:
            require(actual['exception'] is None, 'suite exception')
        else:
            require(actual['passed'] is True, 'suite passed marker')
        names.extend(wanted)
        suites.append({'module':actual['module'],'tests_run':count})
    require(len(names) == len(set(names)) == profile['tests'], 'completion total or duplicate ID')
    return suites

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, required=True)
    parser.add_argument('--collection', type=Path, required=True)
    parser.add_argument('--followup', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root, collection, followup = args.repo_root, args.collection, args.followup
    require(git(root,'rev-parse',HEAD+'^{tree}').decode().strip() == TREE, 'candidate tree')
    ancestor = subprocess.run(['git','--no-replace-objects','-C',str(root),'merge-base','--is-ancestor',BASE,HEAD], capture_output=True)
    require(ancestor.returncode == 0, 'base ancestor relation')
    tree_entries = [x.split(b'\t',1)[0].split() for x in git(root,'ls-tree','-r','-l','-z',HEAD).split(b'\0') if x]
    require(len(tree_entries) == 11144, 'candidate tree entry count')
    merge = load(followup/'merge-commit.stdout')
    require(merge['sha'] == MERGE and merge['tree']['sha'] == TREE and [x['sha'] for x in merge['parents']] == [BASE,HEAD], 'GitHub ordered merge parents/tree')
    report = {'schema':'TRNM-W1-QROM-HOSTED-INDEPENDENT-READBACK1','candidate':HEAD,'candidate_tree':TREE,'base':BASE,'prospective_merge':MERGE,
              'ordered_merge_parents':[BASE,HEAD], 'canonical_merge_tree_reason':'Base is an ancestor of candidate; the canonical merge tree is the candidate tree, matching the separately retrieved GitHub commit.',
              'scope':'Readback and consistency validation of retained GitHub API/artifacts. The local clone has missing historical blob bodies; complete worktree hashing was executed by the identified hosted jobs, not repeated here. Named record checks are not execution attestations independent of GitHub and trusted workflow code.',
              'local_tree_entry_count':len(tree_entries),'local_missing_blob_size_count':sum(not x[3].isdigit() for x in tree_entries),
              'local_available_blob_bytes':sum(int(x[3]) for x in tree_entries if x[3].isdigit()),'artifacts':[], 'qualification':dict(QUALIFICATION)}
    archive_report = load(collection/'collection-report.json')
    require(archive_report['collection_complete'] is True, 'collection incomplete')
    for label, profile in PROFILES.items():
        run = load(collection/(label+'-run.stdout'))
        require(run['id'] == profile['run'] and run['head_sha'] == HEAD and run['status'] == 'completed' and run['conclusion'] == 'success', 'run identity/status')
        jobs = load(collection/(label+'-jobs.stdout'))
        require(type(jobs['total_count']) is int and jobs['total_count'] == len(jobs['jobs']) == 2, 'job completeness')
        index = load(collection/(label+'-artifacts.stdout'))
        require(type(index['total_count']) is int and index['total_count'] == len(index['artifacts']) == 2, 'artifact completeness')
        roster_raw = git(root,'show',HEAD+':'+profile['roster'])
        require(sha(roster_raw) == profile['roster_sha256'], 'source roster hash')
        roster = strict(roster_raw)
        require(type(roster['expected_tests']) is int and roster['expected_tests'] == profile['tests'], 'source roster total')
        kinds = []
        for artifact in index['artifacts']:
            aid = artifact['id']
            raw = (collection/(label+'-artifact-'+str(aid)+'.zip')).read_bytes()
            require(artifact['digest'] == 'sha256:'+sha(raw) and artifact['expired'] is False and artifact['workflow_run']['head_sha'] == HEAD, 'artifact API digest/scope')
            folder = collection/(label+'-'+str(aid))
            with zipfile.ZipFile(collection/(label+'-artifact-'+str(aid)+'.zip')) as archive:
                require(archive.testzip() is None, 'ZIP CRC')
                require(len(archive.namelist()) == len(set(archive.namelist())), 'duplicate ZIP path')
                for name in archive.namelist():
                    require(archive.read(name) == (folder/name).read_bytes(), 'extracted member differs')
            before_raw = (folder/'source-before.json').read_bytes()
            require(before_raw == (folder/'source-after.json').read_bytes(), 'source before/after bytes differ')
            source = strict(before_raw)
            kind = source['kind']; kinds.append(kind)
            require(kind in ('head','prospective-merge'), 'source kind')
            expected_commit = HEAD if kind == 'head' else MERGE
            expected_source = {'schema':'trnm-ci-source-v1','kind':kind,'tested_commit':expected_commit,'tested_tree':TREE,'candidate':HEAD,
                'base':None if kind == 'head' else BASE,'prospective_merge':None if kind == 'head' else MERGE,
                'tracked_worktree_verified':True,'tracked_entries':11144,'tracked_bytes':1100983593,'tests_executed_by_identity_check':False}
            require(source == expected_source and type(source['tracked_entries']) is int and type(source['tracked_bytes']) is int and source['tracked_worktree_verified'] is True and source['tests_executed_by_identity_check'] is False, 'complete hosted source identity')
            job_matches = [x for x in jobs['jobs'] if x['name'] == f'W1 QROM {label} ({kind}, x64)']
            require(len(job_matches) == 1, 'job/source matching')
            job = job_matches[0]
            require(job['head_sha'] == HEAD and job['run_id'] == profile['run'] and job['status'] == 'completed' and job['conclusion'] == 'success', 'job identity/conclusion')
            require(all(x['status'] == 'completed' and x['conclusion'] == 'success' for x in job['steps']), 'GitHub job non-success step')
            status = load(folder/'ci-status.json')
            require(status['schema'] == profile['status_schema'] and status['source_kind'] == kind and status['expected_source'] == expected_commit and status['expected_base'] == BASE, 'CI identity')
            require(status['expected_head' if label == 'closure' else 'expected_candidate'] == HEAD, 'CI candidate')
            require(status['all_required_observations_passed'] is True and status['failed_or_skipped_stages'] == [] and status['required_stages'] == profile['required_stages'], 'CI stages')
            for stage in profile['required_stages']:
                require(status['steps'][stage]['outcome'] == status['steps'][stage]['conclusion'] == 'success', 'CI stage result')
            require(status['steps']['checkout']['outputs']['commit'] == expected_commit, 'checkout output')
            named_raw = (folder/profile['named']).read_bytes()
            named = strict(named_raw)
            suites = check_named(named, profile, roster)
            reproduced = []
            if label == 'closure':
                check_scope(status['qualification'])
                require(status['completion_or_identity_error'] is None, 'closure identity/completion error')
                paths = {'semantics.json':'evidence/pon-w1-qrom-semantics-20261107/report.json','lifetime.json':'evidence/pon-w1-lifetime-20261107/project-report.json'}
                for name in ['composition-unknown','composition-example','joint-oracle-unknown','joint-oracle-alias','joint-oracle-separated']:
                    paths[name+'.json'] = 'evidence/pon-w1-qrom-formal-bridge-20261107/'+name+'.json'
                for name, pinned in paths.items():
                    data = (folder/name).read_bytes()
                    require(data == git(root,'show',HEAD+':'+pinned), 'pinned reproduced report differs: '+name)
                    reproduced.append({'artifact_path':name,'candidate_source_path':pinned,'sha256':sha(data)})
            else:
                check_scope(status)
                require(status['source_identity_error'] is None and status['named_test_completion_error'] is None and status['named_test_completion_verified'] is True and status['named_test_completion_sha256'] == sha(named_raw), 'implementation completion/identity')
                require((folder/'required-tests.json').read_bytes() == roster_raw, 'retained implementation roster differs')
                for suite in named['suites']:
                    require(load(folder/(suite['module']+'.json')) == suite, 'per-suite record differs')
            files = [{'path':str(p.relative_to(folder)),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(folder.rglob('*')) if p.is_file()]
            report['artifacts'].append({'workflow':label,'run_id':profile['run'],'run_url':run['html_url'],'job_id':job['id'],'job_url':job['html_url'],'artifact_id':aid,'artifact_name':artifact['name'],'zip_bytes':len(raw),'zip_sha256':sha(raw),'source':source,'source_before_after_identical_bytes':True,'source_json_sha256':sha(before_raw),'named_tests':profile['tests'],'named_completion_sha256':sha(named_raw),'roster_sha256':profile['roster_sha256'],'suites':suites,'all_GitHub_job_steps_success':True,'ci_status_sha256':sha((folder/'ci-status.json').read_bytes()),'reproduced_pinned_reports':reproduced,'files':files})
        require(Counter(kinds) == Counter(['head','prospective-merge']), 'both source kinds required')
    baseline = load(followup/'baseline-run.stdout')
    require(baseline['id'] == 42379162489 and baseline['head_sha'] == HEAD, 'baseline identity')
    baseline_jobs = load(followup/'baseline-jobs.stdout')
    require(baseline_jobs['total_count'] == len(baseline_jobs['jobs']), 'baseline job pagination')
    truth = [x for x in baseline_jobs['jobs'] if 'repository-truth' in x['name']]
    require({x['name'] for x in truth} == {'repository-truth','prospective-merge (repository-truth)'}, 'repository-truth jobs')
    observations = []
    for job in truth:
        require(job['head_sha'] == HEAD and job['status'] == 'completed' and job['conclusion'] == 'success', 'repository-truth conclusion')
        path = followup/('baseline-job-'+str(job['id'])+'-log.stdout')
        lines = [x for x in path.read_text().splitlines() if x.endswith(' distributed source inventory: PASS')]
        require(len(lines) == 1, 'inventory success observation missing/ambiguous')
        observations.append({'job_id':job['id'],'job_name':job['name'],'conclusion':job['conclusion'],'log_bytes':path.stat().st_size,'log_sha256':sha(path.read_bytes()),'inventory_success_line':lines[0]})
    report['baseline'] = {'run_id':baseline['id'],'status_at_collection':baseline['status'],'conclusion_at_collection':baseline['conclusion'],'repository_truth':observations,'other_failed_jobs_preserved':[{'name':x['name'],'id':x['id'],'conclusion':x['conclusion']} for x in baseline_jobs['jobs'] if x['conclusion'] == 'failure'],'whole_baseline_pass_claimed':False}
    report['all_four_artifacts_consistent_with_identified_hosted_runs'] = True
    with args.out.open('x') as stream:
        json.dump(report,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
    print(json.dumps({'output':str(args.out),'bytes':args.out.stat().st_size,'sha256':sha(args.out.read_bytes()),'artifacts':len(report['artifacts']),'closure_tests_each':105,'implementation_tests_each':81,'repository_truth_jobs_passed':len(observations),'qualification':QUALIFICATION},sort_keys=True))

if __name__ == '__main__':
    main()
