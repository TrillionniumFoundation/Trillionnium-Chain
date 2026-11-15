#!/usr/bin/env python3
"""Stage reviewed documentation/evidence on B; never commit or push."""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile
import time

REPO = Path('/home/qian-qi/work/chain-bt-4a0b-publication02')
CONTROL = Path('/home/qian-qi/chain-bt-owner-convergence-20261112-4a0b-publication-control')
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TREE = 'a897ba4c74897a05ceb364f098b1bfe32c850213'
BRANCH = 'fix/chain-bt-owner-convergence-20261112-4a0b'
ORIGIN = 'https://github.com/TrillionniumFoundation/Trillionnium-Chain.git'
EVIDENCE = 'evidence/cell-bt-owner-convergence-20261112/'
PLAN = 'docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md'
PLAN_SHA = 'f16b368598120fc86b3bdf5062c054f7bded9ac11af32526af4f883cdcfad3f3'
PLAN_PREFIX_BYTES = 863
PLAN_PREFIX_SHA = 'a108265560d803537aac54948664f48df83ace03f9798a75aeb0c09dd0c516b6'
PLAN_SUFFIX_ANCHOR = ('**Cell storage four-gate continuation, 2026-11-12 UTC '
                      '— local native PASS; qualification HOLD:**\n').encode()
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
DOCS = {
    'docs/development/specs/pon/CELL_BT_OWNER_CONVERGENCE_V1.md': 'aa33ebeb9f0224ccb89cc9b2a9ce9054a2c6ed419242594ba09f43adbf9857a6',
    'docs/development/specs/pon/CELL_NATIVE_SHARD_RESEARCH_V2.md': 'f0f7ee6c043f1658c66e21be32af931417597beccc4b96cf4b30fb85d5497ba8',
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def regular(path: Path) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            'not one regular file: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                    after.st_mtime_ns, after.st_ctime_ns),
            'changed read: ' + str(path))
    return raw


def git(*args: str) -> str:
    return subprocess.check_output(['/usr/bin/git', *args], cwd=REPO, text=True).strip()


def write_new(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def replace_expected(path: Path, original: bytes, updated: bytes) -> None:
    require(regular(path) == original, 'pre-write original changed: ' + str(path))
    temporary = path.with_name(path.name + '.bt-publication-pending')
    write_new(temporary, updated)
    require(regular(path) == original, 'original changed before rename')
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet', type=Path, required=True)
    args = parser.parse_args()
    packet_bytes = regular(args.packet)
    packet = json.loads(packet_bytes)
    require(packet['schema'] == 'trnm.bt-reviewed-publication-packet.v1', 'packet schema')
    require(packet['source'] == HEAD and packet['source_tree'] == TREE, 'packet source')
    require(packet['model_result_review_complete'] is True, 'model review incomplete')
    require(packet['candidate_gate_coverage_complete'] is True, 'candidate gates incomplete')
    require(packet['production_activation'] is False and packet['hepta_final_use'] is False,
            'qualification flags must remain false')
    output = CONTROL / packet['stage_output_name']
    require(output.parent == CONTROL and not output.exists(), 'fresh stage output required')
    output.mkdir(mode=0o700)
    control_fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(control_fd)
    finally:
        os.close(control_fd)
    report = {'schema': 'trnm.bt-documentation-publication-stage.v1', 'source': HEAD,
              'source_tree': TREE, 'packet_sha256': sha(packet_bytes),
              'started_unix_ns': time.time_ns(), 'completed': False,
              'passed': False, 'committed': False, 'pushed': False, 'commands': []}

    def save() -> None:
        target = output / 'report.json'
        pending = output / 'report.pending.json'
        with pending.open('w') as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, target)
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def run(name: str, argv: list[str], timeout: int = 600) -> None:
        start = time.monotonic_ns()
        with (output / (name + '.stdout')).open('xb') as stdout, \
             (output / (name + '.stderr')).open('xb') as stderr:
            result = subprocess.run(argv, cwd=REPO, stdout=stdout, stderr=stderr,
                                    timeout=timeout, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        item = {'name': name, 'argv': argv, 'exit_code': result.returncode,
                'elapsed_ns': time.monotonic_ns() - start}
        for stream in ('stdout', 'stderr'):
            raw = regular(output / (name + '.' + stream))
            item[stream + '_bytes'] = len(raw)
            item[stream + '_sha256'] = sha(raw)
        report['commands'].append(item)
        save()
        require(result.returncode == 0, 'stage command failed: ' + name)

    save()
    try:
        require(git('rev-parse', 'HEAD') == HEAD and git('rev-parse', 'HEAD^{tree}') == TREE,
                'frozen B changed')
        require(git('branch', '--show-current') == BRANCH and git('remote', 'get-url', 'origin') == ORIGIN,
                'publication repository identity')
        require(not git('status', '--porcelain=v1', '--untracked-files=all'), 'publication tree dirty')
        run('preflight-before-edits', ['/bin/bash', 'scripts/project-preflight.sh'])
        run('source-before', ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py',
                              '--kind', 'head', '--expected-head', HEAD])
        archive_path = Path(packet['archive_path'])
        require(archive_path.parent == CONTROL, 'packet archive outside control')
        archive = regular(archive_path)
        require(len(archive) == packet['archive_bytes'] and sha(archive) == packet['archive_sha256'],
                'packet archive pin')
        expected = packet['files']
        require(isinstance(expected, dict) and expected, 'empty packet file map')
        require(set(DOCS) <= set(expected), 'both reviewed contract documents required')
        require(all(name in DOCS or name.startswith(EVIDENCE) for name in expected), 'packet scope')
        require(EVIDENCE + 'README.md' in expected and EVIDENCE + 'summary.json' in expected,
                'complete evidence entry points required')
        require(not (REPO / EVIDENCE.rstrip('/')).exists(), 'evidence namespace already exists')
        prepared = {}
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tf:
            for member in tf:
                path = PurePosixPath(member.name)
                require(member.isfile() and not path.is_absolute() and '..' not in path.parts
                        and str(path) == member.name and member.name in expected
                        and member.name not in prepared, 'unexpected archive member')
                raw = tf.extractfile(member).read()
                pin = expected[member.name]
                require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'archive member pin')
                prepared[member.name] = raw
        require(set(prepared) == set(expected), 'missing archive members')
        acceptance_paths = packet['acceptance_evidence']
        require(set(acceptance_paths) == {'candidate_coverage', 'model_observation',
                                         'model_config', 'model_source', 'model_native_result'},
                'complete acceptance evidence bindings required')
        require(all(name in prepared and name.startswith(EVIDENCE)
                    for name in acceptance_paths.values()), 'acceptance evidence outside packet')
        acceptance = {kind: json.loads(prepared[name]) for kind, name in acceptance_paths.items()}
        coverage = acceptance['candidate_coverage']
        require(coverage['source'] == HEAD and coverage['coverage_complete'] is True and
                coverage['expected_candidate_command_count'] == 74 and
                coverage['covered_command_count'] == 74 and not coverage['missing_commands'] and
                coverage['original_summaries_rewritten'] is False,
                'candidate coverage is not the reviewed complete index')
        observation = acceptance['model_observation']
        model_config = acceptance['model_config']
        native = acceptance['model_native_result']
        model_source = acceptance['model_source']
        require(observation['passed'] is True and observation['native_started'] is True and
                observation['production_activation'] is False and
                observation['independent_real_money'] is False, 'actual model observation not accepted')
        require(model_config['head'] == HEAD and model_config['tree'] == TREE and
                observation['start_identity'] == observation['end_identity'] ==
                {'head': HEAD, 'tree': TREE, 'status': ''}, 'model runtime source changed')
        require(observation['config_sha256'] == sha(prepared[acceptance_paths['model_config']]) and
                observation['native_result_sha256'] == sha(prepared[acceptance_paths['model_native_result']]) and
                model_config['source_sha256'] == sha(prepared[acceptance_paths['model_source']]) ==
                observation['source_sha256'] == native['source_input_sha256'],
                'model original evidence byte binding')
        require(native['passed'] is True and native['actual_model_run'] == 'observed_two_forwards' and
                native['operation_pins']['operation'] == observation['operation'] == model_source['operation'] and
                all(native[flag] is False for flag in ('independent_operators', 'hepta_final_use',
                                                       'production_activation')),
                'native result or qualification scope changed')
        originals = {name: regular(REPO / name) for name in DOCS}
        require(all(sha(originals[name]) == DOCS[name] for name in DOCS), 'original docs changed')
        old_plan = regular(REPO / PLAN)
        require(sha(old_plan) == PLAN_SHA and len(old_plan) == 825081, 'original plan changed')
        old_prefix = packet['old_plan_prefix'].encode()
        new_prefix = packet['new_plan_prefix'].encode()
        require(old_plan.startswith(old_prefix) and len(old_prefix) == PLAN_PREFIX_BYTES and
                sha(old_prefix) == PLAN_PREFIX_SHA and
                old_plan[len(old_prefix):].startswith(PLAN_SUFFIX_ANCHOR),
                'old plan prefix mismatch')
        require(new_prefix.endswith(b'\n\n') and 400 < len(new_prefix) <= 16384,
                'new plan prefix incomplete')
        new_plan = new_prefix + old_plan[len(old_prefix):]
        old_corpus = regular(REPO / CORPUS)
        corpus = json.loads(old_corpus)
        updated = copy.deepcopy(corpus)
        require(corpus['schema'] == 'trnm-pq-cross-branch-corpus-v1' and
                corpus['status'] == 'research-only-hold-no-go', 'original corpus status')
        require(len(corpus['pinned_blobs']) == 994 and len(corpus['required_paths']) == 902,
                'original corpus roster')
        require(all(value is False for value in corpus['assertions'].values()), 'original corpus gates')
        require(corpus['pinned_blobs'][PLAN] == blob(old_plan), 'old plan corpus pin')
        require(all(name not in corpus['pinned_blobs'] for name in DOCS), 'unexpected doc corpus pin')
        updated['pinned_blobs'][PLAN] = blob(new_plan)
        new_corpus = (json.dumps(updated, ensure_ascii=False, indent=2) + '\n').encode()
        for name, raw in prepared.items():
            if name in DOCS:
                replace_expected(REPO / name, originals[name], raw)
            else:
                write_new(REPO / name, raw)
        replace_expected(REPO / PLAN, old_plan, new_plan)
        replace_expected(REPO / CORPUS, old_corpus, new_corpus)
        review = {'schema': 'trnm.bt-publication-metadata-binding.v1', 'runtime_source': HEAD,
                  'runtime_source_tree': TREE, 'plan_suffix_preserved': True,
                  'plan_suffix_sha256': sha(old_plan[len(old_prefix):]),
                  'old_plan_sha256': sha(old_plan), 'new_plan_sha256': sha(new_plan),
                  'old_corpus_sha256': sha(old_corpus), 'new_corpus_sha256': sha(new_corpus),
                  'corpus_paths_added': 0, 'corpus_paths_removed': 0,
                  'corpus_required_paths_unchanged': True, 'corpus_assertions_unchanged': True,
                  'corpus_pins_changed': [{'path': PLAN, 'old_blob': blob(old_plan),
                                          'new_blob': blob(new_plan)}],
                  'runtime_execution_relabelled': False, 'production_activation': False}
        review_name = EVIDENCE + 'publication/metadata-binding.json'
        require(review_name not in prepared, 'metadata review must be derived by stage')
        write_new(REPO / review_name, (json.dumps(review, sort_keys=True, indent=2) + '\n').encode())
        artifact_index_name = EVIDENCE + 'artifact-index.json'
        require(artifact_index_name not in prepared, 'artifact index must be derived by stage')
        evidence_members = sorted(name for name in set(prepared) | {review_name}
                                  if name.startswith(EVIDENCE))
        evidence_pins = []
        for name in evidence_members:
            raw = regular(REPO / name)
            evidence_pins.append({'path': name[len(EVIDENCE):], 'bytes': len(raw),
                                  'sha256': sha(raw)})
        artifact_index = {'schema': 'trnm.bt-publication-artifact-index.v1',
                          'runtime_source': HEAD, 'runtime_source_tree': TREE,
                          'self_excluded': True, 'files': evidence_pins,
                          'file_count_excluding_self': len(evidence_pins),
                          'total_bytes_excluding_self': sum(item['bytes'] for item in evidence_pins)}
        write_new(REPO / artifact_index_name,
                  (json.dumps(artifact_index, sort_keys=True, indent=2) + '\n').encode())
        allowed = set(prepared) | {PLAN, CORPUS, review_name, artifact_index_name}
        changed = set(git('diff', '--name-only', HEAD).splitlines())
        untracked = set(git('ls-files', '--others', '--exclude-standard').splitlines())
        require(changed | untracked == allowed, 'staged metadata scope differs from reviewed packet')
        run('diff-check', ['/usr/bin/git', 'diff', '--check'])
        run('preflight-after-edits', ['/bin/bash', 'scripts/project-preflight.sh'])
        run('stage-reviewed-paths', ['/usr/bin/git', 'add', '--', *sorted(allowed)])
        require(set(git('diff', '--cached', '--name-only', HEAD).splitlines()) == allowed,
                'Git index differs from reviewed metadata paths')
        require(not git('diff', '--name-only') and
                not git('ls-files', '--others', '--exclude-standard'),
                'unstaged or untracked change after staging')
        run('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
        run('preflight-staged', ['/bin/bash', 'scripts/project-preflight.sh', '--staged'])
        validation_tree = git('write-tree')
        report['validation_tree_before'] = validation_tree
        report['runtime_subtrees_unchanged'] = {}
        for name in ('trillionnium', 'scripts', 'formal', '.github'):
            original_tree = git('rev-parse', HEAD + ':' + name)
            require(git('rev-parse', validation_tree + ':' + name) == original_tree,
                    'runtime/validation subtree changed: ' + name)
            report['runtime_subtrees_unchanged'][name] = original_tree
        save()
        for name in ('check_repository', 'test_ci_source_integrity',
                     'check_pq_research_integration', 'test_pq_research_integration',
                     'test_pq_authority_effect_register'):
            run(name, ['/usr/bin/python3', '-B', 'scripts/ci/' + name + '.py'])
        run('inventory', ['/usr/bin/python3', '-B', 'scripts/refresh_distributed_source_inventory.py', '--check'])
        require(git('rev-parse', 'HEAD') == HEAD, 'HEAD changed during staging')
        require(git('write-tree') == validation_tree and not git('diff', '--name-only') and
                not git('ls-files', '--others', '--exclude-standard'),
                'validated metadata tree changed during checks')
        report['changed_paths'] = sorted(allowed)
        report['metadata_binding'] = review
        report['git_index_staged'] = True
        report['staged_tree'] = validation_tree
        report['file_pins'] = []
        for name in sorted(allowed):
            raw = regular(REPO / name)
            report['file_pins'].append({'path': name, 'bytes': len(raw), 'sha256': sha(raw)})
        report['passed'] = True
    except BaseException as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)
        raise
    finally:
        report['completed'] = True
        report['finished_unix_ns'] = time.time_ns()
        save()
        report_bytes = regular(output / 'report.json')
        print(json.dumps({'completed': True, 'passed': report['passed'],
                          'committed': False, 'pushed': False,
                          'staged_tree': report.get('staged_tree'),
                          'report': str(output / 'report.json'),
                          'bytes': len(report_bytes), 'sha256': sha(report_bytes)}), flush=True)


if __name__ == '__main__':
    main()
