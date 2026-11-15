#!/usr/bin/env python3
"""Build a byte-pinned metadata/evidence packet; no repository or remote writes."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

ROOT = Path('/workspace/scratch/bt-owner-recovery-20261112-4a0b')
EVIDENCE = 'evidence/cell-bt-owner-convergence-20261112/'
HEAD = '031d442dd0acb693afcfaf42f9cc4db446ba52cb'
TREE = 'a897ba4c74897a05ceb364f098b1bfe32c850213'
CONTROL = '/home/qian-qi/chain-bt-owner-convergence-20261112-4a0b-publication-control/'
DOC_NAMES = ['CELL_BT_OWNER_CONVERGENCE_V1.md', 'CELL_NATIVE_SHARD_RESEARCH_V2.md']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()


def new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    files = {}
    for path in sorted((ROOT / 'publication-stage' / EVIDENCE).rglob('*')):
        if path.is_dir():
            continue
        assert stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink(), path
        name = path.relative_to(ROOT / 'publication-stage').as_posix()
        assert name not in {EVIDENCE + 'artifact-index.json', EVIDENCE + 'publication/metadata-binding.json'}
        files[name] = path.read_bytes()
    for name in DOC_NAMES:
        files['docs/development/specs/pon/' + name] = (ROOT / 'preparation/publication-docs-draft' / name).read_bytes()
    acceptance = {kind: EVIDENCE + 'model/' + name for kind, name in {
        'model_observation': 'observation.json', 'model_config': 'config.json',
        'model_source': 'source-inputs.json', 'model_native_result': 'native-result.json'
    }.items()}
    acceptance['candidate_coverage'] = EVIDENCE + 'candidate-gate-coverage.json'
    records = {key: json.loads(files[path]) for key, path in acceptance.items()}
    obs, cfg, source, native, coverage = (records[key] for key in
        ('model_observation', 'model_config', 'model_source', 'model_native_result', 'candidate_coverage'))
    assert cfg['head'] == HEAD and cfg['tree'] == TREE
    assert obs['passed'] is True and obs['native_started'] is True
    assert obs['start_identity'] == obs['end_identity'] == {'head': HEAD, 'tree': TREE, 'status': ''}
    assert obs['config_sha256'] == sha(files[acceptance['model_config']])
    assert obs['native_result_sha256'] == sha(files[acceptance['model_native_result']])
    assert cfg['source_sha256'] == obs['source_sha256'] == native['source_input_sha256'] == sha(files[acceptance['model_source']])
    assert native['operation_pins']['operation'] == obs['operation'] == source['operation']
    assert native['passed'] is True and native['actual_model_run'] == 'observed_two_forwards'
    assert all(native[key] is False for key in ['independent_operators', 'hepta_final_use', 'production_activation'])
    assert obs['production_activation'] is False and obs['independent_real_money'] is False
    assert coverage['coverage_complete'] is True and coverage['source'] == HEAD
    assert coverage['expected_candidate_command_count'] == coverage['covered_command_count'] == 74
    assert coverage['missing_commands'] == [] and coverage['original_summaries_rewritten'] is False
    inputs = json.loads((ROOT / 'validation/desktop-publication/doc-inputs-v1/publication-doc-inputs-v1.json').read_bytes())
    old_prefix = inputs['plan_prefix']['prefix_bytes'].encode()[:863]
    assert sha(old_prefix) == 'a108265560d803537aac54948664f48df83ace03f9798a75aeb0c09dd0c516b6'
    new_prefix = (ROOT / 'preparation/publication-docs-draft/plan-prefix.txt').read_bytes()
    assert new_prefix.endswith(b'\n\n') and 400 < len(new_prefix) <= 16384
    final_docs = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in files.items()
                  if name.startswith('docs/') or name in {EVIDENCE + 'README.md', EVIDENCE + 'summary.json'}}
    final_docs['plan-prefix.txt'] = {'bytes': len(new_prefix), 'sha256': sha(new_prefix)}
    identity = {'schema': 'trnm.bt-final-reviewed-publication-documents.v1',
                'runtime_source': HEAD, 'runtime_source_tree': TREE, 'files': final_docs,
                'historical_drafts_overwritten': False, 'production_activation': False,
                'model_result_actual_file_binding_verified': True}
    identity_name = EVIDENCE + 'publication/final-documents-identity.json'
    assert identity_name not in files
    files[identity_name] = encoded(identity)
    new(ROOT / 'publication-stage' / identity_name, files[identity_name])
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode='w', format=tarfile.USTAR_FORMAT) as tf:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mode = 0o644
            info.uid = info.gid = info.mtime = 0
            tf.addfile(info, io.BytesIO(files[name]))
    archive = gzip.compress(tar_bytes.getvalue(), compresslevel=9, mtime=0)
    archive_name = 'publication-reviewed-final-01.tar.gz'
    packet = {'schema': 'trnm.bt-reviewed-publication-packet.v1', 'source': HEAD, 'source_tree': TREE,
              'model_result_review_complete': True, 'candidate_gate_coverage_complete': True,
              'production_activation': False, 'hepta_final_use': False,
              'stage_output_name': 'publication-stage-02', 'archive_path': CONTROL + archive_name,
              'archive_bytes': len(archive), 'archive_sha256': sha(archive),
              'files': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(files.items())},
              'old_plan_prefix': old_prefix.decode(), 'new_plan_prefix': new_prefix.decode(),
              'acceptance_evidence': acceptance}
    new(ROOT / 'preparation' / archive_name, archive)
    packet_path = ROOT / 'preparation/publication-reviewed-final-01.packet.json'
    new(packet_path, encoded(packet))
    print(json.dumps({'archive': archive_name, 'archive_bytes': len(archive),
                      'archive_sha256': sha(archive), 'member_count': len(files),
                      'member_bytes': sum(map(len, files.values())), 'packet_bytes': packet_path.stat().st_size,
                      'packet_sha256': sha(packet_path.read_bytes()), 'acceptance_files_verified': True}, indent=2))


if __name__ == '__main__':
    main()
