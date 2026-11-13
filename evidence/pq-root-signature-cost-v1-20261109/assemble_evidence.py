#!/usr/bin/env python3
"""Package this task's retained observations without changing their bytes."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

WORK = Path(__file__).resolve().parent
ROOT = WORK.parent / 'chain-pq'
OUT = ROOT / 'evidence/pq-root-signature-cost-v1-20261109'
CAMPAIGN = WORK / 'frozen-campaign-c9fb3fa6'


def digest(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def archive(name, sources):
    frozen = WORK / 'staged-evidence' / name
    if frozen.is_file():
        expected = {target: source for target, source in sources}
        assert len(expected) == len(sources)
        shutil.copyfile(frozen, OUT / name)
        members = []
        with tarfile.open(OUT / name, 'r:gz') as tar:
            entries = tar.getmembers()
            assert len(entries) == len(expected) and {x.name for x in entries} == set(expected)
            for entry in entries:
                assert entry.isfile()
                with tar.extractfile(entry) as stream:
                    data = stream.read()
                assert data == expected[entry.name].read_bytes(), entry.name
                members.append({'path': entry.name, **digest(data)})
        return {'path': name, 'members': members}
    members = []
    with (OUT / name).open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for target, source in sorted(sources):
                    assert source.is_file() and not source.is_symlink(), source
                    data = source.read_bytes()
                    info = tarfile.TarInfo(target)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = 0
                    tar.addfile(info, io.BytesIO(data))
                    members.append({'path': target, **digest(data)})
    return {'path': name, 'members': members}


def main():
    assert (CAMPAIGN / 'summary.json').is_file(), 'original campaign must terminate first'
    assert (WORK / 'cost-analysis.json').is_file(), 'independent cost analysis must complete first'
    assert (WORK / 'evidence-README.md').is_file(), 'reviewable README required'
    subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=ROOT, check=True)
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == 'd239bc8f683da7cdc8a4b9dc8e763d67e74680f6'
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip(), 'do not overwrite concurrent edits'
    OUT.mkdir(parents=True, exist_ok=False)
    copied = {
        'README.md': WORK / 'evidence-README.md',
        'campaign-summary.json': CAMPAIGN / 'summary.json',
        'source-publication.json': WORK / 'source-publication.json',
        'failure-ledger.json': WORK / 'failure-ledger.json',
        'hosted-correction-source-gates.json': WORK / 'hosted-correction-source-gates.json',
        'cost-analysis.json': WORK / 'cost-analysis.json',
        'cost_analysis.py': WORK / 'cost_analysis.py',
        'source-c9fb3fa6.bundle': WORK / 'source-c9fb3fa6.bundle',
        'run_frozen_campaign.py': WORK / 'run_frozen_campaign.py',
        'verify_evidence.py': WORK / 'verify_evidence.py',
        'assemble_evidence.py': WORK / 'assemble_evidence.py',
        'assembly-observations.json': WORK / 'assembly-observations.json',
    }
    retry = WORK / 'serial-followup-d239bc8f'
    if retry.exists():
        assert (retry / 'summary.json').is_file(), 'follow-up must terminate before packaging'
        copied['followup-summary.json'] = retry / 'summary.json'
        copied['run_serial_followup.py'] = WORK / 'run_serial_followup.py'
    for target, source in copied.items():
        shutil.copyfile(source, OUT / target)
    archives = [archive('raw-campaign.tar.gz', [('frozen-campaign-c9fb3fa6/' + str(p.relative_to(CAMPAIGN)), p) for p in CAMPAIGN.rglob('*') if p.is_file()])]
    hosted = WORK / 'hosted-source-ci'
    archives.append(archive('hosted-source-ci.tar.gz', [('hosted-source-ci/' + str(p.relative_to(hosted)), p) for p in hosted.rglob('*') if p.is_file()]))
    inputs = json.loads((WORK / 'setup-evidence-inputs.json').read_text())
    sources = []
    for entry in inputs['files']:
        source = Path(entry['source_path'])
        assert digest(source.read_bytes()) == {'bytes': entry['bytes'], 'sha256': entry['sha256']}, source
        sources.append((entry['archive_path'], source))
    for name in ['setup-evidence-inputs.json', 'post-failure-resources.json']:
        sources.append((name, WORK / name))
    archives.append(archive('setup-and-provenance.tar.gz', sources))
    if retry.exists():
        archives.append(archive('raw-followup.tar.gz', [('serial-followup-d239bc8f/' + str(p.relative_to(retry)), p) for p in retry.rglob('*') if p.is_file()]))
    frozen_archives = {
        'raw-campaign.tar.gz': (346562, '2ad20733ada2fb647f800be1a5ad78ea741a1d395d313f000b3aeee404a168af'),
        'hosted-source-ci.tar.gz': (101548, '953a5cd378f1bd56855c8b21e5bd5a0957300901dfbca15c4a2959bf4efb4634'),
        'setup-and-provenance.tar.gz': (102004, 'd3a51ef41d61960772c67d5ecf4247a97f2c0ced7dfb85f6abec705070faddc6'),
    }
    for name, (size, sha256) in frozen_archives.items():
        assert digest((OUT / name).read_bytes()) == {'bytes': size, 'sha256': sha256}, name
    manifest = {
        'schema': 'trnm-pq-signature-cost-evidence-manifest-v1',
        'locally_executed_source_commit': 'c9fb3fa61e2aadbdeaf39e85a7e21604d72581b7',
        'published_source_commit': '5840295dd0442804e80449ec7eb4b74dc3e68a3b',
        'complete_source_tree': '704b67dc07f94e1770452f154d72c002b5ac1af0',
        'inventory_correction_and_followup_source_commit': 'd239bc8f683da7cdc8a4b9dc8e763d67e74680f6',
        'inventory_correction_and_followup_source_tree': '37032e79799b9b21acc5b7f4ed1d74cc6bf97185',
        'manifest_self_hash_excluded': True,
        'independent_execution_authentication': False,
        'files': [{'path': str(p.relative_to(OUT)), **digest(p.read_bytes())} for p in sorted(OUT.rglob('*')) if p.is_file()],
        'archives': archives,
    }
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'evidence_directory': str(OUT), 'files': len(manifest['files']) + 1, 'bytes': sum(x['bytes'] for x in manifest['files'])}))


if __name__ == '__main__':
    main()
