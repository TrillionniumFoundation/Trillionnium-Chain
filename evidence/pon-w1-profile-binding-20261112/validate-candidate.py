#!/usr/bin/env python3
"""Record exact-source checks; no mining or production qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import types


def require(ok, message):
    if not ok:
        raise ValueError(message)


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    require(not output.is_relative_to(root), 'output must be external')
    output.mkdir(exist_ok=False)
    os.chdir(root)
    os.environ['PATH'] = '/home/qian-qi/.cargo/bin:' + os.environ['PATH']
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    os.environ['GIT_NO_LAZY_FETCH'] = '1'
    os.environ['CARGO_TARGET_DIR'] = '/home/qian-qi/work/w1-baseline-9082-target-165d'
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / 'scripts/ci'))
    from run_w1_rank_batch_v5 import capture, cargo_configuration_snapshot, require_cargo_configuration, build_environment_overrides
    result = {'schema': 'w1-binding-exact-source-validation-v1',
              'expected_commit': args.expected_commit, 'result': 'HOLD', 'commands': [],
              'native_measurement_source': '229b14c2d366a257f51f287d502a550df2332338',
              'native_measurements_reassigned': False, 'production_activation': False}
    (output / 'executed-validator.py').write_bytes(Path(__file__).read_bytes())

    def run(label, command, timeout=600, expected_exit=0, count=None):
        print(json.dumps({'started': label}), flush=True)
        row = capture(command, output, label, timeout=timeout)
        result['commands'].append({'label': label, **row})
        write(output / (label + '.json'), row)
        with (output / 'commands.jsonl').open('a') as stream:
            stream.write(json.dumps({'label': label, **row}, sort_keys=True) + '\n')
        require(row['exit_code'] == expected_exit and row['timed_out'] is False, label + ': command failed')
        if count is not None:
            text = (output / row['stdout']).read_text() + '\n' + (output / row['stderr']).read_text()
            if count[0] == 'python':
                require([int(n) for n in re.findall(r'(?m)^Ran (\d+) tests? in ', text)] == [count[1]]
                        and re.search(r'(?m)^OK\s*$', text), label + ': test completion differs')
            else:
                require(re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;', text)
                        == [(str(count[1]), '0', '0', '0', '0')], label + ': native test completion differs')
        print(json.dumps({'finished': label, 'exit_code': row['exit_code']}), flush=True)
        return row

    def source(label):
        target = output / (label + '-identity.json')
        run(label, ['/usr/bin/python3', '-B', 'scripts/ci/verify_ci_source.py', '--kind', 'head',
                    '--expected-head', args.expected_commit, '--output', str(target)])
        return json.loads(target.read_bytes())

    try:
        result['source_before'] = source('source-before')
        run('preflight', ['bash', 'scripts/project-preflight.sh'])
        run('unchanged-runtime-and-graphs', ['git', 'diff', '--exit-code',
             '229b14c2d366a257f51f287d502a550df2332338', args.expected_commit, '--',
             'trillionnium', 'formal', '.cargo', 'rust-toolchain.toml', 'tests/fuzz'])
        helper_path = Path('/home/qian-qi/work/w1-baseline-9082-validation-165d/supplemental-provider-clippy/helpers/supplemental-provider-clippy-165d.py')
        raw = helper_path.read_bytes()
        require(len(raw) == 18226 and hashlib.sha256(raw).hexdigest() == '363fa66725ddedf2a6fa1e34b785b31c2e8ddeaa767f058766b2037c0f4ea492', 'provider helper changed')
        (output / 'provider-helper.py').write_bytes(raw)
        provider = types.ModuleType('frozen_provider')
        provider.__file__ = str(helper_path)
        env_before = dict(os.environ)
        exec(compile(raw, str(helper_path), 'exec'), provider.__dict__)
        require(dict(os.environ) == env_before, 'provider import changed environment')
        result['provider_before'] = provider.provider_identity()
        require(result['provider_before']['all_five_match'], 'provider pins differ')
        selection = provider.check_inherited_environment(dict(os.environ))
        require(selection['compatible'], 'inherited provider selection differs')
        os.environ.update(provider.expected_environment())
        result['provider_environment'] = provider.expected_environment()
        result['build_environment_overrides'] = build_environment_overrides(dict(os.environ))
        require(not result['build_environment_overrides'], 'unreviewed compiler/Cargo override')
        result['cargo_configuration_before'] = cargo_configuration_snapshot(root, dict(os.environ))
        require_cargo_configuration(result['cargo_configuration_before'])
        run('rustc', ['rustc', '-vV'], 30)
        require('\nrelease: 1.95.0\n' in (output / 'rustc.stdout').read_text(), 'Rust version differs')
        run('cargo-version', ['cargo', '--version'], 30)
        require((output / 'cargo-version.stdout').read_text().startswith('cargo 1.95.0 '), 'Cargo version differs')
        graph = ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1', '--manifest-path', 'trillionnium/Cargo.toml']
        run('graph-default', graph, 300)
        run('graph-all-features', graph + ['--all-features'], 300)
        run('graph-fuzz', ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1',
                           '--manifest-path', 'tests/fuzz/Cargo.toml'], 300)
        run('workspace-fmt', ['cargo', 'fmt', '--manifest-path', 'trillionnium/Cargo.toml', '--all', '--', '--check'], 300)
        py = ['/usr/bin/python3', '-B']
        for label, path, count in (
            ('profile-controls', 'scripts/ci/test_pq_proof_profile_binding.py', 29),
            ('source-negatives', 'scripts/ci/test_ci_source_integrity.py', 43),
            ('corpus-controls', 'scripts/ci/test_pq_research_integration.py', 60),
            ('zero-lazy-reader', 'scripts/ci/test_pon_w1_zero_paired_lazy_v1.py', 21),
            ('v5-runner-controls', 'scripts/ci/test_run_w1_rank_batch_v5.py', 6),
        ):
            run(label, py + [path], count=('python', count))
        run('profile-descriptor', py + ['scripts/ci/pq_proof_profile_binding.py', '--expected-profile-descriptor-sha256',
             '0d47e23d395d6332a0bdf1c9093cf5b19816aad9841e3db6e8cb24f53e0f18b3'])
        for label, command in (
            ('ci-contract', py + ['scripts/ci/check_ci_contract.py']),
            ('corpus-guard', py + ['scripts/ci/check_pq_research_integration.py']),
            ('distributed-inventory', py + ['scripts/refresh_distributed_source_inventory.py', '--check']),
            ('repository-markdown', py + ['scripts/ci/check_repository.py']),
            ('whitespace', ['git', 'diff', '--check', args.expected_commit + '^', args.expected_commit]),
        ):
            run(label, command)
        run('crypto-lib', ['cargo', 'test', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml',
                          '-p', 'trnm-crypto-primitives', '--lib'], 1800, count=('rust', 199))
        run('workspace-strict-clippy', ['cargo', 'clippy', '--locked', '--offline', '--manifest-path', 'trillionnium/Cargo.toml',
             '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 3600)
        result['provider_after'] = provider.provider_identity()
        require(result['provider_after'] == result['provider_before'], 'provider changed')
        result['cargo_configuration_after'] = cargo_configuration_snapshot(root, dict(os.environ))
        require(result['cargo_configuration_after'] == result['cargo_configuration_before'], 'Cargo configuration changed')
        result['source_after'] = source('source-after')
        require(result['source_before'] == result['source_after'], 'source changed')
        result['result'] = 'EXACT_SOURCE_CHECKS_PASSED'
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['artifact_identities'] = {str(p.relative_to(output)): {'bytes': p.stat().st_size,
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(output.rglob('*')) if p.is_file()}
        write(output / 'validation.json', result)
    print(json.dumps({'result': result['result'], 'error': result.get('error'), 'commands': len(result['commands'])}), flush=True)
    return 0 if result['result'] == 'EXACT_SOURCE_CHECKS_PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
