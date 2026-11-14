#!/usr/bin/env python3
"""Re-read retained transcripts and business reports; never run native code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = json.loads((root/'manifest.json').read_text())
    for entry in manifest['files']:
        raw = (root/entry['path']).read_bytes()
        assert len(raw) == entry['bytes'] and sha(raw) == entry['sha256'], entry['path']
    # The repository supplies the original readers and their imports. Require
    # their exact retained bytes before importing; do not use a relaxed reader.
    for name in ['scripts/ci/check_required_native_test.py','scripts/ci/run_from_zero_native.py',
                 'scripts/ci/replay_pinned_native.py','scripts/ci/verify_ci_source.py',
                 'formal/pon-nakamoto-v1/contract_wire.py','config/pon/ledger-v1.json',
                 'config/pon/work-profile-v1.json','config/pon/model-family-v1.json']:
        relative = Path(name)
        assert (args.repo/relative).read_bytes() == (root/'source'/relative).read_bytes()
    sys.path.insert(0, str(args.repo/'scripts/ci'))
    from check_required_native_test import validate
    from run_from_zero_native import validate_confirmation_report, summarize_confirmation_report
    output = {'schema':'retained-ci-evidence-readback-v1',
              'native_tests_executed':False,'source_builds_executed':False,
              'scope':'Transcript/report consistency only; original process/source receipts remain required',
              'workspace':[],'from_zero':[]}
    for lane in sorted((root/'workspace').iterdir()):
        tests = []
        for line in (lane/'test-exits.tsv').read_text().splitlines()[1:]:
            selector,code,log_code,reader_code = line.split('\t')
            text = (lane/(selector.rsplit('::',1)[1]+'.log')).read_text()
            assert log_code == '0'
            if code == '0':
                assert reader_code == '0'
                result = validate(text.splitlines(),selector)
            else:
                assert code == '101' and reader_code == '1'
                assert len(re.findall(r'^running 1 test$',text,re.M)) == 1
                assert len(re.findall(r'^test '+re.escape(selector)+r' \.\.\.',text,re.M)) == 1
                assert len(re.findall(r'^test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured; [0-9]+ filtered out;',text,re.M)) == 1
                assert 'PUBLIC_MUTATION_CPU_BUDGET' in text
                try:
                    validate(text.splitlines(),selector)
                except ValueError as error:
                    result = {'result':'REJECTED','error':str(error),'test':selector}
                else:
                    raise AssertionError('Failed native execution was accepted by reader')
            tests.append(result)
        output['workspace'].append({'lane':lane.name,'tests':tests})
    for lane in sorted((root/'from-zero').iterdir()):
        native = lane/'from-zero-native'
        original = json.loads((native/'manifest.json').read_text())
        for run in original['runs']:
            assert run['process']['exit_code'] == 0 and run['passed'] is True
            text = (native/run['name']/'stdout').read_text()
            assert validate(text.splitlines(),run['name']) == run['named_execution']
        report = native/'confirmation/report.json'
        try:
            validate_confirmation_report(report)
        except ValueError as error:
            assert str(error) == 'CONFIRMATION_TARGET'
            result = {'lane':lane.name,'result':'REJECTED','error':str(error),
                      'raw_report_sha256':sha(report.read_bytes()),
                      'original_source':original['source_before']['commit'],
                      'five_named_native_controls_passed':True,
                      'observation':summarize_confirmation_report(report)}
        else:
            raise AssertionError('Original finite business target unexpectedly passed')
        output['from_zero'].append(result)
    print(json.dumps(output,indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
