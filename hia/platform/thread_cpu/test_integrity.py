"""Source-closure and public-entry regressions before original compilation."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from .build import INPUTS,OWNED,ORIGINAL_SOURCE,ORIGINAL_SHA256
from .rust_oracle import ROOT,complete_source_manifest,validate_source_bindings,parse_json,original_clock_trace
from .cases import corpus
from .trace_audit import primitive_clock_result,complete_calls


class ThreadCpuIntegrityTests(unittest.TestCase):
    def test_complete_current_source_binding(self):
        current=complete_source_manifest()
        self.assertEqual(len(OWNED),13)
        self.assertTrue(set(INPUTS)<=set(current))
        self.assertEqual(current[ORIGINAL_SOURCE]['sha256'],ORIGINAL_SHA256)
        native={'build':{'source_inputs':copy.deepcopy(current)},'source_inputs':copy.deepcopy(current)}
        self.assertEqual(validate_source_bindings(native),current)
        self.assertIn('hia/platform/thread_cpu/test_integrity.py',current)
        self.assertIn('hia/platform/thread_cpu/rust_reference.rs',current)
        for name in ('trillionnium/Cargo.toml','trillionnium/Cargo.lock',
                     'trillionnium/crates/trnm-pon-node/Cargo.toml'):
            self.assertIn(name,current)

    def test_public_bundle_refuses_incomplete_or_stale_sources_before_copy(self):
        current=complete_source_manifest()
        original={'schema':'trnm.hia.thread-cpu-native-input.v1',
                  'status':'NATIVE_PASS_ORIGINAL_NOT_RUN',
                  'build':{'status':'PASS','source_inputs':copy.deepcopy(current)},
                  'source_inputs':copy.deepcopy(current)}
        variants=[]
        for label,path in (
            ('missing-native-policy','hia/platform/thread_cpu/owner_policy.hepta'),
            ('missing-original-hook','hia/platform/thread_cpu/rust_reference.rs'),
            ('missing-public-oracle','hia/platform/thread_cpu/rust_oracle.py'),
            ('missing-integrity-guard','hia/platform/thread_cpu/test_integrity.py'),
            ('missing-locked-clock-dependency','trillionnium/Cargo.lock')):
            value=copy.deepcopy(original)
            del value['source_inputs'][path]
            del value['build']['source_inputs'][path]
            variants.append((label,value))
        value=copy.deepcopy(original)
        del value['build']['source_inputs']['hia/platform/thread_cpu/cases.py']
        variants.append(('top-build-disagree',value))
        value=copy.deepcopy(original)
        for mapping in (value['source_inputs'],value['build']['source_inputs']):
            mapping['hia/platform/thread_cpu/fixture_entry.hepta']['sha256']='0'*64
        variants.append(('stale-source',value))
        value=copy.deepcopy(original)
        for mapping in (value['source_inputs'],value['build']['source_inputs']):
            mapping['invented/source.hepta']={'bytes':0,'sha256':'0'*64}
        variants.append(('extra-source',value))
        with tempfile.TemporaryDirectory(prefix='trnm-thread-cpu-invalid-bundles-') as temporary:
            base=Path(temporary)
            for name,value in variants:
                with self.subTest(name=name):
                    bundle=base/(name+'-input');bundle.mkdir()
                    (bundle/'native-comparison.json').write_text(json.dumps(value))
                    output=base/(name+'-output')
                    ran=subprocess.run([sys.executable,'-B','-m','hia.platform.thread_cpu.rust_oracle',
                        '--repository',str(ROOT),'--bundle',str(bundle),'--output',str(output)],
                        cwd=ROOT,env={'PATH':'','PYTHONDONTWRITEBYTECODE':'1'},
                        capture_output=True,timeout=30)
                    self.assertNotEqual(ran.returncode,0)
                    report=json.loads((output/'original/report.json').read_text())
                    self.assertEqual(report['status'],'FAIL')
                    self.assertIn('complete source sets differ',report['failure'])
                    self.assertFalse((output/'original/isolated-source').exists())
                    self.assertFalse((output/'original/cargo-target').exists())
                    self.assertEqual(report['stages'],[])

    def test_duplicate_json_key_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError,'Duplicate JSON key'):
            parse_json('{"source_inputs":{},"source_inputs":{"ignored":1}}')


    def test_actual_ptrace_annotation_and_exact_timespec_regression(self):
        # Exact clock line retained from the first real original Rust refusal.
        # These parser controls do not claim a new native execution.
        actual='487087 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=-1, tv_nsec=0}) = 0 (INJECTED: args, retval)\n'
        case=next(value for value in corpus() if value['name']=='controlled_timespec_0')
        variants={
            'missing-injection':actual.replace(' (INJECTED: args, retval)',''),
            'missing-output-bytes':actual.replace('(INJECTED: args, retval)','(INJECTED)'),
            'missing-return':actual.replace('(INJECTED: args, retval)','(INJECTED: args)'),
            # Both decode to None; exact source bytes must still differ.
            'different-invalid-timespec':actual.replace('tv_sec=-1','tv_sec=-2'),
            'second-injection':actual+actual,
            'wrong-clock':actual.replace('CLOCK_THREAD_CPUTIME_ID','CLOCK_MONOTONIC'),
            'unsupported-annotation':actual.replace('args, retval','retval, args'),
        }
        with tempfile.TemporaryDirectory(prefix='trnm-thread-cpu-ptrace-annotation-') as temporary:
            trace=Path(temporary)/'actual-line.trace'
            trace.write_text(actual)
            checked=original_clock_trace(trace,case)
            self.assertEqual(checked['status'],'PASS')
            self.assertEqual(checked['actual_clock_calls'],1)
            for name,mutated in variants.items():
                with self.subTest(name=name):
                    trace.write_text(mutated)
                    with self.assertRaises(ValueError):
                        original_clock_trace(trace,case)
            trace.write_text(actual)
            wrong_ordinal=copy.deepcopy(case)
            wrong_ordinal['injection']=wrong_ordinal['injection'].replace(':when=1',':when=2')
            with self.assertRaisesRegex(ValueError,'another syscall ordinal'):
                original_clock_trace(trace,wrong_ordinal)


    def test_timespec_trace_unsigned_nsec_preserves_exact_signed_bytes(self):
        # Real native trace printed the all-one signed -1 field as unsigned.
        # Both spellings below denote those same 64 bits, without relaxing the
        # 16-byte equality or accepting wider integers that merely wrap.
        actual='560403 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=18446744073709551615}) = 0 (INJECTED: args, retval)\n'
        case=next(value for value in corpus() if value['name']=='controlled_timespec_1')
        with tempfile.TemporaryDirectory(prefix='trnm-thread-cpu-timespec-bits-') as temporary:
            trace=Path(temporary)/'actual-line.trace'
            for representation in ('18446744073709551615','-1'):
                trace.write_text(actual.replace('18446744073709551615',representation))
                self.assertEqual(original_clock_trace(trace,case)['status'],'PASS')
            for representation in ('18446744073709551614','36893488147419103231','-18446744073709551617'):
                with self.subTest(representation=representation):
                    trace.write_text(actual.replace('18446744073709551615',representation))
                    with self.assertRaises(ValueError):
                        original_clock_trace(trace,case)


    def test_actual_backend_one_fallback_boundaries(self):
        # These pure trace mutations target the real V6 44/53 mismatch.
        # They do not count as new native or original-Rust executions.
        good='910 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=7}) = 0\n'
        bad='910 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=-1, tv_nsec=0}) = 0 (INJECTED: args, retval)\n'
        errors={name:'910 clock_gettime(CLOCK_THREAD_CPUTIME_ID, 0x12340000) = -1 '+name+' (controlled) (INJECTED)\n'
                for name in ('EINTR','EINVAL','ENOSYS','EIO')}
        def samples(text):
            return complete_calls(text)[0]
        self.assertEqual(primitive_clock_result(samples(good)),(7,0))
        self.assertEqual(primitive_clock_result(samples(bad)),(None,0))
        self.assertEqual(primitive_clock_result(samples(errors['EINVAL'])),(None,(1<<64)-22))
        for name,number in (('EINTR',4),('ENOSYS',38),('EIO',5)):
            with self.subTest(error=name):
                self.assertEqual(primitive_clock_result(samples(errors[name]+good)),(7,0))
                self.assertEqual(primitive_clock_result(samples(errors[name]+errors[name])),
                                 (None,(1<<64)-number))
                self.assertEqual(primitive_clock_result(samples(errors[name]+errors['EINVAL'])),
                                 (None,(1<<64)-22))
                self.assertEqual(primitive_clock_result(samples(errors[name]+bad)),(None,0))
                for mutated in (errors[name],errors[name]+good+good,
                                errors[name]+good.replace('910 ','911 ',1)):
                    with self.assertRaises(ValueError):
                        primitive_clock_result(samples(mutated))
        for mutated in (good+good,bad+good,errors['EINVAL']+good):
            with self.assertRaises(ValueError):
                primitive_clock_result(samples(mutated))

    def test_persistent_errno_requires_every_actual_ordinal(self):
        first='910 clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=7}) = 0\n'
        fault='910 clock_gettime(CLOCK_THREAD_CPUTIME_ID, 0x12340000) = -1 EINTR (controlled) (INJECTED)\n'
        case=next(value for value in corpus()
                  if value['name']=='clock_persistent_errno_checkpoint_EINTR')
        actual=first+fault+fault
        variants={
            'missing-second-mark':first+fault+fault.replace(' (INJECTED)',''),
            'first-ordinal-too-early':fault+fault+fault,
            'first-ordinal-too-late':first+first+fault,
            'different-thread':first+fault+fault.replace('910 ','911 ',1),
            'different-error':first+fault+fault.replace('EINTR','EIO'),
            'different-clock':first+fault+fault.replace('CLOCK_THREAD_CPUTIME_ID','CLOCK_MONOTONIC'),
        }
        with tempfile.TemporaryDirectory(prefix='trnm-thread-cpu-persistent-errno-') as temporary:
            trace=Path(temporary)/'controlled.trace'
            trace.write_text(actual)
            checked=original_clock_trace(trace,case)
            self.assertEqual(checked['actual_injected_clock_calls'],2)
            self.assertEqual(checked['actual_clock_calls'],3)
            for name,mutated in variants.items():
                with self.subTest(name=name):
                    trace.write_text(mutated)
                    with self.assertRaises(ValueError):
                        original_clock_trace(trace,case)

    def test_optimized_public_entry_rejects_before_output(self):
        with tempfile.TemporaryDirectory(prefix='trnm-thread-cpu-python-optimize-') as temporary:
            base=Path(temporary)
            for flag in ('-O','-OO'):
                for module in ('build','qualify','rust_oracle'):
                    with self.subTest(flag=flag,module=module):
                        output=base/(module+flag)
                        ran=subprocess.run([sys.executable,flag,'-B','-m',
                            'hia.platform.thread_cpu.'+module,'--output',str(output)],
                            cwd=ROOT,env={'PATH':'','PYTHONDONTWRITEBYTECODE':'1'},
                            capture_output=True,timeout=30)
                        self.assertNotEqual(ran.returncode,0)
                        self.assertIn(b'refuses optimized Python',ran.stderr)
                        self.assertFalse(output.exists())


if __name__=='__main__':
    unittest.main()
