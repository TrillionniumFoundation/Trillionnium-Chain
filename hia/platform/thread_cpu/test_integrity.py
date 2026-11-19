"""Source-closure and public-entry regressions before original compilation."""
from __future__ import annotations
import copy
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from .build import INPUTS,OWNED,ORIGINAL_SOURCE,ORIGINAL_SHA256
from .rust_oracle import ROOT,complete_source_manifest,validate_source_bindings,parse_json,original_clock_trace
from .cases import corpus
from .trace_audit import primitive_clock_result,complete_calls,audit_trace
from .qualify import observed_signal_eintr,trace_negative_controls


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

    def test_hosted_actual_sigreturn_tid_padding(self):
        # Exact return line from failed hosted job 133359090163. The actual
        # signal happened; its two-space TID padding defeated the live wait.
        actual='2882  rt_sigreturn({mask=[]})           = -1 EINTR (Interrupted system call)\n'
        for spacing in (' ','  ','       ','\t',' \t '):
            with self.subTest(spacing=repr(spacing)):
                line=actual.replace('2882  ','2882'+spacing,1)
                self.assertTrue(observed_signal_eintr(line,2882))
                resumed=line.replace('rt_sigreturn({mask=[]})',
                                     '<... rt_sigreturn resumed>{mask=[]}')
                self.assertTrue(observed_signal_eintr(resumed,2882))
        variants={
            'other-tid':actual.replace('2882','2883',1),
            'tid-prefix':actual.replace('2882','28820',1),
            'tid-suffix':actual.replace('2882','12882',1),
            'cross-line':actual.replace('2882  ','2882\n',1),
            'cross-line-other-task':actual.replace('2882  ','2882\n2883 ',1),
            'other-syscall':actual.replace('rt_sigreturn','read'),
            'successful-return':actual.replace('-1 EINTR (Interrupted system call)','0'),
            'different-error':actual.replace('EINTR','EIO'),
            'partial-return':actual.split('=')[0],
        }
        for name,line in variants.items():
            with self.subTest(name=name):
                self.assertFalse(observed_signal_eintr(line,2882))


    def test_complete_hosted_trace_negative_controls_with_tid_padding(self):
        # Complete real input/output/trace from hosted job 133396542521 at
        # 535ce9865d6764de8184aab04204459f6f05001b. All 65 semantic histories
        # and 74 physical controls ran; the following negative-control builder
        # failed to locate the real two-space TID + exit_group line.
        actual="2625  execve(\"/proc/self/fd/3\", [\"/proc/self/fd/3\"], [\"PATH=\"]) = 0\n2625  mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f91da449000\n2625  mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f91da439000\n2625  mmap(NULL, 1056768, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7f91da337000\n2625  mprotect(0x7f91da338000, 1048576, PROT_READ|PROT_WRITE) = 0\n2625  rt_sigaction(SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=0}, NULL, 8) = 0\n2625  rt_sigaction(SIGUSR1, {sa_handler=0x400812, sa_mask=[], sa_flags=SA_RESTORER, sa_restorer=0x400813}, NULL, 8) = 0\n2625  gettid()                          = 2625\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=423109}) = 0\n2625  getrandom(\"\\x95\\x7f\\x29\\xcc\\xe2\\x1a\\xc8\\x4f\\x69\\x4d\\x53\\x3d\\xb6\\xb8\\xb0\\x1d\", 16, 0) = 16\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\305t\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  getrandom(\"\\x14\\x1b\\xd2\\xf5\\x18\\x73\\xcc\\xb3\\xff\\x56\\x7e\\x21\\xb6\\xc1\\x8b\\x60\", 16, 0) = 16\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\24\\33\\322\\365\\30s\\314\\263\\377V~!\\266\\301\\213`\\305t\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\305t\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  clone(child_stack=0x7f91da438000, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tid=[2626], child_tidptr=0x7f91da44b000) = 2626\n2626  gettid( <unfinished ...>\n2625  futex(0x7f91da44b004, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2626  <... gettid resumed>)             = 2626\n2626  futex(0x7f91da44b004, FUTEX_WAKE_PRIVATE, 1) = 1\n2625  <... futex resumed>)              = 0\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\2\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  getrandom(\"\\xe7\\x3b\\xf5\\x19\\xd8\\xbb\\x2a\\x91\\x69\\x7a\\x49\\x07\\x4a\\xaf\\x6c\\x56\", 16, 0) = 16\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\347;\\365\\31\\330\\273*\\221izI\\7J\\257lV\\305t\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\305t\\6\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\3\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\347;\\365\\31\\330\\273*\\221izI\\7J\\257lV\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\347;\\365\\31\\330\\273*\\221izI\\7J\\257lV\\305t\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\305t\\6\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\4\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\347;\\365\\31\\330\\273*\\221izI\\7J\\257lV\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\347;\\365\\31\\330\\273*\\221izI\\7J\\257lV\\305t\\6\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\5\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0000u\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\7\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\231^\\220\\fq\\236\\211\\300B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=1577029}) = 0\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\10\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35\\305t\\6\\0\\0\\0\\0\\0\\200\\233\\21\\0\\0\\0\\0\\0E\\20\\30\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\231^\\220\\fq\\236\\211\\300B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=371842}) = 0\n2626  getrandom(\"\\xfe\\x5d\\xc3\\xc3\\x07\\x99\\x79\\x11\\xdd\\xf6\\x67\\xbe\\x90\\x89\\x65\\xa6\", 16, 0) = 16\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\t\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\376]\\303\\303\\7\\231y\\21\\335\\366g\\276\\220\\211e\\246\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\202\\254\\5\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\231^\\220\\fq\\236\\211\\300B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\376]\\303\\303\\7\\231y\\21\\335\\366g\\276\\220\\211e\\246\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  getrandom(\"\\xaf\\xa0\\x15\\x50\\x8d\\x0d\\x0e\\x8b\\x83\\x7e\\x7f\\xed\\x91\\x66\\xfa\\x15\", 16, 0) = 16\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\n\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\257\\240\\25P\\215\\r\\16\\213\\203~\\177\\355\\221f\\372\\25\\202\\254\\5\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\202\\254\\5\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\231^\\220\\fq\\236\\211\\300B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\257\\240\\25P\\215\\r\\16\\213\\203~\\177\\355\\221f\\372\\25\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\v\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\257\\240\\25P\\215\\r\\16\\213\\203~\\177\\355\\221f\\372\\25\\202\\254\\5\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\202\\254\\5\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\231^\\220\\fq\\236\\211\\300B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\5\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0@\\234\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\f\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\3\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\376]\\303\\303\\7\\231y\\21\\335\\366g\\276\\220\\211e\\246\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=1367923}) = 0\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\r\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\376]\\303\\303\\7\\231y\\21\\335\\366g\\276\\220\\211e\\246\\202\\254\\5\\0\\0\\0\\0\\0\\3612\\17\\0\\0\\0\\0\\0s\\337\\24\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\4\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\257\\240\\25P\\215\\r\\16\\213\\203~\\177\\355\\221f\\372\\25\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=1459399}) = 0\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\16\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\257\\240\\25P\\215\\r\\16\\213\\203~\\177\\355\\221f\\372\\25\\202\\254\\5\\0\\0\\0\\0\\0E\\230\\20\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\5\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\4\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\376]\\303\\303\\7\\231y\\21\\335\\366g\\276\\220\\211e\\246\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 1, NULL <unfinished ...>\n2626  gettid()                          = 2626\n2626  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=1575683}) = 0\n2626  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\17\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\376]\\303\\303\\7\\231y\\21\\335\\366g\\276\\220\\211e\\246s\\337\\24\\0\\0\\0\\0\\0\\220+\\3\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377B\\n\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2626  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1 <unfinished ...>\n2625  <... futex resumed>)              = 0\n2626  <... futex resumed>)              = 1\n2625  read(0,  <unfinished ...>\n2626  futex(0x7f91da44b008, FUTEX_WAIT_PRIVATE, 0, NULL <unfinished ...>\n2625  <... read resumed>\"TCREQ001\\7\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  futex(0x7f91da44b008, FUTEX_WAKE_PRIVATE, 1) = 1\n2626  <... futex resumed>)              = 0\n2625  futex(0x7f91da44b000, FUTEX_WAIT, 2626, NULL <unfinished ...>\n2626  exit(0)                           = ?\n2625  <... futex resumed>)              = 0\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\20\\0\\0\\0\\0\\0\\0\\0\\7\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=2089489}) = 0\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\21\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\225\\177)\\314\\342\\32\\310OiMS=\\266\\270\\260\\35E\\20\\30\\0\\0\\0\\0\\0\\314\\321\\7\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\7\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"TCREQ001\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\24\\33\\322\\365\\30s\\314\\263\\377V~!\\266\\301\\213`\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 64) = 64\n2625  gettid()                          = 2625\n2625  clock_gettime(CLOCK_THREAD_CPUTIME_ID, {tv_sec=0, tv_nsec=2159623}) = 0\n2625  write(1, \"TCSTAMP1\\0\\0\\0\\0\\0\\0\\0\\0\\22\\0\\0\\0\\0\\0\\0\\0\\4\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0A\\n\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\2\\0\\0\\0\\0\\0\\0\\0\\24\\33\\322\\365\\30s\\314\\263\\377V~!\\266\\301\\213`\\305t\\6\\0\\0\\0\\0\\0B\\177\\32\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\10\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\271\\256\\332\\303#\\205\\221\\377\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\6\\0\\0\\0\\0\\0\\0\\0\\3\\0\\0\\0\\0\\0\\0\\0@\\0\\0\\0\\0\\0\\0\\0\\1\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\", 224) = 224\n2625  read(0, \"\", 64)                   = 0\n2625  exit_group(0)                     = ?\n"
        data_in=bytes.fromhex("544352455130303101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005443524551303031020000000000000000000000000000000100000000000000957f29cce21ac84f694d533db6b8b01d00000000000000000000000000000000544352455130303106000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005443524551303031020000000000000001000000000000000100000000000000957f29cce21ac84f694d533db6b8b01d000000000000000000000000000000005443524551303031030000000000000001000000000000000300000000000000e73bf519d8bb2a91697a49074aaf6c56000000000000000000000000000000005443524551303031040000000000000001000000000000000300000000000000e73bf519d8bb2a91697a49074aaf6c5600000000000000000000000000000000544352455130303105000000000000000000000000000000000000000000000000000000000000000000000000000000307500000000000000000000000000005443524551303031030000000000000000000000000000000100000000000000957f29cce21ac84f694d533db6b8b01d00000000000000000000000000000000544352455130303101000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005443524551303031020000000000000000000000000000000400000000000000fe5dc3c307997911ddf667be908965a6000000000000000000000000000000005443524551303031030000000000000000000000000000000500000000000000afa015508d0d0e8b837e7fed9166fa1500000000000000000000000000000000544352455130303105000000000000000100000000000000000000000000000000000000000000000000000000000000409c00000000000000000000000000005443524551303031030000000000000001000000000000000400000000000000fe5dc3c307997911ddf667be908965a6000000000000000000000000000000005443524551303031040000000000000001000000000000000500000000000000afa015508d0d0e8b837e7fed9166fa15000000000000000000000000000000005443524551303031040000000000000001000000000000000400000000000000fe5dc3c307997911ddf667be908965a600000000000000000000000000000000544352455130303107000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005443524551303031040000000000000000000000000000000100000000000000957f29cce21ac84f694d533db6b8b01d000000000000000000000000000000005443524551303031040000000000000000000000000000000200000000000000141bd2f51873ccb3ff567e21b6c18b6000000000000000000000000000000000")
        data_out=bytes.fromhex("54435354414d5031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410a0000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000100000000000000020000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000001000000000000000100000000000000000000000000000001000000000000000000000000000000410a00000000000001000000000000000100000000000000957f29cce21ac84f694d533db6b8b01d00000000000000000000000000000000c574060000000000000000000000000000000000000000000100000000000000010000000000000000000000000000000100000000000000000000000000000000000000000000000200000000000000020000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000002000000000000000200000000000000000000000000000001000000000000000000000000000000410a00000000000001000000000000000200000000000000141bd2f51873ccb3ff567e21b6c18b60c5740600000000000000000000000000c574060000000000000000000000000000000000000000000100000000000000020000000000000000000000000000000100000000000000000000000000000000000000000000000300000000000000020000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000003000000000000000600000000000000000000000000000000000000000000000000000000000000410a0000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000020000000000000000000000000000000100000000000000420a00000000000002000000000000000300000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000004000000000000000200000000000000000000000000000001000000000000000100000000000000420a00000000000002000000000000000300000000000000e73bf519d8bb2a91697a49074aaf6c56c5740600000000000000000000000000c574060000000000010000000000000000000000000000000100000000000000030000000000000000000000000000000100000000000000420a00000000000002000000000000000400000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000005000000000000000300000000000000020000000000000000000000000000000100000000000000420a00000000000002000000000000000300000000000000e73bf519d8bb2a91697a49074aaf6c56c5740600000000000000000000000000c574060000000000010000000000000000000000000000000100000000000000030000000000000000000000000000000100000000000000420a00000000000002000000000000000400000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000006000000000000000400000000000000020000000000000000000000000000000100000000000000420a00000000000002000000000000000300000000000000e73bf519d8bb2a91697a49074aaf6c56c57406000000000000000000000000000000000000000000010000000000000000000000000000000100000000000000020000000000000000000000000000000100000000000000420a00000000000002000000000000000400000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000007000000000000000500000000000000000000000000000000000000000000000000000000000000410a000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000010000000000000002000000000000000000000000000000995e900c719e89c0420a00000000000002000000000000000400000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000008000000000000000300000000000000000000000000000001000000000000000000000000000000410a00000000000001000000000000000100000000000000957f29cce21ac84f694d533db6b8b01dc574060000000000809b110000000000451018000000000001000000000000000000000000000000020000000000000002000000000000000000000000000000995e900c719e89c0420a00000000000002000000000000000400000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000009000000000000000100000000000000000000000000000001000000000000000100000000000000420a00000000000002000000000000000400000000000000fe5dc3c307997911ddf667be908965a60000000000000000000000000000000082ac05000000000001000000000000000000000000000000030000000000000003000000000000000000000000000000995e900c719e89c0420a00000000000002000000000000000500000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d503100000000000000000a000000000000000200000000000000000000000000000001000000000000000000000000000000410a00000000000001000000000000000500000000000000afa015508d0d0e8b837e7fed9166fa1582ac050000000000000000000000000082ac05000000000001000000000000000000000000000000030000000000000004000000000000000000000000000000995e900c719e89c0420a00000000000002000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d503100000000000000000b000000000000000300000000000000020000000000000000000000000000000000000000000000410a00000000000001000000000000000500000000000000afa015508d0d0e8b837e7fed9166fa1582ac050000000000000000000000000082ac05000000000001000000000000000000000000000000030000000000000004000000000000000000000000000000995e900c719e89c0420a00000000000002000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d503100000000000000000c000000000000000500000000000000000000000000000000000000000000000100000000000000420a000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000030000000000000004000000000000000000000000000000b9aedac3238591ff420a00000000000002000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d503100000000000000000d000000000000000300000000000000000000000000000001000000000000000100000000000000420a00000000000002000000000000000400000000000000fe5dc3c307997911ddf667be908965a682ac050000000000f1320f000000000073df14000000000001000000000000000000000000000000040000000000000004000000000000000000000000000000b9aedac3238591ff420a00000000000002000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d503100000000000000000e000000000000000400000000000000000000000000000001000000000000000100000000000000420a00000000000002000000000000000500000000000000afa015508d0d0e8b837e7fed9166fa1582ac0500000000004598100000000000000000000000000001000000000000000000000000000000050000000000000003000000000000000000000000000000b9aedac3238591ff420a00000000000002000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d503100000000000000000f000000000000000400000000000000000000000000000001000000000000000100000000000000420a00000000000002000000000000000400000000000000fe5dc3c307997911ddf667be908965a673df140000000000902b030000000000000000000000000001000000000000000000000000000000060000000000000002000000000000000000000000000000b9aedac3238591ff420a00000000000002000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000010000000000000000700000000000000000000000000000000000000000000000000000000000000410a000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000100000000000000060000000000000002000000000000000000000000000000b9aedac3238591ff000000000000000000000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000011000000000000000400000000000000000000000000000001000000000000000000000000000000410a00000000000001000000000000000100000000000000957f29cce21ac84f694d533db6b8b01d4510180000000000ccd1070000000000000000000000000001000000000000000100000000000000070000000000000001000000000000000000000000000000b9aedac3238591ff000000000000000000000000000000000600000000000000030000000000000040000000000000000100000000000000000000000000000054435354414d5031000000000000000012000000000000000400000000000000000000000000000001000000000000000000000000000000410a00000000000001000000000000000200000000000000141bd2f51873ccb3ff567e21b6c18b60c574060000000000427f1a0000000000000000000000000001000000000000000100000000000000080000000000000000000000000000000000000000000000b9aedac3238591ff0000000000000000000000000000000006000000000000000300000000000000400000000000000001000000000000000000000000000000")
        expected={'wrong-clock','private-clear-tid-wait','worker-effect-after-exit',
                  'worker-effect-before-birth','removed-parent-settid','wrong-stack-protection',
                  'missing-child-exit','duplicated-native-exec','extra-syscall',
                  'truncated-stdout','changed-stdout','unfinished-syscall'}
        for spacing in (' ','  ','       ','\t',' \t '):
            with self.subTest(spacing=repr(spacing)), tempfile.TemporaryDirectory(
                    prefix='trnm-hosted-thread-trace-') as temporary:
                root=Path(temporary)
                text=re.sub(r'(?m)^(\d+)[ \t]+',lambda m:m[1]+spacing,actual)
                audited=audit_trace(text,data_in,data_out)
                self.assertEqual(audited['main_tid'],2625)
                (root/'syscalls.raw').write_text(text)
                (root/'stdin.raw').write_bytes(data_in)
                (root/'stdout.raw').write_bytes(data_out)
                physical={'physical':str(root/'physical.json'),'trace':audited}
                controls=trace_negative_controls(physical,root)
                self.assertEqual({row['name'] for row in controls},expected)
                self.assertEqual(len(controls),12)
                self.assertTrue(all(row['status']=='REFUSED' for row in controls))
                self.assertTrue(all(row['failure'] for row in controls))
                # The mutation must select the actual main task, never a
                # nearby decimal PID or a different terminal call.
                wrong=copy.deepcopy(physical)
                wrong['trace']['main_tid']=26250
                with self.assertRaisesRegex(ValueError,'Missing or ambiguous actual terminal'):
                    trace_negative_controls(wrong,root)
                terminal=next(line for line in text.splitlines(keepends=True)
                              if 'exit_group(' in line)
                (root/'syscalls.raw').write_text(text+terminal)
                with self.assertRaisesRegex(ValueError,'Missing or ambiguous actual terminal'):
                    trace_negative_controls(physical,root)

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
