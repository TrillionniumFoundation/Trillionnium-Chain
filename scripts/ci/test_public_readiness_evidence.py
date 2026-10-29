#!/usr/bin/env python3
"""Negative source, artifact, packet, observation and cost tests; no fabricated qualification."""
from __future__ import annotations
import copy
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import check_public_readiness_evidence as check
from test_rust_source_tokens import RustSourceTokenTests


class SourceAndArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)/'repo'; self.root.mkdir()
        self.git('init','-q'); self.git('config','user.email','fixture@example.invalid'); self.git('config','user.name','Fixture')
        for name in ['scripts/run.py','trillionnium/Cargo.toml','config/pon/task.json','.github/workflows/check.yml','docs/readme.md']:
            path = self.root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_text(name+'\n')
        self.git('add','.'); self.git('commit','-qm','real source fixture')
        self.commit = self.git('rev-parse','HEAD'); self.tree = self.git('rev-parse','HEAD^{tree}')
        self.report = {'source_commit':self.commit,'source_tree':self.tree,'source_files_sha256':check.source_inventory(self.root,self.commit)}
        self.manifest = {'implementation_commit':self.commit,'implementation_tree':self.tree}

    def tearDown(self): self.temporary.cleanup()
    def git(self,*args): return subprocess.check_output(['git',*args],cwd=self.root,text=True).strip()

    def test_real_git_source_control_is_valid_and_false_tree_or_hash_rejects(self):
        self.assertEqual(check.validate_source(self.root,self.report,self.manifest),self.commit)
        for field, value in [('source_tree','0'*40),('source_commit','0'*40)]:
            mutated = copy.deepcopy(self.report); mutated[field] = value
            with self.assertRaises((ValueError,subprocess.CalledProcessError)): check.validate_source(self.root,mutated,self.manifest)
        changed = copy.deepcopy(self.report); changed['source_files_sha256']['scripts/run.py'] = '0'*64
        with self.assertRaises(ValueError): check.validate_source(self.root,changed,self.manifest)

    def test_source_inventory_cannot_omit_script_config_or_workflow(self):
        for name in ['scripts/run.py','config/pon/task.json','.github/workflows/check.yml']:
            mutated = copy.deepcopy(self.report); del mutated['source_files_sha256'][name]
            with self.assertRaises(ValueError): check.validate_source(self.root,mutated,self.manifest)

    def test_current_bytes_new_untracked_runtime_and_symlink_reject(self):
        path = self.root/'scripts/run.py'; original = path.read_bytes()
        path.write_bytes(original+b'changed')
        with self.assertRaises(ValueError): check.validate_source(self.root,self.report,self.manifest)
        path.write_bytes(original)
        added = self.root/'scripts/new.py'; added.write_text('new')
        with self.assertRaises(ValueError): check.validate_source(self.root,self.report,self.manifest)
        added.unlink(); path.unlink(); path.symlink_to(self.root/'docs/readme.md')
        with self.assertRaises(ValueError): check.validate_source(self.root,self.report,self.manifest)

    def test_historical_source_check_does_not_silently_qualify_changed_current(self):
        (self.root/'scripts/run.py').write_text('changed current')
        self.assertEqual(check.validate_source(self.root,self.report,self.manifest,current=False),self.commit)
        with self.assertRaises(ValueError): check.validate_source(self.root,self.report,self.manifest,current=True)

    def test_preparation_uses_exact_measured_git_snapshot_after_root_publication(self):
        from prepare_evidence_sources import declarations
        for package in ['pon-v3','pon-v4','pon-evaluation-bundle-v1']:
            path=self.root/'evidence'/package/'manifest.json';path.parent.mkdir(parents=True)
            path.write_text(json.dumps(dict(implementation_commit=self.commit,implementation_tree=self.tree)))
        self.git('add','evidence');self.git('commit','-qm','measured declaration snapshot')
        measured=self.git('rev-parse','HEAD');tree=self.git('rev-parse','HEAD^{tree}')
        expected=declarations(self.root,source=measured)
        record=dict(verified_object_trees=expected,fetched=[],branch_refs_changed=False,acceptance_granted=False)
        path=self.root/'evidence/pon-public-readiness-v1/manifest.json';path.parent.mkdir(parents=True)
        path.write_text(json.dumps(dict(implementation_commit=measured,implementation_tree=tree)))
        self.git('add','evidence');self.git('commit','-qm','later evidence publication')
        self.assertNotEqual(declarations(self.root),expected)
        self.assertEqual(check.validate_source_preparation(self.root,json.dumps(record),measured),expected)
        changed=copy.deepcopy(record);changed['verified_object_trees']=declarations(self.root)
        with self.assertRaisesRegex(ValueError,'source-preparation scope'):
            check.validate_source_preparation(self.root,json.dumps(changed),measured)
        changed=copy.deepcopy(record);del changed['verified_object_trees'][self.commit]
        with self.assertRaisesRegex(ValueError,'source-preparation scope'):
            check.validate_source_preparation(self.root,json.dumps(changed),measured)
        for field in ['branch_refs_changed','acceptance_granted']:
            changed=copy.deepcopy(record);changed[field]=True
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'source-preparation scope'):
                check.validate_source_preparation(self.root,json.dumps(changed),measured)

    def test_source_pinned_environment_rejects_old_crypto_and_inconsistent_records(self):
        requirements=self.root/'formal/pon-nakamoto-v1/requirements.txt';requirements.parent.mkdir(parents=True)
        requirements.write_text('numpy==1.26.4\ncryptography==50.0.2\n')
        report={'environment':dict(python='3.12.14',numpy='1.26.4',cryptography='50.0.2',
                                  cryptography_openssl='OpenSSL 4.0.3',cffi='2.1.1')}
        baseline={'environment':dict(python='3.12.14',numpy='1.26.4',cryptography='50.0.2')}
        child=dict(executable='/isolated/venv/bin/python3',python='3.12.14',numpy='1.26.4',cryptography='50.0.2')
        report['environment']['child_python3']=copy.deepcopy(child)
        baseline['environment']['child_python3']=copy.deepcopy(child)
        check.validate_environment(self.root,report,baseline)
        for field,value in [('executable','python3'),('numpy','1.26.3'),('cryptography','41.0.7'),('python','3.12.13')]:
            changed=copy.deepcopy(report);changed['environment']['child_python3'][field]=value
            with self.subTest(child_field=field),self.assertRaisesRegex(ValueError,'child Python'):
                check.validate_environment(self.root,changed,baseline)
        changed=copy.deepcopy(report);changed['environment'].pop('child_python3')
        with self.assertRaisesRegex(ValueError,'missing child Python'):
            check.validate_environment(self.root,changed,baseline)
        for field,value in [('cryptography','41.0.7'),('numpy','1.26.3'),('python','3.12.13'),
                            ('python','3.12'),('cryptography_openssl',''),('cryptography_openssl',None),
                            ('cffi',' '),('cffi',False)]:
            changed=copy.deepcopy(report);changed['environment'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                check.validate_environment(self.root,changed,baseline)
        old_report=copy.deepcopy(report);old_baseline=copy.deepcopy(baseline)
        old_report['environment']['cryptography']=old_baseline['environment']['cryptography']='41.0.7'
        with self.assertRaisesRegex(ValueError,'environment dependency pin cryptography'):
            check.validate_environment(self.root,old_report,old_baseline)
        requirements.write_text('numpy==1.26.4\ncryptography>=50\n')
        with self.assertRaisesRegex(ValueError,'missing or ambiguous environment pin cryptography'):
            check.validate_environment(self.root,report,baseline)

    def test_qualification_subprocess_ignores_a_poisoned_python_search_path(self):
        sys.path.insert(0,str(check.ROOT/'scripts'))
        from qualification_runtime import bind_python_runtime
        fake=self.root/'fake-bin';fake.mkdir()
        program=fake/'python3';program.write_text('#!/bin/sh\nexit 79\n');program.chmod(0o755)
        poisoned=dict(os.environ,PATH=str(fake)+os.pathsep+os.environ.get('PATH',''))
        self.assertEqual(subprocess.run(['python3','-c','pass'],env=poisoned).returncode,79)
        bound,observed=bind_python_runtime(poisoned)
        output=json.loads(subprocess.check_output(['python3','-c',
            'import sys,platform,json,numpy,cryptography; print(json.dumps(dict('
            'executable=sys.executable,python=platform.python_version(),numpy=numpy.__version__,'
            'cryptography=cryptography.__version__)))'],env=bound,text=True))
        self.assertEqual(output,observed)
        self.assertEqual(output['python'],sys.version.split()[0])

    def artifacts(self):
        folder = self.root/'evidence/test'; folder.mkdir(parents=True)
        (folder/'qualification.json').write_text('{}\n'); (folder/'result.bin').write_bytes(b'actual bytes')
        manifest = {'files':{name:check.sha((folder/name).read_bytes()) for name in ['qualification.json','result.bin']}}
        (folder/'manifest.json').write_text(json.dumps(manifest)); self.git('add','evidence')
        return folder,manifest

    def test_artifacts_must_exist_match_exact_inventory_and_be_tracked(self):
        folder,manifest = self.artifacts(); check.validate_artifacts(self.root,folder,manifest)
        (folder/'extra.log').write_text('unmanifested')
        with self.assertRaises(ValueError): check.validate_artifacts(self.root,folder,manifest)
        (folder/'extra.log').unlink(); (folder/'result.bin').write_bytes(b'mutated')
        with self.assertRaises(ValueError): check.validate_artifacts(self.root,folder,manifest)
        manifest['files']['result.bin'] = check.sha(b'mutated'); self.git('rm','--cached','-q','-f','evidence/test/result.bin')
        with self.assertRaises(ValueError): check.validate_artifacts(self.root,folder,manifest)

    def test_symlink_path_aliases_and_duplicate_json_are_refused(self):
        folder,manifest = self.artifacts()
        for name in ['../result.bin','./result.bin','result.bin/../qualification.json','/tmp/file','result\\bin']:
            with self.assertRaises(ValueError): check.safe(folder,name)
        (folder/'alias').symlink_to(folder/'result.bin')
        with self.assertRaises(ValueError): check.safe(folder,'alias')
        with self.assertRaises(ValueError): check.validate_artifacts(self.root,folder,manifest)
        with self.assertRaises(ValueError): json.loads('{"pass":false,"pass":true}',object_pairs_hook=check.unique)
        (folder/'invalid.json').write_text('{"elapsed":NaN}')
        with self.assertRaises(ValueError): check.load(folder/'invalid.json')
        for raw in ('{"elapsed":1e999}', '{"elapsed":-1e999}'):
            (folder/'invalid.json').write_text(raw)
            with self.assertRaises(ValueError): check.load(folder/'invalid.json')
        linked = self.root/'linked'; linked.symlink_to(folder,target_is_directory=True)
        with self.assertRaises(ValueError): check.safe(linked/'nested','artifact.json')
        with self.assertRaises(ValueError): check.scope_flags({'nested':[{'public_network_ready':True}]})
        with self.assertRaises(ValueError): check.scope_flags({'production_activation':0})
        check.scope_flags({'nested':[{'public_network_ready':False}]})

    def test_pq_and_quantum_claims_cannot_be_promoted_inside_rehashed_artifacts(self):
        flags = check.UNSUPPORTED_AUTHORITY_FLAGS - set(check.FLAGS)
        for flag in flags:
            for invalid in (True, 0, 1, None, 'false', [], {}):
                with self.subTest(flag=flag, invalid=invalid), self.assertRaisesRegex(
                        ValueError, 'artifact unsupported authority'):
                    check.scope_flags({'nested': [{flag: invalid}]})
            check.scope_flags({'nested': [{flag: False}]})
        folder, manifest = self.artifacts()
        path = folder/'qualification.json'
        original = path.read_bytes()
        for flag in flags:
            changed = json.loads(original)
            changed['nested'] = [{flag: True}]
            path.write_text(json.dumps(changed))
            manifest['files']['qualification.json'] = check.sha(path.read_bytes())
            with self.subTest(rehashed_artifact_flag=flag), self.assertRaisesRegex(
                    ValueError, 'artifact unsupported authority'):
                check.validate_artifacts(self.root, folder, manifest, tracked=False)
        path.write_bytes(original)
        manifest['files']['qualification.json'] = check.sha(original)
        check.validate_artifacts(self.root, folder, manifest, tracked=False)
        for flag in flags:
            changed = dict(manifest, nested=[{flag: True}])
            with self.subTest(manifest_flag=flag), self.assertRaisesRegex(
                    ValueError, 'artifact unsupported authority'):
                check.validate_artifacts(self.root, folder, changed, tracked=False)


class PacketAndObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        vectors = check.ROOT/'formal/pon-nakamoto-v1/vectors/accepted-block'
        tx = (vectors/'transaction.bin').read_bytes()
        cls.raw = (vectors/'header.bin').read_bytes()+b'\x01\x00'+len(tx).to_bytes(2,'little')+tx+(vectors/'work.bin').read_bytes()

    def test_actual_packet_frame_control_and_truncations_trailing_bytes_reject(self):
        header,txs,proof = check.decode_packet(self.raw)
        self.assertEqual((len(header),len(txs),len(proof)),(318,1,49188))
        for raw in [self.raw[:-1],self.raw+b'\x00',self.raw[:319],b'XXXX'+self.raw[4:],self.raw[:318]+b'\xff\xff'+self.raw[320:]]:
            with self.assertRaises(ValueError): check.decode_packet(raw)

    def test_pqp1_pqp2_pqp3_never_negotiate_a_legacy_packet(self):
        for version in (1,2,3,4):
            prefix = b'PQP'+str(version).encode()+bytes([version,0,0,0])
            for raw in (prefix+self.raw,prefix+self.raw[8:]):
                with self.subTest(version=version,bytes=len(raw)),self.assertRaisesRegex(ValueError,'header version'):
                    check.decode_packet(raw)
        self.assertEqual(check.decode_packet(self.raw)[0],self.raw[:318])

    def test_hash_repair_does_not_replace_actual_transcript_verification(self):
        sys.path.insert(0,str(check.ROOT/'formal/pon-nakamoto-v1'))
        from contract_wire import H,header_decode
        from work_oracle import verify
        header,_,proof = check.decode_packet(self.raw); decoded = header_decode(header)
        verify(H('challenge',header),decoded['work_task'],decoded['target'],proof)
        altered = bytearray(proof); altered[100] ^= 1
        # A mutable manifest hash can be repaired, while the owner verifier still refuses.
        self.assertNotEqual(check.sha(proof),check.sha(altered))
        with self.assertRaises(ValueError): verify(H('challenge',header),decoded['work_task'],decoded['target'],bytes(altered))

    def test_twenty_block_tails_are_recomputed_and_p99_is_unavailable(self):
        summary = {'requested_blocks':20,'records':[{'intake_to_inclusion_ns':i+1,'intake_to_confirmation_ns':100+i} for i in range(20)]}
        summary['inclusion_latency_block_samples'] = check.quantiles(list(range(1,21)))
        summary['confirmation_latency_block_samples'] = check.quantiles(list(range(100,120)))
        check.validate_tails(summary)
        self.assertIsNone(summary['inclusion_latency_block_samples']['p99_ns'])
        for field in ['p95_ns','p99_ns','count']:
            changed = copy.deepcopy(summary); changed['inclusion_latency_block_samples'][field] = 999
            with self.assertRaises(ValueError): check.validate_tails(changed)
        changed = copy.deepcopy(summary); changed['requested_blocks'] = 19
        with self.assertRaises(ValueError): check.validate_tails(changed)

    def test_true_confirmations_bind_transaction_context_tip_depth_and_work(self):
        target = 2**255-1
        headers = [{'id':hashlib.sha256(str(i).encode()).hexdigest(),'timestamp':100+i,'target':target} for i in range(7)]
        summary = {k:'1'*64 for k in ('network','parameters','genesis')}
        row = {'block':headers[0]['id'],'height':1}; transaction = '2'*64
        fact = dict(summary,transaction=transaction,included_block=row['block'],included_height=1,observed_height=7,
                    observed_tip=headers[-1]['id'],depth=6,active_generation=7,reorged=False,finalized=False,execution_authority=False,
                    policy='installed-depth-and-required-work',work_delta=(12).to_bytes(64,'big').hex(),
                    required_work_delta=(12).to_bytes(64,'big').hex(),confirmed=True,observed_now=200)
        batch = {'observations':[fact]}; cumulative = list(range(0,16,2))
        check.validate_observations(batch,row,[transaction],summary,headers,cumulative,confirmed=True)
        for field,value in [('transaction','3'*64),('parameters','4'*64),('observed_tip',headers[5]['id']),('depth',5),
                            ('work_delta','00'*64),('confirmed',False),('finalized',True),('execution_authority',True)]:
            changed = copy.deepcopy(batch); changed['observations'][0][field] = value
            with self.assertRaises(ValueError): check.validate_observations(changed,row,[transaction],summary,headers,cumulative,confirmed=True)
        with self.assertRaises(ValueError): check.validate_observations({'observations':[]},row,[transaction],summary,headers,cumulative,confirmed=True)


class SocketAccountingTests(unittest.TestCase):
    def rows(self):
        rows = []
        for phase in ['baseline','unpaid_false_transcript','paid_false_transcript','slow_hello_occupancy']:
            paid = int(phase == 'paid_false_transcript'); cheap = int(phase == 'unpaid_false_transcript'); slow = int(phase == 'slow_hello_occupancy')
            streams = 0 if phase == 'baseline' else (3 if slow else 2)
            rows.append(dict(schema='transport-admission-sustained-cost-v2',phase=phase,bits=16,ttl_ms=2000,
                requested_attack_duration_ns=10_000_000_000,observed_wall_ns=10_001_000_000,attacker_streams=streams,
                attacker_observed_ns=[10_000_000_000]*streams,attack_connections=paid+cheap+2*slow,paid_full_work_rejections=paid,
                slow_preface_connections=2*slow,slow_partial_hello_connections=slow,slow_body_hello_connections=slow,
                request_template_bytes=100,attacker_body_bytes_successfully_written=100*(paid+cheap),
                attacker_body_write_success_count=paid+cheap,attacker_body_write_outcome_unknown_count=0,
                attacker_body_not_started_count=0,attack_transport_error_count=0,attack_transport_errors=[],
                cheap_rejections=cheap,busy_rejections=0,forged_ticket_hash_trials=paid+cheap,admission_hash_trials=paid,
                attacker_admission_solve_ns=100*paid,honest_submit_attempts=1,honest_valid_blocks=1,honest_submit_ns=[100],
                honest_submit_errors=[],honest_head_attempts=1,honest_head_ns=[50],honest_head_errors=[],
                metrics={'work_verifications':paid+1,'admission_rejected_before_work':cheap,'admission_accepted':paid+1}))
        return rows

    def log(self,rows):
        return 'test sustained_protected_socket_cost_campaign ... '+json.dumps(rows[0])+'\n'+ '\n'.join(json.dumps(r) for r in rows[1:])+'\nok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'

    def test_actual_paid_unpaid_denominators_and_harness_control(self):
        rows = self.rows(); self.assertEqual(check.validate_socket_log(self.log(rows)),rows)
        for phase,field,value in [(1,'paid_full_work_rejections',1),(2,'admission_hash_trials',0),(2,'attack_connections',2),
                                  (1,'honest_submit_attempts',2),(2,'attacker_streams',1)]:
            changed = copy.deepcopy(rows); changed[phase][field] = value
            with self.assertRaises(ValueError): check.validate_socket_log(self.log(changed))
        with self.assertRaises(ValueError): check.validate_socket_log(self.log(rows).replace('1 passed','0 passed'))
        with self.assertRaises(ValueError): check.validate_socket_log(self.log(rows[:2]))

    def test_honest_failures_are_retained_in_denominator_without_fairness_claim(self):
        rows = self.rows(); row = rows[2]
        row['honest_submit_attempts'] = 2
        row['honest_submit_errors'] = [{'elapsed_ns':20,'error':'BUSY:work-capacity'}]
        check.validate_socket_log(self.log(rows))
        row['honest_submit_errors'] = []
        with self.assertRaises(ValueError): check.validate_socket_log(self.log(rows))
        rows = self.rows(); row = rows[2]
        row['attack_connections'] += 1; row['attack_transport_error_count'] = 1
        row['attack_transport_errors'] = ['ADMISSION_RESERVED_READ_ONLY']
        row['attacker_body_write_outcome_unknown_count'] = 1
        check.validate_socket_log(self.log(rows))
        row['attack_transport_errors'] = []
        with self.assertRaises(ValueError): check.validate_socket_log(self.log(rows))

    def test_baseline_template_bytes_and_honest_busy_outcomes_are_not_attack_cost(self):
        rows=self.rows();row=rows[0]
        self.assertGreater(row['request_template_bytes'],0)
        row['honest_submit_attempts']=2
        row['honest_submit_errors']=[{'elapsed_ns':20,'error':'BUSY:work-capacity'}]
        row['metrics']['admission_reserved_read_only_refusals']=502
        self.assertEqual(check.validate_socket_log(self.log(rows)),rows)
        row['honest_submit_errors']=[]
        with self.assertRaisesRegex(ValueError,'honest outcome denominator'):
            check.validate_socket_log(self.log(rows))
        rows=self.rows();rows[0]['request_template_bytes']=0
        with self.assertRaises(ValueError):check.validate_socket_log(self.log(rows))
        rows=self.rows();rows[1]['request_template_bytes']+=1
        with self.assertRaisesRegex(ValueError,'socket request template size'):
            check.validate_socket_log(self.log(rows))
        rows=self.rows();rows[0]['submitted_wire_bytes']=rows[0]['request_template_bytes']
        with self.assertRaisesRegex(ValueError,'socket request template size'):
            check.validate_socket_log(self.log(rows))

    def test_baseline_real_attack_counters_remain_strictly_zero(self):
        for field in ['attack_connections','paid_full_work_rejections','cheap_rejections','busy_rejections',
                      'slow_preface_connections','slow_partial_hello_connections','slow_body_hello_connections',
                      'attack_transport_error_count','forged_ticket_hash_trials','admission_hash_trials',
                      'attacker_admission_solve_ns','attacker_body_bytes_successfully_written',
                      'attacker_body_write_success_count','attacker_body_write_outcome_unknown_count',
                      'attacker_body_not_started_count']:
            with self.subTest(field=field):
                rows=self.rows();rows[0][field]=1
                with self.assertRaises(ValueError):check.validate_socket_log(self.log(rows))
        # Repair the aggregate denominator too: genuine unsolicited attack work
        # still cannot be presented as an otherwise consistent no-attacker phase.
        rows=self.rows();row=rows[0]
        row['attack_connections']=row['paid_full_work_rejections']=1
        row['admission_hash_trials']=row['attacker_admission_solve_ns']=1
        row['metrics']['work_verifications']+=1;row['metrics']['admission_accepted']+=1
        with self.assertRaisesRegex(ValueError,'baseline attack contamination'):
            check.validate_socket_log(self.log(rows))

    def test_attacker_body_bytes_keep_complete_writes_and_unknown_outcomes_separate(self):
        rows=self.rows();row=rows[2]
        # One completed body is followed by a failed challenge read; two other
        # requests fail in the opaque helper or before invoking that helper.
        row['attack_connections']+=3;row['attack_transport_error_count']=3
        row['attack_transport_errors']=['CHALLENGE_READ','HELPER_ERROR_UNKNOWN_BODY','CONNECT_ERROR']
        row['attacker_body_write_success_count']+=1
        row['attacker_body_bytes_successfully_written']+=row['request_template_bytes']
        row['attacker_body_write_outcome_unknown_count']=1;row['attacker_body_not_started_count']=1
        self.assertEqual(check.validate_socket_log(self.log(rows)),rows)
        for field in ['attacker_body_bytes_successfully_written','attacker_body_write_success_count',
                      'attacker_body_write_outcome_unknown_count','attacker_body_not_started_count']:
            with self.subTest(field=field):
                changed=copy.deepcopy(rows);changed[2][field]+=1
                with self.assertRaises(ValueError):check.validate_socket_log(self.log(changed))
        # Repair both sums, but falsely mark a server rejection as a request
        # whose body never finished writing: this still contradicts the outcome.
        changed=self.rows();row=changed[2]
        row['attacker_body_write_success_count']=row['attacker_body_bytes_successfully_written']=0
        row['attacker_body_write_outcome_unknown_count']=1
        with self.assertRaisesRegex(ValueError,'attacker body outcome accounting'):
            check.validate_socket_log(self.log(changed))
        changed=self.rows();changed[3]['attacker_body_not_started_count']=1
        with self.assertRaisesRegex(ValueError,'unexpected attacker body write'):
            check.validate_socket_log(self.log(changed))


class DurableStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name)
        sys.path.insert(0,str(check.ROOT/'formal/pon-nakamoto-v1'))
        from contract_wire import H,canonical
        self.H,self.canonical = H,canonical
        ddl, self.schema_domain = check.native_durable_schema(check.ROOT)
        self.state = {'test:exact':1}; self.roots = [bytes([i])*32 for i in range(1,5)]
        self.packets = []; self.cumulative = [0,2,4,6]
        self.summary = {'genesis':'3'*64,'parameters':'4'*64,'network':'6'*64,'records':[]}
        from contract_wire import header_encode
        parent = bytes.fromhex(self.summary['genesis'])
        # Actual current SQLite schema and exact native header/index formulas.
        # These opaque work bytes exercise only the durable-store stage; PoN
        # validity is separately checked by packet tests and full native replay.
        self.blocks = []
        for height in range(1,4):
            header = header_encode(dict(network=bytes.fromhex(self.summary['network']),
                parameters=bytes.fromhex(self.summary['parameters']),parent=parent,height=height,
                timestamp=height*10,target=bytes([255])*32,miner=bytes(32),transactions=bytes(32),
                state=self.roots[height],receipts=bytes(32),work_task=bytes(32),nonce=height))
            proof = bytes(49156)+H('owned-store-fixture-trace',height.to_bytes(8,'little'))
            packet = header+b'\x00\x00'+proof; block = H('block',header,proof[-32:])
            self.packets.append(packet); self.blocks.append((block,parent,height))
            self.summary['records'].append({'block':block.hex()}); parent = block
        self.summary['producer_final_state'] = {'tip':parent.hex()}
        for owner in ('producer','validator'):
            directory = self.folder/owner; directory.mkdir()
            with sqlite3.connect(directory/'native.sqlite') as database:
                database.executescript(ddl)
                database.executemany('INSERT INTO metadata VALUES(?,?)',[
                    ('schema',H(self.schema_domain,ddl.encode())),
                    ('parameters',bytes.fromhex(self.summary['parameters'])),('genesis',bytes.fromhex(self.summary['genesis']))])
                database.execute('INSERT INTO active VALUES(1,?,3,0)',(parent,))
                database.execute('INSERT INTO kv VALUES(0,?,?)',('test:exact',canonical(1)))
                database.execute('INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)',
                    (bytes.fromhex('3'*64),bytes(64),self.roots[0]))
                for block,previous,height in self.blocks:
                    database.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?)',
                        (block,previous,height,self.cumulative[height].to_bytes(64,'big'),
                         self.packets[height-1],self.roots[height]))
                if self.schema_domain == 'native-branch-schema-v2':
                    index = {}; zero = bytes(32)
                    for block,previous,height in self.blocks:
                        for level in range(height.bit_length()):
                            if level == 0: ancestor,ancestor_height,left,right = previous,height-1,zero,zero
                            else:
                                half = index[(block,level-1)]; other = index[(half[0],level-1)]
                                ancestor,ancestor_height,left,right = other[0],other[1],half[4],other[4]
                            seal = H('native-derived-ancestry-row-v1',bytes.fromhex(self.summary['network']),
                                bytes.fromhex(self.summary['parameters']),bytes.fromhex(self.summary['genesis']),
                                block,previous,height.to_bytes(8,'little'),bytes([level]),ancestor,
                                ancestor_height.to_bytes(8,'little'),left,right)
                            row = (ancestor,ancestor_height,left,right,seal);index[(block,level)] = row
                            database.execute('INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)',(block,level,*row))
        self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())

    def tearDown(self): self.temporary.cleanup()
    def verify(self):
        check.validate_durable_store(check.ROOT,self.folder,self.summary,self.packets,self.roots,self.cumulative,self.state,self.canonical,self.H)

    def test_owned_sqlite_control_and_changed_packet_or_work_reject(self):
        self.verify()
        self.summary['ledger_disk_bytes'] += 1
        with self.assertRaises(ValueError): self.verify()
        self.summary['ledger_disk_bytes'] -= 1
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute('UPDATE blocks SET packet=? WHERE height=1',(b'forged bytes',))
        with self.assertRaises(ValueError): self.verify()
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute('UPDATE blocks SET packet=?,chainwork=? WHERE height=1',(self.packets[0],bytes(64)))
        with self.assertRaises(ValueError): self.verify()

    def test_changed_published_state_and_injected_schema_reject(self):
        with sqlite3.connect(self.folder/'producer/native.sqlite') as database:
            database.execute('UPDATE kv SET value=?',(self.canonical(2),))
        with self.assertRaises(ValueError): self.verify()
        with sqlite3.connect(self.folder/'producer/native.sqlite') as database:
            database.execute('UPDATE kv SET value=?',(self.canonical(1),))
            database.execute('CREATE TRIGGER injected AFTER INSERT ON metadata BEGIN SELECT 1; END')
        with self.assertRaises(ValueError): self.verify()

    def assert_user_schema_object_rejected(self, kind, name, sql):
        # Real catalog objects, not source-text assertions. The complete fixture
        # still has valid metadata, state, packets and ancestry, and disk bytes
        # are remeasured so the schema boundary is the intended refusal.
        for owner in ('producer', 'validator'):
            path = self.folder/owner/'native.sqlite'
            with self.subTest(owner=owner,kind=kind,name=name):
                with sqlite3.connect(path) as database:
                    database.execute(sql)
                    actual = database.execute(
                        'SELECT type,name,sql FROM sqlite_master WHERE name=?', (name,)).fetchone()
                    self.assertEqual(actual[:2], (kind,name))
                    self.assertIsInstance(actual[2], str)
                    self.assertEqual(database.execute('PRAGMA integrity_check').fetchall(), [('ok',)])
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                try:
                    with self.assertRaisesRegex(ValueError,'durable schema additions/omissions/changes'):
                        self.verify()
                finally:
                    with sqlite3.connect(path) as database:
                        database.execute('DROP '+kind.upper()+' "'+name+'"')
                    self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                    self.verify()

    def test_sqlite_like_prefix_user_table_is_not_internal(self):
        self.assert_user_schema_object_rejected('table','sqliteXshadow',
            'CREATE TABLE sqliteXshadow(value BLOB NOT NULL)')

    def test_sqlite_like_prefix_user_index_is_not_internal(self):
        self.assert_user_schema_object_rejected('index','SqliteXshadow',
            'CREATE INDEX SqliteXshadow ON kv(key)')

    def test_sqlite_like_prefix_user_trigger_is_not_internal(self):
        self.assert_user_schema_object_rejected('trigger','SQLITEXshadow',
            'CREATE TRIGGER SQLITEXshadow AFTER INSERT ON metadata BEGIN SELECT 1; END')

    def test_sqlite_like_prefix_user_view_is_not_internal(self):
        self.assert_user_schema_object_rejected('view','sqlite7shadow',
            'CREATE VIEW sqlite7shadow AS SELECT key FROM metadata')

    def test_real_sqlite_internal_autoindexes_and_statistics_remain_supported(self):
        for owner in ('producer', 'validator'):
            with sqlite3.connect(self.folder/owner/'native.sqlite') as database:
                autoindexes = database.execute(
                    'SELECT name,sql FROM sqlite_master WHERE type="index"').fetchall()
                self.assertTrue(any(name.startswith('sqlite_autoindex_') and sql is None
                                    for name,sql in autoindexes))
                # ANALYZE creates the genuine reserved statistics table; callers
                # cannot create an ordinary table with this reserved spelling.
                database.execute('ANALYZE')
                self.assertEqual(database.execute(
                    'SELECT type,name FROM sqlite_master WHERE name="sqlite_stat1"').fetchone(),
                    ('table','sqlite_stat1'))
        self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
        self.verify()

    def test_current_v2_schema_and_complete_index_positive_control(self):
        self.assertEqual(self.schema_domain,'native-branch-schema-v2')
        self.verify()
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            self.assertEqual(database.execute('SELECT count(*) FROM ancestry_jump').fetchone()[0],5)

    def test_v2_schema_metadata_cannot_use_legacy_hash_domain(self):
        ddl,_ = check.native_durable_schema(check.ROOT)
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute("UPDATE metadata SET value=? WHERE key='schema'",
                             (self.H('native-branch-schema-v1',ddl.encode()),))
        with self.assertRaisesRegex(ValueError,'durable metadata/context'): self.verify()

    def test_authenticated_domain_cannot_relabel_legacy_tables(self):
        ddl,_ = check.native_durable_schema(check.ROOT)
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute("UPDATE metadata SET value=? WHERE key='schema'",
                             (self.H('native-authenticated-branch-schema-v1',ddl.encode()),))
        with self.assertRaisesRegex(ValueError,'durable metadata/context'): self.verify()

    def test_authenticated_tables_are_out_of_scope_even_with_resealed_metadata(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        extension = ('CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);\n'
                     'CREATE TABLE native_state_commitments(block BLOB PRIMARY KEY,data BLOB NOT NULL);\n')
        original = self.H(domain,ddl.encode())
        for schema in (original,self.H(domain,(ddl+extension).encode()),
                       self.H('native-authenticated-branch-schema-v1',(ddl+extension).encode())):
            with self.subTest(schema=schema.hex()):
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.executescript(extension)
                    database.execute('INSERT INTO archive_nodes VALUES(?,?)',(bytes(32),b'unverified node'))
                    database.execute('INSERT INTO native_state_commitments VALUES(?,?)',(bytes(32),b'unverified commitment'))
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(schema,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                with self.assertRaisesRegex(ValueError,'durable schema additions/omissions/changes'): self.verify()
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute('DROP TABLE archive_nodes')
                    database.execute('DROP TABLE native_state_commitments')
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(original,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                self.verify()

    def test_growth_domains_cannot_relabel_legacy_tables(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        for foreign in ('native-growth-reference-branch-schema-v2',
                        'native-permanent-account-growth-schema-v2'):
            with self.subTest(domain=foreign):
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",
                                     (self.H(foreign,ddl.encode()),))
                with self.assertRaisesRegex(ValueError,'durable metadata/context'): self.verify()
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute("UPDATE metadata SET value=? WHERE key='schema'",
                             (self.H(domain,ddl.encode()),))
        self.verify()

    def test_pq_domains_cannot_relabel_legacy_tables(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        for foreign in ('native-pq-transfer-branch-schema-v1',
                        'native-pq-accounts-branch-schema-v2',
                        'native-pq-quota-branch-schema-v3',
                        'native-pq-task-branch-schema-v4'):
            with self.subTest(domain=foreign):
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",
                                     (self.H(foreign,ddl.encode()),))
                with self.assertRaisesRegex(ValueError,'durable metadata/context'): self.verify()
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute("UPDATE metadata SET value=? WHERE key='schema'",
                             (self.H(domain,ddl.encode()),))
        self.verify()

    def test_pq_tables_cannot_borrow_legacy_qualification_after_resealing(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        original = self.H(domain,ddl.encode())
        for version,foreign in ((1,'native-pq-transfer-branch-schema-v1'),
                                (2,'native-pq-accounts-branch-schema-v2'),
                                (3,'native-pq-quota-branch-schema-v3'),
                                (4,'native-pq-task-branch-schema-v4')):
            table = 'local_pq_statements_v'+str(version)
            extension = 'CREATE TABLE '+table+'(statement BLOB PRIMARY KEY);'
            for schema in (original,self.H(domain,(ddl+extension).encode()),
                           self.H(foreign,(ddl+extension).encode())):
                with self.subTest(version=version,schema=schema.hex()):
                    with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                        database.execute(extension)
                        database.execute("UPDATE metadata SET value=? WHERE key='schema'",(schema,))
                    self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                    try:
                        with self.assertRaisesRegex(ValueError,'durable schema additions/omissions/changes'):
                            self.verify()
                    finally:
                        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                            database.execute('DROP TABLE '+table)
                            database.execute("UPDATE metadata SET value=? WHERE key='schema'",(original,))
                        self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
        self.verify()

    def test_replayed_and_stored_pq_packet_still_fails_legacy_ancestry(self):
        original = self.packets[0]
        for version in (1,2,3,4):
            changed = b'PQP'+str(version).encode()+bytes([version,0,0,0])+original
            with self.subTest(version=version):
                self.packets[0] = changed
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute('UPDATE blocks SET packet=? WHERE height=1',(changed,))
                # Also replace the producer packet and the replay input: exact
                # equality alone must never authorize another header profile.
                with sqlite3.connect(self.folder/'producer/native.sqlite') as database:
                    database.execute('UPDATE blocks SET packet=? WHERE height=1',(changed,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                with self.assertRaisesRegex(ValueError,'header version'): self.verify()
                self.packets[0] = original
                for owner in ('producer','validator'):
                    with sqlite3.connect(self.folder/owner/'native.sqlite') as database:
                        database.execute('UPDATE blocks SET packet=? WHERE height=1',(original,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
        self.verify()

    def test_pq4_revocation_history_cannot_borrow_a_resealed_legacy_schema(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        original = self.H(domain,ddl.encode())
        extension = ('CREATE TABLE local_pq_task_revocations_v4('
            'ordinal INTEGER PRIMARY KEY CHECK(ordinal>=1 AND ordinal<=1024),'
            'lease BLOB UNIQUE NOT NULL CHECK(length(lease)=32),'
            'demand BLOB NOT NULL CHECK(length(demand)=32),'
            'block BLOB NOT NULL REFERENCES blocks(id),'
            'generation INTEGER NOT NULL CHECK(generation>0));')
        for schema in (original,self.H(domain,(ddl+extension).encode()),
                       self.H('native-pq-task-branch-schema-v4',(ddl+extension).encode())):
            with self.subTest(schema=schema.hex()):
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute(extension)
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(schema,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                try:
                    with self.assertRaisesRegex(ValueError,'durable schema additions/omissions/changes'):
                        self.verify()
                finally:
                    with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                        database.execute('DROP TABLE local_pq_task_revocations_v4')
                        database.execute("UPDATE metadata SET value=? WHERE key='schema'",(original,))
                    self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
        self.verify()

    def test_shared_layout_table_and_resealed_domain_remain_out_of_scope(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        extension = 'CREATE TABLE native_io_shared_snapshots(block BLOB PRIMARY KEY,data BLOB NOT NULL);'
        original = self.H(domain,ddl.encode())
        shared_domain = 'native-io-shared-authenticated-branch-schema-v1'
        shared = self.H(shared_domain,original,extension.encode(),
                        b'native-io-shared-authenticated-snapshot-v1')
        for schema in (original,self.H(domain,(ddl+extension).encode()),shared):
            with self.subTest(schema=schema.hex()):
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.executescript(extension)
                    database.execute('INSERT INTO native_io_shared_snapshots VALUES(?,?)',
                                     (bytes(32),b'unverified shared snapshot'))
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(schema,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                with self.assertRaisesRegex(ValueError,'durable schema additions/omissions/changes'): self.verify()
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute('DROP TABLE native_io_shared_snapshots')
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(original,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                self.verify()
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            database.execute("UPDATE metadata SET value=? WHERE key='schema'",(shared,))
        with self.assertRaisesRegex(ValueError,'durable metadata/context'): self.verify()

    def test_permanent_growth_tables_remain_out_of_scope_after_metadata_resealing(self):
        ddl,domain = check.native_durable_schema(check.ROOT)
        extension = ('CREATE TABLE archive_nodes(id BLOB PRIMARY KEY,data BLOB NOT NULL);\n'
                     'CREATE TABLE growth_states(block BLOB PRIMARY KEY,data BLOB NOT NULL);\n')
        original = self.H(domain,ddl.encode())
        for schema in (original,self.H(domain,(ddl+extension).encode()),
                       self.H('native-permanent-account-growth-schema-v2',(ddl+extension).encode())):
            with self.subTest(schema=schema.hex()):
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.executescript(extension)
                    database.execute('INSERT INTO archive_nodes VALUES(?,?)',(bytes(32),b'unverified node'))
                    database.execute('INSERT INTO growth_states VALUES(?,?)',(bytes(32),b'unverified growth state'))
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(schema,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                with self.assertRaisesRegex(ValueError,'durable schema additions/omissions/changes'): self.verify()
                with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
                    database.execute('DROP TABLE archive_nodes')
                    database.execute('DROP TABLE growth_states')
                    database.execute("UPDATE metadata SET value=? WHERE key='schema'",(original,))
                self.summary['ledger_disk_bytes'] = sum(path.stat().st_size for path in self.folder.rglob('*') if path.is_file())
                self.verify()

    def test_resealed_wrong_half_link_is_not_accepted_as_derived_structure(self):
        block,previous,height = self.blocks[1]
        with sqlite3.connect(self.folder/'validator/native.sqlite') as database:
            ancestor,ancestor_height,_,right,_ = database.execute(
                'SELECT ancestor,ancestor_height,left_seal,right_seal,seal FROM ancestry_jump WHERE block=? AND level=1',(block,)).fetchone()
            left = bytes([9])*32
            seal = self.H('native-derived-ancestry-row-v1',bytes.fromhex(self.summary['network']),
                bytes.fromhex(self.summary['parameters']),bytes.fromhex(self.summary['genesis']),
                block,previous,height.to_bytes(8,'little'),bytes([1]),ancestor,
                ancestor_height.to_bytes(8,'little'),left,right)
            database.execute('UPDATE ancestry_jump SET left_seal=?,seal=? WHERE block=? AND level=1',(left,seal,block))
        with self.assertRaisesRegex(ValueError,'ancestry derived row/half-link/seal'): self.verify()

    def test_missing_extra_or_changed_derived_rows_are_refused(self):
        for mode in ('missing','extra','seal','ancestor'):
            with self.subTest(mode=mode):
                database = sqlite3.connect(self.folder/'validator/native.sqlite')
                try:
                    row = database.execute('SELECT * FROM ancestry_jump WHERE level=1 LIMIT 1').fetchone()
                    if mode == 'missing':
                        database.execute('DELETE FROM ancestry_jump WHERE block=? AND level=?',row[:2])
                    elif mode == 'extra':
                        database.execute('INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)',(row[0],2,*row[2:]))
                    elif mode == 'seal':
                        database.execute('UPDATE ancestry_jump SET seal=? WHERE block=? AND level=?',(bytes(32),*row[:2]))
                    else:
                        database.execute('UPDATE ancestry_jump SET ancestor=? WHERE block=? AND level=?',(bytes([8])*32,*row[:2]))
                    database.commit()
                    with self.assertRaisesRegex(ValueError,'ancestry derived row'): self.verify()
                finally:
                    database.execute('DELETE FROM ancestry_jump WHERE block=? AND level=2',(row[0],))
                    database.execute('DELETE FROM ancestry_jump WHERE block=? AND level=?',row[:2])
                    database.execute('INSERT INTO ancestry_jump VALUES(?,?,?,?,?,?,?)',row)
                    database.commit(); database.close()
        self.verify()

class NativeDurableSchemaTests(unittest.TestCase):
    selected_bindings = ('let storage_layout =\n'
        '            shared_snapshot::Layout::for_opening(state_backend, native_io.as_ref());\n'
        '        let ddl = storage_layout.ddl(state_backend.selected_ddl(&settings));\n'
        '        let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings));')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = self.root/'trillionnium/crates/trnm-pon-node/src/store.rs'
        self.store.parent.mkdir(parents=True)
        self.index = self.store.with_name('ancestry_index.rs')
        self.shared = self.store.with_suffix('')/'shared_snapshot.rs'
        self.shared.parent.mkdir()
        self.current = (check.ROOT/'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
        self.current_index = (check.ROOT/'trillionnium/crates/trnm-pon-node/src/ancestry_index.rs').read_text()
        self.current_shared = (check.ROOT/'trillionnium/crates/trnm-pon-node/src/store/shared_snapshot.rs').read_text()
        self.auxiliary = {name:(check.ROOT/name).read_text() for name in (
            'trillionnium/crates/trnm-pon-node/src/lib.rs',
            'trillionnium/crates/trnm-pon-node/src/native_packet.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_native_v1.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_accounts_v2.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_quota_v3.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_tasks_v4.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_tasks_v5.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_native_v1.rs',
            'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs',
        )}

    def tearDown(self): self.temporary.cleanup()

    def extract(self, source, index=None, shared=None, auxiliary=None):
        self.store.write_text(source)
        self.index.write_text(self.current_index if index is None else index)
        self.shared.write_text(self.current_shared if shared is None else shared)
        files = dict(self.auxiliary)
        if auxiliary is not None:
            files.update(auxiliary)
        for name, text in files.items():
            path = self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(text)
        return check.native_durable_schema(self.root)

    def replace_once(self, source, before, after):
        self.assertEqual(source.count(before),1,'source control must target exactly one occurrence: '+before)
        return source.replace(before,after,1)

    def selected_schema_bindings(self):
        return self.selected_bindings

    def historical_backend_source(self):
        # Explicit non-PQ parser fixture. Removing just the shared wrapper from
        # today's PQ source would leave its selector/constructor contract active.
        base = re.search(r'\bconst\s+BASE_DDL\s*:\s*&str\s*=\s*"[^"\\]*"\s*;', self.current)
        self.assertIsNotNone(base)
        return base[0] + '''
            fn ddl() -> String { format!("{}{}", BASE_DDL, crate::ancestry_index::DDL) }
            enum StateBackend { Legacy, AuthenticatedV1, PermanentAccountGrowthV2, }
            impl StateBackend {
                fn ddl(self) -> String {
                    match self {
                        Self::Legacy => ddl(),
                        Self::AuthenticatedV1 => format!("{}{}", ddl(), native_authenticated::DDL),
                        Self::PermanentAccountGrowthV2 => format!("{}{}", ddl(), growth::DDL),
                    }
                }
                fn selected_schema_id(self, settings: &Settings) -> Hash {
                    if growth_profile_v2::enabled(&settings.app) {
                        hash(b"native-growth-reference-branch-schema-v2", &[self.ddl().as_bytes()],)
                    } else { self.schema_id() }
                }
                fn schema_id(self) -> Hash {
                    let domain: &[u8] = match self {
                        Self::Legacy => b"native-branch-schema-v2",
                        Self::AuthenticatedV1 => b"native-authenticated-branch-schema-v1",
                        Self::PermanentAccountGrowthV2 => b"native-permanent-account-growth-schema-v2",
                    };
                    hash(domain, &[self.ddl().as_bytes()])
                }
            }
            struct NativeStoreOpening {
                state_backend: StateBackend,
                growth_observation_only: bool,
                native_io: Option<NativeIoLease>,
            }
            impl Node {
                fn open() { Self::open_with_fault(path, settings, workers, None) }
                fn open_with_fault() {
                    ensure(!owner_marker_present(path)?, "OWNER_TASK_POLICY_REQUIRED")?;
                    Self::open_inner(path, settings, workers, hook, None, None, None)
                }
                fn open_inner() {
                    Self::open_selected(path, settings, workers, hook,
                        NativeOwners { policy: owner_policy, mining: mining_owner, continuous: continuous_owner, },
                        StateBackend::Legacy, false,)
                }
                fn open_with_authenticated_state() {
                    Self::open_with_authenticated_state_and_fault(path, settings, workers, None)
                }
                fn open_with_authenticated_state_and_fault() {
                    ensure(!owner_marker_present(path)?, "OWNER_TASK_POLICY_REQUIRED")?;
                    Self::open_selected(path, settings, workers, hook,
                        NativeOwners { policy: None, mining: None, continuous: None, }, StateBackend::AuthenticatedV1, false,)
                }
                fn open_selected(
                    path: &Path, settings: Settings, workers: usize,
                    hook: Option<&mut Hook<'_>>, owners: NativeOwners,
                    state_backend: StateBackend, growth_observation_only: bool,
                ) -> Result<Self> {
                    Self::open_selected_with_io(path, settings, workers, hook, owners,
                        NativeStoreOpening { state_backend, growth_observation_only, native_io: None, },)
                }
                fn open_selected_with_io(
                    path: &Path, settings: Settings, workers: usize,
                    mut hook: Option<&mut Hook<'_>>, owners: NativeOwners,
                    opening: NativeStoreOpening,
                ) -> Result<Self> {
                    let NativeStoreOpening { state_backend, growth_observation_only, native_io, } = opening;
                    let ddl = state_backend.ddl();
                    let schema_id = state_backend.selected_schema_id(&settings);
                }
            }
        '''

    def test_historical_literal_v1_and_inline_composed_v2_stay_supported(self):
        ddl = 'CREATE TABLE exact(key BLOB);'
        v1 = 'const DDL : &str = "'+ddl+'";fn open(){let id=hash(b"native-branch-schema-v1", &[ DDL.as_bytes() ]);}'
        index_ddl = 'CREATE TABLE jumps(key BLOB);'
        index = 'const DDL: &str = "'+index_ddl+'";'
        v2 = ('const BASE_DDL: &str = "'+ddl+'";'
              'fn ddl() -> String { format!("{}{}", BASE_DDL, crate::ancestry_index::DDL) }'
              'fn open(){ let ddl = ddl(); let id = hash(b"native-branch-schema-v2", &[ddl.as_bytes()]); }')
        self.assertEqual(self.extract(v1),(ddl,'native-branch-schema-v1'))
        self.assertEqual(self.extract(v2,index),(ddl+index_ddl,'native-branch-schema-v2'))
        # Mentioning the new type in non-code must not select its parser branch.
        noncode = '\n// StateBackend\nconst NOTE: &str = r#"StateBackend"#;\n'
        self.assertEqual(self.extract(v2+noncode,index),(ddl+index_ddl,'native-branch-schema-v2'))
        for label,source in [('v1-wrong-domain',v1.replace('native-branch-schema-v1','native-branch-schema-v2')),
                             ('v1-auth-domain',v1.replace('native-branch-schema-v1','native-authenticated-branch-schema-v1')),
                             ('v1-duplicate',v1+v1),('v1-missing-literal',v1.replace('const DDL','const OTHER')),
                             ('v2-wrong-domain',v2.replace('native-branch-schema-v2','native-branch-schema-v1')),
                             ('v2-auth-domain',v2.replace('native-branch-schema-v2','native-authenticated-branch-schema-v1')),
                             ('v2-unknown-domain',v2.replace('native-branch-schema-v2','native-branch-schema-unknown')),
                             ('v2-incomplete',v2.replace('format!("{}{}", BASE_DDL, crate::ancestry_index::DDL)','format!("{}", BASE_DDL)')),
                             ('v2-reversed',v2.replace('BASE_DDL, crate::ancestry_index::DDL','crate::ancestry_index::DDL, BASE_DDL'))]:
            with self.subTest(label=label),self.assertRaises(ValueError): self.extract(source,index)
        for source,domain in [(v1,'native-branch-schema-v1'),(v2,'native-branch-schema-v2')]:
            broken = source.replace(domain,'native-branch-schema-unknown')
            for decoy in ['\n// '+source+'\n','\nconst NOTE: &str = '+json.dumps(source)+';\n',
                          '\nconst NOTE: &str = r##"'+source+'"##;\n']:
                with self.subTest(domain=domain,decoy=decoy),self.assertRaises(ValueError):
                    self.extract(broken+decoy,index)

    def test_current_backend_returns_the_exact_preserved_legacy_bytes(self):
        sys.path.insert(0,str(check.ROOT/'formal/pon-nakamoto-v1'))
        from contract_wire import H
        ddl,domain = self.extract(self.current)
        self.assertEqual(domain,'native-branch-schema-v2')
        # Pinned to the independently recomputed pre-backend V2 bytes, not to
        # another call through this extractor or to a resealed fixture.
        self.assertEqual(len(ddl.encode()),4775)
        self.assertEqual(H(domain,ddl.encode()).hex(),
                         '8c2627fa0b06e51742e7e6d40662c61d4b4727e810abc02b24634a8a817dc0e0')
        self.assertNotRegex(ddl,r'archive_nodes|native_state_commitments')
        changed = self.replace_once(self.current,'format!("{}{}", BASE_DDL, crate::ancestry_index::DDL)',
                                    'format!("{}", BASE_DDL)')
        with self.assertRaisesRegex(ValueError,'durable V2 schema composition'): self.extract(changed)

    def test_backend_domains_and_composition_fail_closed(self):
        legacy = 'b"native-branch-schema-v2"'
        authenticated = 'b"native-authenticated-branch-schema-v1"'
        auth_arm = 'Self::AuthenticatedV1 => format!("{}{}", ddl(), native_authenticated::DDL),'
        mutations = [
            ('legacy-v1',legacy,'b"native-branch-schema-v1"'),
            ('legacy-auth',legacy,authenticated),('auth-legacy',authenticated,legacy),
            ('legacy-unknown',legacy,'b"native-branch-schema-unknown"'),
            ('auth-unknown',authenticated,'b"native-authenticated-branch-schema-unknown"'),
            ('literal-space',legacy,'b"native-branch- schema-v2"'),
            ('legacy-extension','Self::Legacy => ddl(),','Self::Legacy => format!("{}{}", ddl(), native_authenticated::DDL),'),
            ('auth-omitted',auth_arm,'Self::AuthenticatedV1 => ddl(),'),
            ('auth-reversed',auth_arm,'Self::AuthenticatedV1 => format!("{}{}", native_authenticated::DDL, ddl()),'),
            ('auth-format',auth_arm,'Self::AuthenticatedV1 => format!("{}", ddl(), native_authenticated::DDL),'),
            ('unselected-hash','hash(domain, &[self.ddl().as_bytes()])','hash(domain, &[ddl().as_bytes()])'),
            ('extra-hash-input','hash(domain, &[self.ddl().as_bytes()])','hash(domain, &[self.ddl().as_bytes(), b"extra"])'),
            ('shadowed-domain','hash(domain, &[self.ddl().as_bytes()])','let domain = b"other"; hash(domain, &[self.ddl().as_bytes()])'),
            ('extra-variant','enum StateBackend {\n    Legacy,\n    AuthenticatedV1,','enum StateBackend {\n    Legacy,\n    AuthenticatedV1,\n    Other,'),
            ('wildcard',auth_arm,'_ => format!("{}{}", ddl(), native_authenticated::DDL),'),
            ('wrong-impl-owner','impl StateBackend {','impl StateBackend for Other {'),
        ]
        for label,before,after in mutations:
            with self.subTest(label=label),self.assertRaises(ValueError):
                self.extract(self.replace_once(self.current,before,after))
        backend = self.current[self.current.index('impl StateBackend {'):self.current.index('\nstruct NativeOwners {')]
        with self.assertRaisesRegex(ValueError,'durable source body StateBackend'):
            self.extract(self.current+'\n'+backend)

    def test_permanent_growth_mapping_is_exact_without_qualifying_its_storage(self):
        ddl,domain = self.extract(self.current)
        self.assertEqual(domain,'native-branch-schema-v2')
        self.assertNotRegex(ddl,r'archive_nodes|native_state_commitments|growth_states')
        growth = 'b"native-permanent-account-growth-schema-v2"'
        arm = 'Self::PermanentAccountGrowthV2 => format!("{}{}", ddl(), growth::DDL),'
        mutations = [
            ('domain-legacy',growth,'b"native-branch-schema-v2"'),
            ('domain-authenticated',growth,'b"native-authenticated-branch-schema-v1"'),
            ('domain-gsc2',growth,'b"native-growth-reference-branch-schema-v2"'),
            ('domain-unknown',growth,'b"native-permanent-account-growth-schema-unknown"'),
            ('domain-literal-space',growth,'b"native-permanent-account-growth- schema-v2"'),
            ('growth-omitted',arm,'Self::PermanentAccountGrowthV2 => ddl(),'),
            ('growth-authenticated',arm,'Self::PermanentAccountGrowthV2 => format!("{}{}", ddl(), native_authenticated::DDL),'),
            ('growth-reversed',arm,'Self::PermanentAccountGrowthV2 => format!("{}{}", growth::DDL, ddl()),'),
            ('growth-format',arm,'Self::PermanentAccountGrowthV2 => format!("{} {}", ddl(), growth::DDL),'),
            ('growth-format-arity',arm,'Self::PermanentAccountGrowthV2 => format!("{}", ddl(), growth::DDL),'),
            ('growth-wildcard',arm,'_ => format!("{}{}", ddl(), growth::DDL),'),
            ('legacy-growth','Self::Legacy => ddl(),','Self::Legacy => format!("{}{}", ddl(), growth::DDL),'),
        ]
        for label,before,after in mutations:
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,'durable backend'):
                self.extract(self.replace_once(self.current,before,after))

    def test_permanent_growth_table_cannot_be_inserted_into_legacy_literals(self):
        for name in ('growth_states','GrOwTh_StAtEs','native_io_shared_snapshots','NaTiVe_Io_ShArEd_SnApShOtS'):
            extension = 'CREATE TABLE '+name+'(block BLOB PRIMARY KEY,data BLOB NOT NULL);'
            literal = 'const DDL: &str = "'+extension+'";'
            v1 = literal+'fn open() { hash(b"native-branch-schema-v1", &[DDL.as_bytes()]); }'
            sources = [
                (v1,None),
                (self.replace_once(self.current,'CREATE TABLE metadata',extension+'CREATE TABLE metadata'),None),
                (self.current,self.replace_once(self.current_index,'CREATE TABLE ancestry_jump',extension+'CREATE TABLE ancestry_jump')),
            ]
            for source,index in sources:
                with self.subTest(name=name,index=index is not None),self.assertRaisesRegex(ValueError,'tables in legacy durable schema'):
                    self.extract(source,index)

    def test_actual_opener_and_selected_schema_bindings_cannot_be_replaced(self):
        pair = self.selected_schema_bindings()
        mutations = [
            ('default-open','Self::open_with_fault(path, settings, workers, None)',
             'Self::open_with_authenticated_state_and_fault(path, settings, workers, None)'),
            ('fault-open','Self::open_inner(path, settings, workers, hook, None, None, None)',
             'Self::open_with_authenticated_state_and_fault(path, settings, workers, hook)'),
            ('legacy-selected','StateBackend::Legacy,\n            false,\n        )\n    }\n    fn open_selected',
             'StateBackend::AuthenticatedV1,\n            false,\n        )\n    }\n    fn open_selected'),
            ('auth-selected','StateBackend::AuthenticatedV1,\n            false,\n        )\n    }\n    /// Explicit local operator policy',
             'StateBackend::Legacy,\n            false,\n        )\n    }\n    /// Explicit local operator policy'),
            ('legacy-observation','StateBackend::Legacy,\n            false,\n        )\n    }\n    fn open_selected',
             'StateBackend::Legacy,\n            true,\n        )\n    }\n    fn open_selected'),
            ('auth-observation','StateBackend::AuthenticatedV1,\n            false,\n        )\n    }\n    /// Explicit local operator policy',
             'StateBackend::AuthenticatedV1,\n            true,\n        )\n    }\n    /// Explicit local operator policy'),
            ('ddl-unselected','let ddl = storage_layout.ddl(state_backend.selected_ddl(&settings));','let ddl = ddl();'),
            ('schema-unselected','let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings));','let schema_id = StateBackend::Legacy.schema_id();'),
            ('nested-pair',pair,'if false { '+pair+' }'),
        ]
        for label,before,after in mutations:
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,'durable backend (?:opener|selected schema)'):
                self.extract(self.replace_once(self.current,before,after))
        rebound = [
            'let state_backend = StateBackend::AuthenticatedV1;',
            'let settings = settings;',
            'let (settings, _) = (settings, ());',
            'let ddl = StateBackend::AuthenticatedV1.ddl();',
            'let mut ddl = StateBackend::AuthenticatedV1.ddl();',
            'let ddl: String = StateBackend::AuthenticatedV1.ddl();',
            'let schema_id: Hash = StateBackend::AuthenticatedV1.schema_id();',
            'let (ddl, schema_id) = (StateBackend::AuthenticatedV1.ddl(), StateBackend::AuthenticatedV1.schema_id());',
            'let (state_backend, _) = (StateBackend::AuthenticatedV1, ());',
            'state_backend = StateBackend::AuthenticatedV1;',
            'ddl = StateBackend::AuthenticatedV1.ddl();',
            'schema_id = StateBackend::AuthenticatedV1.schema_id();',
            'schema_id[0] = 0;',
        ]
        for statement in rebound:
            with self.subTest(statement=statement),self.assertRaisesRegex(ValueError,'durable backend selected schema rebound'):
                self.extract(self.replace_once(self.current,pair,pair+'\n        '+statement))

    def test_legacy_and_authenticated_openers_cannot_enable_growth_observation_mode(self):
        for backend, after in (('Legacy', 'fn open_selected'),
                               ('AuthenticatedV1', '/// Explicit local operator policy')):
            tail = '\n        )\n    }\n    '+after
            current = 'StateBackend::'+backend+',\n            false,'+tail
            for replacement in ('true', 'growth_observation_only', 'false || true',
                                '{ false }', 'false, true'):
                changed = 'StateBackend::'+backend+',\n            '+replacement+','+tail
                with self.subTest(backend=backend, replacement=replacement), \
                        self.assertRaisesRegex(ValueError, 'durable backend opener'):
                    self.extract(self.replace_once(self.current,current,changed))

    def test_selected_settings_cannot_be_mutated_through_fields_or_borrowed(self):
        header = 'fn open_selected(\n        path: &Path,\n        settings: Settings,'
        pair = self.selected_schema_bindings()
        statements = [
            'settings.app.params["work_task_profile"] = serde_json::json!("legacy-task-v1");',
            'settings.app.params["work_task_profile"][0] = serde_json::json!(0);',
            'settings.app = settings.app.clone();',
            'let alias = &mut settings;',
            'let alias = &mut settings.app;',
            'let alias = &mut (settings.app);',
        ]
        for statement in statements:
            with self.subTest(statement=statement),self.assertRaisesRegex(ValueError,'durable backend selected schema rebound'):
                # Even when the ordinary bridge's parameter is mutable, source
                # inspection must refuse field writes/aliases in the callee.
                changed = self.replace_once(self.current,header,header.replace('settings:','mut settings:',1))
                self.extract(self.replace_once(changed,pair,statement+'\n        '+pair))

    def test_growth_selection_is_exact_without_widening_legacy_evidence(self):
        # Recognizing the current selector must not permit a changed growth
        # namespace, bypassed selector or an unapproved implementation body.
        # Every negative still targets exactly one real current-source site.
        selector = self.function_part(self.current,'selected_schema_id')
        mutations = [
            ('wrong-growth-domain', 'b"native-growth-reference-branch-schema-v2"',
             'b"native-branch-schema-v2"'),
            ('growth-literal-space', 'b"native-growth-reference-branch-schema-v2"',
             'b"native-growth-reference-branch- schema-v2"'),
            ('flipped-growth-selector', selector, selector.replace('if growth_', 'if !growth_', 1)),
            ('bypassed-growth-selector', selector,
             selector.replace('if growth_profile_v2::enabled(&settings.app) {', 'if false {', 1)),
            ('default-instead-selected', 'let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings));',
             'let schema_id = storage_layout.schema_id(state_backend.schema_id());'),
            ('bypassed-backend', 'let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings));',
             'let schema_id = storage_layout.schema_id(StateBackend::Legacy.selected_schema_id(&settings));'),
            ('ignored-settings', 'let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings));',
             'let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings.clone()));'),
            ('unapproved-method', 'impl StateBackend {',
             'impl StateBackend { fn other(self) -> Hash { self.schema_id() }'),
        ]
        for label,before,after in mutations:
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,'durable (?:backend|growth schema domain)'):
                self.extract(self.replace_once(self.current,before,after))

    def test_backend_decoys_and_historical_hash_cannot_authorize_bad_active_mapping(self):
        backend = self.current[self.current.index('impl StateBackend {'):self.current.index('\nstruct NativeOwners {')]
        bad = self.replace_once(self.current,'b"native-branch-schema-v2"','b"native-branch-schema-unknown"')
        decoys = ['\n'+''.join('// '+line+'\n' for line in backend.splitlines()),
                  '\n/* outer /* nested */ '+backend+' */\n',
                  '\nconst DECOY: &str = '+json.dumps(backend)+';\n',
                  '\nconst DECOY: &str = r###"'+backend+'"###;\n',
                  '\nmod historical { '+backend+' }\n',
                  '\nignored!('+backend+');\n','\nignored!['+backend+'];\n']
        expected = self.extract(self.current)
        for decoy in decoys:
            with self.subTest(decoy=decoy):
                self.assertEqual(self.extract(self.current+decoy),expected)
                with self.assertRaisesRegex(ValueError,'durable backend (?:domain Legacy|composition/domain)'): self.extract(bad+decoy)
        inline = '\nfn historical(ddl: String) -> Hash { hash(b"native-branch-schema-v2", &[ddl.as_bytes()]) }\n'
        for broken in (bad,self.replace_once(self.current,'Self::Legacy => ddl(),','Self::Legacy => native_authenticated::DDL.to_string(),')):
            with self.subTest(broken=broken[-80:]),self.assertRaisesRegex(ValueError,'durable backend'):
                self.extract(broken+inline)

    def test_schema_literals_must_be_direct_items_and_cannot_include_authenticated_tables(self):
        literal = 'const DDL: &str = "CREATE TABLE exact(key BLOB);";'
        opener = 'fn open() { hash(b"native-branch-schema-v1", &[DDL.as_bytes()]); }'
        for decoy in ['mod historical { '+literal+' }','ignored!('+literal+');','ignored!['+literal+'];']:
            with self.subTest(decoy=decoy),self.assertRaisesRegex(ValueError,'durable schema literal DDL'):
                self.extract(decoy+'\nuse other::DDL;\n'+opener)
        for name in ['archive_nodes','native_state_commitments','ArChIvE_NoDeS','native_io_shared_snapshots']:
            extension = 'CREATE TABLE '+name+'(id BLOB PRIMARY KEY,data BLOB NOT NULL);'
            sources = [
                (literal.replace('CREATE TABLE exact',extension+'CREATE TABLE exact')+opener,None),
                (self.replace_once(self.current,'CREATE TABLE metadata',extension+'CREATE TABLE metadata'),None),
                (self.current,self.replace_once(self.current_index,'CREATE TABLE ancestry_jump',extension+'CREATE TABLE ancestry_jump')),
            ]
            for source,index in sources:
                with self.subTest(name=name,index=index is not None),self.assertRaisesRegex(ValueError,'authenticated tables in legacy durable schema'):
                    self.extract(source,index)

    def held_io_parts(self):
        code = check.rust_code(self.current)
        parts = {}
        for kind,name in [('fn','open_selected'),('fn','open_selected_with_io'),
                          ('struct','NativeStoreOpening')]:
            matches = list(re.finditer(r'\b'+kind+r'\s+'+name+r'\b',code))
            self.assertEqual(len(matches),1)
            match = matches[0]
            start = code.index('{',match.end())
            end = check.rust_group_end(code,start)
            self.assertIsNotNone(end)
            parts[name] = (self.current[match.start():end],
                           self.current[match.start():start],self.current[start+1:end-1])
        return parts

    def test_actual_held_io_bridge_preserves_the_independent_legacy_schema(self):
        parts = self.held_io_parts()
        self.assertIn('NativeStoreOpening {',parts['open_selected'][2])
        self.assertIn('opening: NativeStoreOpening',parts['open_selected_with_io'][1])
        ddl,domain = self.extract(self.current)
        self.assertEqual(domain,'native-branch-schema-v2')
        self.assertEqual(len(ddl.encode()),4775)
        self.assertEqual(self.H_legacy_schema(ddl,domain),
                         '8c2627fa0b06e51742e7e6d40662c61d4b4727e810abc02b24634a8a817dc0e0')
        bridge = parts['open_selected'][2]
        changed = self.replace_once(self.current,bridge,
                                   bridge.replace('path,','path /* original root */,',1))
        self.assertEqual(self.extract(changed),(ddl,domain))

    def H_legacy_schema(self, ddl, domain):
        sys.path.insert(0,str(check.ROOT/'formal/pon-nakamoto-v1'))
        from contract_wire import H
        return H(domain,ddl.encode()).hex()

    def test_held_io_bridge_refuses_changed_fields_effects_or_nested_delegation(self):
        bridge = self.held_io_parts()['open_selected'][2]
        pair = self.selected_schema_bindings()
        replacements = [
            bridge.replace('path,','other_path,',1),
            bridge.replace('state_backend,','state_backend: StateBackend::AuthenticatedV1,',1),
            bridge.replace('growth_observation_only,','growth_observation_only: true,',1),
            bridge.replace('native_io: None,','native_io: Some(io),',1),
            bridge.replace('Self::open_selected_with_io','Other::open_selected_with_io',1),
            'if true { '+bridge+' }',
            pair+'\n'+bridge,
            'let settings = other_settings;\n'+bridge,
        ]
        for replacement in replacements:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(
                    ValueError,'durable backend selector bridge'):
                self.extract(self.replace_once(self.current,bridge,replacement))

    def test_held_io_parameter_field_and_destructure_join_is_exact(self):
        parts = self.held_io_parts()
        opening,_,_ = parts['NativeStoreOpening']
        _,header,callee = parts['open_selected_with_io']
        unpack = callee[:callee.index('} = opening;')+len('} = opening;')]
        changes = [
            (parts['open_selected'][1],parts['open_selected'][1].replace(
                'state_backend: StateBackend','other_backend: StateBackend')),
            (header,header.replace('opening: NativeStoreOpening','other: NativeStoreOpening')),
            (opening,opening.replace('state_backend: StateBackend','state_backend: bool')),
            (opening,opening.replace('native_io: Option<NativeIoLease>','native_io: Option<OtherLease>')),
            (unpack,unpack.replace('state_backend,','state_backend: other_backend,',1)),
            (unpack,unpack.replace('= opening;','= other;',1)),
            (unpack,'if false { '+unpack+' }'),
            (unpack,unpack+'\n'+unpack),
        ]
        for before,after in changes:
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'durable (?:backend|PQ opening guard)'):
                self.extract(self.replace_once(self.current,before,after))

    def test_held_io_nested_decoy_duplicate_and_string_binding_are_refused(self):
        parts = self.held_io_parts()
        whole,header,_ = parts['open_selected_with_io']
        pair = self.selected_schema_bindings()
        for replacement in ['if false { '+pair+' }',
                            'let NOTE: &str = '+json.dumps(pair)+';',
                            'let NOTE: &str = r###"'+pair+'"###;',
                            '/* '+pair+' */',
                            pair.replace('selected_schema_id(&settings)','schema_id()')]:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(
                    ValueError,'durable backend selected schema'):
                self.extract(self.replace_once(self.current,pair,replacement))
        invalid = [
            self.replace_once(self.current,whole,whole+'\n'+whole),
            self.replace_once(self.current,whole,'mod hidden { '+whole+' }'),
            self.replace_once(self.current,whole,header+'{ }\n/* '+whole+' */'),
            self.replace_once(self.current,whole,header+'{ }\nignored!('+whole+');'),
        ]
        for source in invalid:
            with self.subTest(source=source[-80:]),self.assertRaisesRegex(ValueError,'durable'):
                self.extract(source)

    def test_pre_layout_backend_binding_remains_a_separate_supported_contract(self):
        # This is a historical source-parser fixture, not a native build. The
        # active current wrapper must never use this branch as a fallback.
        direct = 'let ddl = state_backend.ddl();\n        let schema_id = state_backend.selected_schema_id(&settings);'
        historical = self.historical_backend_source()
        ddl,domain = self.extract(historical)
        self.assertEqual(len(ddl.encode()),4775)
        self.assertEqual(domain,'native-branch-schema-v2')
        self.assertEqual(self.H_legacy_schema(ddl,domain),
                         '8c2627fa0b06e51742e7e6d40662c61d4b4727e810abc02b24634a8a817dc0e0')
        for replacement in (direct,direct+'\n/* '+self.selected_schema_bindings()+' */',
                            direct+'\nif false { '+self.selected_schema_bindings()+' }'):
            with self.subTest(replacement=replacement),self.assertRaisesRegex(
                    ValueError,'durable backend selected schema'):
                self.extract(self.replace_once(self.current,self.selected_schema_bindings(),replacement))

    def test_shared_layout_mapping_condition_identity_and_namespace_are_exact(self):
        ddl_identity = 'Self::CanonicalJson => base,\n            Self::SharedAccountsV1 => format!'
        hash_identity = 'Self::CanonicalJson => base,\n            Self::SharedAccountsV1 => hash('
        condition = 'backend == StateBackend::AuthenticatedV1 && io.is_some()'
        mutations = [
            ('legacy-backend',condition,condition.replace('AuthenticatedV1','Legacy')),
            ('or-instead-and',condition,condition.replace('&&','||')),
            ('none-instead-some',condition,condition.replace('is_some','is_none')),
            ('always-shared',condition,'true'),('always-canonical',condition,'false'),
            ('swapped-selection','Self::SharedAccountsV1\n        } else {\n            Self::CanonicalJson',
             'Self::CanonicalJson\n        } else {\n            Self::SharedAccountsV1'),
            ('nonidentity-ddl',ddl_identity,ddl_identity.replace('=> base,','=> format!("{base}{DDL}"),')),
            ('nonidentity-hash',hash_identity,hash_identity.replace('=> base,','=> hash(b"other", &[&base]),')),
            ('extra-variant','CanonicalJson,\n    SharedAccountsV1,','CanonicalJson,\n    SharedAccountsV1,\n    Other,'),
            ('wrong-ddl','CREATE TABLE native_io_shared_snapshots','CREATE TABLE other_shared_snapshots'),
            ('wrong-ddl-key','block BLOB PRIMARY KEY,data BLOB NOT NULL','block TEXT PRIMARY KEY,data BLOB NOT NULL'),
            ('wrong-record-schema','const SCHEMA: &str = "native-io-shared-authenticated-snapshot-v1";',
             'const SCHEMA: &str = "native-io-shared-authenticated-snapshot-v2";'),
            ('wrong-domain','b"native-io-shared-authenticated-branch-schema-v1"','b"native-branch-schema-v2"'),
            ('domain-whitespace','b"native-io-shared-authenticated-branch-schema-v1"',
             'b"native-io-shared-authenticated-branch- schema-v1"'),
            ('reverse-ddl','format!("{base}{DDL}")','format!("{DDL}{base}")'),
            ('omit-ddl','format!("{base}{DDL}")','format!("{base}")'),
            ('reverse-hash-inputs','&[&base, DDL.as_bytes(), SCHEMA.as_bytes()]',
             '&[&base, SCHEMA.as_bytes(), DDL.as_bytes()]'),
            ('omit-base-hash','&[&base, DDL.as_bytes(), SCHEMA.as_bytes()]','&[DDL.as_bytes(), SCHEMA.as_bytes()]'),
            ('wrong-io-type','io: Option<&NativeIoLease>','io: Option<&OtherLease>'),
            ('wrong-impl-owner','impl Layout {','impl Layout for Other {'),
            ('extra-mapping-method','impl Layout {','impl Layout { fn other(self) -> bool { true }'),
            ('changed-shared-test','self == Self::SharedAccountsV1','self != Self::SharedAccountsV1'),
        ]
        for label,before,after in mutations:
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,'durable shared layout'):
                self.extract(self.current,shared=self.replace_once(self.current_shared,before,after))

    def test_shared_layout_module_file_and_declaration_are_bound(self):
        declaration = 'mod shared_snapshot;'
        declarations = [
            '#[path = "other_snapshot.rs"]\n'+declaration,
            '#[cfg(test)]\n'+declaration,
            '#[cfg_attr(any(), path = "other_snapshot.rs")]\n'+declaration,
            'pub '+declaration,'mod shared_snapshot { }',
            'mod hidden { '+declaration+' }','ignored!('+declaration+');',
            '/* '+declaration+' */','const NOTE: &str = '+json.dumps(declaration)+';',
            'const NOTE: &str = r##"'+declaration+'"##;',
            'use other::shared_snapshot;',declaration+'\n'+declaration,
        ]
        for replacement in declarations:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'durable shared layout'):
                self.extract(self.replace_once(self.current,declaration,replacement))
        for before,after in [
            ('#[derive(Clone, Copy, Debug, PartialEq, Eq)]','#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n#[other]'),
            ('pub(super) enum Layout','pub enum Layout'),
            ('impl Layout {','#[cfg(test)]\nimpl Layout {'),
            ('impl Layout {','#[other]\nimpl Layout {'),
        ]:
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'durable shared layout declaration'):
                self.extract(self.current,shared=self.replace_once(self.current_shared,before,after))
        self.extract(self.current)
        self.shared.unlink()
        with self.assertRaisesRegex(ValueError,'missing artifact'):
            check.native_durable_schema(self.root)
        alternate = self.root/'alternate-snapshot.rs'
        alternate.write_text(self.current_shared)
        self.shared.symlink_to(alternate)
        with self.assertRaisesRegex(ValueError,'symlink artifact'):
            check.native_durable_schema(self.root)
        self.shared.unlink()
        self.extract(self.current)
        directory_module = self.shared.with_suffix('')/'mod.rs'
        directory_module.parent.mkdir()
        directory_module.write_text(self.current_shared)
        with self.assertRaisesRegex(ValueError,'ambiguous module path'):
            check.native_durable_schema(self.root)

    def test_shared_layout_comment_string_nested_and_duplicate_decoys_cannot_authorize_a_mapper(self):
        start = self.current_shared.index('impl Layout {')
        end = check.rust_group_end(check.rust_code(self.current_shared),self.current_shared.index('{',start))
        self.assertIsNotNone(end)
        implementation = self.current_shared[start:end]
        decoys = [
            '\n// '+implementation.replace('\n','\n// ')+'\n',
            '\n/* outer /* nested */ '+implementation+' */\n',
            '\nconst NOTE: &str = '+json.dumps(implementation)+';\n',
            '\nconst NOTE: &str = r###"'+implementation+'"###;\n',
            '\nmod historical { '+implementation+' }\n',
            '\nignored!('+implementation+');\n',
        ]
        expected = self.extract(self.current)
        broken = self.replace_once(self.current_shared,
                                   'backend == StateBackend::AuthenticatedV1 && io.is_some()','true')
        for decoy in decoys:
            with self.subTest(decoy=decoy):
                self.assertEqual(self.extract(self.current,shared=self.current_shared+decoy),expected)
                with self.assertRaisesRegex(ValueError,'durable shared layout mapping'):
                    self.extract(self.current,shared=broken+decoy)
        for replacement in [implementation+'\n'+implementation,
                            'mod historical { '+implementation+' }',
                            '/* '+implementation+' */',
                            'const NOTE: &str = '+json.dumps(implementation)+';']:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'durable shared layout declaration'):
                self.extract(self.current,shared=self.replace_once(self.current_shared,implementation,replacement))
        formatted = self.replace_once(self.current,self.selected_schema_bindings(),
                                      self.selected_schema_bindings().replace('shared_snapshot::Layout',
                                          'shared_snapshot /* exact owner */ :: Layout'))
        self.assertEqual(self.extract(formatted),expected)

    def test_shared_layout_and_native_io_bindings_cannot_be_rebound_or_bypassed(self):
        bindings = self.selected_schema_bindings()
        for statement in [
            'let storage_layout = shared_snapshot::Layout::SharedAccountsV1;',
            'let native_io = None;',
            'let (native_io, _) = (None, ());',
            'let (storage_layout, _) = (shared_snapshot::Layout::SharedAccountsV1, ());',
            'storage_layout = shared_snapshot::Layout::SharedAccountsV1;',
            'native_io = Some(io);',
            'let alias = &mut native_io;','let alias = &mut (storage_layout);',
        ]:
            for before in (False,True):
                replacement = statement+'\n'+bindings if before else bindings+'\n'+statement
                with self.subTest(statement=statement,before=before),self.assertRaisesRegex(
                        ValueError,'durable backend selected schema rebound'):
                    self.extract(self.replace_once(self.current,bindings,replacement))
        for replacement in [
            bindings.replace('state_backend, native_io.as_ref()','state_backend, None'),
            bindings.replace('state_backend, native_io.as_ref()','StateBackend::Legacy, native_io.as_ref()'),
            bindings.replace('state_backend, native_io.as_ref()','native_io.as_ref(), state_backend'),
            bindings.replace('native_io.as_ref()','native_io.clone().as_ref()'),
            bindings.replace('storage_layout.ddl(state_backend.selected_ddl(&settings))','state_backend.ddl()'),
            bindings.replace('storage_layout.schema_id(state_backend.selected_schema_id(&settings))',
                             'state_backend.selected_schema_id(&settings)'),
            bindings.replace('        let ddl','        effect();\n        let ddl'),
            bindings+'\n'+bindings,
        ]:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'durable backend selected schema'):
                self.extract(self.replace_once(self.current,bindings,replacement))

    def test_shared_snapshot_table_never_enters_the_legacy_evidence_namespace(self):
        for name in ('native_io_shared_snapshots','NaTiVe_Io_ShArEd_SnApShOtS'):
            extension = 'CREATE TABLE '+name+'(block BLOB PRIMARY KEY,data BLOB NOT NULL);'
            v1 = ('const DDL: &str = "'+extension+'";'
                  'fn open() { hash(b"native-branch-schema-v1", &[DDL.as_bytes()]); }')
            sources = [
                (v1,None),
                (self.replace_once(self.current,'CREATE TABLE metadata',extension+'CREATE TABLE metadata'),None),
                (self.current,self.replace_once(self.current_index,'CREATE TABLE ancestry_jump',extension+'CREATE TABLE ancestry_jump')),
            ]
            for source,index in sources:
                with self.subTest(name=name,index=index is not None),self.assertRaisesRegex(ValueError,'tables in legacy durable schema'):
                    self.extract(source,index)



    def test_shared_layout_mapping_cannot_relabel_or_append_to_legacy(self):
        mutations = [
            ('select-legacy', 'backend == StateBackend::AuthenticatedV1', 'backend == StateBackend::Legacy'),
            ('unheld-shared', 'io.is_some()', 'io.is_none()'),
            ('select-either', 'StateBackend::AuthenticatedV1 && io.is_some()',
             'StateBackend::AuthenticatedV1 || io.is_some()'),
            ('canonical-ddl', 'Self::CanonicalJson => base,\n            Self::SharedAccountsV1 => format!',
             'Self::CanonicalJson => format!("{base}{DDL}"),\n            Self::SharedAccountsV1 => format!'),
            ('canonical-schema', 'Self::CanonicalJson => base,\n            Self::SharedAccountsV1 => hash(',
             'Self::CanonicalJson => [0; 32],\n            Self::SharedAccountsV1 => hash('),
            ('shared-order', 'format!("{base}{DDL}")', 'format!("{DDL}{base}")'),
            ('shared-ddl', 'native_io_shared_snapshots(block BLOB PRIMARY KEY,data BLOB NOT NULL)',
             'snapshots(block BLOB PRIMARY KEY,data BLOB NOT NULL)'),
            ('shared-domain', 'b"native-io-shared-authenticated-branch-schema-v1"',
             'b"native-branch-schema-v2"'),
            ('shared-wire', 'const SCHEMA: &str = "native-io-shared-authenticated-snapshot-v1";',
             'const SCHEMA: &str = "native-io-shared-authenticated-snapshot-unknown";'),
            ('shared-variant', '    CanonicalJson,\n    SharedAccountsV1,',
             '    CanonicalJson,\n    SharedAccountsV1,\n    Other,'),
            ('extra-method', 'impl Layout {', 'impl Layout { fn other(self) -> Self { self }'),
            ('other-owner', 'impl Layout {', 'impl Layout for Other {'),
        ]
        for label,before,after in mutations:
            changed = self.replace_once(self.current_shared,before,after)
            reason = 'durable shared layout declaration Layout' if label == 'other-owner' else 'durable shared layout'
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,reason):
                self.extract(self.current,shared=changed)
        # This table is outside the legacy contract even if metadata is resealed.
        extension = 'CREATE TABLE native_io_shared_snapshots(block BLOB PRIMARY KEY,data BLOB NOT NULL);'
        for name in ['native_io_shared_snapshots','NaTiVe_Io_ShArEd_SnApShOtS']:
            changed = self.replace_once(self.current,'CREATE TABLE metadata',
                extension.replace('native_io_shared_snapshots',name)+'CREATE TABLE metadata')
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'tables in legacy durable schema'):
                self.extract(changed)

    def test_shared_layout_binding_has_no_old_pair_fallback_or_rebinding(self):
        pair = ('let ddl = storage_layout.ddl(state_backend.selected_ddl(&settings));\n        '
                'let schema_id = storage_layout.schema_id(state_backend.selected_schema_id(&settings));')
        selection = ('let storage_layout =\n            '
                     'shared_snapshot::Layout::for_opening(state_backend, native_io.as_ref());')
        triple = selection+'\n        '+pair
        old_pair = ('let ddl = state_backend.ddl();\n        '
                    'let schema_id = state_backend.selected_schema_id(&settings);')
        replacements = [
            old_pair,
            'if false { '+triple+' }',
            triple+'\n        '+triple,
            '/* '+triple+' */',
            'let NOTE: &str = '+json.dumps(triple)+';',
            triple.replace('for_opening(state_backend, native_io.as_ref())',
                           'for_opening(StateBackend::Legacy, native_io.as_ref())'),
            triple.replace('native_io.as_ref()', 'None'),
            triple.replace('storage_layout.ddl(state_backend.selected_ddl(&settings))', 'state_backend.ddl()'),
            triple.replace('storage_layout.schema_id(state_backend.selected_schema_id(&settings))',
                           'state_backend.selected_schema_id(&settings)'),
        ]
        for replacement in replacements:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(
                    ValueError,'durable backend selected schema'):
                self.extract(self.replace_once(self.current,triple,replacement))
        for statement in [
            'let storage_layout = shared_snapshot::Layout::SharedAccountsV1;',
            'storage_layout = shared_snapshot::Layout::SharedAccountsV1;',
            'let native_io = Some(other);',
            'native_io = None;',
            'let alias = &mut native_io;',
        ]:
            with self.subTest(statement=statement),self.assertRaisesRegex(
                    ValueError,'durable backend selected schema rebound'):
                self.extract(self.replace_once(self.current,triple,triple+'\n        '+statement))

    def test_shared_layout_module_and_exact_file_are_required(self):
        declaration = 'mod shared_snapshot;'
        for replacement in [
            '#[path = "other.rs"]\n'+declaration,
            '#[cfg(any())]\n'+declaration,
            'mod shared_snapshot {}',
            declaration+'\n'+declaration,
        ]:
            reason = ('durable shared layout module' if replacement == 'mod shared_snapshot {}'
                      else 'durable shared layout declaration shared_snapshot')
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,reason):
                self.extract(self.replace_once(self.current,declaration,replacement))
        self.extract(self.current)
        self.shared.unlink()
        with self.assertRaisesRegex(ValueError,'missing artifact'):
            check.native_durable_schema(self.root)
        self.shared.symlink_to(self.index)
        with self.assertRaisesRegex(ValueError,'symlink artifact'):
            check.native_durable_schema(self.root)

    def test_shared_layout_selection_composition_and_literal_domains_are_exact(self):
        selector = 'backend == StateBackend::AuthenticatedV1 && io.is_some()'
        mutations = [
            (selector,selector.replace('&&','||')),
            (selector,selector.replace('AuthenticatedV1','Legacy')),
            (selector,selector.replace('is_some','is_none')),
            (selector,'true'),
            ('} else {\n            Self::CanonicalJson','} else {\n            Self::SharedAccountsV1'),
            ('Self::CanonicalJson => base,\n            Self::SharedAccountsV1 => format!',
             'Self::CanonicalJson => format!("{base}{DDL}"),\n            Self::SharedAccountsV1 => format!'),
            ('"{base}{DDL}"','"{DDL}{base}"'),
            ('&[&base, DDL.as_bytes(), SCHEMA.as_bytes()]','&[DDL.as_bytes(), SCHEMA.as_bytes()]'),
            ('&[&base, DDL.as_bytes(), SCHEMA.as_bytes()]','&[&base, SCHEMA.as_bytes(), DDL.as_bytes()]'),
            ('b"native-io-shared-authenticated-branch-schema-v1"','b"native-branch-schema-v2"'),
            ('b"native-io-shared-authenticated-branch-schema-v1"','b"native-io-shared- authenticated-branch-schema-v1"'),
            ('const SCHEMA: &str = "native-io-shared-authenticated-snapshot-v1";',
             'const SCHEMA: &str = "native-branch-schema-v2";'),
            ('CREATE TABLE native_io_shared_snapshots','CREATE TABLE snapshots'),
            ('data BLOB NOT NULL);"','data BLOB NOT NULL); CREATE TABLE injected(x BLOB);"'),
            ('impl Layout {','impl Layout { fn unknown(self) -> Self { Self::CanonicalJson }'),
            ('#[derive(Clone, Copy, Debug, PartialEq, Eq)]','#[cfg(any())]\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]'),
            ('impl Layout {','#[cfg(any())]\nimpl Layout {'),
            ('const DDL: &str','#[cfg(any())]\nconst DDL: &str'),
            ('const SCHEMA: &str','#[cfg(any())]\nconst SCHEMA: &str'),
        ]
        for before,after in mutations:
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'durable shared layout'):
                self.extract(self.current,shared=self.replace_once(self.current_shared,before,after))

    def test_shared_layout_module_and_implementation_cannot_be_forged(self):
        declaration = 'mod shared_snapshot;'
        # These visibility + path/cfg and local-shadow counterexamples were
        # accepted by the initial uncommitted wrapper reader. Keep them explicit.
        for replacement in ('#[path = "other.rs"]\n'+declaration,
                            '#[path = "other.rs"]\npub '+declaration,
                            '#[path = "other.rs"]\npub(crate) '+declaration,
                            '#[cfg(any())]\npub '+declaration,
                            '#[cfg(any())]\npub(crate) '+declaration,
                            '#[cfg(any())]\n'+declaration,
                            'mod shared_snapshot {}',
                            'mod hidden { '+declaration+' }',
                            '/* '+declaration+' */',declaration+'\n'+declaration):
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'durable shared layout (?:declaration shared_snapshot|module path)'):
                self.extract(self.replace_once(self.current,declaration,replacement))
        code = check.rust_code(self.current_shared)
        start = code.index('impl Layout {')
        end = check.rust_group_end(code,code.index('{',start))
        implementation = self.current_shared[start:end]
        bad = self.replace_once(self.current_shared,'impl Layout {','impl Other {')
        for decoy in ('mod hidden { '+implementation+' }',
                      '/* '+implementation+' */',
                      'const NOTE: &str = '+json.dumps(implementation)+';',
                      'ignored!('+implementation+');'):
            with self.subTest(decoy=decoy),self.assertRaisesRegex(ValueError,'durable shared layout declaration Layout'):
                self.extract(self.current,shared=bad+'\n'+decoy)
        with self.assertRaisesRegex(ValueError,'durable shared layout declaration Layout'):
            self.extract(self.current,shared=self.current_shared+'\n'+implementation)

    def test_shared_layout_binding_cannot_be_bypassed_or_mixed(self):
        pair = self.selected_bindings
        changes = [
            ('shared_snapshot::Layout::for_opening','Other::for_opening'),
            ('for_opening(state_backend, native_io.as_ref())','for_opening(StateBackend::Legacy, native_io.as_ref())'),
            ('for_opening(state_backend, native_io.as_ref())','for_opening(state_backend, None)'),
            ('for_opening(state_backend, native_io.as_ref())','for_opening(state_backend, other_io.as_ref())'),
            ('storage_layout.ddl(state_backend.selected_ddl(&settings))','state_backend.ddl()'),
            ('storage_layout.schema_id(state_backend.selected_schema_id(&settings))','state_backend.selected_schema_id(&settings)'),
            ('storage_layout.schema_id(','other_layout.schema_id('),
            ('&settings','&settings.clone()'),
        ]
        invalid = [pair.replace(before,after,1) for before,after in changes]
        invalid += [pair+'\n'+pair,
                    'let ddl = state_backend.ddl();\n        let schema_id = state_backend.selected_schema_id(&settings);']
        for replacement in invalid:
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'durable backend selected schema'):
                self.extract(self.replace_once(self.current,pair,replacement))

    def test_shared_layout_and_io_cannot_be_rebound_or_mutably_aliased(self):
        pair = self.selected_bindings
        for local in ('use forged as shared_snapshot;', 'use forged::*;',
                      'mod shared_snapshot {}', 'type shared_snapshot = Other;',
                      'extern crate forged as shared_snapshot;'):
            with self.subTest(local=local),self.assertRaisesRegex(ValueError,'durable shared layout local scope'):
                self.extract(self.replace_once(self.current,pair,local+'\n'+pair))
        statements = [
            'let storage_layout = shared_snapshot::Layout::CanonicalJson;',
            'let (storage_layout, _) = (shared_snapshot::Layout::SharedAccountsV1, ());',
            'storage_layout = shared_snapshot::Layout::SharedAccountsV1;',
            'let native_io = None;',
            'native_io = Some(other_io);',
            'let alias = &mut native_io;',
            'let alias = &mut (storage_layout);',
        ]
        for statement in statements:
            for before in (True,False):
                replacement = statement+'\n'+pair if before else pair+'\n'+statement
                with self.subTest(statement=statement,before=before),self.assertRaisesRegex(
                        ValueError,'durable backend selected schema rebound'):
                    self.extract(self.replace_once(self.current,pair,replacement))

    def function_part(self, source, name):
        code = check.rust_code(source)
        matches = list(re.finditer(r'\bfn\s+'+name+r'\b',code))
        self.assertEqual(len(matches),1)
        start = code.index('{',matches[0].end())
        end = check.rust_group_end(code,start)
        self.assertIsNotNone(end)
        return source[matches[0].start():end]

    def test_pq_selected_ddl_and_domain_order_are_closed_contracts(self):
        ddl = self.function_part(self.current,'selected_ddl')
        schema = self.function_part(self.current,'selected_schema_id')
        changes = []
        for version,module,domain in ((1,'pq_native_v1','native-pq-transfer-branch-schema-v1'),
                                      (2,'pq_accounts_v2','native-pq-accounts-branch-schema-v2'),
                                      (3,'pq_quota_v3','native-pq-quota-branch-schema-v3'),
                                      (4,'pq_tasks_v4','native-pq-task-branch-schema-v4'),
                                      (5,'pq_tasks_v5','native-pq-task-branch-schema-v5')):
            selector = 'settings.is_native_pq_v'+str(version)+'()'
            for part in (ddl,schema):
                changes.append((part,self.replace_once(part,selector,'false')))
                changes.append((part,self.replace_once(part,selector,'!'+selector)))
            changes.append((ddl,self.replace_once(ddl,module+'::ddl(self.ddl())','self.ddl()')))
            changes.append((schema,self.replace_once(schema,domain,'native-branch-schema-v2')))
        changes.extend([
            (ddl,ddl.replace('is_native_pq_v3','is_native_pq_vTEMP').replace('is_native_pq_v2','is_native_pq_v3').replace('is_native_pq_vTEMP','is_native_pq_v2')),
            (schema,schema.replace('self.selected_ddl(settings).as_bytes()','self.ddl().as_bytes()',1)),
            (ddl,ddl.replace('self.ddl()\n        }','pq_quota_v3::ddl(self.ddl())\n        }',1)),
        ])
        for before,after in changes:
            self.assertNotEqual(before,after)
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'durable backend composition/domain'):
                self.extract(self.replace_once(self.current,before,after))
        self.assertEqual(self.extract(self.current)[1],'native-branch-schema-v2')

    def test_pq_settings_and_executor_selectors_cannot_change_the_legacy_branch(self):
        node = 'trillionnium/crates/trnm-pon-node/src/'
        executor = 'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/'
        changes = []
        for version,module in ((1,'pq_native_v1'),(2,'pq_accounts_v2'),(3,'pq_quota_v3'),(4,'pq_tasks_v4'),(5,'pq_tasks_v5')):
            path = node+module+'.rs'; source = self.auxiliary[path]
            method = self.function_part(source,'is_native_pq_v'+str(version))
            changed = method[:method.index('{')+1]+' false }'
            changes.append((path,self.replace_once(source,method,changed)))
            changes.append((path,self.replace_once(source,'impl Settings {','#[cfg(any())]\nimpl Settings {')))
            changes.append((path,self.replace_once(source,'use trnm_mvcc_fee::','use forged_mvcc::')))
        for module,method in (('pq_native_v1','enabled'),('pq_accounts_v2','enabled'),('pq_accounts_v2','quota_v3_enabled'),('pq_accounts_v2','tasks_v4_enabled'),('pq_accounts_v2','tasks_v5_enabled')):
            path = executor+module+'.rs'; source = self.auxiliary[path]
            part = self.function_part(source,method)
            changed = part[:part.index('{')+1]+' false }'
            changes.append((path,self.replace_once(source,part,changed)))
        path = executor+'pq_accounts_v2.rs'; source = self.auxiliary[path]
        changes.append((path,self.replace_once(source,'const SELECTOR: &str = "native_pq_accounts_profile";',
                                              'const SELECTOR: &str = "native_pq_profile";')))
        part = self.function_part(source,'tasks_v4_enabled')
        changes.append((path,self.replace_once(source,part,part.replace('AccountProfile::TasksV4','AccountProfile::QuotaV3'))))
        path = node+'pq_accounts_v2.rs'; source = self.auxiliary[path]
        part = self.function_part(source,'is_native_pq_v2')
        changes.append((path,self.replace_once(source,part,self.replace_once(part,'&& !pq::tasks_v4_enabled(&self.app)',''))))
        path = node+'pq_tasks_v4.rs'; source = self.auxiliary[path]
        part = self.function_part(source,'is_native_pq_v4')
        changes.append((path,self.replace_once(source,part,part.replace('pq::tasks_v4_enabled','pq::quota_v3_enabled'))))
        for path,changed in changes:
            with self.subTest(path=path,tail=changed[-40:]),self.assertRaisesRegex(ValueError,'durable (?:PQ (?:settings selector|selector provider owner|executor selector)|source item trnm_mvcc_fee)'):
                self.extract(self.current,auxiliary={path:changed})

    def test_pq5_selector_exclusion_and_separate_profile_never_borrow_legacy_qualification(self):
        node='trillionnium/crates/trnm-pon-node/src/'
        executor='trillionnium/crates/trnm-mvcc-fee/src/pon_executor/'
        changes=[]
        path=node+'pq_accounts_v2.rs'; source=self.auxiliary[path]
        changes.append((path,self.replace_once(source,'&& !pq::tasks_v5_enabled(&self.app)','')))
        path=node+'pq_tasks_v5.rs'; source=self.auxiliary[path]
        changes.append((path,self.replace_once(source,'pq::tasks_v5_enabled(&self.app)','pq::tasks_v4_enabled(&self.app)')))
        path=executor+'pq_accounts_v2.rs'; source=self.auxiliary[path]
        part=self.function_part(source,'tasks_v5_enabled')
        changes.append((path,self.replace_once(source,part,self.replace_once(part,'AccountProfile::TasksV5','AccountProfile::TasksV4'))))
        for path,changed in changes:
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'durable PQ (?:settings selector|executor selector)'):
                self.extract(self.current,auxiliary={path:changed})
        self.assertEqual(self.extract(self.current)[1],'native-branch-schema-v2')

    def test_pq_explicit_constructor_guards_cannot_be_weakened_or_moved(self):
        prefix = check.pq_contract.OPENING_PREFIX
        mutations = [
            ('settings.packet_profile()','crate::native_packet::Profile::Legacy'),
            ('== pq_explicit','!= pq_explicit'),
            ('Profile::Legacy','Profile::Pq3'),
            ('pq_explicit.is_none()','true'),
            ('|| (','&& ('),
            ('state_backend == StateBackend::AuthenticatedV1','state_backend == StateBackend::Legacy'),
            ('native_io.is_none()','true'),
            ('!growth_observation_only','true'),
            ('owners.policy.is_none()','true'),
            ('owners.mining.is_none()','true'),
            ('owners.continuous.is_none()','true'),
            ('"PQ_EXPLICIT_CONSTRUCTOR_REQUIRED"','"IGNORED"'),
        ]
        for before,after in mutations:
            with self.subTest(before=before),self.assertRaisesRegex(ValueError,'durable PQ opening guard'):
                self.extract(self.replace_once(self.current,prefix,self.replace_once(prefix,before,after)))
        for replacement in (prefix.replace(')?;',');',1),
                            prefix[:prefix.index('        ensure(')],
                            'if false {'+prefix+'}',
                            prefix+'\nlet pq_explicit = Some(crate::native_packet::Profile::Pq3);'):
            with self.subTest(replacement=replacement),self.assertRaisesRegex(ValueError,'durable (?:PQ opening guard|backend opening bindings|backend selected schema rebound)'):
                self.extract(self.replace_once(self.current,prefix,replacement))
        bridge = self.held_io_parts()['open_selected'][2]
        for replacement in ('Some(crate::native_packet::Profile::Pq1)',
                            'Some(crate::native_packet::Profile::Pq2)',
                            'Some(crate::native_packet::Profile::Pq3)',
                            'Some(crate::native_packet::Profile::Pq4)',
                            'Some(crate::native_packet::Profile::Pq5)'):
            changed = self.replace_once(bridge,'pq_explicit: None,','pq_explicit: '+replacement+',')
            with self.subTest(profile=replacement),self.assertRaisesRegex(ValueError,'durable backend selector bridge'):
                self.extract(self.replace_once(self.current,bridge,changed))

    def test_pq_opening_owner_attributes_and_nested_decoys_do_not_authorize(self):
        for name in ('open_selected','open_selected_with_io'):
            part = self.function_part(self.current,name)
            for replacement in ('#[cfg(any())]\n'+part,'mod hidden { '+part+' }',part+'\n'+part):
                with self.subTest(name=name,replacement=replacement[:60]),self.assertRaisesRegex(ValueError,'durable'):
                    self.extract(self.replace_once(self.current,part,replacement))
        for before in ('impl Node {','impl StateBackend {','struct NativeStoreOpening {'):
            with self.subTest(before=before),self.assertRaisesRegex(ValueError,'durable backend'):
                self.extract(self.replace_once(self.current,before,'#[cfg(any())]\n'+before))

    def test_packet_profile_dispatch_and_legacy_header_are_not_negotiated(self):
        path = 'trillionnium/crates/trnm-pon-node/src/native_packet.rs'
        source = self.auxiliary[path]
        mutations = [
            ('Profile::Legacy => crate::pq_native_v1::header_prefix_bytes(false)',
             'Profile::Legacy => crate::pq_native_v1::header_prefix_bytes(true)'),
            ('Profile::Legacy => crate::pq_native_v1::decode_header_projection(bytes, false)',
             'Profile::Legacy => crate::pq_native_v1::decode_header_projection(bytes, true)'),
            ('Profile::Legacy => Packet::decode(raw)','Profile::Legacy => Ok(crate::pq_quota_v3::PqPacketV3::decode(raw)?.inner)'),
            ('Profile::Legacy => packet.encode_for_native_profile(false)',
             'Profile::Legacy => packet.encode_for_native_profile(true)'),
            ('if self.is_native_pq_v3()','if false'),
            ('if self.is_native_pq_v4()','if false'),
            ('if self.is_native_pq_v5()','if false'),
            ('Profile::Pq5 => Ok(crate::pq_tasks_v5::PqPacketV5::decode(raw)?.inner)',
             'Profile::Pq5 => Ok(crate::pq_tasks_v4::PqPacketV4::decode(raw)?.inner)'),
            ('Profile::Pq4 => Ok(crate::pq_tasks_v4::PqPacketV4::decode(raw)?.inner)',
             'Profile::Pq4 => Ok(crate::pq_quota_v3::PqPacketV3::decode(raw)?.inner)'),
            ('} else {\n            Profile::Legacy','} else {\n            Profile::Pq1'),
            ('Profile::Pq2 | Profile::Pq3 | Profile::Pq4 | Profile::Pq5 => HEADER_BYTES + 8','Profile::Pq2 | Profile::Pq3 | Profile::Pq4 | Profile::Pq5 => HEADER_BYTES'),
        ]
        for before,after in mutations:
            changed = self.replace_once(source,before,after)
            with self.subTest(before=before),self.assertRaisesRegex(ValueError,'durable PQ packet selection/legacy header contract'):
                self.extract(self.current,auxiliary={path:changed})

    def test_pq_packet_module_owner_cannot_be_cfg_path_or_alias_substituted(self):
        path = 'trillionnium/crates/trnm-pon-node/src/lib.rs'; source = self.auxiliary[path]
        for declaration in ('mod native_packet;','pub mod pq_native_v1;','pub mod pq_accounts_v2;','pub mod pq_quota_v3;','pub mod pq_tasks_v4;','pub mod pq_tasks_v5;'):
            for replacement in ('#[cfg(any())]\n'+declaration,'#[path="other.rs"]\n'+declaration,
                                'mod hidden { '+declaration+' }',declaration+'\n'+declaration):
                with self.subTest(declaration=declaration,replacement=replacement),self.assertRaisesRegex(ValueError,'durable (?:PQ packet module owner|source item)'):
                    self.extract(self.current,auxiliary={path:self.replace_once(source,declaration,replacement)})

    def test_original_legacy_header_projection_cannot_be_replaced(self):
        path = 'trillionnium/crates/trnm-pon-node/src/pq_native_v1.rs'; source = self.auxiliary[path]
        for method,token,replacement in (
                ('header_prefix_bytes','HEADER_BYTES + if pq { 8 } else { 0 }','HEADER_BYTES + 8'),
                ('decode_header_projection','if pq {','if true {'),
                ('decode_header_projection','Header::decode(bytes)','Header::decode(&bytes[8..])')):
            part = self.function_part(source,method)
            changed = self.replace_once(source,part,self.replace_once(part,token,replacement))
            with self.subTest(method=method,token=token),self.assertRaisesRegex(ValueError,'durable PQ original legacy header'):
                self.extract(self.current,auxiliary={path:changed})
        for method in ('header_prefix_bytes','decode_header_projection'):
            declaration = 'pub(crate) fn '+method
            changed = self.replace_once(source,declaration,'#[cfg(any())]\n'+declaration)
            with self.subTest(method=method),self.assertRaisesRegex(ValueError,'durable PQ legacy header owner'):
                self.extract(self.current,auxiliary={path:changed})

    def test_ancestry_context_and_projected_header_share_the_selected_profile(self):
        for selected in ('crate::native_packet::Profile::Legacy','crate::native_packet::Profile::Pq3','crate::native_packet::Profile::Pq4','crate::native_packet::Profile::Pq5'):
            changed = self.replace_once(self.current,'pq_packet: self.settings.packet_profile(),','pq_packet: '+selected+',')
            with self.subTest(selected=selected),self.assertRaisesRegex(ValueError,'durable PQ ancestry context selection'):
                self.extract(changed)
        mutations = [
            ('crate::native_packet::header_prefix_bytes(pq)','318'),
            ('crate::native_packet::header_prefix_bytes(ctx.pq_packet)','318'),
            ('read_header(db, id, ctx.pq_packet)','read_header(db, id, crate::native_packet::Profile::Legacy)'),
            ('crate::native_packet::decode_header_projection(&prefix, ctx.pq_packet)',
             'crate::native_packet::decode_header_projection(&prefix, crate::native_packet::Profile::Pq3)'),
            ('SELECT parent,state_root,substr(packet,1,?),substr(packet,-32)',
             'SELECT parent,state_root,substr(packet,9,?),substr(packet,-32)'),
        ]
        for before,after in mutations:
            with self.subTest(before=before),self.assertRaisesRegex(ValueError,'durable PQ ancestry header selection'):
                self.extract(self.current,index=self.replace_once(self.current_index,before,after))
        for method in ('read_header','metadata'):
            changed = self.replace_once(self.current_index,'fn '+method+'(','#[cfg(any())]\nfn '+method+'(')
            with self.subTest(method=method),self.assertRaisesRegex(ValueError,'durable PQ ancestry header owner'):
                self.extract(self.current,index=changed)

    def test_pq_namespace_cannot_enter_historical_or_current_legacy_ddl(self):
        for name in ('local_pq_statements_v1','local_pq_removed_statements_v2',
                     'local_pq_statements_v3','local_pq_statements_v4',
                     'local_pq_task_revocations_v4','LoCaL_Pq_Unknown'):
            extension = 'CREATE TABLE '+name+'(statement BLOB PRIMARY KEY);'
            v1 = ('const DDL: &str = "'+extension+'";'
                  'fn open(){hash(b"native-branch-schema-v1",&[DDL.as_bytes()]);}')
            changes = ((v1,None),
                (self.replace_once(self.current,'CREATE TABLE metadata',extension+'CREATE TABLE metadata'),None),
                (self.current,self.replace_once(self.current_index,'CREATE TABLE ancestry_jump',extension+'CREATE TABLE ancestry_jump')))
            for source,index in changes:
                with self.subTest(name=name,index=index is not None),self.assertRaisesRegex(ValueError,'tables in legacy durable schema'):
                    self.extract(source,index)

    def test_pq_token_contract_allows_comments_but_not_literal_or_current_file_changes(self):
        path = 'trillionnium/crates/trnm-pon-node/src/native_packet.rs'; source = self.auxiliary[path]
        expected = self.extract(self.current)
        comments = source.replace('Profile::Legacy => Packet::decode(raw)',
                                  'Profile /* nested /* inner */ comment */ :: Legacy => Packet::decode(raw)')
        self.assertEqual(self.extract(self.current,auxiliary={path:comments}),expected)
        # Same path, same byte length, new input: a previous successful parse
        # must never cache its verdict or its source bytes across invocations.
        changed = self.replace_once(source,'"PQ2_HEADER_PROFILE"','"PQ3_HEADER_PROFILE"')
        self.assertEqual(len(source),len(changed))
        with self.assertRaisesRegex(ValueError,'durable PQ packet selection/legacy header contract'):
            self.extract(self.current,auxiliary={path:changed})
        self.assertEqual(self.extract(self.current),expected)

    def test_shared_layout_refuses_split_joint_operator_and_byte_literal(self):
        # Both real source mutations were ACCEPTed by the original 53-method
        # reader. Keep them distinct from the direct tokenizer tests.
        mutations = [
            ('backend == StateBackend::AuthenticatedV1 && io.is_some()',
             'backend == StateBackend::AuthenticatedV1 & & io.is_some()'),
            ('b"native-io-shared-authenticated-branch-schema-v1"',
             'b "native-io-shared-authenticated-branch-schema-v1"'),
        ]
        for before,after in mutations:
            with self.subTest(after=after),self.assertRaisesRegex(ValueError,'durable shared layout mapping'):
                self.extract(self.current,shared=self.replace_once(self.current_shared,before,after))
        self.assertEqual(self.extract(self.current)[1],'native-branch-schema-v2')

    def test_pq_exact_contract_refuses_split_joint_operator_and_byte_literal(self):
        prefix = check.pq_contract.OPENING_PREFIX
        changed = self.replace_once(prefix,'&& native_io.is_none()','& & native_io.is_none()')
        with self.assertRaisesRegex(ValueError,'durable PQ opening guard'):
            self.extract(self.replace_once(self.current,prefix,changed))
        changed = self.replace_once(self.current,'b"native-pq-quota-branch-schema-v3"',
                                    'b "native-pq-quota-branch-schema-v3"')
        with self.assertRaisesRegex(ValueError,'durable backend composition/domain'):
            self.extract(changed)


if __name__ == '__main__': unittest.main(verbosity=2)
