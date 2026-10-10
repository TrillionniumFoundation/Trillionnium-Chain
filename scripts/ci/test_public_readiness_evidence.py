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
        linked = self.root/'linked'; linked.symlink_to(folder,target_is_directory=True)
        with self.assertRaises(ValueError): check.safe(linked/'nested','artifact.json')
        with self.assertRaises(ValueError): check.scope_flags({'nested':[{'public_network_ready':True}]})
        with self.assertRaises(ValueError): check.scope_flags({'production_activation':0})
        check.scope_flags({'nested':[{'public_network_ready':False}]})


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
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = self.root/'trillionnium/crates/trnm-pon-node/src/store.rs'
        self.store.parent.mkdir(parents=True)
        self.index = self.store.with_name('ancestry_index.rs')
        self.current = (check.ROOT/'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
        self.current_index = (check.ROOT/'trillionnium/crates/trnm-pon-node/src/ancestry_index.rs').read_text()

    def tearDown(self): self.temporary.cleanup()

    def extract(self, source, index=None):
        self.store.write_text(source)
        self.index.write_text(self.current_index if index is None else index)
        return check.native_durable_schema(self.root)

    def replace_once(self, source, before, after):
        self.assertEqual(source.count(before),1,'source control must target exactly one occurrence: '+before)
        return source.replace(before,after,1)

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

    def test_actual_opener_and_selected_schema_bindings_cannot_be_replaced(self):
        pair = 'let ddl = state_backend.ddl();\n        let schema_id = state_backend.schema_id();'
        mutations = [
            ('default-open','Self::open_with_fault(path, settings, workers, None)',
             'Self::open_with_authenticated_state_and_fault(path, settings, workers, None)'),
            ('fault-open','Self::open_inner(path, settings, workers, hook, None, None, None)',
             'Self::open_with_authenticated_state_and_fault(path, settings, workers, hook)'),
            ('legacy-selected','StateBackend::Legacy,\n        )\n    }\n    fn open_selected',
             'StateBackend::AuthenticatedV1,\n        )\n    }\n    fn open_selected'),
            ('auth-selected','StateBackend::AuthenticatedV1,\n        )\n    }\n    /// Explicit local operator policy',
             'StateBackend::Legacy,\n        )\n    }\n    /// Explicit local operator policy'),
            ('ddl-unselected','let ddl = state_backend.ddl();','let ddl = ddl();'),
            ('schema-unselected','let schema_id = state_backend.schema_id();','let schema_id = StateBackend::Legacy.schema_id();'),
            ('nested-pair',pair,'if false { '+pair+' }'),
        ]
        for label,before,after in mutations:
            with self.subTest(label=label),self.assertRaisesRegex(ValueError,'durable backend (?:opener|selected schema)'):
                self.extract(self.replace_once(self.current,before,after))
        rebound = [
            'let state_backend = StateBackend::AuthenticatedV1;',
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
                with self.assertRaisesRegex(ValueError,'durable backend domain Legacy'): self.extract(bad+decoy)
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
        for name in ['archive_nodes','native_state_commitments','ArChIvE_NoDeS']:
            extension = 'CREATE TABLE '+name+'(id BLOB PRIMARY KEY,data BLOB NOT NULL);'
            sources = [
                (literal.replace('CREATE TABLE exact',extension+'CREATE TABLE exact')+opener,None),
                (self.replace_once(self.current,'CREATE TABLE metadata',extension+'CREATE TABLE metadata'),None),
                (self.current,self.replace_once(self.current_index,'CREATE TABLE ancestry_jump',extension+'CREATE TABLE ancestry_jump')),
            ]
            for source,index in sources:
                with self.subTest(name=name,index=index is not None),self.assertRaisesRegex(ValueError,'authenticated tables in legacy durable schema'):
                    self.extract(source,index)


if __name__ == '__main__': unittest.main(verbosity=2)
