#!/usr/bin/env python3
"""Negative source, artifact, packet, observation and cost tests; no fabricated qualification."""
from __future__ import annotations
import copy
import hashlib
import json
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
        source = (check.ROOT/'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
        ddl = re.search(r'const DDL:&str="(.*?)";',source,re.S)[1]
        self.state = {'test:exact':1}; self.roots = [bytes([1])*32,bytes([2])*32]
        self.packets = [b'owned-test-packet']; self.cumulative = [0,2]
        self.summary = {'genesis':'3'*64,'parameters':'4'*64,'records':[{'block':'5'*64}],
                        'producer_final_state':{'tip':'5'*64}}
        for owner in ('producer','validator'):
            directory = self.folder/owner; directory.mkdir()
            with sqlite3.connect(directory/'native.sqlite') as database:
                database.executescript(ddl)
                database.executemany('INSERT INTO metadata VALUES(?,?)',[
                    ('schema',H('native-branch-schema-v1',ddl.encode())),
                    ('parameters',bytes.fromhex(self.summary['parameters'])),('genesis',bytes.fromhex(self.summary['genesis']))])
                database.execute('INSERT INTO active VALUES(1,?,1,0)',(bytes.fromhex('5'*64),))
                database.execute('INSERT INTO kv VALUES(0,?,?)',('test:exact',canonical(1)))
                database.execute('INSERT INTO blocks VALUES(?,NULL,0,?,NULL,?)',
                    (bytes.fromhex('3'*64),bytes(64),self.roots[0]))
                database.execute('INSERT INTO blocks VALUES(?,?,1,?,?,?)',
                    (bytes.fromhex('5'*64),bytes.fromhex('3'*64),(2).to_bytes(64,'big'),self.packets[0],self.roots[1]))
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


if __name__ == '__main__': unittest.main(verbosity=2)
