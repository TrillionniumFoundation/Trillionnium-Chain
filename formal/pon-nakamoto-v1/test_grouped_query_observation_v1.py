"""First-hand native observer controls, using the actual bound owner binary.

All keys, tasks, clocks and customers are the repository's CONTROLLED fixtures.
Passing this class proves neither independent control nor public completeness.
The full native captures and interrupted prefixes are printed into the retained
unittest command log before temporary test directories disappear. Independent
Python hash checks are inspection replays, not original native query events.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from contract_wire import ROOT, canonical, unique
import grouped_fresh_admission_wire_v0 as admission
import grouped_fresh_work_v0 as seal
import grouped_work_profile_v1 as profile
from test_grouped_fresh_admission_wire_v0 import fixture


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


@unittest.skipUnless(os.environ.get('TRNM_GROUPED_AUTHORITY_NATIVE'),
                     'TRNM_GROUPED_AUTHORITY_NATIVE is unset: actual native observation not executed')
class NativeQueryObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = Path(os.environ['TRNM_GROUPED_AUTHORITY_NATIVE']).resolve()
        if not cls.runner.is_file():
            raise AssertionError('configured original native authority runner is missing')
        cls.runner_sha = digest(cls.runner.read_bytes())
        cls.source = subprocess.check_output(
            ['git', '--no-replace-objects', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()

    def retain_original_artifacts(self, reason):
        """Copy failed-invocation bytes BEFORE reopen can reconcile STARTED.

        These bounded controlled-fixture directories stay outside the source
        checkout. The retained path/hash inventory is printed for collection by
        the enclosing exact-source validation campaign. Failure is never PASS.
        """
        self.preserve_directory = True
        self.snapshot_number += 1
        destination = self.directory.with_name(self.directory.name + '-retained-' + str(self.snapshot_number))
        destination.mkdir(exist_ok=False)
        rows, captures = [], []
        for source in sorted(self.directory.rglob('*')):
            if not source.is_file():
                continue
            self.assertFalse(source.is_symlink(), 'controlled native artifact became a symlink')
            relative = source.relative_to(self.directory)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = source.read_bytes()
            with target.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            self.assertEqual(target.read_bytes(), raw)
            rows.append(dict(path=str(relative), bytes=len(raw), sha256=digest(raw)))
            if source.name.endswith(('.queries.ndjson', '.response.json')):
                captures.append(dict(path=str(relative), bytes=len(raw), sha256=digest(raw), raw_hex=raw.hex()))
        manifest = dict(schema='pon-grouped-query-retained-native-failure-v1',
            case=self.id(), reason=reason, original_directory=str(self.directory),
            retained_directory=str(destination), files=rows,
            captured_before_next_owner_open=True, source_commit=self.source,
            runner_sha256=self.runner_sha,
            controller_snapshot_work_is_not_in_native_replay_cost=True)
        with (destination / 'RETENTION_MANIFEST.json').open('xb') as stream:
            stream.write(canonical(manifest))
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps(dict(manifest=manifest, raw_query_and_response_captures=captures),
                         sort_keys=True), flush=True)

    def cleanup_fixture(self):
        result = getattr(getattr(self, '_outcome', None), 'result', None)
        failed = result is None or any(test is self or getattr(test, 'test_case', None) is self for test, _ in
            list(getattr(result, 'errors', ())) + list(getattr(result, 'failures', ())))
        if failed and not self.preserve_directory:
            self.retain_original_artifacts('unittest_failure')
        if self.preserve_directory:
            print(json.dumps(dict(schema='pon-grouped-query-retained-directory-v1',
                case=self.id(), directory=str(self.directory), reason='failure_or_interruption_evidence'),
                sort_keys=True), flush=True)
        else:
            shutil.rmtree(self.directory)

    def native(self, args):
        try:
            result = subprocess.run([str(self.runner), *map(str, args)], cwd=ROOT,
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as failure:
            print(json.dumps(dict(schema='pon-grouped-query-native-timeout-test-v1',
                case=self.id(), arguments=list(map(str, args)), timeout_seconds=30,
                stdout=(failure.stdout or b'').decode(errors='replace'),
                stderr=(failure.stderr or b'').decode(errors='replace'),
                source_commit=self.source, runner_sha256=self.runner_sha), sort_keys=True), flush=True)
            self.retain_original_artifacts('native_timeout')
            raise
        # Process exits and diagnostics are evidence even for negative controls.
        print(json.dumps(dict(schema='pon-grouped-query-native-process-test-v1',
            case=self.id(), arguments=list(map(str, args)), returncode=result.returncode,
            stdout_sha256=digest(result.stdout), stdout=result.stdout.decode(errors='replace'),
            stderr=result.stderr.decode(errors='replace'),
            source_commit=self.source, runner_sha256=self.runner_sha), sort_keys=True), flush=True)
        if result.returncode != 0:
            self.retain_original_artifacts('native_exit_' + str(result.returncode))
        return result

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='pon-query-observer-v1-')).resolve()
        self.preserve_directory = False
        self.snapshot_number = 0
        self.addCleanup(self.cleanup_fixture)
        self.owner = self.directory / 'owner'
        _, frozen, model, requests, *_ = fixture()
        limit = 3_600_000_000_000
        for row in requests:
            row['deadline_ns'] = limit
        frozen.update(admission.material_commitments(model, requests, now_ns=1))
        frozen.update(not_before_ns=1, now_ns=1, expires_ns=limit,
                      available_until_ns=limit, nonce_first=1, nonce_count=4)
        self.config = dict(schema='pon-grouped-owner-fixture-config-v0',
            source_commit=self.source, clock_anchor_unix_ns=time.time_ns(),
            init=model, requests=requests, freeze=frozen,
            epoch=digest(('controlled-observer-' + self.id()).encode()), generation=1,
            aggregate_limit=4, per_candidate_limit=4)
        path = self.directory / 'config.json'
        path.write_bytes(canonical(self.config))
        print(json.dumps(dict(schema='pon-grouped-query-native-preparation-request-test-v1',
            case=self.id(), config=self.config, source_commit=self.source,
            runner_sha256=self.runner_sha), sort_keys=True), flush=True)
        preparation = self.native(['prepare', self.owner, path])
        self.assertEqual(preparation.returncode, 0, preparation.stderr.decode(errors='replace'))
        self.prepared = read_json(self.owner / 'preparation.json')
        self.assertEqual(self.prepared['source_commit'], self.source)
        self.assertEqual(self.prepared['runner_sha256'], self.runner_sha)
        self.assertEqual(self.prepared['config_sha256'], digest(canonical(self.config)))
        self.candidate = self.prepared['candidates'][0]
        self.producer_trace = []
        self.proof = seal.prove(self.candidate['challenge'], self.candidate['statement'],
                               on_step=self.producer_trace.append)
        self.assertEqual(len(self.producer_trace), 64)
        print(json.dumps(dict(schema='pon-grouped-query-native-fixture-test-v1',
            case=self.id(), config=self.config, native_preparation=self.prepared,
            python_producer_trace=self.producer_trace,
            python_producer_seed_queries=1, python_producer_step_queries=64,
            keys_and_demand_are_controlled_fixtures=True,
            source_commit=self.source, runner_sha256=self.runner_sha), sort_keys=True), flush=True)

    def command(self, label='operation', *, proof=None):
        return dict(action='execute', request_id=digest(label.encode()),
            candidate=self.candidate['candidate'], claim=copy.deepcopy(self.candidate['claim']),
            proof_hex=(self.proof if proof is None else proof).hex())

    def execute(self, label, command, *, cancel=None, abort=None, expected_exit=0):
        request = dict(schema='pon-grouped-owner-observed-command-v1', command=command,
                       cancel_after_query=cancel, abort_after_query=abort)
        request_path = self.directory / (label + '.request.json')
        output_path = self.directory / (label + '.response.json')
        request_path.write_bytes(canonical(request))
        print(json.dumps(dict(schema='pon-grouped-query-native-request-test-v1',
            case=self.id(), label=label, request=request,
            source_commit=self.source, runner_sha256=self.runner_sha), sort_keys=True), flush=True)
        result = self.native(['execute_observed_v1', self.owner, request_path, output_path, 73])
        trace_path = output_path.with_name(output_path.name + '.queries.ndjson')
        prefix_raw = trace_path.read_bytes() if trace_path.is_file() else b''
        output_raw = output_path.read_bytes() if output_path.is_file() else b''
        try:
            prefix = [json.loads(line, object_pairs_hook=unique) for line in prefix_raw.splitlines()]
            report = json.loads(output_raw, object_pairs_hook=unique) if output_raw else None
        except (ValueError, UnicodeError):
            print(json.dumps(dict(schema='pon-grouped-query-native-malformed-capture-test-v1',
                case=self.id(), label=label, durable_prefix_hex=prefix_raw.hex(),
                output_hex=output_raw.hex(), process_returncode=result.returncode), sort_keys=True), flush=True)
            self.retain_original_artifacts('malformed_native_capture')
            raise
        print(json.dumps(dict(schema='pon-grouped-query-native-capture-test-v1',
            case=self.id(), label=label, request=request, native_response=report,
            durable_prefix=prefix, durable_prefix_sha256=digest(prefix_raw),
            process_returncode=result.returncode,
            interruption_stdout=result.stdout.decode(errors='replace') if abort is not None else None,
            native_response_sha256=digest(output_path.read_bytes()) if output_path.is_file() else None,
            source_commit=self.source, runner_sha256=self.runner_sha,
            independent_customers_or_public_coverage_established=False), sort_keys=True), flush=True)
        self.assertEqual(result.returncode, expected_exit, result.stderr.decode(errors='replace'))
        if expected_exit == 0:
            self.assertIsNotNone(report)
            self.assertEqual(report, json.loads(result.stdout, object_pairs_hook=unique))
            self.assertEqual(report['schema'], 'pon-grouped-owner-execution-observation-v1')
            self.assertEqual(report['query_observations'], prefix)
            self.assertEqual(report['source_commit'], self.source)
            self.assertEqual(report['runner_sha256'], self.runner_sha)
            self.assertEqual(report['request_sha256'], digest(canonical(request)))
            self.assertEqual(report['policy']['policy'], self.prepared['policy']['policy'])
            self.assertEqual(report['policy']['epoch'], self.config['epoch'])
            self.assertEqual(report['chainwork_awarded'], 0)
            self.assertFalse(report['production_activation'])
            self.assertFalse(report['historical_trace_reconstructed'])
            self.assertFalse(report['public_query_coverage_complete'])
            self.assertFalse(report['physical_resource_lower_bound_proved'])
        return report, prefix, output_path, request_path

    def inspect_observations(self, observations, *, receipt=None):
        self.assertLessEqual(len(observations), 65)
        previous = None
        ids = set()
        for ordinal, row in enumerate(observations):
            self.assertEqual(row['schema'], 'pon-grouped-owner-query-observation-v1')
            self.assertEqual(row['ordinal'], ordinal)
            self.assertEqual(row['profile_hash'], seal.profile_hash().hex())
            self.assertEqual(row['candidate'], self.candidate['candidate'])
            self.assertEqual(row['challenge'], self.candidate['challenge'])
            self.assertEqual(row['statement'], self.candidate['statement'])
            self.assertEqual(row['policy'], self.prepared['policy']['policy'])
            self.assertEqual(row['authority'], self.prepared['policy']['authority'])
            self.assertEqual(row['epoch'], self.config['epoch'])
            self.assertEqual(row['generation'], self.config['generation'])
            if receipt is not None:
                for field in ('policy', 'authority', 'epoch', 'generation', 'sequence',
                              'receiver', 'request_id', 'candidate', 'request_fingerprint'):
                    self.assertEqual(row[field], receipt[field], field)
            parts = [bytes.fromhex(row[field]) for field in ('policy', 'authority', 'epoch')]
            parts += [row[field].to_bytes(8, 'big') for field in ('generation', 'sequence')]
            parts += [bytes.fromhex(row[field]) for field in
                      ('receiver', 'request_id', 'candidate', 'request_fingerprint')]
            parts.append(ordinal.to_bytes(2, 'big'))
            self.assertEqual(row['event_id'], admission.pon_hash(
                b'pon-grouped-owner-query-event-v1', *parts).hex())
            self.assertNotIn(row['event_id'], ids)
            ids.add(row['event_id'])
            if ordinal == 0:
                self.assertEqual(row['kind'], 'seed')
                self.assertEqual(row['denomination'], 'seed_hash')
                self.assertIsNone(row['index'])
                self.assertIsNone(row['predecessor'])
                expected = seal.hash_preimage(b'seed', seal.profile_hash(),
                    bytes.fromhex(self.candidate['challenge']), bytes.fromhex(self.candidate['statement']))
                self.assertEqual(len(expected), 139)
            else:
                self.assertEqual(row['kind'], 'step')
                self.assertEqual(row['denomination'], 'classical-seal-step-oracle-query')
                self.assertEqual(row['index'], ordinal)
                self.assertEqual(row['predecessor'], previous)
                expected = seal.step_preimage(self.candidate['challenge'], ordinal, bytes.fromhex(previous))
                self.assertEqual(len(expected), 145)
            raw = bytes.fromhex(row['input_hex'])
            self.assertEqual(raw, expected)
            self.assertEqual(digest(raw), row['answer'])
            previous = row['answer']

    def profile_readback(self, report):
        """Native data, separately disclosed reader ordinals, no authentic clock."""
        state = report['native_result']['result']
        receipt = state['receipt']
        op = receipt['request_id']
        cid = receipt['candidate']
        candidate = self.candidate
        frozen = self.config['freeze']
        selected = dict(schema=profile.POLICY_SCHEMA,
            campaign=digest(('native-observation-inspection-' + self.id()).encode()),
            profile=profile.PROFILE, denomination=profile.DENOMINATION,
            actors=[dict(id=actor, control_group='one-controlled-fixture')
                    for actor in ('authority', 'requester', 'native-node')],
            candidates=[dict(id=cid, task=frozen['request_precommitment'],
                material=frozen['model_commitment'], challenge=candidate['challenge'],
                statement=candidate['statement'], target=candidate['target'],
                task_authority='requester', target_authority='native-node',
                authorized_at=1, expires_at=1000)], demands=[],
            operations=[dict(id=op, actor='authority', role='verifier', candidates=[cid],
                authorized_at=1, deadline=1000, required_costs=[
                    dict(stage='seal', unit='step_query'), dict(stage='seed', unit='seed_hash'),
                    dict(stage='owner_replay', unit='wall_ns')])])
        carrier = digest(canonical(report))
        observed = dict(schema=profile.EVIDENCE_SCHEMA, policy_sha256=profile.policy_digest(selected),
            queries=[dict(id=row['event_id'], operation=op, candidate=cid,
                at=row['ordinal'] + 2, index=row['index'], predecessor=row['predecessor'],
                answer=row['answer'], carrier_sha256=carrier)
                for row in report['query_observations'] if row['kind'] == 'step'],
            terminals=[dict(id=op, at=100,
                outcome={'verified_hit': 'completed', 'verified_miss': 'completed',
                         'cancelled': 'canceled', 'relation_rejected': 'rejected',
                         'context_rejected': 'rejected'}[receipt['outcome']],
                receipt_sha256=digest(canonical(receipt)), carrier_sha256=carrier)], uses=[], costs=[])
        for stage, unit, amount in (
                ('seal', 'step_query', receipt['cost']['step_queries']),
                ('seed', 'seed_hash', receipt['cost']['seed_queries']),
                ('owner_replay', 'wall_ns', receipt['cost']['wall_ns'])):
            observed['costs'].append(dict(id=digest((op + stage).encode()), operation=op,
                stage=stage, unit=unit, amount=amount, upper_bound=None,
                meter='authority', payer=None, beneficiary=None,
                receipt_sha256=digest(canonical(receipt)),
                coverage=[digest((op + ':' + unit).encode())], included_in=None,
                carrier_sha256=carrier))
        assessment = profile.assess(observed, expected_policy=selected,
                                    expected_policy_sha256=profile.policy_digest(selected))
        print(json.dumps(dict(schema='pon-grouped-query-native-reader-test-v1',
            case=self.id(), expected_policy=selected, observations=observed, assessment=assessment,
            ordering_scope='reader-assigned ordinals; not authenticated prequery wall-clock facts',
            preparation_and_transport_costs_excluded_from_this_callback_scope=True,
            observed_payer_and_beneficiary_not_established=True), sort_keys=True), flush=True)
        self.assertEqual(assessment['queries']['observed_execution_events'], receipt['cost']['step_queries'])
        self.assertEqual(assessment['qualification'], 'HOLD')
        self.assertEqual(assessment['actual_chainwork'], 0)
        self.assertFalse(assessment['consensus_weight_eligible'])
        return assessment

    def test_actual_native_full_trace_matches_raw_inputs_receipt_and_reader(self):
        report, prefix, _, _ = self.execute('complete', self.command())
        state = report['native_result']['result']
        self.assertFalse(state['cached'])
        self.assertIn(state['receipt']['outcome'], ('verified_hit', 'verified_miss'))
        self.assertEqual(len(prefix), 65)
        self.assertEqual(report['observed_seed_queries'], 1)
        self.assertEqual(report['observed_step_queries'], 64)
        self.assertTrue(report['this_invocation_trace_complete'])
        self.inspect_observations(prefix, receipt=state['receipt'])
        self.assertEqual(prefix[-1]['answer'], state['receipt']['endpoint'])
        assessment = self.profile_readback(report)
        self.assertEqual(assessment['queries']['distinct_native_inputs'], 64)
        self.assertEqual(len(assessment['queries']['complete_seal_traces']), 1)

    def test_observer_cancellation_charges_seed_and_including_final_completed_step(self):
        for stop in (0, 17, 64):
            with self.subTest(stop=stop):
                report, prefix, _, _ = self.execute('cancel-' + str(stop),
                    self.command('cancel-operation-' + str(stop)), cancel=stop)
                receipt = report['native_result']['result']['receipt']
                self.assertEqual(receipt['outcome'], 'cancelled')
                self.assertEqual(receipt['cost']['seed_queries'], 1)
                self.assertEqual(receipt['cost']['step_queries'], stop)
                self.assertEqual(len(prefix), stop + 1)
                self.assertFalse(receipt['first_record'])
                self.assertIsNone(receipt['endpoint'])
                self.assertTrue(report['this_invocation_trace_complete'])
                self.inspect_observations(prefix, receipt=receipt)
                self.profile_readback(report)

    def test_cached_result_after_reopen_emits_no_new_queries_or_refund(self):
        command = self.command()
        first, original, _, _ = self.execute('first', command)
        second, replay, _, _ = self.execute('cached', command)
        self.assertEqual(len(original), 65)
        self.assertEqual(replay, [])
        state = second['native_result']['result']
        self.assertTrue(state['cached'])
        self.assertEqual(state['receipt'], first['native_result']['result']['receipt'])
        self.assertEqual(state['new_step_queries'], 0)
        self.assertEqual(state['new_seed_queries'], 0)
        snapshot = second['snapshot']['result']
        self.assertEqual(snapshot['reserved'], 1)
        self.assertEqual(snapshot['step_queries_known'], 64)
        self.assertEqual(snapshot['step_queries_unknown_upper'], 0)

    def test_synced_partial_trace_survives_interruption_and_original_operation_is_unknown(self):
        command = self.command('interrupted-operation')
        absent, prefix, output, _ = self.execute('interrupted', command, abort=17, expected_exit=86)
        self.assertIsNone(absent)
        self.assertEqual(output.read_bytes(), b'')
        self.assertEqual(len(prefix), 18)
        self.inspect_observations(prefix)
        report, retry, _, _ = self.execute('reconciled', command)
        self.assertEqual(retry, [])
        state = report['native_result']['result']
        self.assertEqual(state['state'], 'unknown')
        self.assertFalse(state['retry_permitted'])
        self.assertFalse(state['refunded'])
        self.assertEqual(state['step_queries_unknown_upper'], 64)
        snapshot = report['snapshot']['result']
        self.assertEqual(snapshot['reserved'], 1)
        self.assertEqual(snapshot['step_queries_known'], 0)
        self.assertEqual(snapshot['step_queries_unknown_upper'], 64)
        self.assertEqual(snapshot['rows'][0]['fingerprint'], prefix[0]['request_fingerprint'])
        self.assertEqual(snapshot['rows'][0]['sequence'], prefix[0]['sequence'])
        self.assertEqual(snapshot['rows'][0]['state'], 'unknown')
        # The observed 17-step prefix is inside the 64-step UNKNOWN cap.
        # It is not an additional 17 charged on top of that upper bound.

    def test_forged_endpoint_still_exposes_only_the_actual_full_replay(self):
        forged = self.proof[:102] + bytes(32)
        self.assertNotEqual(forged, self.proof)
        report, prefix, _, _ = self.execute('forged', self.command(proof=forged))
        receipt = report['native_result']['result']['receipt']
        self.assertEqual(receipt['outcome'], 'relation_rejected')
        self.assertEqual(receipt['cost']['step_queries'], 64)
        self.assertEqual(len(prefix), 65)
        self.assertIsNone(receipt['endpoint'])
        self.inspect_observations(prefix, receipt=receipt)
        self.assertEqual(prefix[-1]['answer'], self.proof[102:].hex())

    def test_framing_rejection_emits_no_fabricated_query_rows(self):
        bad = bytes([self.proof[0] ^ 1]) + self.proof[1:]
        report, prefix, _, _ = self.execute('framing', self.command(proof=bad))
        receipt = report['native_result']['result']['receipt']
        self.assertEqual(prefix, [])
        self.assertEqual(receipt['outcome'], 'relation_rejected')
        self.assertEqual(receipt['cost']['full_cell_calls'], 0)
        self.assertEqual(receipt['cost']['seed_queries'], 0)
        self.assertEqual(receipt['cost']['step_queries'], 0)
        self.assertEqual(report['snapshot']['result']['reserved'], 1)

    def test_export_paths_are_create_only_before_a_new_attempt_can_start(self):
        command = self.command()
        _, _, output, request = self.execute('retained', command)
        trace = output.with_name(output.name + '.queries.ndjson')
        original = output.read_bytes(), trace.read_bytes()
        rejected = self.native(['execute_observed_v1', self.owner, request, output, 73])
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual((output.read_bytes(), trace.read_bytes()), original)
        report, empty, _, _ = self.execute('after-refused-overwrite', command)
        self.assertEqual(empty, [])
        self.assertEqual(report['snapshot']['result']['reserved'], 1)


if __name__ == '__main__':
    unittest.main()
