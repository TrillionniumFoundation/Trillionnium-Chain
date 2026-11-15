"""Revision12 native/scalar parity; missing native example is a failure, not a skip."""
import json, os, subprocess, unittest
from pathlib import Path
from contract_wire import ROOT, state_root
import continuity_oracle as oracle

BINARY = Path(os.environ.get('TRNM_CONTINUITY_BINARY', str(ROOT/'trillionnium/target/debug/examples/continuity_vectors')))

class ContinuityTests(unittest.TestCase):
    def test_native_context_material_and_twenty_four_transitions_match_independent_oracle(self):
        if not BINARY.is_file():
            raise RuntimeError('Build native continuity_vectors; no skipped pass')
        result = subprocess.run([str(BINARY)],capture_output=True,check=True,timeout=60)
        self.assertLess(len(result.stdout),65536)
        native = json.loads(result.stdout)
        params,network,parameters = oracle.context()
        self.assertEqual(native['params'],params)
        self.assertEqual(native['network'],network.hex())
        self.assertEqual(native['parameters'],parameters.hex())
        state = native['initial']
        self.assertEqual(state[oracle.MAINTENANCE_KEY],oracle.maintenance_record())
        for step in native['steps']:
            state = oracle.empty(state,step['height'],step['miner'])
            self.assertEqual(state_root(state).hex(),step['root'])
            for key,value in oracle.capacity(state,step['height']).items():
                self.assertEqual(step[key],value)
        self.assertEqual(state,native['final'])

    def test_actual_cap_distinguishes_safe_queue_from_old_reward_recipient_trap(self):
        state = {oracle.MAINTENANCE_KEY:oracle.maintenance_record(), 'meta:issued':0,
                 'model:current':'00'*32, 'account:'+'01'*32:dict(balance=0,nonce=7)}
        for height in range(21,41):
            state['reward:'+str(height)] = dict(owner='01'*32,amount=0,maturity=height)
        for index in range(oracle.CAP-len(state)):
            state['account:'+f'{index+100:064x}'] = dict(balance=0,nonce=9)
        self.assertEqual(len(state),oracle.CAP)
        self.assertEqual(oracle.check(state,20)['required_keys'],oracle.CAP)
        state['reward:21']['owner'] = 'ff'*32
        with self.assertRaisesRegex(ValueError,'STATE_CAPACITY'):
            oracle.check(state,20)
        self.assertEqual(len(state),oracle.CAP)

if __name__ == '__main__': unittest.main()
