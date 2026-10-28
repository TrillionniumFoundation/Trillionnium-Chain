"""Independent native PQL3 byte/conservation oracle against exact upstream PQG1/PQS1/PQL2 grammar.

The fixtures are public deterministic bytes, NOT verified historical signatures or
source-chain authority. The verifier accepts caller-supplied pin files and never
imports a live account or issues a production permission.
"""
from __future__ import annotations
from dataclasses import replace
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

DIR = Path(__file__).resolve().parent
U64 = (1 << 64) - 1
SOURCE_DOMAIN = b'TRNM/PQ/GenesisSource/v1\x00'
STATE_DOMAIN = b'TRNM/PQ/GenesisState/v1\x00'
GENESIS_DOMAIN = b'TRNM/PQ/GenesisID/v1\x00'
PQL2_DOMAIN = b'TRNM/PQ/PQL2State/v1\x00'

def u64(x: int) -> bytes: return x.to_bytes(8, 'big')
def u16(x: int) -> bytes: return x.to_bytes(2, 'big')
def h(x: bytes) -> bytes: return hashlib.sha256(x).digest()
def commit(d: bytes, raw: bytes) -> bytes:
    return hashlib.sha384(d + u64(len(raw)) + raw).digest()

class Fixture:
    def __init__(self):
        self.old = tuple(sorted((h(b'real-old-public-fixture-A'), h(b'real-old-public-fixture-B'))))
        self.legacy_network = h(b'legacy-unique-network')
        self.new_network = h(b'pq-fresh-network')
        self.legacy_head = h(b'legacy-confirmed-but-UNAUTHENTICATED-in-test')
        self.withdrawal_head = h(b'out-of-band-withdrawal-head')
        self.protocol = h(b'pq-new-protocol')
        self.issued = 1800
        self.accounts = ((self.old[0], 200, 23, 11), (self.old[1], 500, 91, 30))
        self.liabilities = tuple(sorted((
            (h(b'task-liability'), self.old[0], 300, 112, 1),
            (h(b'reward-liability'), self.old[0], 200, 132, 2),
            (h(b'quota-liability'), self.old[1], 400, 140, 3),
            (h(b'escrow-liability'), self.old[1], 200, 202, 4),
        )))
        self.pqkey = h(b'genuine-MLDSA-SPKI-ID-fixture-not-a-signed-proof')
        self.source = b''
        self.state = b''
        self.projection = b''
        self.pin = b''
        self.make()

    def account_wire(self, a):
        return a[0] + u64(a[1]) + u64(a[2]) + u64(a[3])

    def liability_wire(self, l):
        return l[0] + l[1] + u64(l[2]) + u64(l[3]) + bytes([l[4]])

    def target_account(self, a, migrated: bool):
        pq = self.pqkey if migrated else bytes(32)
        identity_domain = b'TRNM/PQ/Account/v1\x00' if migrated else b'TRNM/PQ/Quarantine/v1\x00'
        account_id = h(identity_domain + self.new_network + a[0] + (pq if migrated else b''))
        return bytes([int(migrated)]) + account_id + pq + self.account_wire(a) + u64(a[3] + 1)

    def make(self, statuses=(True, False)):
        self.source = (b'PQG1\x01' + self.legacy_network + self.new_network
                       + self.legacy_head + self.withdrawal_head + self.protocol
                       + u64(self.issued) + u16(len(self.accounts)) + u16(len(self.liabilities))
                       + b''.join(self.account_wire(a) for a in self.accounts)
                       + b''.join(self.liability_wire(l) for l in self.liabilities))
        self.target_records = b''.join(self.target_account(a, b)
                                       for a, b in zip(self.accounts, statuses, strict=True))
        liabilities = b''.join(self.liability_wire(l) for l in self.liabilities)
        self.state = (b'PQS1\x01' + self.new_network + self.protocol
                      + u16(len(self.accounts)) + self.target_records
                      + u16(len(self.liabilities)) + liabilities + u64(self.issued))
        source_digest = commit(SOURCE_DOMAIN, self.source)
        target_root = commit(STATE_DOMAIN, self.state)
        genesis = commit(GENESIS_DOMAIN, self.new_network + self.protocol + source_digest + target_root)
        quarantine = sum(a[1] for a, flag in zip(self.accounts, statuses, strict=True) if not flag)
        locked = sum(l[2] for l in self.liabilities)
        self.projection = (b'PQL2\x01' + self.new_network + self.protocol
                           + self.legacy_head + self.withdrawal_head + source_digest + genesis
                           + u16(len(self.accounts)) + self.target_records
                           + u16(len(self.liabilities)) + liabilities + u64(self.issued)
                           + u64(quarantine) + u64(locked))
        output_root = commit(PQL2_DOMAIN, self.projection)
        self.pin = (b'PQLP\x01' + source_digest + target_root + genesis + output_root
                    + self.legacy_network + self.new_network + self.legacy_head
                    + self.withdrawal_head + self.protocol + u64(self.issued))
        assert len(self.pin) == 365


class PQL3NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compile_root = tempfile.TemporaryDirectory(prefix='pql3-native-')
        cls.addClassCleanup(cls.compile_root.cleanup)
        cls.executable = Path(cls.compile_root.name) / 'pql3_native_verify'
        sanitize = os.environ.get('PQL3_SANITIZE') == '1'
        cmd = ['cc', '-std=c11', '-O1' if sanitize else '-O2', '-g', '-Wall', '-Wextra',
               '-Werror', '-pedantic', str(DIR / 'pql3_native_verify.c'), '-o', str(cls.executable), '-lcrypto']
        if sanitize:
            cmd.extend(['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pql3-case-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = Fixture()

    def run_c(self, source=None, state=None, projection=None, pin=None, *, paths=None):
        data = (self.fixture.source if source is None else source,
                self.fixture.state if state is None else state,
                self.fixture.projection if projection is None else projection,
                self.fixture.pin if pin is None else pin)
        files = []
        for i, raw in enumerate(data):
            path = self.root / f'data-{i}-{len(list(self.root.iterdir()))}'
            path.write_bytes(raw)
            files.append(path)
        if paths:
            for idx, new_path in paths.items(): files[idx] = new_path
        p = subprocess.run([str(self.executable), *map(str, files)], capture_output=True,
                           timeout=10, check=False)
        return p.returncode, p.stdout, p.stderr

    def assert_reject(self, **kwargs):
        code, out, err = self.run_c(**kwargs)
        self.assertEqual(code, 2, (out, err))
        self.assertEqual(out, b'')
        self.assertEqual(err, b'PQL3_REJECT\n')

    @staticmethod
    def mutation_offsets(length):
        # Normal mode checks *every* byte. ASan/UBSan mode samples every
        # field boundary to keep expensive instrumented process startups finite.
        if os.environ.get('PQL3_SANITIZE') != '1':
            return range(length)
        return sorted({i for i in (0,1,4,5,6,32,48,53,68,69,70,71,72,100,101,127,
                                   128,129,132,133,148,149,164,165,172,173,174,175,
                                   176,177,196,197,228,229,230,231,260,261,292,
                                   293,324,325,356,357,364,length//2,length-2,length-1)
                       if 0 <= i < length})

    def test_independent_original_structures_and_pins_accepted(self):
        code, out, err = self.run_c()
        self.assertEqual((code, out, err), (0, b'PQL3_VALID_RESEARCH_OBSERVATION_ONLY\n', b''))
        self.assertEqual(len(self.fixture.source), 177 + 2*56 + 4*81)
        self.assertEqual(len(self.fixture.state), 71 + 2*129 + 2 + 4*81 + 8)
        self.assertEqual(len(self.fixture.projection), 231 + 2*129 + 2 + 4*81 + 24)
        self.assertEqual(self.fixture.state[71+65+40:71+65+48], u64(23))
        self.assertEqual(self.fixture.state[71+129+65+40:71+129+65+48], u64(91))

    def test_every_source_header_byte_mutation_rejected(self):
        for i in self.mutation_offsets(177):
            b = bytearray(self.fixture.source); b[i] ^= 1
            with self.subTest(byte=i): self.assert_reject(source=bytes(b))

    def test_every_target_state_byte_mutation_rejected(self):
        original = self.fixture.state
        for i in self.mutation_offsets(len(original)):
            b = bytearray(original); b[i] ^= 1
            with self.subTest(byte=i): self.assert_reject(state=bytes(b))

    def test_every_pql2_byte_mutation_rejected(self):
        original = self.fixture.projection
        for i in self.mutation_offsets(len(original)):
            b = bytearray(original); b[i] ^= 1
            with self.subTest(byte=i): self.assert_reject(projection=bytes(b))

    def test_every_pin_byte_mutation_rejected(self):
        for i in self.mutation_offsets(len(self.fixture.pin)):
            p = bytearray(self.fixture.pin); p[i] ^= 1
            with self.subTest(byte=i): self.assert_reject(pin=bytes(p))

    def test_quarantined_account_is_not_a_fresh_pq_spender(self):
        # Even if an attacker recomputes every structural digest, a zero-signer
        # quarantined record cannot claim a different address or a PQ key.
        f=self.fixture
        f.state = f.state[:71+129+33] + f.pqkey + f.state[71+129+65:]
        f.projection=f.projection[:231+129+33]+f.pqkey+f.projection[231+129+65:]
        self.assert_reject()
        # Rehash all pins; the structure still refuses invalid quarantine.
        src_digest=commit(SOURCE_DOMAIN,f.source);target_root=commit(STATE_DOMAIN,f.state)
        gid=commit(GENESIS_DOMAIN,f.new_network+f.protocol+src_digest+target_root)
        f.pin=(f.pin[:53]+target_root+gid+commit(PQL2_DOMAIN,f.projection)+f.pin[197:])
        self.assert_reject()

    def test_nonce_floor_and_target_generation_cannot_reset_with_rehash(self):
        f=self.fixture
        # Keeping PQL2 bytes/pins untouched refuses a changed sender nonce.
        s=bytearray(f.source)
        s[177+40:177+48]=u64(1)
        self.assert_reject(source=bytes(s))
        s=bytearray(f.state)
        s[71+121:71+129]=u64(11) # source generation 11 -> must be 12
        self.assert_reject(state=bytes(s))

    def test_zero_and_duplicate_pq_signers_reject_even_with_mutated_input(self):
        f=self.fixture
        # Both old accounts migrated to same PQ ID, with individually correct
        # SHA256 account IDs, but duplicate PQ key reuse is still forbidden.
        f.make(statuses=(True, True))
        self.assert_reject()
        for field in (b'PQS1\x02', b'ED251\x01'):
            self.assert_reject(state=field+f.state[5:])

    def test_liability_drop_or_silent_unlock_rejected(self):
        f=self.fixture
        self.assert_reject(state=f.state[:-8-81] + f.state[-8:])
        mutated=bytearray(f.projection)
        mutated[-8:]=u64(0)
        self.assert_reject(projection=bytes(mutated))
        mutated=bytearray(f.source)
        mutated[175:177]=u16(3)
        self.assert_reject(source=bytes(mutated))

    def test_wrong_external_pin_or_consistent_different_source_reject(self):
        f=self.fixture
        forged=bytearray(f.source)
        old_balance=int.from_bytes(forged[177+32:177+40], 'big')
        forged[177+32:177+40]=u64(old_balance+1)
        forged[165:173]=u64(f.issued+1)
        self.assert_reject(source=bytes(forged))
        for n in [0,1,2,3,4]:
            new=bytearray(f.pin)
            new[5+48*n] ^= 1
            self.assert_reject(pin=bytes(new))

    def test_truncated_trailing_unknown_types_and_symlinks(self):
        f=self.fixture
        self.assert_reject(source=f.source+b'z')
        self.assert_reject(state=f.state[:-1])
        self.assert_reject(projection=f.projection+b'\x00')
        self.assert_reject(pin=f.pin+b'\x00')
        self.assert_reject(pin=b'PQLP\x02'+f.pin[5:])
        real=self.root/'real';real.write_bytes(f.source)
        link=self.root/'link';link.symlink_to(real)
        self.assert_reject(paths={0:link})
        self.assert_reject(paths={1:self.root})

    def test_old_new_network_identical_or_unknown_obligation_owner_reject(self):
        f=self.fixture
        changed=bytearray(f.source)
        changed[37:69]=f.legacy_network
        self.assert_reject(source=bytes(changed))
        changed=bytearray(f.source)
        off=177+2*56
        changed[off+32:off+64]=h(b'not-an-existing-account')
        self.assert_reject(source=bytes(changed))

    def test_pins_not_independently_authenticated_is_open_blocker(self):
        # Deliberate counterexample: a valid-looking entirely rehashed world can
        # pass this structural verifier if the caller trusts the attacker's pins.
        # This is NOT a security success. PQL3 MUST NOT issue source provenance.
        f=self.fixture
        f.accounts=((f.old[0],250,23,11),(f.old[1],500,91,30))
        f.issued=1850
        f.make()
        c,out,_=self.run_c()
        self.assertEqual(c,0)
        self.assertIn(b'RESEARCH_OBSERVATION_ONLY',out)

    def test_boolean_or_forged_authority_is_not_encoded_in_success(self):
        _,out,_=self.run_c()
        self.assertNotIn(b'ACTIVATED',out)
        self.assertNotIn(b'FINAL_USE',out)
        self.assertNotIn(b'CHAINWORK',out)

    @unittest.skipUnless(importlib.util.find_spec('pq_genesis_state_bridge'),
                         'full stacked GitHub checkout needed for upstream parity')
    def test_upstream_pql2_project_exact_parity(self):
        from pq_genesis_state_bridge import (Source,SourceAccount,Liability,NewAccount,project)
        f=self.fixture
        source=Source(f.legacy_network,f.new_network,f.legacy_head,f.withdrawal_head,
                      f.protocol,f.issued,
                      tuple(SourceAccount(*a) for a in f.accounts),
                      tuple(Liability(*l) for l in f.liabilities))
        accounts=[]
        for a,flag in zip(f.accounts,(True,False),strict=True):
            row=f.target_account(a,flag)
            accounts.append(NewAccount(row[0],row[1:33],row[33:65],SourceAccount(*a),a[3]+1))
        assert source.encode()==f.source
        p=project(f.source,f.state,expected_source_digest=f.pin[5:53],
            expected_pqs1_root=f.pin[53:101],expected_genesis_id=f.pin[101:149],
            expected_legacy_network=f.legacy_network,expected_new_network=f.new_network,
            expected_legacy_head=f.legacy_head,expected_withdrawal_head=f.withdrawal_head,
            expected_protocol=f.protocol,expected_issued=f.issued)
        self.assertEqual(p.state,f.projection)
        self.assertEqual(p.pql2_root,f.pin[149:197])
        self.assertEqual(p.inherited_nonce_floors[0][1],23)
        self.assertEqual(p.inherited_nonce_floors[1][1],91)

if __name__ == '__main__':
    unittest.main()
