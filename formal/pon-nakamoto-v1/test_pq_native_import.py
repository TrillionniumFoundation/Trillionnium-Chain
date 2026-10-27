"""Separate native OpenSSL C11 versus Python PQI1 import byte/negative parity."""
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_pq_import_projection as inputs
from pq_import_projection import (Reject,project_pqs1,decode_import_exact,
                                   ACCOUNT_SIZE,LIABILITY_SIZE,STATE_DOMAIN,GENESIS_ID_DOMAIN)


class NativePQImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='trnm-pqi1-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.dir=Path(cls.tmp.name)
        cls.binary=cls.dir/'pqi1_native'
        src=Path(__file__).with_name('pqi1_native.c')
        args=['cc','-std=c11','-Wall','-Wextra','-Werror','-O2']
        if os.getenv('PQI1_SANITIZE')=='1':
            args+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-O1']
        args += [str(src),'-lcrypto','-o',str(cls.binary)]
        subprocess.run(args,check=True,capture_output=True,timeout=40)
        cls.original=inputs.fixture()[0]
        cls.pins=inputs.pinned(cls.original)

    def run_native(self,raw: bytes | None=None,pins=None,*,path=None):
        if raw is None:raw=self.original
        if pins is None:pins=self.pins
        if path is None:
            path=self.dir/'snapshot.pqs1'
            path.write_bytes(raw)
        return subprocess.run([str(self.binary),str(path)]+[
            pins[k].hex() for k in ('expected_network','expected_profile',
                                    'expected_source_digest','expected_state_root',
                                    'expected_genesis_id')],capture_output=True,timeout=10)

    def test_exact_byte_parity_and_read_only_scope(self):
        a=self.run_native()
        self.assertEqual(a.returncode,0,a.stderr)
        self.assertEqual(a.stdout,project_pqs1(self.original,**self.pins).projection_bytes)
        self.assertEqual(decode_import_exact(a.stdout).liability_count,4)
        self.assertNotIn(b'PQI1_VALID',a.stdout)

    def test_all_input_bytes_tampered_original_pin_reject(self):
        # All 760+ offsets exercise the native framing/roots and no fallback.
        for i in range(len(self.original)):
            mutated=bytearray(self.original);mutated[i]^=1
            with self.subTest(offset=i):
                got=self.run_native(bytes(mutated))
                self.assertNotEqual(got.returncode,0,got.stdout[:60])
                self.assertEqual(got.stdout,b'')

    def test_context_source_genesis_identity_and_production_signer_flags(self):
        for key in self.pins:
            pins=dict(self.pins)
            value=bytearray(pins[key]);value[-1]^=1;pins[key]=bytes(value)
            with self.subTest(key=key):
                got=self.run_native(pins=pins)
                self.assertNotEqual(got.returncode,0)
                self.assertEqual(got.stdout,b'')

    def test_reanchored_structural_invalid_inputs_still_reject(self):
        src=self.original
        start=71+3*ACCOUNT_SIZE+2
        malformed=[]
        for at,content in ((71,b'\x02'),(71+33,bytes(32)),
                           (71+105,bytes(8)),(71+113,bytes(8)),
                           (start+64,bytes(8)),(start+80,b'\xff'),
                           (start+32,bytes([199])*32)):
            malformed.append(src[:at]+content+src[at+len(content):])
        malformed += [src[:start+LIABILITY_SIZE]+src[start:start+LIABILITY_SIZE]+src[start+2*LIABILITY_SIZE:],
                      src[:-8]+(inputs.fixture()[3]+1).to_bytes(8,'big')]
        for raw in malformed:
            with self.subTest(sample=hashlib.sha256(raw).hexdigest()[:12]):
                pins=inputs.pinned(raw)
                self.assertNotEqual(self.run_native(raw,pins).returncode,0)
                with self.assertRaises(Reject):project_pqs1(raw,**pins)

    def test_disallowed_uppercase_pin_and_invalid_length(self):
        path=self.dir/'plain.pqs1';path.write_bytes(self.original)
        keys=('expected_network','expected_profile','expected_source_digest',
              'expected_state_root','expected_genesis_id')
        argv=[str(self.binary),str(path)]+[self.pins[k].hex() for k in keys]
        for index in range(2,7):
            altered=list(argv)
            altered[index]=altered[index][:-1]
            self.assertNotEqual(subprocess.run(altered,capture_output=True).returncode,0)
        altered=list(argv);altered[2]=argv[2].replace('31','3A',1)
        self.assertNotEqual(subprocess.run(altered,capture_output=True).returncode,0)

    def test_symlink_directory_and_trailing_noncanonical_refuse(self):
        path=self.dir/'ref.pqs1';path.write_bytes(self.original)
        link=self.dir/'alias.pqs1';link.symlink_to(path)
        for item in (link,self.dir):
            with self.subTest(path=item):
                got=self.run_native(path=item)
                self.assertNotEqual(got.returncode,0)
                self.assertEqual(got.stdout,b'')
        for data in (self.original[:-1],self.original+b'x',b'PQL1'+self.original[4:]):
            self.assertNotEqual(self.run_native(data).returncode,0)

    def test_zero_liability_snapshot_parity(self):
        raw,aa,_,_=inputs.fixture()
        total=sum(int.from_bytes(v[97:105],'big') for v in aa)
        raw=b'PQS1\x01'+inputs.NET+inputs.PROFILE+(len(aa)).to_bytes(2,'big')+b''.join(aa)+b'\0\0'+total.to_bytes(8,'big')
        pins=inputs.pinned(raw)
        result=self.run_native(raw,pins)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,project_pqs1(raw,**pins).projection_bytes)

    def test_maximum_account_and_liability_bounds_parity(self):
        aa=[]
        for i in range(1,129):
            old=i.to_bytes(32,'big')
            kid=(i+200).to_bytes(32,'big')
            mode=i%3!=0
            aa.append(inputs.acct(old,int(mode),kid,3,2**40+i,1+i))
        ll=[]
        for i in range(1,257):
            owner=((i-1)%128+1).to_bytes(32,'big')
            ll.append(i.to_bytes(32,'big')+owner+(5).to_bytes(8,'big')+i.to_bytes(8,'big')+bytes([(i-1)%4+1]))
        raw=(b'PQS1\x01'+inputs.NET+inputs.PROFILE+(128).to_bytes(2,'big')+b''.join(aa)+
             (256).to_bytes(2,'big')+b''.join(ll)+(128*3+256*5).to_bytes(8,'big'))
        pins=inputs.pinned(raw)
        result=self.run_native(raw,pins)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,project_pqs1(raw,**pins).projection_bytes)
        self.assertEqual(len(result.stdout),225+128*ACCOUNT_SIZE+256*LIABILITY_SIZE)

    def test_duplicated_pq_key_and_issued_overflow_reject(self):
        raw,aa,ll,_=inputs.fixture()
        second=inputs.acct(inputs.OLD_2,1,inputs.KID_1,550,18,4)
        duplicate=raw[:71+ACCOUNT_SIZE]+second+raw[71+2*ACCOUNT_SIZE:]
        self.assertNotEqual(self.run_native(duplicate,inputs.pinned(duplicate)).returncode,0)
        huge=inputs.acct(inputs.OLD_1,1,inputs.KID_1,2**64-1,2,9)
        overflow=raw[:71]+huge+raw[71+ACCOUNT_SIZE:]
        self.assertNotEqual(self.run_native(overflow,inputs.pinned(overflow)).returncode,0)

    def test_pqi1_is_distinct_from_pql1_and_pqs1(self):
        out=self.run_native()
        self.assertEqual(out.returncode,0)
        self.assertTrue(out.stdout.startswith(b'PQI1\x01'))
        self.assertNotEqual(out.stdout,self.original)
        self.assertNotEqual(out.stdout[:4],b'PQL1')
        self.assertNotIn(b'activation',out.stdout)

if __name__=='__main__':unittest.main()
