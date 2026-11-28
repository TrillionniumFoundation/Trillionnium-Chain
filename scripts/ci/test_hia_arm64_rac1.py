"""Local source/Core controls only. No native ARM result is implied."""
from pathlib import Path
import unittest
import tempfile
import io
import tarfile
import zipfile
import hia_arm64_rac1 as diagnostic
from hia_arm64_rac1_carrier import compose, ENTRY
from hia_arm64_rac1_data import typed_corpus, oracle_parse, packed, BAD, SHORT
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import execute_program
from hepta.hia_program_llvm import emit_program_llvm

ROOT=Path(__file__).resolve().parents[2]

class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=(ROOT/'hia/src/release_bundle/artifact_header.hepta').read_bytes()
        cls.combined=compose(cls.original)
        cls.core=assemble_program(cls.combined)

    def test_verbatim_original_and_scoped_ir(self):
        self.assertEqual(self.combined.split(b"\n",2)[2][:len(self.original.split(b"\n",1)[1])],
                         self.original.split(b"\n",1)[1])
        self.assertEqual(emit_program_llvm(self.core,target='aarch64-unknown-linux-gnu').exports,(ENTRY,))
        self.assertEqual(len(self.core.as_dict()['functions']),12)
        with self.assertRaises(ValueError):compose(self.original+b" ")

    def test_bounds_refuse_with_no_core_live_owners(self):
        for args in ([193,216,0]+[0]*24,[0,217,0]+[0]*24,[0,0,28]+[0]*24):
            result=execute_program(self.core,ENTRY,args)
            self.assertEqual(result['result'],2**64-1)
            self.assertEqual(result['resources']['allocations'],0)

    def test_scope_statuses_and_sentinels_in_core_only(self):
        rows=typed_corpus()
        for raw,cap,expect in ((rows[0],216,128),(rows[0],0,SHORT),(b"",216,BAD),(rows[7],216,208)):
            result=execute_program(self.core,ENTRY,packed(raw,cap,0))
            self.assertEqual(result['result'],expect)
            self.assertEqual(result['resources']['live_owners'],0)
            self.assertEqual(result['resources']['live_local_loans'],0)
        got=execute_program(self.core,ENTRY,packed(rows[0],216,1))
        self.assertEqual(got['result'].to_bytes(8,'little'), b'RAC1'+b'\0'*4)
        canary=execute_program(self.core,ENTRY,packed(b"",216,27))
        self.assertEqual(canary['result'].to_bytes(8,'little'),b'\xcd'*8)

    def test_external_receipt_negative_controls(self):
        with self.assertRaisesRegex(ValueError,"duplicate"):
            diagnostic.stable_json(b'{"head":"good","head":"forged"}')
        with self.assertRaisesRegex(ValueError,"original stdout differs"):
            diagnostic.summarize(b"forged")
        with self.assertRaisesRegex(ValueError,"wrong ELF"):
            raw=bytearray(64)
            raw[:7]=b"\x7fELF\x02\x01\x01"
            raw[16:24]=bytes((1,0,62,0,1,0,0,0))
            diagnostic.elf(bytes(raw),{1})
        with tempfile.TemporaryDirectory() as temp:
            z=Path(temp)/"bad.zip"
            raw=io.BytesIO()
            with tarfile.open(fileobj=raw,mode="w") as tar:
                bad=tarfile.TarInfo("../escape")
                bad.size=1
                tar.addfile(bad,io.BytesIO(b"x"))
            with zipfile.ZipFile(z,"w") as wrapped:
                wrapped.writestr("hia-arm64-rac1.tar",raw.getvalue())
            for digest,msg in ((diagnostic.sha(z.read_bytes()),"TAR members"),("0"*64,"ZIP SHA")):
                with self.subTest(msg=msg),self.assertRaisesRegex(ValueError,msg):
                    diagnostic.verify_archive(z,digest=digest,head="a"*40,tree="b"*40,run_id="123",attempt="1")
            self.assertFalse((Path(temp)/"escape").exists())

    def test_bad_oracle_receipts_and_corpus(self):
        self.assertEqual(len(typed_corpus()),528)
        self.assertEqual(max(map(len,typed_corpus())),192)
        for bad in (b'', b'\xff'*5, b'\1\0\0\0R', b'\0'*4):
            with self.subTest(bad=bad),self.assertRaises(ValueError):oracle_parse(bad,1)

if __name__=='__main__':unittest.main()
