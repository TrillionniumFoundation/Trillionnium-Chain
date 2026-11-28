"""Exact private native-owned SQLite CTE compared with actual frozen Rust."""
from hashlib import sha256
import json
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from hia.platform.history_cte.fixture_host_64 import SQL
from hia.platform.task_kernel.build_provider import ProviderBuild
from hia.platform.task_kernel.readback_provider import Reader, check_provider
from hia.tests import history_page_fold_original as frozen
from hia.tests.native_support import NativeModule

ROOT=Path(__file__).resolve().parents[2]
PLATFORM=ROOT/"hia/platform/history_cte"
REFERENCE=Path(__file__).with_name("rust_history_cte_acquire_64_reference.rs")


def exact_original():
    files,pins=frozen.extract()
    driver=files["main.rs"]
    [query]=re.findall(rb'"(WITH RECURSIVE ancestry.*?ORDER BY a.ordinal)"',driver,re.DOTALL)[:1]
    if driver.count(b"fn main() {")!=1 or sha256(query).hexdigest()!=SQL[4]:
        raise ValueError("Unexpected frozen SQLite projection/query seam")
    return {**files,"main.rs":driver[:driver.index(b"fn main() {")]+REFERENCE.read_bytes()},pins


class HistoryCteAcquire64(unittest.TestCase):
    def test_actual_original_limit_64_and_shorter_in_both_stock_providers(self):
        with tempfile.TemporaryDirectory(prefix="trnm-history-cte-") as temporary:
            root=Path(temporary)
            original=root/"original"
            original.mkdir()
            raw,pins=frozen.original(original,source_factory=exact_original)
            expected=[]
            at=0
            while at<len(raw):
                n,=struct.unpack_from("<Q",raw,at)
                at+=8
                expected.append(raw[at:at+n])
                at+=n
            self.assertEqual((at,len(expected)),(len(raw),3))
            self.assertEqual([struct.unpack_from("<Q",x)[0] for x in expected],[64,3,0])

            cargo=Path(os.environ.get("CARGO_HOME",Path.home()/".cargo"))
            [dependency]=sorted(cargo.glob("registry/src/*/libsqlite3-sys-0.39.1"))
            provider=ProviderBuild(dependency,root/"provider").run()
            reader=Reader()
            check_provider(reader.read,provider.parent,ROOT)
            provider_pin=reader.checked[str(provider)]["sha256"]
            observations={}
            for backend in ("direct","selfhost"):
                with self.subTest(backend=backend), NativeModule(
                    ROOT/"hia/src/node/history_cte_acquire_64.hepta",byte_exports=("f0",),backend=backend,
                ) as native:
                    # Keep the old 8 KiB owner separate at the entry itself.
                    mode=bytes(8)
                    old_owner=bytes(8192)
                    refused=native.call("f0",[mode,old_owner,b""]).require_returned()
                    self.assertEqual((refused.abi_status,refused.value,refused.arguments),
                                     (0,100,[mode,old_owner,b""]))
                    transcripts=[]
                    for i in range(4):
                        with self.subTest(mode=i):
                            input_data={"reader":[str(native.library),native.artifact_sha256],
                                        "provider":[str(provider),provider_pin],"mode":i}
                            process=subprocess.run([sys.executable,"-I","-S","-B",str(PLATFORM/"fixture_host_64.py")],
                                input=json.dumps(input_data),capture_output=True,text=True,timeout=30)
                            self.assertEqual((process.returncode,process.stderr),(0,""))
                            result=json.loads(process.stdout)
                            self.assertEqual(result["released"],0)
                            if i==3:
                                self.assertEqual((result["status"],result["log"],result["sql"],result["result"]),
                                                 (100,[],[],None))
                                continue
                            self.assertEqual(result["status"],0)
                            self.assertEqual(bytes.fromhex(result["result"]),expected[i])
                            self.assertEqual(result["sql"],list(SQL))
                            wanted=[2]+[5,7,9]*4+[5,13]+[6]*4
                            wanted+=([7]+[8]*11)*(64,3,0)[i]+[7,9,5,7,9,3]
                            self.assertEqual([x[1] for x in result["log"]],wanted)
                            self.assertEqual(result["log"][-1],[7,3,24,0])
                            transcripts.append(result["log"])
                    observations[backend]=dict(artifact=native.artifact_sha256,
                        source=native.receipt["chain_migration"],transcripts=transcripts)
            self.assertNotEqual(observations["direct"]["artifact"],observations["selfhost"]["artifact"])
            if proof:=os.environ.get("HIA_HISTORY_CTE_64_PROOF"):
                Path(proof).write_text(json.dumps(dict(original=pins,original_stream=sha256(raw).hexdigest(),
                    provider=provider_pin,projection_lengths=list(map(len,expected)),native=observations),
                    indent=2,sort_keys=True)+"\n")
