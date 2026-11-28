"""Actually linked, locked original Model canonical serialization vs both stocks."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_cell_model_artifact import ROOT, ORIGINAL, PINS, original

SOURCE = ROOT/"hia/src/model/cell_model_canonical.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_model_canonical_reference.rs")
WORD_BYTES = 5*3*257*8
FRAME_SIZE = 8+WORD_BYTES


class CellModelCanonicalTests(unittest.TestCase):
    def test_locked_original_complete_typed_serialization(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-model-canonical-") as tmp:
            raw=original(Path(tmp), reference=REFERENCE)
        stream=memoryview(raw)
        pos=0
        corpus=[]
        while pos<len(raw):
            length,=struct.unpack_from("<I",stream,pos)
            pos+=4
            bound=pos+WORD_BYTES
            self.assertLessEqual(bound+length,len(raw))
            corpus.append((b"CMCV0001"+bytes(stream[pos:bound]),bytes(stream[bound:bound+length])))
            pos=bound+length
        self.assertEqual(len(corpus),33)
        exact=[len(x) for _,x in corpus]
        self.assertEqual(exact[:3],[7830,27105,23250])
        self.assertEqual((min(exact),max(exact)),(7830,27105))
        self.assertEqual(len({sha256(v).hexdigest() for _,v in corpus}),33)
        basis=json.loads(corpus[4][1])
        self.assertEqual(list(basis),["base","deltas","router","schema"])
        self.assertEqual([m[2][-1] for m in [basis["base"],*basis["deltas"],basis["router"]]],
                         [-1002,-2002,-3002,-4002,-5002])
        self.assertEqual(basis["schema"],"pon-cell-stateful-native-int257-v1/model")

        seed=corpus[0][0]
        def patch(frame,word,value):
            pos=8+word*8
            return frame[:pos]+struct.pack("<q",value)+frame[pos+8:]
        malformed=[seed[:-1],seed+b"\0",b"?"+seed[1:],
                   patch(seed,0,-32768),patch(seed,0,32768),patch(seed,257,1<<55),
                   patch(seed,771*4,-(1<<63)),patch(seed,3854,32768),
                   patch(seed,3854,-32768)]
        calls=[("f0",[frame,b"\xa5"*(len(expected)+i%2*11),b"\xd3"*(i%3*19)])
               for i,(frame,expected) in enumerate(corpus)]
        outcomes=[(len(expected),expected) for _,expected in corpus]
        calls += [("f0",[frame,b"\xa5"*27112,b"\xd3"*11]) for frame in malformed]
        outcomes += [(1,b"")]*len(malformed)
        for i in (0,1,17):
            frame,canon=corpus[i]
            calls.append(("f0",[frame,b"\xa5"*(len(canon)-1),b""]))
            outcomes.append((102,b""))
        calls.append(("f0",[malformed[-1],b"",b""]))
        outcomes.append((1,b""))
        hashes={}
        for backend in ("direct","selfhost"):
            with NativeModule(SOURCE,byte_exports=("f0",),backend=backend) as m:
                hashes[backend]=m.artifact_sha256
                for i in range(0,len(calls),5):
                    batch=calls[i:i+5]
                    for ask,ret,(status,canon) in zip(batch,m.call_many(batch,timeout=30),outcomes[i:i+5],strict=True):
                        ret.require_returned()
                        frame,out,arena=ask[1]
                        self.assertEqual((ret.value,ret.arguments),(status,[frame,canon+out[len(canon):],arena]))
        save=os.environ.get("HIA_CELL_MODEL_CANONICAL_PROOF")
        if save:
            Path(save).write_text(json.dumps(dict(original_workspace_git_tree=ORIGINAL,
                original_pins=PINS, original_stdout_sha256=sha256(raw).hexdigest(),
                rust_reference_sha256=sha256(REFERENCE.read_bytes()).hexdigest(), original_models=len(corpus),
                native_cases_each=len(calls), native_artifacts=hashes, minimum_bytes=min(exact),
                maximum_bytes=max(exact), max_frame=FRAME_SIZE, scratch_touched=False),
                sort_keys=True,indent=2)+"\n")
