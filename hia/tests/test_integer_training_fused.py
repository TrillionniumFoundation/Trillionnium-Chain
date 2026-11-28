"""One immutable frame, exact frozen three-stage train, both stock engines."""
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import struct
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_integer_training_batch_update import (
    E, IMAX, LOGIT, RESULT, active, cases, frame, projection, raw_frame, result_bytes, run,
)

SOURCE=Path(__file__).parents[1]/"src/state/integer_training_fused.hepta"
INPUT_FIXED=74096
RAW_MAX=208240
OUT_MAX=159360
GMAX=137988390912
MARK=b"\x9d"
ARENA=b"\x6e"


@lru_cache(maxsize=1)
def fixtures():
    source={c["tag"]:c for c in cases()}
    wanted=[source[tag] for tag in ("empty-none","empty-some-max","first-active-none-unmasked",
        "active-all-frozen","step-overflow-before-coordinate","weight-first-group",
        "weight-last-group-after-prefix","successful-mirrored-bound-and-step-carry",
        "signed-fraction-changes")]
    full=deepcopy(source["maximum-old-moment-with-lr-zero"])
    full.update(tag="max-opposing-gradients",rows=tuple(
        active(j%3,0,(-LOGIT,LOGIT,-LOGIT),(8,-8)+(0,)*254+(8,)) for j in range(64)))
    full["settings"]=(*full["settings"][:-1],64)
    assert full["moments"][0]==IMAX
    wanted.append(full)
    return wanted


def wire(case):
    settings=case["settings"]
    assert len(case["rows"])==settings[7]
    return (b"CTRN0002"+struct.pack("<9Q",settings[7],0,settings[5],settings[6],*settings[:5])
            +struct.pack(f"<{3*E}q",*case["weights"],*case["moments"],*case["mask"])
            +frame(case["rows"])[16:])


@lru_cache(maxsize=1)
def original_cases():
    rows,proof=run(fixtures())
    result=[]
    for case,stages in zip(fixtures(),rows,strict=True):
        f=wire(case)
        assert len(f)==INPUT_FIXED+len(case["rows"])*2096
        b=projection(stages[:2],len(case["rows"]))
        code,u=result_bytes(stages)
        assert len(b)==30848+80*len(case["rows"])
        assert len(u)==(RESULT if code==0 else 0)
        # Independent old wrapper has no user-supplied projection in the fused input.
        assert f[80:INPUT_FIXED]==raw_frame(case,stages)[80:INPUT_FIXED]
        result.append((case["tag"],f,code,b,u))
    return result,proof


class IntegerTrainingFusedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mods={k:cls.enterClassContext(NativeModule(SOURCE,backend=k,byte_exports=("f0",)))
                  for k in ("direct","selfhost")}
        if len({x.artifact_sha256 for x in cls.mods.values()})!=2:
            raise ValueError("Both authentic stock artifacts required")

    def invoke(self,native,f,code,want,*,out_len=None,arena_len=None,touch=None):
        if out_len is None: out_len=len(want)+13
        if arena_len is None: arena_len=len(want)+11
        out=MARK*out_len
        arena=ARENA*arena_len
        call=native.call("f0",[f,out,arena],timeout=30).require_returned()
        self.assertEqual((call.abi_status,call.value),(0,code))
        self.assertEqual(call.arguments[:2],[f,want+out[len(want):]])
        if code==0:
            self.assertEqual(call.arguments[2],want+arena[len(want):])
        if touch is not None:
            self.assertEqual(call.arguments[2][touch:],arena[touch:])
        return call.arguments[2]

    def test_full_train_from_one_immutable_frame(self):
        rows,proof=original_cases()
        self.assertEqual(len(proof["body_sha256"]),64)
        self.assertEqual(len(rows),10)
        self.assertEqual({code for _,_,code,_,_ in rows},{0,201,203})
        by_tag={tag:(f,s,b,u) for tag,f,s,b,u in rows}
        self.assertEqual(struct.unpack_from("<4Q",by_tag["empty-none"][3]),(0,0,0,0))
        self.assertEqual(struct.unpack_from("<4Q",by_tag["empty-some-max"][3]),(1,(1<<64)-1,0,0))
        carry=by_tag["successful-mirrored-bound-and-step-carry"][3]
        self.assertEqual(struct.unpack_from("<4Q",carry),(1,1<<63,1,1))
        self.assertEqual(struct.unpack_from("<5q",carry,32),(-32767,3,2,1,1))
        self.assertEqual(struct.unpack_from("<5q",carry,RESULT-40),(32767,-3,-16,-1,-1))
        max_f,_,b,u=by_tag["max-opposing-gradients"]
        self.assertEqual((len(max_f),len(b)+len(u)),(RAW_MAX,OUT_MAX))
        self.assertEqual(struct.unpack_from("<2q",b,8),(-GMAX,GMAX))
        self.assertEqual(struct.unpack_from("<4Q",u)[2:],(1,0))
        for tag,f,code,b,u in rows:
            expected=b+u if code==0 else b""
            nn=len(b)+RESULT
            for k,native in self.mods.items():
                with self.subTest(tag=tag,stock=k):
                    scratch=self.invoke(native,f,code,expected,out_len=nn+7,arena_len=nn+11,
                                        touch=0 if code==201 else nn)
                    if code==203:
                        self.assertEqual(scratch[:len(b)],b)
                    if tag=="weight-last-group-after-prefix":
                        self.assertEqual(scratch[len(b)+32:len(b)+72],carry[32:72])
                        self.assertEqual(scratch[nn-40:nn],ARENA*40)

    def test_physical_bound_and_failure_priority(self):
        rows,_=original_cases()
        by_tag={t:(f,s,b,u) for t,f,s,b,u in rows}
        full,_,b,u=by_tag["max-opposing-gradients"]
        w=b+u
        late,status,lb,_=by_tag["weight-last-group-after-prefix"]
        need=len(lb)+RESULT
        bad_bias=full[:-8]+struct.pack("<q",7)
        bad_res=full[:16]+struct.pack("<Q",1)+full[24:]
        for native in self.mods.values():
            self.invoke(native,full,0,w,out_len=OUT_MAX,arena_len=OUT_MAX)
            for malformed in (bad_bias,bad_res,full+b"X",full[:-1]):
                self.invoke(native,malformed,100,b"",out_len=17,arena_len=23,touch=0)
            self.invoke(native,full,102,b"",out_len=OUT_MAX,arena_len=OUT_MAX-1,touch=0)
            complete=self.invoke(native,full,102,b"",out_len=OUT_MAX-1,arena_len=OUT_MAX)
            self.assertEqual(complete,w)
            failed=self.invoke(native,late,status,b"",out_len=need-1,arena_len=need)
            self.assertEqual(failed[:len(lb)],lb)
            f=by_tag["step-overflow-before-coordinate"][0]
            self.invoke(native,f,201,b"",out_len=7,arena_len=8,touch=0)
