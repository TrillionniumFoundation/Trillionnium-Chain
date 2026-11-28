"""Mechanical extension of the exact ordinary row, without redoing arithmetic."""
import hashlib
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src/state/routed_int257_ordinary.hepta"
PIN = "c440bff6a36e0184a63c456965c6009fe17cbb1157741cf29e6ac5c2dd235156"
BEGIN = "fn rid_emit("


def derive(data=None):
    raw = SOURCE.read_bytes() if data is None else data
    if hashlib.sha256(raw).hexdigest() != PIN:
        raise ValueError("Published ordinary row source differs")
    left = raw.decode("ascii").split("fn rio_emit(", 1)[1]
    row = "fn rid_emit(" + left.split("\nend\n", 1)[0]
    done = '  zero:u64 = const() {"value":0}\n  ret(zero)'
    if row.count(done) != 1:
        raise ValueError("No unique published row boundary")
    return row.replace(done, '''  d26:u64 = const() {"value":26}
  score0:u64 = int.add.wrap(out,d26)
  score1:u64 = int.add.wrap(score0,step8)
  score2:u64 = int.add.wrap(score1,step8)
  r0_bits:u64 = int.cast(r0) {"mode":"wrap"}
  r1_bits:u64 = int.cast(r1) {"mode":"wrap"}
  r2_bits:u64 = int.cast(r2) {"mode":"wrap"}
  _r0:u64 = call(o,score0,r0_bits) {"function":"tr_put"}
  _r1:u64 = call(o,score1,r1_bits) {"function":"tr_put"}
  _r2:u64 = call(o,score2,r2_bits) {"function":"tr_put"}
  ret(expert)''') + "\nend\n"
