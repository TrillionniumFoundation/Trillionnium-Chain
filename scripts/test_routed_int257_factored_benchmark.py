"""Opt-in exact guard and original Rust fixtures for the Factored diagnostic."""
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hia.tests import test_routed_int257_factored as factored
from scripts import routed_int257_factored_benchmark as bench


def original_results(cases):
    ordinary = bench.warm.ordinary
    raw = b"".join(struct.pack("<I",len(c.factored))+c.factored for c in cases)
    with tempfile.TemporaryDirectory(prefix="trnm-factored-bench-original-") as tmp:
        with patch.object(ordinary,"CALLER",factored.CALLER):
            out = ordinary.locked_ordinary(Path(tmp),raw)
    result = []
    pos = 0
    for case in cases:
        status, n = struct.unpack_from("<BI",out,pos)
        pos += 5
        bench.require(status == 0 and n == bench.warm.output_extent(case.count)+bench.COUNTS.size,
                      "the unchanged public locked original refused a benchmark fixture")
        result.append(out[pos:pos+n])
        pos += n
    bench.require(pos == len(out), "unconsumed original output")
    return result


class FactoredWarmBenchmark(unittest.TestCase):
    def test_fixed_panel_and_equivalent_dense_bytes(self):
        panel = list(bench.panel())
        self.assertEqual(len(panel),40)
        for begin in range(0,len(panel),4):
            same = panel[begin:begin+4]
            self.assertEqual(tuple(c.rank for c in same),bench.RANKS)
            self.assertEqual(len({c.dense for c in same}),1)
            self.assertEqual(len({c.factored for c in same}),4)
            self.assertEqual(len({c.routes for c in same}),1)
            for c in same:
                self.assertEqual(c.dense[4:15424],c.factored[32:15452])
                self.assertEqual(c.dense[:4],c.factored[40460:40464])
                self.assertEqual(c.dense[15424:],c.factored[40464:])
        self.assertEqual({c.count for c in panel},{1,8,32,64})

    def test_actual_locked_rust_for_every_timing_case(self):
        cases = list(bench.panel())
        originals = original_results(cases)
        for k,(c,x) in enumerate(zip(cases,originals,strict=True)):
            normalized = bench.normalize_factored(x,c.count)
            product, _ = bench.exact_results(c,dict(direct=normalized,grouped=normalized,factored=x))
            self.assertEqual(product,bench.warm.sha(normalized))
            self.assertEqual(normalized,bench.normalize_factored(originals[k-k%4],c.count))
        fixture, raw = cases[-1], originals[-1]
        front = bench.normalize_factored(raw,fixture.count)
        changed_product = bytes([raw[0]^1])+raw[1:]
        with self.assertRaisesRegex(ValueError,"Factored Product"):
            bench.exact_results(fixture,dict(direct=front,grouped=front,factored=changed_product))
        changed_count = raw[:-1]+bytes([raw[-1]^1])
        with self.assertRaisesRegex(ValueError,"diagnostic counts"):
            bench.exact_results(fixture,dict(direct=front,grouped=front,factored=changed_count))

    def test_orders_balanced_and_pin_forgery_refused(self):
        keys = bench.LANES
        names = []
        calls = {k:(lambda k=k: names.append(k)) for k in keys}
        def measure(call,count):
            self.assertEqual(count,17)
            call()
            return 1
        rows = bench.run_blocks(calls,17,2,4,measure=measure)
        self.assertEqual(set(r["order"] for r in rows),set(bench.ORDERS))
        self.assertEqual(names,[k for r in rows for k in r["order"]])
        for i in range(3):
            self.assertEqual([sum(r["order"][i]==k for r in rows) for k in keys],[4]*3)
        make = {b: {k:str(i)*64 for i,k in enumerate(keys,1+3*j)}
                for j,b in enumerate(bench.warm.BACKENDS)}
        self.assertEqual(bench.elf_pins(bench.json.dumps(make)),make)
        del make["selfhost"]["factored"]
        with self.assertRaises(ValueError):
            bench.elf_pins(bench.json.dumps(make))
