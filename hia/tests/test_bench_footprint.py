"""Whole freestanding Bench CLI proof for one corrected FootprintDesc scope."""
from collections import Counter
import json
import unittest

from hia.tests import test_bench_reader_high_water as base


class BenchFootprintDesc(base.BenchReaderHighWaterFixture, unittest.TestCase):
    observation_env = "HIA_BENCH_FOOTPRINT_OBSERVATIONS"

    def test_corrected_mixed_footprint_changes_ordered_groups_and_matches_real_profile(self):
        row = (1, 20_000, 2_000, 3, 1, 1)
        # Shared helpers compare every native output byte (including ordered
        # membership) with the exact locked, privately corrected Rust oracle;
        # independently check the access graph; then run the real standalone.
        refs, result = self.compare_cohort(0, row)
        widths = Counter(len({key for key, _ in (*item.reads, *item.writes)}) for item in refs)
        self.assertEqual(widths, {4: 19_960, 3: 40})
        self.assertEqual(sum(map(len, result["groups"])), 20_000)
        footprint = self.results[0]
        spec = ["--workload=mixed", "--determinism-repeats=2"]
        grouped = {}
        for strategy in ("original", "write-first", "footprint-desc"):
            flags = [*spec, f"--strategy={strategy}"]
            rust = self.actual(f"footprint-compare-{strategy}-rust", [str(self.cli), *flags])
            native, wall, *_ = self.standalone_process(f"footprint-compare-{strategy}-native", [base.MODE, *flags])
            self.assertEqual((native.returncode, native.stderr), (0, b""))
            self.assertEqual(native.stdout.count(base.STAMP), 1)
            ns = dict(line.split(b"=", 1) for line in native.stdout.splitlines()[1:])
            rs = dict(line.split(b"=", 1) for line in rust.splitlines()[1:])
            self.assertLessEqual(int(ns.pop(b"elapsed_ms")), wall // 1_000_000)
            self.assertGreaterEqual(int(rs.pop(b"elapsed_ms")), 0)
            self.assertEqual(ns.pop(b"schedule_semantics"), base.SEMANTICS.encode())
            self.assertEqual(ns, rs)
            self.assertEqual(ns[b"determinism.input_sha256"].decode(), footprint["input_sha256"])
            self.assertEqual(ns[b"determinism.replay_match"], b"true")
            grouped[strategy] = {"groups": int(ns[b"groups"]), "digest": ns[b"determinism.groups_sha256"].decode()}
        self.assertEqual(grouped["footprint-desc"]["digest"], footprint["group_sha256"])
        self.assertEqual(grouped["original"], grouped["write-first"])
        self.assertNotEqual(grouped["original"]["digest"], grouped["footprint-desc"]["digest"])
        self.assertFalse(list((self.anchor / "run/bench").iterdir()))
        (self.root / "footprint-discrimination.json").write_text(json.dumps(
            {"widths": widths, "strategies": grouped, "semantics": base.SEMANTICS}, sort_keys=True) + "\n")

    def test_footprint_denies_nonexact_shape_unmarked_mode_and_ambient_entries(self):
        marked = [base.MODE, "--workload=mixed", "--strategy=footprint-desc", "--profile"]
        invalid = [
            (marked[1:], {}), (marked[1:] + ["--determinism-repeats=1001"], {}),
            ([base.MODE, "--workload=hot-streak", *marked[2:]], {}),
            ([base.MODE, "--workload=classic", *marked[2:]], {}),
            (marked + ["--txs=19999"], {}), (marked + ["--txs=20001"], {}),
            (marked + ["--keys=1"], {}), (marked + ["--keys=1999"], {}),
            (marked + ["--read-fanout=2"], {}), (marked + ["--write-every=2"], {}),
            (marked + ["--strategy", "footprint-desc"], {}),
            ([*marked[:2], "--strategy=FootprintDesc"], {}),
            ([*marked[:2], "--strategy=footprint-desC"], {}),
            ([*marked[:2], "--strategy=footprint-des"], {}),
            (marked, {b"TRNM_HOT_BUCKETS": b"8"}),
            (marked, {b"HIA_BENCH_FIXTURE_UNRELATED": b"synthetic-no-read"}),
        ]
        for i, (args, env) in enumerate(invalid):
            with self.subTest(args=args, env_keys=list(env)):
                r, *_ = self.standalone_process(f"footprint-denied-{i}", args, env=env)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (2, b"", base.OUTSIDE))
        r, *_ = self.standalone_process("footprint-repeat-over", [*marked, "--determinism-repeats=1001"])
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (2, b"", b"--determinism-repeats exceeds bounded maximum 1000\n"))
        profile = self.anchor / "run/bench"
        self.assertFalse(profile.exists() and list(profile.iterdir()))
