"""Run actual independent Go ASERT process against Python exact-integer oracle.

Research-only. This is not W1 proof, consensus validation, or security acceptance.
The process executes bounded scalar cases with intentionally mismatched/overflowing
contexts and retains both successful targets and failure classifications.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import tempfile
from pathlib import Path
from daa_research_oracle import asert_target

FIXTURE_SEED = 20261025
N_CASES = 128
HALF_LIVES = (1, 2, 3600, 7200, 14400, 28800, (1 << 64) - 1)
MAX_U64 = (1 << 64) - 1
MAX_U256 = (1 << 256) - 1


def cases(count=N_CASES, seed=FIXTURE_SEED):
    if not 1 <= count <= 512 or not 0 <= seed <= MAX_U64:
        raise ValueError("cases/count/seed")
    r = random.Random(seed)
    for i in range(count):
        cap = r.choice((MAX_U256, (1 << 240) - 1, 1 << 255, 1 << 128))
        anchor = r.choice((1, 1 << 220, cap, r.randint(1, cap)))
        if anchor > cap:
            anchor = cap
        # Diverse high-value and negative signed deltas; all scalar fields u64.
        anchor_time = r.choice((0, 1_000_000, MAX_U64, r.getrandbits(64)))
        parent_time = r.choice((0, 1_000_000, MAX_U64, r.getrandbits(64)))
        anchor_height = r.choice((1, 50, MAX_U64 - 100, 1_000))
        candidate_height = min(MAX_U64, anchor_height + r.choice((1, 2, 999, 1_000_000)))
        spacing = r.choice((1, 10, 600, MAX_U64))
        if i % 13 == 0:
            # True i128 multiplication overflow in native ASERT ideal-span.
            anchor_height, candidate_height, spacing = 1, MAX_U64, MAX_U64
        elif i % 17 == 0:
            # Ideal fits i128, but multiplying its negative deviation by 2^16 doesn't.
            anchor_height, candidate_height, spacing = 1, MAX_U64, 1 << 62
        half_life = HALF_LIVES[i % len(HALF_LIVES)]
        yield {"anchor_target": anchor, "pow_limit": cap,
               "anchor_parent_time": anchor_time, "parent_time": parent_time,
               "anchor_height": anchor_height, "candidate_height": candidate_height,
               "spacing": spacing, "half_life": half_life}


def run(binary: Path, count=N_CASES, seed=FIXTURE_SEED, *, expose_rows=False):
    """Compare real Go process results; optional raw rows are test-only.

    Default return schema/digest remains unchanged for frozen evidence.
    """
    rows = []
    for i, x in enumerate(cases(count, seed)):
        args = [str(binary), "--anchor", f"{x['anchor_target']:064x}",
                "--limit", f"{x['pow_limit']:064x}"]
        for key, option in (("anchor_parent_time", "--anchor-parent-time"),
                            ("parent_time", "--parent-time"),
                            ("anchor_height", "--anchor-height"),
                            ("candidate_height", "--height"),
                            ("spacing", "--spacing"), ("half_life", "--half-life")):
            args += [option, str(x[key])]
        native = subprocess.run(args, text=True, capture_output=True, timeout=5, check=False)
        try:
            expected = asert_target(x['anchor_target'], x['anchor_parent_time'],
                                    x['parent_time'], x['anchor_height'],
                                    x['candidate_height'], x['spacing'],
                                    x['half_life'], x['pow_limit'])
            want = f"{expected:064x}"
            actual = native.stdout.strip()
            match = native.returncode == 0 and actual == want
            kind = "target"
        except ValueError as error:
            want = None
            actual = native.stderr.strip()
            # A parameter refusal is not an i128 range overflow. In the Go
            # reference these are distinct observable error domains; do not
            # reclassify a bad anchor/height/zero half-life as a range event.
            message = str(error)
            if message in (
                "anchor target", "pow limit", "ASERT anchor exceeds limit",
                "ASERT heights/spacing/half-life",
            ):
                expected_error = "ASERT_RESEARCH_PARAMETERS"
                kind = "rejected-parameters"
            elif message in (
                "ASERT ideal span overflows i128",
                "ASERT deviation overflows i128",
                "ASERT exponent overflows i128",
            ):
                expected_error = "ASERT_RESEARCH_RANGE"
                kind = "rejected-range"
            else:
                # Go flags/hex codecs have different input grammars from Python
                # scalar objects. Refuse ambiguous probes rather than credit a
                # match under a guessed error kind.
                raise ValueError("UNCOMPARABLE_ASERT_INPUT") from error
            match = native.returncode != 0 and actual == expected_error
        if not match:
            raise RuntimeError(f"independent oracle mismatch case={i} input={x} go_rc={native.returncode} got={actual!r} expected={want!r}")
        rows.append({"case": i, "kind": kind, "go_result": actual})
    report = {"schema": "pon-asert-go-python-differential-v1",
              "seed": seed, "cases": len(rows),
              "compared": sum(1 for x in rows if x['kind'] == 'target'),
              "rejected": sum(1 for x in rows if x['kind'] != 'target'),
              "all_equal": True,
              "outputs_sha256": hashlib.sha256(json.dumps(
                  rows, separators=(',', ':'), sort_keys=True).encode()).hexdigest(),
              "observed_go_binary": str(binary), "consensus_activation": False,
              "valid_w1_proofs": 0, "independent_operators": 0}
    if expose_rows:
        report["rows"] = rows
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--go-source', type=Path, default=Path(__file__).with_name('daa_reference_go') / 'main.go')
    p.add_argument('--count', type=int, default=N_CASES)
    p.add_argument('--seed', type=int, default=FIXTURE_SEED)
    p.add_argument('--output', type=Path)
    ns = p.parse_args()
    with tempfile.TemporaryDirectory(prefix='asert-go-diff-') as tmp:
        binary = Path(tmp) / 'asert-go'
        subprocess.run(['go', 'build', '-o', str(binary), str(ns.go_source)],
                       check=True, capture_output=True, timeout=90)
        report = run(binary, ns.count, ns.seed)
    report.pop('observed_go_binary', None)  # ephemeral path is not reproducible evidence
    text = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if ns.output:
        with ns.output.open('x', encoding='utf8') as handle:
            handle.write(text)
    else:
        print(text, end='')


if __name__ == '__main__':
    main()
