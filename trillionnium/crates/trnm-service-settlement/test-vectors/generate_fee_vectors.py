"""Regenerate exact fee vectors using Python's independent arbitrary-size integers."""
import json
import random
from pathlib import Path

maximum = (1 << 128) - 1
edges = [0, 1, 2, 3, (1 << 64) - 1, 1 << 64, (1 << 127) - 1,
         1 << 127, (1 << 127) + 1, maximum - 1, maximum]
cases = set()
for amount in edges:
    for denominator in edges[1:]:
        for numerator in {0, 1, denominator // 2, denominator - 1, denominator}:
            cases.add((amount, numerator, denominator))
rng = random.Random(20261015)
for _ in range(512):
    denominator = rng.randrange(1, maximum + 1)
    cases.add((rng.getrandbits(128), rng.randrange(denominator + 1), denominator))
rows = [[str(a), str(n), str(d), str(a * n // d)] for a, n, d in sorted(cases)]
Path(__file__).with_name('protocol_fee_u128.json').write_text('[\n' + ',\n'.join(json.dumps(row, separators=(',', ':')) for row in rows) + '\n]\n')
