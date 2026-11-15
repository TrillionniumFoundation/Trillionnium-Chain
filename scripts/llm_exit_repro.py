#!/usr/bin/env python3
"""Reproduce CPU torch teardown under the unchanged strict RSS supervisor.

This never loads training data or a model, never uses a GPU, and does not change
an observation failure into success. Each child and diagnostic belongs to a
new create-only output directory. Requires the project's pinned CPU venv.
"""
import argparse
import json
import os
from pathlib import Path
import sys

import llm_runtime_pilot as runtime

CHILD = '''import gc,json,sys,torch
assert torch.__version__ == "2.9.1+cpu", torch.__version__
torch.set_num_threads(4)
torch.set_num_interop_threads(1)
size,mode=int(sys.argv[1]),sys.argv[2]
value=torch.empty(size*1024*1024//4,dtype=torch.float32,device="cpu")
value.fill_(0.125)
weight=torch.nn.Parameter(torch.ones((1024,1024),dtype=torch.float32,device="cpu"))
loss=(weight@weight).square().mean()
loss.backward()
if mode == "explicit-gc":
    del value,weight,loss
    gc.collect()
print(json.dumps({"torch":torch.__version__,"mib":size,"mode":mode}),flush=True)
'''


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--runs', type=int, default=12)
    parser.add_argument('--mib', type=int, default=512)
    args = parser.parse_args()
    runtime.require(Path(args.python).is_absolute() and Path(args.output).is_absolute() and
                    1 <= args.runs <= 32 and 64 <= args.mib <= 3072, 'EXIT_REPRO_BOUNDS')
    root = Path(args.output)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    results = []
    for index in range(args.runs):
        mode = 'explicit-gc' if index % 2 else 'exit-retained'
        result = runtime.supervise([args.python, '-c', CHILD, str(args.mib), mode],
            root/f'child-{index:02d}', dict(wall_seconds=30, rss_bytes=4*1024**3))
        results.append(dict(index=index, mode=mode, **result))
        print(json.dumps(dict(index=index, mode=mode, outcome=result['outcome'],
            reason=result['stop_reason'], gaps=result['rss_observation_gaps'])), flush=True)
    runtime.save(root/'summary.json', dict(scope='owned-cpu-torch-teardown-diagnostics-only', results=results))
    return 1 if any(row['outcome'] != 'success' for row in results) else 0


if __name__ == '__main__':
    sys.exit(main())
