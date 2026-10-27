"""Fixed tiny real-child diagnostic; never a model, throughput, or authority gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time

import llm_runtime_pilot as runtime
import llm_runtime_exit_mm_observation as mm

CHILD = '''import os,sys,time
data=bytearray(64*1024**2)
for offset in range(0,len(data),4096): data[offset]=1
remaining=(int(sys.argv[1])-time.monotonic_ns())/10**9
if remaining>0: time.sleep(remaining)
os._exit(0)
'''
BUDGET = dict(wall_seconds=2, rss_bytes=128*1024**2)
DELAYS_MS = tuple(100+7*index for index in range(16))


def resource_snapshot():
    root = Path('/sys/fs/cgroup')
    return {name:(root/name).read_text().strip() for name in
            ('memory.max', 'memory.current', 'memory.peak', 'memory.events')}


def main(output):
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    resources = resource_snapshot()
    runtime.require(resources['memory.max'].isdecimal() and resources['memory.current'].isdecimal()
        and int(resources['memory.max'])-int(resources['memory.current']) >= 256*1024**2,
        'EXIT_MM_PROBE_HOST_CAPACITY')
    source_paths = ('llm_runtime_pilot.py', 'llm_runtime_exit_observation.py',
                    'llm_runtime_exit_mm_observation.py', Path(__file__).name)
    sources = {name:runtime.file_sha(Path(__file__).parent/name) for name in source_paths}
    plan = dict(schema='llm-exit-mm-tiny-real-probe-v1', sources=sources,
        exit_profile=runtime.exit_observation_profile(mm.PROFILE), budget=BUDGET,
        allocation_bytes=64*1024**2, exit_delays_ms=list(DELAYS_MS),
        child_source_sha256=hashlib.sha256(CHILD.encode()).hexdigest(),
        python_sha256=runtime.file_sha(Path(sys.executable).resolve()),
        python_version=sys.version, reported_kernel=platform.release(),
        kernel_binary_attested=False, frozen_before_children=True,
        original_supervisor_sample_interval_ms=50, resources_before=resources,
        scope='Original wait4 supervisor, tiny owned Python child with direct os._exit; no model qualification')
    runtime.save(output/'plan.json', plan)
    records = []
    for index, delay in enumerate(DELAYS_MS):
        resources = resource_snapshot()
        runtime.require(int(resources['memory.max'])-int(resources['memory.current']) >= 256*1024**2,
                        'EXIT_MM_PROBE_HOST_CAPACITY')
        command = [sys.executable, '-I', '-B', '-c', CHILD, str(time.monotonic_ns()+delay*10**6)]
        result = runtime.supervise(command, output/f'child-{index:02d}', BUDGET,
            exit_observation=plan['exit_profile'])
        records.append(dict(index=index, delay_ms=delay, result=result))
        runtime.save(output/'outcomes.json', records)
    runtime.require(all(runtime.file_sha(Path(__file__).parent/name)==digest for name,digest in sources.items()),
                    'EXIT_MM_PROBE_SOURCE_CHANGED')
    captures = [row for row in records if row['result'].get('exit_cleanup_observation', {}).get('snapshots')]
    running = [row for row in captures if row['result']['exit_cleanup_observation']['snapshots'][0]
               .get('original_leader_state') == 'R']
    result = dict(schema='llm-exit-mm-tiny-real-result-v1', completed_children=len(records),
        supervisor_failed_children=[row['index'] for row in records if row['result']['outcome']!='success'],
        original_sample_captures=[row['index'] for row in captures],
        original_running_leader_captures=[row['index'] for row in running],
        observation='observed' if running else 'not-observed-in-fixed-bound',
        resources_after=resource_snapshot(), model_executed=False,
        independent_qualification=False, installed_child=False, kernel_binary_attested=False,
        scope='Reported host observation only; missing capture is inconclusive, and old failures remain failures')
    runtime.save(output/'result.json', result)
    print(json.dumps(result, sort_keys=True))
    return int(bool(result['supervisor_failed_children']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(main(parser.parse_args().output))
