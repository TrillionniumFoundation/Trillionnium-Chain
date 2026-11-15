#!/usr/bin/env python3
"""Execute unchanged Cargo executor and real HIA native candidate separately.

Missing Cargo/rustc or missing original sources is NOT_RUN (exit 2), never a
skip/pass. Source disagreement, panic on valid input, unsafe native output or
unexplained behavior differences are FAIL (exit 1). The only intended correction
is the per-key maximum reader group, represented by two independent set models.
No network download, compiler substitution or source rewriting is performed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import platform
import random
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hia.tests.native_support import NativeModule
from hia.tests.test_executor_schedule import (Config, Tx, U64, SOURCE,
    adaptive_reference, decoded_output, domains, float_bits, frame,
    graph_violations, original_counterexample, schedule_reference, sizes, tx)

PINS = ROOT / 'hia/tests/oracles/executor_original_sources.json'
ADAPTER = ROOT / 'hia/tests/oracles/executor_original.rs'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_original(repository):
    pins = json.loads(PINS.read_bytes())
    observed = {}
    for row in pins['sources']:
        path = repository / row['path']
        raw = path.read_bytes()
        if len(raw) != row['bytes'] or sha256(raw) != row['sha256']:
            raise AssertionError('original source pin differs: '+row['path'])
        observed[row['path']] = {'bytes':len(raw), 'sha256':sha256(raw)}
    return observed


def corpus():
    """Stable deterministic corpus; payload identity is opaque to both kernels."""
    rows = []
    base = Config()
    for strategy in range(7):
        rows.append((original_counterexample(), strategy, base, 0))
    choices = [tx(0), tx(0,[0]), tx(0,[],[0]), tx(0,[1]),
               tx(0,[],[1]), tx(0,[0,1]), tx(0,[0],[1]), tx(0,[0],[0])]
    for ordinal, indices in enumerate(itertools.product(range(8),repeat=4)):
        items = [replace(choices[value],identity=(position+ordinal)%3)
                 for position,value in enumerate(indices)]
        strategy = ordinal%7
        flags = (1,3,5,7)[ordinal%4] if strategy == 6 else 6
        rows.append((items,strategy,replace(base,flags=flags,seed=U64-ordinal,
                                           window=(0,1,2)[ordinal%3]),0))
    rng = random.Random(0x0A1C1E)
    keys = [0,1,2,3,4,5,7,8,31,1<<32,1<<63,U64]
    for _ in range(120):
        items = [tx(rng.choice([0,1,U64,index]),
                    [rng.choice(keys) for _ in range(rng.randrange(7))],
                    [rng.choice(keys) for _ in range(rng.randrange(7))],
                    rng.randbytes(rng.randrange(17)),version=rng.getrandbits(64))
                 for index in range(rng.randrange(1,80))]
        config = replace(base,flags=rng.randrange(8),buckets=rng.randrange(4,65),
                         minimum_batch=64,sample=rng.choice([64,65,511,2048]),
                         window=rng.choice([0,1,2,17,4096]),seed=rng.getrandbits(64))
        rows.extend((items,strategy,config,0) for strategy in range(7))
    for flags in range(8):
        for window in (0,1,2,4096):
            for seed in (0,1,U64):
                rows.append((original_counterexample()+[tx(9),tx(1,[0])],6,
                             replace(base,flags=flags,window=window,seed=seed),0))
    for buckets in range(4,65):
        items = [tx(i,[key]) for i,key in enumerate([3]*5+[1,5,2,2,2,2])]
        rows.append((items,4,replace(base,buckets=buckets),0))
        items = [tx(i,[],[key]) for i,key in enumerate([U64,1<<63,0,1<<32]*7)]
        rows.append((items,4,replace(base,buckets=buckets),0))
    configs = [replace(base,minimum_batch=64,sample=64),
               replace(base,minimum_batch=64,threshold=1<<63,margin=1<<63,
                       minimum_hot=1<<63,minimum_gain=1<<63),
               replace(base,minimum_batch=64,threshold=1,margin=(1<<52)-1,
                       minimum_hot=1,minimum_gain=1),
               replace(base,minimum_batch=64,minimum_hot=float_bits(.75)),
               replace(base,minimum_batch=64,minimum_gain=float_bits(.9))]
    samples = [[],[tx(i) for i in range(64)], [tx(i,[1]) for i in range(64)],
               [tx(i,[i%2]) for i in range(64)],
               [tx(i,[1]) if i%2 else tx(i) for i in range(64)],
               [tx(i,[0,1,2],[0,3,4]) if i%3 == 0 else tx(i,[5,7],[5,6])
                if i%3 == 1 else tx(i,[2,6],[5,8]) for i in range(64)]]
    rows.extend((items,5,config,operation) for config in configs for items in samples
                for operation in (0,2))
    streak = [tx(i,[1 if i<49 else i]) for i in range(64)]
    config = replace(base,minimum_batch=64,sample=64)
    measured = adaptive_reference(streak,config)
    for field,value in [('threshold',measured[3]),('minimum_hot',measured[6]),
                        ('minimum_gain',measured[8])]:
        for adjacent in (value-1,value,value+1):
            for margin in (0,1):
                candidate = replace(config,threshold=0,margin=margin,minimum_hot=0,minimum_gain=0)
                rows.append((streak,5,replace(candidate,**{field:adjacent}),2))
    for count,sample in [(65,64),(2049,2048),(4097,64),(4097,2048)]:
        items = [tx(i,[1 if i>count//3 else (i%19)+2]) for i in range(count)]
        items[0],items[-1] = tx(0,[U64]),tx(U64,[0])
        rows.append((items,5,replace(base,minimum_batch=64,sample=sample),2))
    rows.extend((pair,0,base,1) for pair in
        [[tx(1,[0],version=0),tx(1,[0],version=U64)],
         [tx(1,[0],version=0),tx(1,[],[0],version=U64)],
         [tx(1,[],[U64]),tx(1,[],[U64])],[tx(1),tx(1)]])
    skew = [Tx(1,((0,0),(0,1))), Tx(1,(),((U64,0),(U64,U64))),
            Tx(1,((1,1),),((1,2),))]
    for invalid in skew:
        rows.extend(([invalid],strategy,base,0) for strategy in range(7))
        rows.append(([invalid],0,base,2))
        rows.append(([invalid,tx(2)],0,base,1))
    # Distinct opaque bytes identify clones without changing ids or access sets.
    return [([replace(item,payload=b'QIDX'+struct.pack('<Q',i)+item.payload)
              for i,item in enumerate(items)],strategy,config,operation)
            for items,strategy,config,operation in rows]


def cargo_link_inputs(raw, target_directory):
    """Use only library filenames reported by this Cargo invocation.

    Cargo may publish the selected rlib at the profile root while its metadata
    and transitive dependencies live elsewhere. Do not infer a directory from
    that one rlib, scan a cache, or silently choose between repeated externs.
    """
    target_directory = target_directory.resolve()
    required = {'trnm_executor', 'trnm_types'}
    library_kinds = {'lib', 'rlib', 'dylib', 'cdylib', 'staticlib', 'proc-macro'}
    artifacts = {}
    directories = set()
    finished = False
    for line in raw.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise AssertionError('invalid Cargo JSON event')
        if event.get('reason') == 'build-finished':
            if finished or event.get('success') is not True:
                raise AssertionError('Cargo did not report one successful build')
            finished = True
        if event.get('reason') != 'compiler-artifact':
            continue
        target = event.get('target')
        if not isinstance(target, dict) or not isinstance(target.get('kind'), list):
            raise AssertionError('invalid Cargo artifact target')
        if not all(isinstance(kind, str) for kind in target['kind']):
            raise AssertionError('invalid Cargo artifact kind')
        if not library_kinds.intersection(target['kind']):
            continue
        name = target.get('name')
        if not isinstance(name, str) or not name:
            raise AssertionError('invalid Cargo library target name')
        filenames = event.get('filenames')
        if (not isinstance(filenames, list) or not filenames
                or not all(isinstance(name, str) for name in filenames)
                or len(filenames) != len(set(filenames))):
            raise AssertionError('invalid or duplicate Cargo library filenames')
        paths = []
        for filename in filenames:
            path = Path(filename)
            if (not path.is_absolute() or str(path) != filename or '..' in path.parts
                    or not path.is_relative_to(target_directory)):
                raise AssertionError('Cargo library artifact outside this build target: '+filename)
            paths.append(path)
            directories.add(path.parent)
        if name in required:
            libraries = [path for path in paths if path.suffix == '.rlib']
            if name in artifacts or len(libraries) != 1:
                raise AssertionError('duplicate or ambiguous Cargo library artifact: '+name)
            artifacts[name] = libraries[0]
    if not finished or set(artifacts) != required:
        raise AssertionError('Cargo did not identify both real libraries in a successful build')
    return artifacts, sorted(directories, key=str)


def compile_original(repository, work, cargo, rustc):
    command = [cargo,'build','--locked','--manifest-path',str(repository/'trillionnium/Cargo.toml'),
               '--package','trnm-executor','--lib','--target-dir',str(work/'target'),
               '--message-format=json']
    completed = subprocess.run(command,capture_output=True,text=True,timeout=600,check=False)
    (work/'cargo-build.jsonl').write_text(completed.stdout)
    (work/'cargo-build.stderr').write_text(completed.stderr)
    if completed.returncode:
        raise RuntimeError('unchanged Cargo executor build failed; see '+str(work/'cargo-build.stderr'))
    artifacts, dependency_directories = cargo_link_inputs(completed.stdout, work/'target')
    executable = work/'executor-original'
    command = [rustc,'--edition=2021','-C','opt-level=1','-C','debug-assertions=yes',
               '-C','overflow-checks=yes',str(ADAPTER),'-o',str(executable)]
    for name,path in sorted(artifacts.items()):
        command.extend(['--extern',name+'='+str(path)])
    for directory in dependency_directories:
        command.extend(['-L','dependency='+str(directory)])
    (work/'adapter-build.command.json').write_text(json.dumps(command,indent=2)+'\n')
    completed = subprocess.run(command,capture_output=True,text=True,timeout=120,check=False)
    (work/'adapter-build.stderr').write_text(completed.stderr)
    if completed.returncode:
        raise RuntimeError('original library adapter compilation failed; see '+str(work/'adapter-build.stderr'))
    return executable, {name:{'sha256':sha256(path.read_bytes()),'bytes':path.stat().st_size}
                        for name,path in artifacts.items()}


def read_original_output(raw, count):
    position = 0
    answers = []
    for _ in range(count):
        if len(raw)-position < 16:
            raise AssertionError('original reference truncated its terminal protocol')
        status,size = struct.unpack_from('<QQ',raw,position)
        position += 16
        if size > len(raw)-position:
            raise AssertionError('original reference truncated its payload')
        answers.append((status,raw[position:position+size]))
        position += size
    if position != len(raw):
        raise AssertionError('original reference emitted trailing observations')
    return answers


def qualify(repository, work, cargo, rustc, record):
    record['original_sources'] = verify_original(repository)
    record['adapter_sha256'] = sha256(ADAPTER.read_bytes())
    record['rustc_version'] = subprocess.run([rustc,'-Vv'],capture_output=True,text=True,check=True).stdout
    record['cargo_version'] = subprocess.run([cargo,'-V'],capture_output=True,text=True,check=True).stdout.strip()
    executable, artifacts = compile_original(repository,work,cargo,rustc)
    record['original_library_artifacts'] = artifacts
    record['original_adapter_artifact_sha256'] = sha256(executable.read_bytes())
    rows = corpus()
    frames = [frame(*row[:3],operation=row[3]) for row in rows]
    protocol = b''.join(struct.pack('<Q',len(raw))+raw for raw in frames)
    record['corpus_sha256'] = sha256(protocol)
    record['corpus_count'] = len(rows)
    original = subprocess.run([str(executable)],input=protocol,capture_output=True,timeout=120,check=False)
    (work/'original-execution.stderr').write_bytes(original.stderr)
    if original.returncode:
        raise AssertionError('original reference process did not complete: '+str(original.returncode))
    original_answers = read_original_output(original.stdout,len(rows))
    record['original_observations_sha256'] = sha256(original.stdout)
    record['original_execution'] = 'RAN'
    record['native_calls'] = 0
    differences = []
    native_digest = hashlib.sha256()
    panic_count = 0
    with NativeModule(SOURCE,byte_exports=('f0',)) as native:
        record['native_build_receipt'] = native.receipt
        record['native_artifact_sha256'] = native.artifact_sha256
        for begin in range(0,len(rows),32):
            chunk = rows[begin:begin+32]
            calls = []
            for index,(items,_,_,operation) in enumerate(chunk):
                output,scratch = sizes(items,operation)
                calls.append(('f0',[frames[begin+index],b'\xa7'*(output+11),b'\xc4'*(scratch+13)]))
            results = native.call_many(calls,timeout=60)
            record['native_calls'] += len(results)
            for offset,(row,call,result) in enumerate(zip(chunk,calls,results)):
                index = begin+offset
                items,strategy,config,operation = row
                result.require_returned()
                old_status,old_bytes = original_answers[index]
                try:
                    domains(items)
                except ValueError:
                    if old_status != 1 or result.value != 5 or result.arguments[1] != call[1][1]:
                        raise AssertionError('version-skew rejection disagrees at case '+str(index))
                    panic_count += 1
                    native_digest.update(struct.pack('<Q',result.value))
                    continue
                if old_status != 0 or result.value != 0:
                    raise AssertionError('valid case failed at '+str(index)+': '+str((old_status,result.value)))
                observed_old,written_old = decoded_output(old_bytes,len(items),operation)
                if written_old != len(old_bytes):
                    raise AssertionError('original result extent mismatch')
                old_model = schedule_reference(items,strategy,config,False,operation)
                repaired_model = schedule_reference(items,strategy,config,True,operation)
                if observed_old != old_model:
                    record['unexplained_failure'] = {'case':index,'input_hex':frames[index].hex(),
                        'original_observed':observed_old,'legacy_model':old_model}
                    raise AssertionError('real original disagrees with legacy reference at '+str(index))
                observed_new,written = decoded_output(result.arguments[1],len(items),operation)
                if observed_new != repaired_model:
                    record['unexplained_failure'] = {'case':index,'input_hex':frames[index].hex(),
                        'native_observed':observed_new,'repaired_model':repaired_model}
                    raise AssertionError('native disagrees with repaired reference at '+str(index))
                if result.arguments[0] != call[1][0] or result.arguments[1][written:] != call[1][1][written:]:
                    raise AssertionError('native changed source or output tail')
                if result.arguments[2][sizes(items,operation)[1]:] != b'\xc4'*13:
                    raise AssertionError('native changed scratch tail')
                native_digest.update(struct.pack('<Q',written)+result.arguments[1][:written])
                if operation == 0:
                    if sorted(itertools.chain.from_iterable(observed_new['groups'])) != list(range(len(items))):
                        raise AssertionError('native lost or repeated a transaction')
                    if graph_violations(items,observed_new['groups']):
                        raise AssertionError('native emitted a conflicting group')
                if observed_old != observed_new:
                    differences.append({'case':index,'input_sha256':sha256(frames[index]),
                        'strategy':strategy,'count':len(items),'config':config.words(),
                        'original':observed_old,'native':observed_new,
                        'original_conflicts':graph_violations(items,observed_old['groups'])})
    verify_original(repository)
    record['native_observations_sha256'] = native_digest.hexdigest()
    record['original_expected_version_panics'] = panic_count
    record['intentional_reader_high_water_differences'] = differences
    record['difference_strategy_counts'] = dict(Counter(row['strategy'] for row in differences))
    record['original_unsafe_case_count'] = sum(bool(row['original_conflicts']) for row in differences)
    record['status'] = 'PASS_WITH_EXPLICIT_ORIGINAL_SAFETY_DEFECT'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',type=Path,required=True,help='unchanged original Chain checkout')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,required=True,help='new isolated build/log directory')
    arguments = parser.parse_args()
    started = time.monotonic()
    record = {'schema':'trnm.hia.executor-original-qualification.v1','status':'NOT_RUN',
              'original_execution':'NOT_RUN','source_sha256':sha256(SOURCE.read_bytes()),
              'native_kernel_complete':False,'whole_executor_crate_native':False,
              'environment_parser_native':False,'derived_ln_metrics_native':False,
              'ordinary_node_dependency':False,'whole_chain_native':False,
              'service_performance_qualified':False}
    exit_code = 2
    try:
        repository = arguments.repository.resolve(strict=True)
        record['original_sources'] = verify_original(repository)
        cargo,rustc = shutil.which('cargo'),shutil.which('rustc')
        if not cargo or not rustc:
            record['reason'] = 'cargo and/or rustc unavailable; unchanged Rust was not executed'
        elif platform.machine() != 'x86_64':
            record['reason'] = 'qualification target requires original Linux x86_64 behavior'
        else:
            arguments.work_dir.mkdir(parents=True,exist_ok=False)
            qualify(repository,arguments.work_dir.resolve(),cargo,rustc,record)
            record['native_kernel_complete'] = True
            exit_code = 0
    except (OSError,ValueError,AssertionError,RuntimeError,subprocess.SubprocessError) as error:
        record['status'] = 'FAIL'
        record['reason'] = str(error)
        exit_code = 1
    record['wall_seconds'] = time.monotonic()-started
    arguments.output.parent.mkdir(parents=True,exist_ok=True)
    arguments.output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'status':record['status'],'output':str(arguments.output),
                      'reason':record.get('reason'),'native_calls':record.get('native_calls',0)}))
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
