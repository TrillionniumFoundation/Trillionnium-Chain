"""Interleaved exact-input native executor comparison; not ledger TPS or proof cost."""
from __future__ import annotations
import argparse, hashlib, json, os, random, statistics, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ledger import GENESIS, NETWORK, PARAMETER_HASH, H, canonical, execute_reference, key, public, sign, u64, genesis_state, unique
from bounded_process import run_bounded

def run(out, baseline, candidate, samples=7):
    if not 3 <= samples <= 31:
        raise ValueError('SAMPLES')
    out = Path(out); out.mkdir(parents=True, exist_ok=False)
    binaries = {'baseline': Path(baseline).resolve(), 'candidate': Path(candidate).resolve()}
    identities = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()}
    state = genesis_state()
    funding = [sign(key(0), i+1, 'transfer', dict(recipient=public(key(i+4)), amount=100000)) for i in range(64)]
    state, _ = execute_reference(state, funding, 1, public(key(0)), GENESIS)
    cases = {
      'independent-senders-and-recipients': [sign(key(i+4), 1, 'transfer', dict(recipient=H('independent-recipient', u64(i)), amount=1)) for i in range(64)],
      'independent-senders-hot-recipient': [sign(key(i+4), 1, 'transfer', dict(recipient=public(key(1)), amount=1)) for i in range(64)],
      'single-hot-sender-recipient': [sign(key(4), i+1, 'transfer', dict(recipient=public(key(1)), amount=1)) for i in range(64)],
    }
    results = []; random_order = random.Random(20260929)
    for scenario, transactions in cases.items():
        expected, receipts = execute_reference(state, transactions, 2, public(key(0)), H('comparison-parent'))
        request = dict(network=NETWORK.hex(), parameters=PARAMETER_HASH.hex(), state=state,
                       transactions=[t.hex() for t in transactions], height=2, miner=public(key(0)).hex(), parent=H('comparison-parent').hex())
        for workers in [1, 2, 4, 8]:
            request['workers'] = workers; data = canonical(request)
            request_digest = hashlib.sha256(data).hexdigest()
            for sample in range(-1, samples):
                # One warmup for each binary/shape; alternate order rather than timing
                # all old and then all new samples under a changing host load.
                order = list(binaries); random_order.shuffle(order)
                for name in order:
                    usage = out / f'usage-{scenario}-{workers}-{sample}-{name}.txt'
                    command = [str(binaries[name])]
                    measured = Path('/usr/bin/time').is_file()
                    if measured: command = ['/usr/bin/time', '-f', '%M %U %S', '-o', str(usage)] + command
                    start = time.perf_counter_ns(); response = run_bounded(command, data); wall = time.perf_counter_ns() - start
                    if response.returncode: raise ValueError('NATIVE_COMPARISON: '+response.stderr.decode(errors='replace'))
                    actual = json.loads(response.stdout, object_pairs_hook=unique)
                    if actual['state'] != expected or [bytes.fromhex(x) for x in actual['receipts']] != receipts:
                        raise ValueError('PARALLEL_PARITY')
                    if actual['network'] != NETWORK.hex() or actual['parameters'] != PARAMETER_HASH.hex():
                        raise ValueError('CONTEXT')
                    if name == 'candidate':
                        if actual['metrics']['workers_spawned'] > workers or actual['metrics']['signature_verifications'] != len(transactions):
                            raise ValueError('RESOURCE_ACCOUNTING')
                    if sample < 0: continue
                    results.append(dict(scenario=scenario, workers=workers, sample=sample, binary=name,
                        input_sha256=request_digest, transactions=len(transactions), transaction_bytes=sum(map(len, transactions)),
                        root=actual['root'], receipt_digest=H('comparison-receipts', *receipts).hex(), metrics=actual['metrics'],
                        wall_ns_including_process=wall, peak_rss_kib=int(usage.read_text().split()[0]) if measured else None,
                        state_keys=len(expected), state_bytes=len(canonical(expected)), vram_bytes=None, gpu_used=False,
                        submitted=None, queued=None, executed=len(transactions), included=None, client_confirmed=None,
                        proof_verification_ns=None, confirmation_policy='not exercised'))
    summary=[]
    for scenario in cases:
        for workers in [1,2,4,8]:
            selected=[r for r in results if r['scenario']==scenario and r['workers']==workers]
            values={name:[int(r['metrics']['elapsed_ns']) for r in selected if r['binary']==name] for name in binaries}
            b=statistics.median(values['baseline']); c=statistics.median(values['candidate'])
            summary.append(dict(scenario=scenario,workers=workers,baseline_median_ns=b,candidate_median_ns=c,
                                candidate_to_baseline=c/b,regression_observed=c>b))
    report=dict(schema='pon-interleaved-executor-comparison-v1', binary_sha256=identities,
        baseline_source='209f742279044327ad8c763012b6fdda54e5e61e',
        candidate_source=subprocess.check_output(['git','rev-parse','HEAD'],text=True,cwd=Path(__file__).resolve().parents[3]).strip(),
        source_clean=not subprocess.check_output(['git','status','--porcelain'],text=True,cwd=Path(__file__).resolve().parents[3]).strip(),
        sample_count_per_case=samples, randomized_interleaving_seed=20260929, warmups_per_case_and_binary=1,
        includes_process_start=False, wall_field_includes_process_start=True, native_application_only=True,
        consensus_tps_claimed=False, independent_accepted=False, production_activation=False,
        samples=results, summary=summary)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'samples':len(results),'summary':summary,'consensus_tps_claimed':False}),flush=True)

if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);parser.add_argument('--baseline',required=True)
    parser.add_argument('--candidate',required=True);parser.add_argument('--samples',type=int,default=7)
    args=parser.parse_args();run(args.out,args.baseline,args.candidate,args.samples)
