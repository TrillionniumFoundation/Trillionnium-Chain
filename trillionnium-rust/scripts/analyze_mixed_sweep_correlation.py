#!/usr/bin/env python3
import csv, glob, os
from pathlib import Path
from datetime import datetime

def latest(pat):
    xs=sorted(glob.glob(pat), key=os.path.getmtime, reverse=True)
    return xs[0] if xs else None

def f(x):
    try:return float(x)
    except:return 0.0

def i(x):
    try:return int(float(x))
    except:return 0

root=Path(__file__).resolve().parent.parent
bench=root/'run'/'bench'
csv_path=latest(str(bench/'bench-regression-mixed-sweep-*.csv'))
if not csv_path:
    raise SystemExit('no mixed sweep csv found')
rows=list(csv.DictReader(open(csv_path,'r',encoding='utf-8')))
cases={}
for r in rows:
    k=(r['txs'],r['keys'],r['read_fanout'],r['write_every'])
    cases.setdefault(k,{})[r['strategy']]=r
out=[]
for k,p in sorted(cases.items()):
    if 'original' not in p or 'aggressive-greedy' not in p: continue
    o,a=p['original'],p['aggressive-greedy']
    om,am=f(o['elapsed_ms']),f(a['elapsed_ms'])
    ratio=(am/om) if om else 0
    out.append({
      'txs':i(k[0]),'keys':i(k[1]),'rf':i(k[2]),'we':i(k[3]),'ratio':ratio,
      'scan':i(a.get('candidate_groups_scanned','0'))
    })

ts=datetime.now().strftime('%Y%m%d-%H%M%S')
md=bench/f'mixed-sweep-correlation-{ts}.md'
lines=['# Mixed Sweep Correlation Report',f'generated_at={datetime.now().isoformat()}',f'source_csv={csv_path}','',
'| txs | keys | read_fanout | write_every | aggr/orig | aggr_scan |','|---:|---:|---:|---:|---:|---:|']
for r in out:
    lines.append(f"| {r['txs']} | {r['keys']} | {r['rf']} | {r['we']} | {r['ratio']:.3f} | {r['scan']} |")
if out:
    ratios=[r['ratio'] for r in out]
    scans=[r['scan'] for r in out]
    lines += ['',f"avg_ratio={sum(ratios)/len(ratios):.3f}",f"max_ratio={max(ratios):.3f}",f"scan_min={min(scans)} scan_max={max(scans)}"]
md.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(md)
