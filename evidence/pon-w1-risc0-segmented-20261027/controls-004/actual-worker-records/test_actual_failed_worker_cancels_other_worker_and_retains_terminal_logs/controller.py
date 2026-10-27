import sys
sys.path.insert(0, '/workspace/scratch/301262829a43/pon-work-impl/integration/w1-transparent9e05/trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0')
import signal,time,json
from pathlib import Path
import prove_segments as s
signal.signal(signal.SIGTERM,s.stopping)
steps=Path('/tmp/pon-segment-control-83hk0tfn/steps')
a=s.Stage(steps,'failed',[sys.executable,'-c',"print('worker-a'); raise SystemExit(7)"],2)
b=s.Stage(steps,'cancelled',[sys.executable,'-c',"import signal,time,sys; signal.signal(signal.SIGTERM,lambda *_: (print('worker-b-tail',file=sys.stderr,flush=True),sys.exit(23))); print('ready',flush=True); time.sleep(20)"],2)
deadline=time.monotonic()+3
while b'ready' not in (steps/('cancelled.stdout.log')).read_bytes() and time.monotonic()<deadline: time.sleep(0.01)
assert b'ready' in (steps/'cancelled.stdout.log').read_bytes()
while a.poll() is None and time.monotonic()-a.started<a.timeout: time.sleep(0.01)
assert a.finished==7, 'worker A did not reach its actual expected terminal'
try:
 a.check(); raise AssertionError('actual nonzero not rejected')
except RuntimeError: pass
assert not s.cleanup([a,b])
assert a.finished==7 and b.finished==23
