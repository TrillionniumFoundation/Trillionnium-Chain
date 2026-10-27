import sys
sys.path.insert(0, '/workspace/scratch/301262829a43/pon-work-impl/integration/w1-transparent9e05/trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0')
import signal,time,json
from pathlib import Path
import prove_segments as s
signal.signal(signal.SIGTERM,s.stopping)
steps=Path('/tmp/pon-segment-control-5x7ihfj4/steps')
a=s.Stage(steps,'deadline',[sys.executable,'-c',"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(20)"],0.05)
deadline=time.monotonic()+3
while b'ready' not in (steps/'deadline.stdout.log').read_bytes() and time.monotonic()<deadline: time.sleep(0.01)
assert b'ready' in (steps/'deadline.stdout.log').read_bytes()
while time.monotonic()-a.started<=a.timeout: time.sleep(0.01)
try:
 a.check(); raise AssertionError('deadline not enforced')
except TimeoutError: pass
assert not s.cleanup([a])
assert a.finished==-9
