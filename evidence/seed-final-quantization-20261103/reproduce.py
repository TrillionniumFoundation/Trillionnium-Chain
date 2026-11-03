"""Replay frozen runner outside the evidence folder, preserving original outputs."""
import contextlib,gzip,hashlib,importlib.util,json,shutil,tempfile
from pathlib import Path
p=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('frozen_runner',p/'run.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
with tempfile.TemporaryDirectory(prefix='chain-seed-quantization-replay-') as d:
 out=Path(d);shutil.copyfile(p/'PLAN.json',out/'PLAN.json');runner.HERE=out
 with (out/'report.json').open('w')as f,contextlib.redirect_stdout(f):runner.run()
 for name in ('report.json','weights.json'):
  expected=gzip.decompress((p/(name+'.gz')).read_bytes());actual=(out/name).read_bytes()
  assert actual==expected,name
  assert hashlib.sha256(expected).hexdigest()==json.loads((p/'decoded-hashes.json').read_text())[name]
print('PASS: independent output directory; report and weights byte-identical; frozen evidence unchanged.')
