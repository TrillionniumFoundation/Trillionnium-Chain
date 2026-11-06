import json,subprocess
from pathlib import Path
repo=Path('/home/qian-qi/work/chain-throughput-20261106-ee79/repo')
paths=['trillionnium/crates/trnm-pon-node/tests/architecture_delivery_compare.rs','trillionnium/crates/trnm-pon-node/tests/support/current_elf_host.rs','trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs','trillionnium/crates/trnm-pon-node/src/ingress.rs']
commands=[
['git','rev-parse','HEAD','HEAD^{tree}'],
['git','status','--porcelain=v1','--untracked-files=all'],
['git','rev-parse','54ea3ef3^{commit}'],
['git','log','--format=%h %s','54ea3ef3..e7466106a2a647c8032556273101440384d88b70','--',*paths],
['git','diff','--stat','54ea3ef3..e7466106a2a647c8032556273101440384d88b70','--',*paths],
['git','diff','54ea3ef3..e7466106a2a647c8032556273101440384d88b70','--',*paths[:2]],
]
for argv in commands:
 p=subprocess.run(argv,cwd=repo,capture_output=True,text=True,timeout=30)
 print(json.dumps({'argv':argv,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}),flush=True)
