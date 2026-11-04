"""Runtime allowlist for application file reads during independent validation."""
import json
import sys
from pathlib import Path
import verify

allowed = {p.resolve() for p in verify.PACKAGE.iterdir() if p.is_file()}
allowed.update((verify.TRAIN.resolve(), verify.CONTROL.resolve()))
opened = set()


def audit(event, args):
    if event != 'open' or not isinstance(args[0], (str, bytes)):
        return
    path = Path(args[0]).resolve()
    if path not in allowed:
        raise RuntimeError('Application read outside frozen package/TRAIN/control allowlist: ' + str(path))
    opened.add(str(path.relative_to(verify.ROOT)))


# Imports occur above the hook; no training/repository computation module is imported.
sys.addaudithook(audit)
result = verify.validate(*verify.load())
print(json.dumps({'result': result['result'], 'scope': 'Python open events after verifier imports; not an OS syscall sandbox', 'opened_files': sorted(opened), 'training_modules_imported': any(k in sys.modules for k in ('experiments.model_loop', 'evaluation', 'frozen_runner')), 'held_out_task_reads': 0}, indent=2))
