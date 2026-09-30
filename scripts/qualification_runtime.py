"""Bind qualification subprocesses to the observer's actual Python environment."""
import json
import os
from pathlib import Path
import subprocess
import sys


def bind_python_runtime(environment):
    # Preserve the venv path: resolving its interpreter symlink selects system Python.
    environment = dict(environment)
    environment['PATH'] = str(Path(sys.executable).parent) + os.pathsep + environment.get('PATH', '')
    observation = json.loads(subprocess.check_output([
        'python3', '-c',
        'import sys,platform,json,numpy,cryptography; '
        'print(json.dumps(dict(executable=sys.executable,python=platform.python_version(),'
        'numpy=numpy.__version__,cryptography=cryptography.__version__)))',
    ], env=environment, text=True, timeout=30))
    return environment, observation
