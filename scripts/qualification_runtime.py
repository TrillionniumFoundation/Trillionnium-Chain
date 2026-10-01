"""Bind qualification subprocesses and read optional observer measurements."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def read_gnu_time_peak_rss(usage):
    """Return recorded GNU time RSS, or None when its measurement is unavailable.

    Killing the whole subprocess group can kill GNU time before it writes a
    summary. Missing, empty or malformed output must not hide the child's actual
    exit status or timeout. Zero is returned only when the file records zero.
    """
    try:
        lines = Path(usage).read_text().splitlines()
        if not lines:
            return None
        values = lines[-1].split()
        if (len(values) != 3 or not re.fullmatch(r'[0-9]+', values[0])
                or any(not re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value)
                       for value in values[1:])):
            return None
        return int(values[0])
    except (OSError, UnicodeError, ValueError):
        return None


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
