#!/usr/bin/env python3
"""One exact public dependency download; no compiler, extraction or proving."""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import time
import urllib.request

URL = 'https://static.crates.io/crates/risc0-build/risc0-build-3.0.6.crate'
EXPECTED = 'bd8216cdd9f573808a94769767480b06ad1e74ae60841c9582fdf51b8e29ba53'
LIMIT = 2 * 1024 * 1024
OUT = Path('/tmp/w1-batch-phase0-attempt2-download-20261028-r8')
DEST = Path('/tmp/pure-pon-cargo-20261027/registry/cache/index.crates.io-1949cf8c6b5b557f/risc0-build-3.0.6.crate')


def alarm(_signal, _frame):
    raise TimeoutError('35 second total dependency-download deadline')


def main():
    OUT.mkdir(exist_ok=False)
    declared = {'schema': 'TRNM-W1-BATCH-PHASE0-ATTEMPT2-DOWNLOAD1', 'url': URL,
                'expected_sha256': EXPECTED, 'maximum_bytes': LIMIT,
                'socket_timeout_seconds': 30, 'total_deadline_seconds': 35,
                'destination': str(DEST), 'started_unix_ns': time.time_ns(),
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'purpose': 'explicitly authorized second attempt: repair sandbox-blocked transport only',
                'prior_attempt_result_sha256': 'a3df8f28c13dc78a369289ad9eae672abb07dc046ab13d8c0dba4f324539d09d',
                'compiler_restored': False, 'native_build_started': False,
                'guest_executed': False, 'receipt_verified': False, 'prover_executed': False}
    (OUT/'declaration.json').write_text(json.dumps(declared, indent=2)+'\n')
    started = time.monotonic()
    signal.signal(signal.SIGALRM, alarm)
    signal.setitimer(signal.ITIMER_REAL, 35)
    result = dict(declared)
    try:
        if DEST.exists():
            raise RuntimeError('destination already exists; no overwrite or unreviewed adoption')
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(LIMIT + 1)
            result['final_url'] = response.geturl()
        actual = hashlib.sha256(data).hexdigest()
        if len(data) > LIMIT or actual != EXPECTED:
            raise RuntimeError('exact registry archive size/checksum failed')
        with DEST.open('xb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        result.update(outcome='CHECKSUM_BOUND_PUBLIC_DOWNLOAD_COMPLETE', bytes=len(data), sha256=actual)
    except BaseException as error:
        result.update(outcome='FAILED', error=repr(error))
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result.update(finished_unix_ns=time.time_ns(), wall_seconds=time.monotonic()-started,
                      process_user_seconds=usage.ru_utime, process_system_seconds=usage.ru_stime,
                      process_maxrss_bytes=usage.ru_maxrss*1024)
        (OUT/'result.json').write_text(json.dumps(result, indent=2)+'\n')
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
