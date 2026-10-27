"""Real two-process SIGKILL / restart of one original W2-C epoch inode."""
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import tempfile
import unittest
from w2c_durable_epoch import DurableEpochOwner, EpochOwnerError


class RealCrashEpochControls(unittest.TestCase):
    def test_sigkill_releases_old_lock_but_cannot_reuse_its_epoch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'epoch'
            root.mkdir(mode=0o700)
            child = r'''
import sys,time
from w2c_durable_epoch import DurableEpochOwner
with DurableEpochOwner(sys.argv[1],entropy=lambda n:bytes([0x12])*n) as owner:
    print(owner.epoch().hex(),flush=True)
    time.sleep(30)
'''
            module_path = str(Path(__file__).resolve().parent)
            env = dict(os.environ)
            env['PYTHONPATH'] = module_path
            process = subprocess.Popen(
                [sys.executable, '-c', child, str(root)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            try:
                # Startup fsync and Python import may contend with other tests.
                # A retained deadline and a process-status diagnostic distinguish
                # actual startup failure from slow readiness; never count timeout
                # as crash-recovery acceptance.
                deadline = time.monotonic() + 15
                readable = []
                while not readable and time.monotonic() < deadline:
                    readable, _, _ = select.select(
                        [process.stdout], [], [], min(1, deadline-time.monotonic()))
                    if process.poll() is not None:
                        break
                if not readable:
                    status = process.poll()
                    stderr = process.stderr.read(4096) if status is not None else '<child-live>'
                    self.fail(f'child did not persist original Epoch: status={status} stderr={stderr}')
                prior = process.stdout.readline().strip()
                self.assertEqual(len(prior), 64)
                with self.assertRaisesRegex(EpochOwnerError, 'EPOCH_OWNER_BUSY'):
                    DurableEpochOwner(str(root))
                process.kill()
                self.assertEqual(process.wait(timeout=3), -9)
                with DurableEpochOwner(str(root), entropy=lambda n:bytes([0x13])*n) as recovered:
                    self.assertNotEqual(recovered.epoch().hex(), prior)
                    self.assertEqual(len(recovered.epoch()), 32)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                process.stdout.close()
                process.stderr.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
