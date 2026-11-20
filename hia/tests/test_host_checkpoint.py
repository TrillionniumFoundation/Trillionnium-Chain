"""Evidence/CLI controls; synthetic traces are not physical syscall evidence."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hia.platform.host_checkpoint import build, qualify


def synthetic_trace():
    rows=['execve("/proc/self/fd/9", ["/proc/self/fd/9"], 0x0) = 0',
          'mmap(NULL, 16384, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x700000',
          'mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x710000']
    old=None
    for index,path in enumerate(['.','sys','fs','cgroup','trnmponpublic.slice']):
        fd=3+index%2
        directory='AT_FDCWD' if old is None else str(old)
        flags='O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH'
        if index!=4:flags+='|O_DIRECTORY'
        rows.append(f'openat({directory}, "{path}", {flags}) = {fd}')
        if old is not None:rows.append(f'close({old}) = 0')
        old=fd
    rows.extend([f'fstat({old}, {{st_mode=S_IFDIR|0700}}) = 0',f'close({old}) = 0',
                 'newfstatat(AT_FDCWD, "controllers", {st_mode=S_IFREG|0644}, 0) = 0',
                 f'newfstatat(AT_FDCWD, "{qualify.PARENT}", {{st_mode=S_IFDIR|0700}}, AT_SYMLINK_NOFOLLOW) = 0'])
    def stream(path,fd,dirfd='AT_FDCWD',limit=False):
        flags='O_RDONLY|O_CLOEXEC'+('|O_NOFOLLOW|O_NONBLOCK' if limit else '')
        rows.append(f'openat({dirfd}, "{path}", {flags}) = {fd}')
        if limit:rows.append(f'fstat({fd}, {{st_mode=S_IFREG|0600}}) = 0')
        rows.extend([f'read({fd}, "data", 129) = 4',f'read({fd}, "", 125) = 0',f'close({fd}) = 0'])
    def checkpoint(initial=False):
        stream('boot',3)
        rows.extend([f'openat(AT_FDCWD, "{qualify.PARENT}", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY) = 3',
                     'fstat(3, {st_mode=S_IFDIR|0700}) = 0'])
        if not initial:stream('membership',4)
        for name in qualify.LIMITS:stream(name,4,dirfd='3',limit=True)
        if not initial:
            rows.append(f'newfstatat(AT_FDCWD, "{qualify.PARENT}", {{st_mode=S_IFDIR|0700}}, AT_SYMLINK_NOFOLLOW) = 0')
        rows.append('close(3) = 0')
    checkpoint(initial=True)
    checkpoint()
    rows.extend(['write(1, "receipt", 128) = 128','read(0, "command", 24) = 24'])
    checkpoint()
    rows.extend(['write(1, "receipt", 128) = 128','read(0, "", 24) = 0','exit(0) = ?'])
    return '\n'.join(rows)+'\n'


class HostEvidenceTests(unittest.TestCase):
    def test_absolute_cli_works_from_independent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (build.HERE/'build.py',build.HERE/'qualify.py'):
                result=subprocess.run([sys.executable,'-B',str(path),'--help'],
                    cwd=directory,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr.decode())
                self.assertIn(b'--output',result.stdout)

    def test_optimized_python_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for path in (build.HERE/'build.py',build.HERE/'qualify.py'):
                for arguments,setting in ((['-O'],None),(['-OO'],None),([], '2')):
                    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
                    if setting is not None:env['PYTHONOPTIMIZE']=setting
                    else:env.pop('PYTHONOPTIMIZE',None)
                    result=subprocess.run([sys.executable,*arguments,'-B',str(path),'--help'],
                        cwd=directory,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn(b'refuses optimized Python',result.stderr)

    def test_complete_original_sources_are_bound_and_tamper_is_rejected(self):
        original=('trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs',
                  'trillionnium/crates/trnm-pon-node/src/error.rs')
        manifest=build.source_manifest()
        for path in original:
            self.assertIn(path,manifest)
            self.assertGreater(manifest[path]['bytes'],30000)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in build.INPUTS:
                target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((build.ROOT/name).read_bytes())
            with patch.object(build,'ROOT',root),patch.object(build.PinnedBuild,'check_pin',return_value=None):
                owner=object.__new__(build.Build)
                owner.host_manifest=build.source_manifest()
                owner.check_pin()
                target=root/original[0];saved=target.read_bytes()
                target.write_bytes(saved+b'\n')
                with self.assertRaisesRegex(ValueError,'comparison source changed'):owner.check_pin()
                target.unlink()
                with self.assertRaises(ValueError):owner.check_pin()
                elsewhere=root/'unchanged.rs';elsewhere.write_bytes(saved);target.symlink_to(elsewhere)
                with self.assertRaises(ValueError):owner.check_pin()
                target.unlink();target.write_bytes(saved)
                owner.check_pin()

    def test_synthetic_trace_parser_rejects_missing_boundaries(self):
        good=synthetic_trace()
        parsed=qualify.audit_trace(good,expected_checks=2,expected_error=0)
        self.assertEqual(parsed['status'],'PASS')
        self.assertEqual([check['core_syscalls'] for check in parsed['checks']],[37,37])
        parent=str(qualify.PARENT)
        fence=f'newfstatat(AT_FDCWD, "{parent}", {{st_mode=S_IFDIR|0700}}, AT_SYMLINK_NOFOLLOW) = 0\n'
        mutations={
            'missing-initial-metadata':good.replace('newfstatat(AT_FDCWD, "controllers", {st_mode=S_IFREG|0644}, 0) = 0\n','',1),
            'missing-eof':good.replace('read(4, "", 125) = 0\n','',1),
            'missing-final-fence':good.rsplit(fence,1)[0]+good.rsplit(fence,1)[1],
            'follow-limit':good.replace('O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK','O_RDONLY|O_CLOEXEC|O_NONBLOCK',1),
            'writable-resource':good.replace('O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK','O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK',1),
            'unclosed-parent':good.replace('close(3) = 0\nwrite(1, "receipt", 128) = 128','write(1, "receipt", 128) = 128',1),
            'mutation-syscall':good.replace('exit(0) = ?','unlink("boot") = 0\nexit(0) = ?'),
            'missing-initial-walk':good.replace('openat(AT_FDCWD, ".", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY) = 3\n','',1),
            'ancestor-follow':good.replace('O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH|O_DIRECTORY','O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY',1),
        }
        # Drop EOF in a full check, not solely the initial acquisition prefix.
        at=mutations['missing-eof'].rfind('read(4, "", 125) = 0\n')
        mutations['missing-eof']=mutations['missing-eof'][:at]+mutations['missing-eof'][at+len('read(4, "", 125) = 0\n'):]
        for name,text in mutations.items():
            self.assertNotEqual(text,good,name)
            with self.subTest(name=name),self.assertRaises(ValueError):
                qualify.audit_trace(text,expected_checks=2,expected_error=0)
