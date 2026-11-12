import hashlib, os, pathlib, stat, sys
script = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
meta = script.lstat()
assert stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
raw = script.read_bytes()
assert hashlib.sha256(raw).hexdigest() == expected
sys.argv = [str(script), *sys.argv[3:]]
exec(compile(raw, str(script), 'exec'), {'__name__': '__main__', '__file__': str(script)})
