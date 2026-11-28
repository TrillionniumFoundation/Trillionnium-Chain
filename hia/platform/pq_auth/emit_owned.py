"""Execute the actual HIA emitter in a separate, sealed-image observation process."""
from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import os
import resource
import sys

request = json.load(sys.stdin)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
source = Path(request['image'])
raw = source.read_bytes()
assert hashlib.sha256(raw).hexdigest() == request['sha256']
fd = os.memfd_create('pq-owned-emitter', os.MFD_ALLOW_SEALING)
try:
    position = 0
    while position < len(raw):
        written = os.write(fd, raw[position:])
        assert written > 0
        position += written
    fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    library = ctypes.CDLL('/proc/self/fd/' + str(fd))
finally:
    os.close(fd)
entry = library.f0
entry.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
entry.restype = ctypes.c_uint64
incoming = ctypes.create_string_buffer(b'PQOWN001')
outgoing = ctypes.create_string_buffer(1048576)
work = ctypes.create_string_buffer(1)
code = entry(incoming, 8, outgoing, len(outgoing), work, 0)
assert code == 0
size = int.from_bytes(outgoing.raw[:8], 'little')
assert 0 < size <= len(outgoing) - 8
result = outgoing.raw[8:8 + size]
assert result.startswith(b'\x7fELF\x02\x01')
target = Path(request['output'])
with target.open('xb') as stream:
    stream.write(result)
print(json.dumps({'status': 'PASS', 'image_sha256': request['sha256'], 'object_bytes': size,
                  'object_sha256': hashlib.sha256(result).hexdigest(),
                  'host_compiler_modules_loaded': [name for name in sys.modules if name.startswith('hepta')]}), flush=True)
