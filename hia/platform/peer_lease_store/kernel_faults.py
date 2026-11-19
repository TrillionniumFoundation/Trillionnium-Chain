"""Explicit Linux kernel fault fixture. Never used by the native store runtime."""
import ctypes, os

class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
LIBC.prctl.restype=ctypes.c_int

def fsync_errno(fd,errno):
    # seccomp_data: nr at 0, arch at 4, first u64 argument at 16.
    rows=(Filter*9)(Filter(0x20,0,0,4),Filter(0x15,1,0,0xc000003e),Filter(0x06,0,0,0x80000000),
        Filter(0x20,0,0,0),Filter(0x15,0,3,74),Filter(0x20,0,0,16),Filter(0x15,0,1,fd),
        Filter(0x06,0,0,0x00050000|errno),Filter(0x06,0,0,0x7fff0000))
    program=Program(len(rows),rows)
    if LIBC.prctl(38,1,0,0,0)!=0 or LIBC.prctl(22,2,ctypes.addressof(program),0,0)!=0:
        os._exit(125)
