"""Test-only declarations for the public Candidate native ABI."""
from pathlib import Path
import ctypes as C
import fcntl
import os


class Result(C.Structure):
    _fields_ = [('status', C.c_uint64), ('value', C.c_void_p)]


class Scalar(C.Structure):
    _fields_ = [('status', C.c_uint64), ('value', C.c_uint64)]


class View(C.Structure):
    _fields_ = [('data', C.c_void_p), ('size', C.c_uint64)]


P, U = C.c_void_p, C.c_uint64
SIGNATURES = {
    'seed_copy': (Result, P, U), 'signing_from_owned_seed': (Result, U, P),
    'verifier_from_pinned_raw': (Result, U, P, U), 'sign': (Result, P, P, U),
    'verify': (Result, P, P, U, P, U), 'algorithm_all': (Result,),
    'algorithm_name': (Result, U), 'algorithm_public_key_bytes': (Scalar, U),
    'algorithm_signature_bytes': (Scalar, U), 'algorithm_nist_category': (Scalar, U),
    'signing_algorithm': (Scalar, P), 'verifier_algorithm': (Scalar, P),
    'signing_public_key': (View, P), 'verifier_public_key': (View, P),
    'candidate_error_display': (Result, U, U, U), 'error_display': (Result, P),
    'drop': (U, P), 'kind': (U, P), 'value_code': (U, P),
    'value_expected': (U, P), 'value_actual': (U, P),
    'value_bytes': (View, P), 'signature_bytes': (View, P),
    'algorithm_name_bytes': (View, P), 'algorithm_all_bytes': (View, P),
}
assert len(SIGNATURES) == 25


def buffer(raw):
    return C.create_string_buffer(raw, max(1, len(raw)))


def load(path):
    raw = Path(path).read_bytes()
    fd = os.memfd_create('candidate-owned-test', os.MFD_ALLOW_SEALING)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            assert count > 0
            at += count
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
        library = C.CDLL('/proc/self/fd/' + str(fd))
    finally:
        os.close(fd)
    functions = {}
    for name, types in SIGNATURES.items():
        function = getattr(library, 'trnm_candidate_' + name)
        function.restype, function.argtypes = types[0], list(types[1:])
        functions[name] = function
    return library, functions
