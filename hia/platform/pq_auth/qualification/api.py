"""Test-only declarations for the public native ABI; no acceptance logic."""
from pathlib import Path
import ctypes as C
import fcntl
import os


class Result(C.Structure):
    _fields_ = [('status', C.c_uint64), ('value', C.c_void_p)]


class View(C.Structure):
    _fields_ = [('data', C.c_void_p), ('size', C.c_uint64)]


U, P = C.c_uint64, C.c_void_p
SIGNATURES = {
    'seed_copy': (Result, P, U), 'public_spki_from_seed': (Result, P),
    'signing_from_owned_seed': (Result, P, P), 'verifier_from_pinned_spki': (Result, P, U, P),
    'sign_exact_message': (Result, P, P, U), 'verify_exact_message': (Result, P, P, U, P, U),
    'sign_statement': (Result, P, P, U, P, P, U), 'verify_frame': (Result, P, P, U, P, P, U),
    'verify_tpq1': (Result, P, U, P, P, U, P, U), 'verify_ml_dsa_65': (Result, P, U, P, U, P, U, P, U),
    'profile_from_pinned_keys': (Result, U, P, P, U), 'profile_snapshot': (Result, P),
    'profile_signer_ids': (Result, P), 'profile_pinned_keys': (Result, P),
    'profile_verify': (Result, P, P, P, U, P, U), 'budget_new': (Result,),
    'budget_snapshot': (Result, P), 'budget_reserve': (Result, P, U, U),
    'profile_candidate_message': (Result, P, P, U), 'profile_commitment': (Result, P, U, P, U),
    'profile_active_at': (Result, P, U), 'profile_require_claim': (Result, P, P),
    'drop': (U, P), 'kind': (U, P), 'value_code': (U, P), 'value_detail_a': (U, P), 'value_detail_b': (U, P),
    'candidate_signer_count': (U, P), 'bound_kind': (U, P),
    'budget_attempts': (U, P), 'budget_total_bytes': (U, P), 'budget_exhausted': (U, P),
    'profile_signer_id_at': (View, P, U), 'profile_pinned_key_at': (View, P, U),
    'error_display': (Result, P), 'native_error_display': (Result, U, U),
    'profile_error_display': (Result, U, U, U, U),
}
for name in ('value_bytes', 'identity_spki', 'identity_key_id', 'signature_bytes', 'key_public_spki',
    'key_public_key_id', 'message_authenticated_message', 'message_signer_key_id', 'signed_frame_bytes',
    'frame_authenticated_statement', 'frame_statement', 'frame_signer_key_id', 'candidate_message',
    'candidate_crypto_profile_id', 'bound_profile_id', 'bound_work_digest', 'bound_binding', 'bound_configuration_bytes'):
    SIGNATURES[name] = (View, P)
assert len(SIGNATURES) == 55


def buffer(raw):
    return C.create_string_buffer(raw, max(1, len(raw)))


def load(path):
    raw = Path(path).read_bytes()
    fd = os.memfd_create('pq-owned-test', os.MFD_ALLOW_SEALING)
    assert os.write(fd, raw) == len(raw)
    fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    lib = C.CDLL('/proc/self/fd/' + str(fd))
    os.close(fd)
    functions = {}
    for name, types in SIGNATURES.items():
        f = getattr(lib, 'trnm_pq_' + name)
        f.restype, f.argtypes = types[0], list(types[1:])
        functions[name] = f
    return lib, functions


def data(function, handle, *args):
    view = function(handle, *args)
    assert view.data
    return C.string_at(view.data, view.size)
