"""W2-C research only: independent security PoW, optional W1 useful-work attestation.

Demonstrates a cheap pre-W1 verification work barrier and its unqualified
attacker/honest costs. This is NOT a Chain profile, block acceptance, crypto
hardness proof or an invitation to replace PoN with arbitrary Hashcash.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import time
from typing import Optional

from contract_wire import H
import work_oracle as W

HEADER_BYTES = 318
MAX_ATTEMPTS = 1_048_576
DOMAIN = b'w2c-research-security-v0'
PROFILE = 'pon-w2c-dual-work-research-only-v0'


@dataclass(frozen=True)
class Candidate:
    header: bytes
    proof: bytes
    nonce: int


def proposal_digest(header: bytes, proof: bytes) -> bytes:
    if type(header) is not bytes or len(header) != HEADER_BYTES:
        raise ValueError('HEADER_LENGTH')
    if type(proof) is not bytes or len(proof) != W.PROOF_BYTES:
        raise ValueError('PROOF_LENGTH')
    # Full packet/proof commitment is computed only once by the producer;
    # verifier always recomputes it from the exact, immutable bytes.
    return H('w2c-proposal', DOMAIN, header, proof)


def security_ticket(commitment: bytes, nonce: int) -> bytes:
    if type(commitment) is not bytes or len(commitment) != 32:
        raise ValueError('COMMITMENT')
    if type(nonce) is not int or not 0 <= nonce < (1 << 64):
        raise ValueError('NONCE')
    return H('w2c-security', DOMAIN, commitment, struct.pack('<Q', nonce))


def qualifies(ticket: bytes, bits: int) -> bool:
    if type(ticket) is not bytes or len(ticket) != 32:
        raise ValueError('TICKET')
    if type(bits) is not int or not 8 <= bits <= 28:
        raise ValueError('BITS')
    full, rest = divmod(bits, 8)
    return (not any(ticket[:full])) and (rest == 0 or ticket[full] >> (8-rest) == 0)


def search(header: bytes, proof: bytes, bits: int, cap: int = MAX_ATTEMPTS):
    if type(cap) is not int or not 1 <= cap <= MAX_ATTEMPTS:
        raise ValueError('CAP')
    qualifies(bytes(32), bits)
    digest = proposal_digest(header, proof)
    start_wall, start_cpu = time.perf_counter_ns(), time.process_time_ns()
    attempts = 0
    candidate = None
    for nonce in range(cap):
        attempts += 1
        if qualifies(security_ticket(digest, nonce), bits):
            candidate = Candidate(header, proof, nonce)
            break
    return candidate, {
        'bits': bits, 'attempted_hashes': attempts, 'cap': cap,
        'search_cpu_ns': time.process_time_ns()-start_cpu,
        'search_wall_ns': time.perf_counter_ns()-start_wall,
        'status': 'FOUND' if candidate else 'EXHAUSTED',
        'unverified_claim': True,
    }


def validate(candidate: Candidate, task: bytes, bits: int):
    """Local demonstration ONLY. Even VALID_W1 has zero consensus authority."""
    start_cpu = time.process_time_ns()
    header, proof = candidate.header, candidate.proof
    digest = proposal_digest(header, proof)
    if not qualifies(security_ticket(digest, candidate.nonce), bits):
        return {'outcome':'SECURITY_TARGET', 'w1_replayed':False,
                'cpu_ns':time.process_time_ns()-start_cpu}
    challenge = H('challenge', header)
    if type(task) is not bytes or len(task) != 32:
        raise ValueError('TASK')
    try:
        W.precheck(challenge, task, bytes.fromhex('ff'*32), proof)
    except ValueError as error:
        return {'outcome':'W1_'+str(error), 'w1_replayed':False,
                'cpu_ns':time.process_time_ns()-start_cpu}
    replay_started = time.process_time_ns()
    try:
        W.verify(challenge, task, bytes.fromhex('ff'*32), proof)
    except ValueError as error:
        return {'outcome':'W1_'+str(error), 'w1_replayed':True,
                'w1_replay_cpu_ns':time.process_time_ns()-replay_started,
                'cpu_ns':time.process_time_ns()-start_cpu,
                'verified_work':False}
    return {'outcome':'VALID_W1_RESEARCH_ONLY','w1_replayed':True,
            'w1_replay_cpu_ns':time.process_time_ns()-replay_started,
            'cpu_ns':time.process_time_ns()-start_cpu,
            'verified_work':False}


def comparison(bits=(8,12), cap=65536):
    header = H('w2c-research-header',b'A') * 9 + b'\x00'*30
    assert len(header)==HEADER_BYTES
    a = [0]*W.CELLS
    task = W.task_id(a,a)
    challenge = H('challenge',header)
    legitimate_start = time.process_time_ns()
    actual_proof = W.prove(challenge,a,a)
    honest_w1_cpu_ns = time.process_time_ns()-legitimate_start
    forged_prefix = b'PNW1'+W.field_bytes(a)*3
    trace = H('w2c-false-trace',challenge)
    if trace == actual_proof[-32:]:
        raise AssertionError('UNEXPECTED_VALID_TRACE')
    forged_proof = forged_prefix+trace
    rows = []
    for difficulty in bits:
        for label,proof in [('honest-W1',actual_proof),('from-zero-false-W1',forged_proof)]:
            candidate,cost = search(header,proof,difficulty,cap)
            verification = validate(candidate,task,difficulty) if candidate else None
            rows.append({'arm':label,'security_work':cost,
                         'full_receiver':verification,'honest_w1_production_cpu_ns':
                         honest_w1_cpu_ns if label=='honest-W1' else None,
                         'consensus_chainwork_granted':False,
                         'security_profile_activated':False})
    return {'schema':'w2c-research-only-v0','profile':PROFILE,
            'separate_security_pow':True,'w1_original_consensus_unchanged':True,
            'header_source':'synthetic 318 bytes; not signed native Header',
            'gpu_measurement':None,'independent_security_acceptance':False,
            'rows':rows}
