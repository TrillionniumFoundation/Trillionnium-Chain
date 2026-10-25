# W2-B: exact W1 relation witness and cryptographic proof obligations

**Research only. There is no STARK/SNARK prover, no trusted setup, no
succinct verifier, no Chain block authority and no production activation.**

Source: 'formal/pon-nakamoto-v1/w2b_relation_witness.py'.
Four negative/reference tests: 'test_w2b_relation_witness.py'.
This is a preparatory exact relation *witness*, not a cryptographic proof.
It deliberately recomputes the complete existing W1 operation.

## Public statement and private witness

Frozen W1: n=64, r=8, q=2^32-5, proof PNW1 49,188 bytes.
Public: selected work profile/version, 32-byte challenge, exact TaskId,
current expected branch target, canonical A/B and claimed C/t bytes, and
transaction/header commitment. Only an independently authenticated Node
context may supply those values; this helper does not.

Witness: all 512 canonical 8x8 transcript tiles in (bi,bj,bk,i,j) order,
exactly 512*64*4=131,072 bytes. The current helper compares this stream
to a second implementation of the W1 arithmetic recurrence, and validates
the complete SHA256 digest. An actual proof system would need to prove
this arithmetic and SHA-256 relation without revealing/replaying the entire
witness; simply posting the bytes offers no succinctness.

Required arithmetic constraints before cryptographic acceptance:
1. Canonical A/B/C field elements and exact LE encoding; no reduction of
   arbitrary wire inputs, overflow, endianness aliases or silent padding.
2. Challenge-derived four 512-element noise arrays, exact rejection
   sampling (<q), 128-block/label bound and exact challenge/tag domains.
3. 64x64 challenge-encoded matrices with modulo-q operations, followed
   by all 512 consecutive 8x8 tile updates. Every preceding tile state
   must agree. There are 32,768 serialized intermediate u32 words.
4. Full SHA-256 transcript starting with 'TRNM-PON-TRACE1\\0' || challenge,
   updating all tile words in the original order. An unproved transcript
   digest leaves the original cheap-fake vulnerability unchanged.
5. Decode and enforce C = C' - (A FL) FR - EL (ER B') over Fq,
   check C's exact bytes and W1 ticket threshold, and bind the 318-byte
   header and one current admissible task.
6. Proof randomness, alternative witnesses, batching, repeated model
   output and serialization flexibility must NOT generate fresh
   unpriced lottery tickets or repeat useful-model rewards.

The original dense 64x64 multiplication contains 64^3=262,144 scalar
multiply-accumulate positions in its straightforward arithmetic schedule,
before noise generation, other matrix products, SHA and constraints.
This is a reference operation count, **not** a lower bound on every
possible optimal prover/circuit. The field q has q-1 divisible by only 2,
so a native radix-2 polynomial FFT implementation cannot simply assume
large powers-of-two roots in Fq. A different proof field requires
explicit sound cross-field range and reduction constraints.

## Checked research counterexamples

The local Python witness prototype insists on all 512 tiles and
131,072 bytes; it refuses single-byte alterations at the first,
middle or final tile **even if the attacker updates the claimed SHA256
digest**, because the tile recurrence is fully replayed. It also
rejects forged claimed C, wrong TaskId and missing witness bytes.
All passing research verdicts carry:
'succinct_proof=false', 'cryptographic_proof=false',
'verified_work=false', 'consensus_chainwork=false'.

A full independent backend must implement and audit a versioned circuit,
setup/reference string policy (if any), public input byte grammar,
proof length bound, constant-time/verifier DoS properties, and a canonical
third-party verifier. Publish complete producer setup/search/proof CPU/GPU,
prover RAM/VRAM, proof bytes and verification cost on matched real tasks.
The current witness-bytes helper **does not** close P5 or P6.

Example reference controls (no native W1 or real STARK):
    python3 formal/pon-nakamoto-v1/test_w2b_relation_witness.py

## Decision boundary

If proof generation consumes far more CPU/GPU than the useful forward
or training work, or proof verification becomes expensive from invalid
inputs again, W2-B is not an economically qualified PoN. Do not let
extra proving cost be mislabelled as NDU benefit. Compare it against
the lower-cost W2-A filtered-but-unsound profile and the explicitly
non-neural security Hashcash of W2-C under the same task and hardware.

Existing PNW1 remains unchanged until a separately governed protocol
upgrade passes a third independent verifier, adversarial hardness
review, fault injection, actual WAN measurements and acceptance policy.
