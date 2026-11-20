# Ordinary M06 legacy preparation owner

This private candidate constructs the existing default Settings entirely inside
one native process and owns each complete input wire, validation result and
successful Prepared value. The admitted configuration is precisely
Config::installed() / Settings::development(None), with legacy-first-two-v3,
legacy-task-v1 and linear-expert-dev-v1. Callers supply transaction bytes and
height; they cannot supply Config, network, signature success, Prepared, State,
Patch, an expected root or persistence authority.

The process uses the unchanged canonical HIA Settings constructor, complete
PNX1 grammar, SHA-256 and strict Ed25519 verifier. No Rust library, interpreter,
Python algorithm or external success flag executes in the product process.
Python authors checked HIA source and concatenates the exact native-emitted ELF
prefix with five exact compiler outputs. The literal Linux ABI adapter remains
a separately visible trusted boundary.

## Relation to ordinary Node

The semantic operation is pon_executor::prepare with the internal default
Config and a real signature attempt counter. BeforePrepare and AfterPrepare
are explicit optional callback boundaries, including AfterPrepare after a
semantic preparation rejection. There is no callback inside prepare.
Profile refusals precede network, network precedes expiry, signature attempts
increase only after both pass, and tx-id is computed only after real strict
signature verification. Full PNX1 decoding precedes all command profile gates.

This is a finite private preparation owner. Mandatory block transitions, State
fee/nonce application, batch transaction limits, worker spawning/joining,
canonical transaction error consumption, nondefault Config, PQ, task execution,
expected-root checking, AdmissionPersistence and durable commit remain open.
A serialized observation from READ cannot authorize any of those operations.

## Transport and lifetime

Standard descriptors are actual unaliased-direction pipes checked using fstat
and fcntl before any protocol read, diagnostic write or other runtime output.
stdout and stderr may share a writable pipe. Optional progress pipes must have
the correct modes and distinct kernel identities from every standard/control
pipe. These are finite transport admission conditions, not original Rust
transaction errors. Incorrect standard descriptors fail silently.

BOOT is 64 bytes: MPBOOT01, zero flags, progress write/read descriptors or two
u64::MAX values, then 32 zero bytes. The owner returns MPREADY1, total bytes,
the actual SDO1 length, 40 zero bytes, then the complete native SDO1 snapshot.
No timestamp or configuration override is accepted.

Each request is eight little-endian u64 words: MPREQ001, operation, strictly
increasing sequence starting at 1, height, body length, expected generation,
zero, zero. PREPARE=1 accepts arbitrary u64 height and a body whose actual
transferred extent must match the declared length. Bodies greater than the
original 2048-byte transaction bound are fully consumed using a 32768-byte
transport buffer and then rejected as ENCODING. They do not create a larger
transaction or an additional transaction-size policy. Partial bodies have
transport failure and no semantic result.

READ=2 requires a successful current private generation; CLEAR=3 destroys it;
CLOSE=4 destroys it and closes the process after its response. Every new
PREPARE first destroys the old generation, including on rejection/cancellation.
No externally supplied result can create a generation.

MPRESULT has 12 words: magic, request sequence, semantic code, attempts,
actual input extent, height, PNX1 error, strict-verifier error, successful
generation or zero, payload length or zero, encoded length or zero, zero.
Semantic codes are 0 success, 1 ENCODING, 2 SERVICE_CONTRACT_PROFILE,
3 WORK_TASK_PROFILE, 4 PUBLIC_EVAL_PROFILE, 5 FACTOR_PROFILE,
6 EVOLUTION_PROFILE, 7 NETWORK, 8 EXPIRED, 9 SIGNATURE.

READ returns MPVALUE1 with 8-word header: magic, total length, preparation
generation, height, encoded length, payload length, attempts=1, zero; then
the actual tx-id, actual signing digest and complete original wire. CLEAR and
CLOSE return 4-word MPCLEAR1/MPCLOSED, request sequence, total attempts, zero.

A progress record is 4-word MPPROG01, monotonically increasing callback sequence,
kind 1 BeforePrepare or 2 AfterPrepare, request sequence. A reply is 3-word
MPGO0001, exact callback sequence, classification 0 continue or 1 cancel.
Cancellation exits 80 without a current result/value. It is distinct from
canonical preparation rejection. Wrong replies are transport/protocol failure.

Exit 64 is malformed protocol/standard descriptor, 65 is control capability
admission, 66 is an internal component invariant, 67 is absent/stale private
generation, 70 is transport failure, 78 is literal-adapter refusal, 79 is
mapping/setup failure and 80 is callback cancellation. After safe standard
descriptor admission, diagnostics contain seven words: exit, phase, actual
last syscall/component result, request sequence, semantic code, attempts and
callback kind.

## Qualification status

This source is a new unqualified candidate. Native runtime controls, source
admission, strict complete original differential and original retained tests
must all execute on its final source identity before a PASS can be claimed.
