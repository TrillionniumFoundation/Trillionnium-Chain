# Framed MMCS messages and sponge accounting

Status: **HOLD_NO_GO**. This adds per-call accounting to the actual P3 0.8.0
pruned-MMCS checker. The starting implementation is PR #803,
`ebc31f07f96060fe1e9fb165aae0123de0fcbc1a`. The R1 profile, hash functions,
commitments, accepted openings and production admission are unchanged.
Historical reports retain their original contents and source identities.

## The counted observation

Only cases carrying `verification_sponge_accounting` have verifier ledgers:
the two native mixed-height cases, and the two-opening verification in each
artificial-collision extraction case. Within those captured verifications,
`tagged_sha3_mmcs_binding` records every leaf/branch call. Recording occurs
before the collision table's digest deduplication, so repeated identical
messages are charged repeatedly. Both roles contribute to one total. Each
record contains its role, evaluation kind, header/payload/suffix lengths and
complete-message padded-block count.

Successful collision-witness rechecks have a separate
`collision_recheck_sponge_accounting` ledger for their two independent calls.
These evaluate complete framed messages with `Sha3_512::digest`, without the
R1 cached prefix. Artificial overrides remain artificial in this ledger too.
The two witness message lengths are retained separately; the
`candidate_collision_padded_block_total` is their sum after padding, including
both headers and both length suffixes.

The honest ledger is frozen immediately after `verify_batch_pruned`, before
the checker's full-message parity checks and restored-path controls. The
separate `extension`/base-flattening parity case uses uninstrumented native
MMCS; its verification and restored-path checks are not counted. Commit,
opening generation, prefix construction, other parity checks, restored-path
verification, rejection tests, transcripts, other W1 preprocessing and
failed/aborted processes are also outside this observation. It is not an
accounting of the entire executable.

## Units, padding and cached prefixes

SHA3-512 has a 72-byte rate and a 64-byte output. For a complete `m`-byte
framed message, domain suffix and padding require `floor(m / 72) + 1`
absorption blocks; no additional squeeze is required for that output. In
particular, an exact multiple of 72 requires another block. The frame includes
the final eight-byte payload length. Arithmetic uses checked `u64` sums and
rejects overflow before changing counters or adding a call record.

The fixed R1 header is 322 bytes. `LeafHasher::new` and
`BranchCompressor::new` pre-hash it, and each call clones that state. Its
geometry is four full rate blocks plus 34 buffered bytes. A branch frame is
`322 + 128 + 8 = 458` bytes:

| Quantity for one branch call | Block equivalents |
|---|---:|
| Complete framed message evaluated from the initial state | 7 |
| Complete header blocks represented in the cached prefix | 4 |
| Continuation after cloning that prefix | 3 |

These are source-based, complete-message and continuation equivalents. No
instrumentation of Keccak permutation invocations is added.
`native_permutation_telemetry=false`, `native_permutation_calls=null`, and
`prefix_initializations_counted=false` are explicit. Summing the four reused
prefix blocks over calls does not count how many prefixes were initialized.
Unused prefix initializations can also perform work; the ledger excludes
them. Consequently its total is not a bound on the whole native process.

The all-call complete-message total includes hypothetical block equivalents
for artificial messages. Separate counters identify native cached-prefix
calls, native full-message rechecks, and artificial overrides. Artificial
block equivalents are never added to either native execution category. This
also preserves the fact that a non-overridden role can still call real SHA3
within an otherwise artificial oracle experiment.

## Independent check and meaningful limits

Run these focused commands from a complete checkout, with a separate target
directory and the locked Rust 1.95.0 dependencies already available:

```sh
cargo +1.95.0 test --manifest-path formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.toml \
  --release --locked --offline --example tagged_sha3_mmcs_binding
cargo +1.95.0 run --manifest-path formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.toml \
  --release --locked --offline --example tagged_sha3_mmcs_binding > /tmp/mmcs-accounting.json
python3 -B formal/pon-nakamoto-v1/p3_shared_primitive_qualification/pruned_mmcs/check_sponge_accounting.py \
  /tmp/mmcs-accounting.json
python3 -B -m unittest discover \
  -s formal/pon-nakamoto-v1/p3_shared_primitive_qualification/pruned_mmcs \
  -p 'test_sponge_accounting.py' -v
```

The Python reader independently reconstructs all counter totals from ordered
call records and checks the two full collision-message encodings. It rejects
misclassified artificial calls, omitted duplicate charges, missing suffixes,
wrong padding boundaries, invalid bounds and positive security/telemetry
claims. Its unit-test reports are explicitly synthetic arithmetic fixtures;
they do not substitute for running it on a fresh Rust report. The reader's
2 MiB and 8,192-call limits protect that local tool and are not protocol limits.
It checks internal consistency, not the authenticity of a report; source and
binary identity still need an exact-commit execution receipt.

This is a bridge between framed-message lengths and the units needed by the
[conditional sponge calculator](../budget/README.md). It does not choose a
real-to-ideal oracle simulation, the swap/XOR conversion, or an adversary's
whole-lifetime query bound. A witness's observed `L` is not a maximum over
every allowed adversarial output. Applying a theorem still requires the
appropriate worst-case lengths, shared-oracle query domain and accounting of
its additional verification term; no automatic `q + 2L` substitution is made.
All `qualified` fields remain false and all security-bit and adversary-budget
fields remain null. Quantum commitment/PCS extraction, Fiat-Shamir knowledge
soundness and end-to-end W1/PQ qualification remain open.
