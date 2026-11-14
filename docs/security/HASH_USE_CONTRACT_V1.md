# Hash purposes, inputs and migration contract V1

Status: **HOLD / NO-GO**. This is a source-bound review contract, not a
cryptographic qualification or a change to an active network format.

The [manifest](../../config/pon/hash-use-contract-v1.json) and
[checker](../../scripts/ci/hash_use_contract.py) make the distinction between
hash purposes executable. A named algorithm, output width, valid signature or
consistent source digest must not silently become a claim about all objects
reachable through that digest. Both the checker and its
[negative controls](../../scripts/ci/test_hash_use_contract.py) run in the
mandatory `repository-truth` lane.

## Reviewed current-source map, 2026-11-14 UTC

The full local `repository-truth` run at source checkpoint
`7d8d4c59fcd01480a12e1c64835b202079091800` stopped at this contract:
the original 33 controls reported 31 passes, one failure and one error because
the first declared input had changed. The preserved run has summary SHA-256
`79d37af0ecec1749098bdfd1cfc7127de2cf9aa928b7271ca4ef8de39cd4061b`.
Its 2,700-second limit was unchanged; it exited after 30.922 seconds. Later
commands in that fail-fast run did not execute.

This successor makes a manual source review of all 31 declared paths.
The old pins exactly match their bytes at
`57b069ae1e7ed32ff95e4f2a18a74d5eadcda550`. Twenty-five inputs are unchanged;
the six changed inputs are the proof-profile binding descriptor, native
`pon_work.rs`, Cell `store.rs` and `cell.rs`, and Node `lib.rs` and `store.rs`.
All 31 source blobs at the reviewed `7d8d4c` checkpoint are also identical to
their earlier `dc42ce4df5cff79cc61c5addbaf01074b56b06ca` bytes. The previous
lifetime-register repair did not introduce these changes.

The proof descriptor changes only the byte length and SHA-256 of its current
W1 mapping. Its selected profile, image/control/parameter identities and
withdrawal boundary remain unchanged. The five Rust-file deltas retain the
declared hash encodings and output widths while adding separately reviewed
APIs or owner/readback checks. Those additional APIs do not acquire coverage
under this finite 19-use inventory.

The newly reviewed source-map commitment is
`15a8d91e0b2c50908d17c6bb9743e8ef5a44927814e59354874d77d9654f9ee7`.
The 19-use semantics commitment remains
`29189f8e96a255472577479d46204b2b403a1f8e27806da6aa616e417ced0b5b`,
and `e4abb172147e941b62483652b0ceabaae4317624` remains the original semantic
review context. The source checkpoint identifies the reviewed input blobs;
it is not claimed to contain this successor's new mapping metadata.

The [review packet](../../evidence/hash-use-current-source-review-20261114/README.md)
preserves the previous manifest, reader, original controls, full six-file
source deltas, all 31 old/current identities and original failure records.
All original 33 controls, reader functions, source-reading limits and
qualification values remain unchanged. The independent source-map commitment
still rejects unreviewed repinning; the CLI still returns `HOLD_NO_GO` on a
successful source inspection. This repair does not establish a full-lane pass,
hosted qualification, a complete call graph, a cryptographic security bound
or production activation.

## Composed W1 mapping review, 2026-11-12 America/New_York

The integration combines the 19-use, 31-source TCG3/CMH2 review from #927
with #935's fixed 139-input mapping and #931's upstream withdrawal policy.
Only the proof-binding descriptor pin changes inside the 31-source table:
its 2,378 bytes now hash to
`48606e3eb29fb1a8b2613f268bc828c120bd4720b40398afc1c6bf55d1981de2`.
All other table entries match their reviewed source bytes; the purpose/game
semantics digest remains unchanged. The resulting fixed source-map digest is
`5255345f514f5ac0e0abc92a9c756f35c81eed4c880c0108019be408b0fd4d69`.

Both profile readers pin the same 44,427-byte mapping. Its selected historical
proof identity is still withdrawn: the approved-current-profile list remains
empty and `--require-current` refuses it. This source reconciliation executes no
proof verifier and supplies no current proof-use or production qualification.

## Candidate and existing work

This continuation starts from PR #876 at
`e4abb172147e941b62483652b0ceabaae4317624`. Its native hash owners, signed domains,
stored schemas and production activation policy remain the baseline. The
existing [CCH1 full-content interfaces](CPQ1_FULL_CONTENT_COMMITMENTS_V1.md)
already distinguish observed bytes from old digest wrappers. They are existing
implementation, not a new result of this contract.

The separate PR #844 at `f7be5b9dc06faa3c4882819adbe238cbe48c3438`
adds lifetime composition and query-budget-overrun accounting. PR #864 at
`7b7826c5c9623a1310969d1cbb636b4c66c1bc6d` reviews five archived content-to-use
records. Neither branch is an ancestor of this baseline. Their test counts and
observations are not transferred to this candidate. This contract supplements
the baseline [lifetime budget](PQ128_LIFETIME_BUDGET_V1.md) and
[root lifetime obligations](PQ_ROOT_LIFETIME_GAPS_V2.md); it does not replace
their missing reductions with generic query exponents.

## Current composition scope

The account, TLS and Root continuation retained the original 17-use / 26-path
contract. The typed content/history continuation preserves those 17 use
definitions and adds two explicitly scoped uses, giving 19 uses and 31 reviewed
source paths. Its [TCG3 and CMH2 contract](CONTENT_GRAPH_AND_HISTORY_READBACK_V1.md)
distinguishes declared typed-graph traversal and a bounded complete-State
ancestry archive from live adoption and historical provenance. The added V5 Root witness enrollment,
policy binding, request digest and receipt obligations are recorded separately
by the [41-path Root dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md).
Account development-scope checks restrict executable configurations without
changing the retained hash encodings. These inventories do not establish their
union as a complete call graph, shared-query allocation or lifetime failure
bound. The V5 typed owner is not an installed witness daemon or effect sink.

## The security game comes before the bit count

| Purpose | Attacker's choice and protected event | Required distinction |
| --- | --- | --- |
| Fixed-target preimage | A target output is fixed independently of the search; find an accepted input | The exact accepted domain, number of targets and oracle must be fixed |
| Second preimage | A specific original object is fixed before the replacement search | Preprocessing, advice, message length and the original selection procedure matter |
| Chosen-pair collision | Prepare two different objects, obtain acceptance of one, then substitute the other | A later signature does not make the earlier chosen-pair search a fixed-target game |
| Merkle/content binding | Open an accepted commitment to a different object or ordered tree | Include leaf/node roles, framing, tree shape, index, count and all digest dependencies |
| Signature authorization | An unauthorized message is accepted under a permitted key/role | Message binding is one component; the signature and current authority need their own games |
| Work threshold | Find a valid ticket satisfying the actual target and full relation | Generic preimage or collision estimates do not establish the cheapest legal mining strategy |
| Fiat-Shamir/PCS | A verifier accepts a false statement in the actual proof system | Fix the transcript, parameters, oracle model, recursion and project reduction |

For sufficiently large-domain ideal random functions at constant success
probability, single-target preimage search has a generic query exponent near
`n/2`; chosen-pair collision search has one near `n/3`. Thus 256-bit outputs
suggest 128 and 85.33... respectively; 384 suggests 192 and 128; 512 suggests
256 and 170.66.... These are illustrative query-work exponents. They are not
actual SHA security probabilities, circuit costs, or lifetime PQ128 guarantees.

In particular, reaching constant success after about `2^128` queries is a
different assertion from lifetime failure probability at most `2^-128`.
Unknown query counts, constants, multi-target factors, model replacement and
reduction losses remain unknown. Domain or epoch changes do not create a new
independent public SHA primitive or erase preprocessing already performed.

## Actual owners and migration boundary

The machine register binds the reviewed source bytes and the exact uses in its
declared roster. It is deliberately not an automatically proved whole-repository
call graph. Its digest checks establish source consistency, not an independent
review of those bytes or an authenticated deployment.

| Owner/use in the baseline | What is actually committed | Consequence for migration |
| --- | --- | --- |
| TCM1/TCR1/TMR1 and router references | Legacy SHA-256 manifests and nested payload/dependency identifiers | A SHA-512 wrapper over these encodings does not strengthen the referenced content |
| Transaction sequence root | Leaves bind LE64 position and transaction bytes; empty/leaf/node tags differ and odd layers duplicate the last leaf | No explicit outer count field exists; tree shape, indexed leaves and accepted transaction bytes need their own binding analysis |
| Header/block history | SHA-256 block identity and 32-byte parent references | A new checkpoint commitment does not rebuild or authenticate all ancestors |
| TPQ1 verification and candidate content signature join | The complete TPQ1 unsigned frame or CPQ1 envelope containing a complete CCH1 record, under separately selected key/profile rules | These are signature observations; a digest's width does not establish current signing authority, custody, freshness or FinalUse |
| BEP52 pieces and internal nodes | The prescribed SHA-256 piece/tree format; node hashing has no CCH1 domain tag | Keep the format's actual geometry and verification rules; do not invent inherited domain separation |
| CCH1, TCM2/TCC2, CST1 and CMG1 | Actual bytes covered by their individually specified candidate adapters | Retain each adapter's direct-content, dependency and ancestry limits |

For any deterministic wrapper `W`, `h(x) == h(y)` implies
`W(h(x)) == W(h(y))`. Length framing and a fresh outer domain do not recover
the distinction lost by `h`. A regression fixture can demonstrate this using
an explicitly short toy digest; that demonstrates the composition property,
not a practical SHA-256 collision.

Computing a new content commitment requires the actual canonical object bytes
and the newly specified encoding. Production migration additionally needs an
independently pinned expected commitment, complete applicable dependency
readback, current migration authorization, retirement of obsolete authority
and owner/recovery state that cannot rewind consumed liabilities. These are
adoption obligations, not runtime properties proved by this checker. Historical
ambiguity, consumed effects, revocations and unknown external effects do not
disappear because new bytes have been hashed.
The existing CMG1 adapter still treats embedded ancestry IDs as references;
the existing TCC2 adapter covers its five declared direct dependencies, not
every transitive dependency of those objects.

TCG3 separately parses every reachable typed node only after that node's actual
complete CCH1 readback, then follows all encoded edges. It does not discover
undeclared loader dependencies or establish that an absent ancestor never
existed. CMH2 separately reads actual genesis State/configuration and every
Header/trace/State through its selected checkpoint, within the explicit
32-block/32-MiB limits. Its Node adapter uses a single read snapshot. It does
not commit transaction/proof/receipt bodies or external effect journals,
reauthenticate lost history, reverify W1, authorize cutover or truncate a
longer history. Complete new expectations must be pinned independently.

## Proof-system qualification remains separate

The proof mapping records the concrete reviewed source and profile. A backend
label such as STARK, FRI or zkVM is not sufficient. Qualification must bind
the field and extension, degree bounds, rate/blowup, folding schedule, query
count and sampling, Merkle hash and consumed output length, transcript and
challenge mapping, grinding, batching, recursion depth, program/verifier key,
implementation and build. Shared hash calls and failed/helper work belong in
the same lifetime accounting where the common experiment requires it.

A QROM theorem for one protocol class is not an automatic theorem for a
different multi-round IOP, recursive verifier or SHA implementation. Concrete
FRI work also distinguishes proved guarantees from conjectured security. This
register never fills these gaps by assigning zero loss or converting an output
width into a whole-chain security flag.

## Validation and remaining obligations

The checker rejects malformed/ambiguous contracts, incomplete declared rosters,
source drift, inconsistent game/selection claims and unsupported upgrades from
old digest references. Its source checks and unit controls are mandatory, once
each, in the straight-line `repository-truth` lane. The existing CI-contract
controls reject removal, duplication, movement, hidden branches and suppressed
failures. The corpus also pins the new contract and its implementation.

```sh
python3 scripts/ci/test_hash_use_contract.py
python3 scripts/ci/hash_use_contract.py
python3 scripts/ci/test_ci_contract.py
python3 scripts/ci/check_ci_contract.py
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/check_pq_research_integration.py
```

Successful execution establishes only the declared structural checks. Actual
security bits and lifetime failure remain null; whole-chain hash-scope closure,
PQ qualification and production activation remain false. A release still needs
the complete effect-bearing dependency map, applicable concrete reductions and
attacker-resource bounds, independently authorized migration/recovery, and
tests of the exact adopted joint candidate. The evidence packet records which
commands actually ran; commands documented here are not execution receipts.

## Primary references

- [Grover, database search](https://arxiv.org/abs/quant-ph/9605043): square-root search; this reference alone does not establish collision complexity.
- [Brassard, Hoyer and Tapp, collision problem](https://arxiv.org/abs/quant-ph/9705002): the r-to-one collision algorithm and time-space tradeoff.
- [Zhandry, quantum collision and set equality](https://arxiv.org/abs/1312.1027): random-function query bounds and their domain/range conditions.
- [NIST PQ evaluation criteria](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization/Evaluation-Criteria/Security-%28Evaluation-Criteria%29): security definitions and comparative resource categories, not a universal quantum bit conversion.
- [Don, Fehr, Majenz and Schaffner, Fiat-Shamir in the QROM](https://arxiv.org/abs/1902.07556): protocol-specific conditions for the quantum-oracle reduction.
- [Block and Tiwari, concrete non-interactive FRI](https://eprint.iacr.org/2024/1161): parameter-sensitive proved versus conjectured guarantees; not a project QROM qualification.
