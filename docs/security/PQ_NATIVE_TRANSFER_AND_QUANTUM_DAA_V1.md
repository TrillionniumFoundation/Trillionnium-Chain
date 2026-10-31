# Native PQ transfer boundary and conditional quantum DAA experiments

This is an implementation contract within the sole development plan's PN1/PN2
and M00/M01/M02/M06 owners. It adds no roadmap, consensus replacement, production
profile or activation decision.

## Frozen inputs

- Native PQ integration input: `5e797326b9c7635e43b93f97c65a309e51eafb46`.
- Its real upstream child `21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`
  is retained as a merge parent for the corrected fuzz lock, binary fixture
  cold-build closure and existing native integration fixes. No parallel owner
  or replacement dependency graph is introduced here.
- The earlier transaction fixtures were created against native input
  `4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251` and PQ research input
  `6f4b9cae0dafcb0e6bc171e2aa9b8f630e74eca6`; their provenance remains unchanged.
- These integration branches diverged. This increment reuses the newer branch's
  actual M01 and existing local PQ owner; it does not merge the older Cargo graph.
- Original native M02 blob: `2f63dd18dc5893e3020bb00b18f7dcb90bae41ae`.
- The M02 arithmetic blob is identical in both native inputs. The newer input's
  26-package Cargo graph, Cargo.lock and strict `forbid(unsafe_code)` M01 boundary
  remain unchanged. Its existing `ml-dsa = 0.1.1` dependency enables only `alloc`.
  Exact final-source Rust and independent implementation/audit gates retain their
  separate meanings.

## Implemented native component path

M00 retains the existing TPQ1 framing from the PQ branch and adds bounded QTX1
decoding. M01 uses RustCrypto ML-DSA-65 in the node process to perform actual
FIPS-204 verification with empty context. It returns a privately constructed
`SignatureCheckedPqFrame`; the parser cannot construct it and no caller-supplied
Boolean or verifier callback can grant verification. The existing strict SPKI
prefix/OID, signer key ID, network, purpose, owner context, generation, nonce,
expiry and SHA-384 payload commitment are checked first. ML-KEM is not used for
signatures. No subprocess or OpenSSL CLI exit status is a native authority.

The explicit M06 `preview_fresh_transfer` then checks the actual supplied
parent's nonce, funds, byte-priced fee and resulting canonical root. It reuses
the same private fee/nonce and transfer-balance functions as installed PNX1,
without creating an Envelope carrying a fake classical signature. Every call
rechecks its bytes and current parent. Failed transfers publish no writes.
The transfer identity excludes randomized signature bytes, so re-signing the
same statement does not create a new transaction identity.
The returned fee is a separate transaction component output. Block reward/fee
allocation and complete monetary conservation remain the block owner's work.

This component preview is deliberately not installed node admission. It does
not commit SQLite, include a block, reserve a mempool nonce, import an account,
issue a final-use capability or qualify whole-node PQ. Its receipt says
`preview_only` and `native_pq_node_integrated = false`.

### Fresh namespace and ownership

The research network is SHA-256 of `TRNM/PoN/QTX1NativeTransfer/v1\0`, the base
network and base parameter commitment. Only generation 1 key-ID-addressed fresh
accounts are supported. The signer ID must equal the sender and must be derived
from the exact supplied ML-DSA-65 SPKI. Existing installed PNX1 remains closed to
QTX1. A future persistence owner must store the explicit research namespace; it
cannot silently import the base State or use a parser result as a parent proof.

QTX1 `expires_at` retains its existing UTC-second meaning. It is not reinterpreted
as installed PNX1's height expiry. The controlled caller supplies observed UTC
time, never a time copied from the transaction itself.

### Remaining native integration obligations

1. Reuse the existing locked dependency graph and run the affected packages,
   retained M06 regressions, strict Clippy and formatting with the repository's
   declared toolchain on the final source. Published vectors do not replace an
   independent implementation audit or side-channel assessment.
2. Specify the actual versioned block/transaction dispatch, PQ byte/CPU limits,
   mempool reservation, atomic durable state owner and exact parent binding.
   Current 2,048-byte installed transactions cannot carry a 3,309-byte signature.
3. Add branch-aware key epochs, revocation, migration and liability preservation.
   Do not reset old nonce floors or permit classical OR PQ fallback after an
   explicit PQ activation. Reorged chain state and irreversible local effects
   require separate retention rules; this pure preview creates no effect journal.
4. Cover ordinary P2P identity, Cell discovery/release, governance and Hepta
   final-use paths. Hybrid key exchange alone does not authenticate those owners.
5. Keep production, public-WAN, independent-operator and quantum-work qualification
   false until their own evidence exists. PQ authentication does not establish
   useful-work hardness, data availability or model improvement.

## Existing local authorization owner hardening

The existing [native authorization owner](../protocol/pon-nakamoto-v1/details/PQ_NATIVE_AUTHORIZATION_V1.md)
remains the sole local TPQ1 sequence owner. The original source could return a
successful record when an INSERT trigger silently ignored the statement, when a
trigger reset the sequence, or when TEMP tables redirected unqualified writes
away from the durable main database. These local schema-corruption cases were
reproduced using the original native owner, real signatures and SQLite; they are
not claims that an unauthenticated remote caller can modify SQLite's schema.

The increment preserves the v1 schema/domain and checks its exact two table
definitions, absence of TEMP schema objects, pinned identity and retained tip.
All mutation queries explicitly name `main`. Inside the immediate transaction,
it checks both affected-row counts and reads back the exact statement, digest
and sequence before commit. Changed schema, missing/corrupt tips and failed
writes return no recorded capability. The original abort-trigger regression now
expects earlier schema refusal. A separate test exhausts real SQLite pages and
checks that a real `SQLITE_FULL` failure rolls back the counter and record
together before retry succeeds after capacity is restored.

This check reads the current tip, not every historical row. It cannot detect an
attacker replacing the complete database with a consistent earlier copy. The
existing ordinary SQLite owner still does not qualify the native physical I/O
boundary, power-loss behavior, rollback-resistant monotonic hardware/remote
anchors, or execution of an irreversible external effect. No authorization
record becomes Hepta install authority.

## Actual signature vectors and negative cases

`trillionnium/crates/trnm-protocol/tests/fixtures/pq_transfer` contains public bytes only. Its manifest records
the exact cryptography/OpenSSL producer and decoded-byte SHA-256 fingerprints.
The generator never writes private keys, refuses to overwrite an existing fixture
directory, and creates real positive signatures for wrong-purpose, stale-nonce,
wrong-network, low-fee and unsupported-generation cases. Those are crypto-valid
but must fail the corresponding native permission or state checks.

The duplicate-hint negative inserts a repeated index while preserving the hint
bitset, then requires actual verification refusal. This guards the strict-order
regression disclosed for early RustCrypto release candidates; stable 0.1.1 is
after the published fix. Other controls include all-zero and bit-flipped
signatures, substituted SPKI, appended DER, changed payload/context and classical
algorithm IDs. No fixture validity is inferred from matching source hashes.

Useful verification commands (each is a separate evidence scope):

```bash
bash scripts/project-preflight.sh
python3 scripts/pon_pq_native_fixtures.py --check trillionnium/crates/trnm-protocol/tests/fixtures/pq_transfer
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol --lib pq_
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --lib pq_auth
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --lib pon_executor::pq_transfer
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib pq_authority
```

Fixture generation and real Python cryptography success do not imply that the
Rust tests compiled or ran. Record both command output and actual toolchain.

## Conditional quantum search over exact DAA arithmetic

`formal/pon-nakamoto-v1/quantum_daa.py` reads the actual devnet parameter file and
replays required work, branch-local retarget, MTP-11 and future-skew checks using
integers. Required work is `floor(2^256/(T+1))`; the elapsed-span lower clamp is
ceiling(desired/4), and checked u64/512-bit boundaries are preserved.
`quantum_daa_native.rs` includes the original M02 source directly. The differential
tests compile that source and compare 1,079 boundary/random vectors; they do not
copy the Python arithmetic into a second Rust implementation. Missing Rust is a
visible skip, not native parity success.
The standalone report checks the frozen native source blob but does not execute
the Rust differential test itself; its output labels that boundary explicitly.
The existing protocol-contract CI lane includes the differential test without
removing any prior command or changing its original controls.

The schedule assumes valid fresh W1 for every synthetic header. It generates
neither W1 proofs nor a reversible W1 circuit. Its two cost assumptions scale an
isolated block's expected time with inverse success probability or its square
root. Constants, variance, physical qubits, T-depth, error correction, data loads
and public-tip interruptions are not measured. The reported private-chain weight
comparison is conditional arithmetic, never a stochastic attack probability or
proof that an actual quantum machine can break this chain.

The supplied ramp, hold and final-tip-timestamp cases are checked against the
actual time/target rules. A fixed-target comparison is an explicitly different,
unactivated experiment. Tightening a per-epoch clamp or inspecting only the final
timestamp is not assumed to close the general quantum difficulty problem.

```bash
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_quantum_daa.py -v
python3 formal/pon-nakamoto-v1/quantum_daa.py --output /tmp/pon-quantum-daa.json
```

### Fixed probability with fresh neural work is unproven

The sensitivity output considers fixed `p0`, work weight proportional to `m`,
and an explicitly assumed reversible oracle cost `Cq(m)`. Relative quantum
weight rate is `m / (Cq(m)/Cq(1))`. Linear cost removes this particular arbitrary
target-difficulty amplification; sublinear cost restores an advantage. Neither
cost law is proven by this code or by a STARK correctness proof.

Any successor must bind m and the complete header before work, forbid selectable
or reusable prefixes, bind each round to prior outputs, exclude proof randomness
from ticket/block identity, and assess low-rank shortcuts, batching, parallelism,
actual useful outputs, resource volume, block latency and liveness. Poisson/race
assumptions, chain quality and mixed classical/quantum security need a new
analysis. No new work relation or fork-choice rule is selected here.

### Complete W1 oracle ledger: static accounting only

The following ledger is derived from the frozen native source retained by
`21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`. It is an accounting template for a
future reversible implementation, not a measured quantum circuit, a minimum
cost proof, or an estimate obtained from the CPU test duration. Consider a fixed,
independently eligible task and parent/header context, with the nonce as the
search variable. If additional header fields or tasks vary, their construction,
authorization and cache-invalidation costs must also enter the oracle.

The public constants are `N=64`, `R=8`, `q=2^32-5`. A and B contain 8,192
canonical 32-bit words in total: 32,768 material bytes. That is a byte count,
not a claim that the computation requires or achieves any particular number of
qubits. Classical fixed material may be compiled as constants, loaded through a
QROM circuit, or accessed through an explicitly priced quantum-memory design;
none of those access models is free by default.

| Stage in the general prepared producer | Exact source-level accounting | Quantum accounting that remains unknown |
| --- | --- | --- |
| Fixed-task setup | Establish the outer task/header context, including its task digest over a 32,792-byte framed message as required. Separately, `PreparedTask::new` checks A/B, computes C=A*B once with 262,144 multiply-accumulate terms and 4,096 output reductions in the ordinary kernel, and retains the 49,156-byte PNW1 prefix; `new` itself does not call `task_id`. | Coherent material loading, chosen multiplication/reduction circuit, setup reuse across searches and amortization. The cached product cannot be charged again to every candidate. |
| Header challenge | The complete framed 318-byte header gives a 343-byte SHA-256 message, six compression blocks including padding. | A fixed header with only its final nonce changing permits reuse of five complete compression blocks; a full six-block hash is not a lower bound per candidate. A changed parent, time, task or root may invalidate that setup. |
| Noise generation | Four arrays of 512 accepted field words. Each framed noise message is 66 bytes, hence two SHA-256 compression blocks. A successful array uses 64 through 128 hash calls; 128 is a hard per-array budget. A successful full four-array expansion uses 256 through 512 calls. A failed expansion can stop at the first array after 128 calls; range checks, compaction and failure behavior remain part of the relation. | Reversible rejection sampling, output indices, counters and the NoiseBudget flag. Failed branches must remain coherently unmarked and be cleaned up. A fixed padded circuit must cover the bounded control flow; a variable-time construction needs its own security/cost argument. The common no-rejection path cannot silently stand in for every superposed input. |
| E=EL*ER and F=FL*FR | Two N-by-R-by-N products: 65,536 multiply-accumulate terms and 8,192 reductions in the ordinary prepared kernel. | Actual field multiplication, accumulator widths, reduction, ancilla and coherent access cost. |
| A'=A+E and B'=B+F | 8,192 additions and 8,192 reductions, plus the producer's B' transpose. | Reversible addition/reduction, memory layout and transposition. |
| All ordered transcript prefixes | 512 tiles; each updates 64 cells using eight products. There are 262,144 multiply-accumulate terms and 32,768 prefix reductions. All 32,768 intermediate field values enter the transcript. | A circuit for every required prefix, including any exact algebraic shortcut, its storage and cleanup. Merely obtaining the final matrix product is insufficient. |
| Trace hash | **512 `update` calls are not 512 independent SHA hashes.** Each contributes 256 bytes to one streaming SHA-256 computation. The 16-byte trace domain, 32-byte challenge and 131,072 prefix bytes form a 131,120-byte message: 2,049 compression blocks including padding. | Reversible compression and message preparation, serial dependency, retained garbage versus recomputation, and the chosen reversible pebbling schedule. |
| Ticket and predicate | The framed challenge/trace ticket message is 90 bytes: two SHA-256 compression blocks, followed by a 256-bit target comparison and all validity flags. | Comparator/phase cost and the definition of the marked set. Uniform independent tickets are a model assumption, not a distribution theorem established by these tests. |
| Successful output and independent replay | A successful PNW1 witness is 49,188 bytes. The full verifier additionally decodes/range-checks the three matrices and recomputes the four product-correction multiplications: 131,072 multiply-accumulate terms, 13,312 reductions including final correction, and comparison with 4,096 claimed C words. It also performs its framing, commitments and public-statement checks. | Proof construction, actual proof-system cost and native admission. A miner can construct the winning witness after measurement from its valid prepared task; these verifier-only corrections must not be artificially charged to every Grover query. |

For one explicitly chosen reversible construction and an additive metric such
as logical T-count, write its forward cost as

\[
C_F = C_{\mathrm{load}}+C_{\mathrm{challenge}}+C_{\mathrm{expand}}
    +C_{E,F}+C_{A',B'}+C_{\mathrm{prefixes}}+C_{\mathrm{trace}}
    +C_{\mathrm{ticket}}+C_{\mathrm{validity}}.
\]

This separates all operations that a single-SHA estimate would omit. The
ordinary prepared arithmetic subtotal is 327,680 multiply-accumulate terms
and 49,152 reductions, plus the separate additions, packing and accesses.
Those word-level counts are not reversible-gate counts. The existing
paired-product producer already uses a different arithmetic schedule; periodic
maintenance-prefix producers and zero/structured inputs provide further
competitors. No table entry is a lower bound against these or future algorithms.
Any claimed least-cost quantum oracle must compare legal complete competitors,
including their setup and retained material, rather than benchmark only this
general reference schedule.

A conventional clean phase oracle has the form

\[
O_f = U_F^\dagger\,Z_{\mathrm{valid\ ticket}}\,U_F,
\qquad C_{O_f}=C_F+C_{\mathrm{phase}}+C_{F^\dagger}.
\]

The adjoint must restore work registers and validity flags coherently. It cannot
erase intermediate values for free. For a literal circuit followed by its
adjoint the gate counts match, while other clean constructions can make different
time/space tradeoffs. Peak live qubits, circuit depth, quantum-memory hardware,
error-correction volume and wall time require a separate resource schedule;
they are not obtained by summing byte counts or multiplying CPU seconds by a
Grover factor.

Under additional idealized amplitude-amplification assumptions, a search ledger
would contain

\[
C_{\mathrm{search}}=C_{\mathrm{setup}}+
 k\bigl(C_{O_f}+C_{\mathrm{diffusion}}\bigr)
 +C_{\mathrm{measurement}}+C_{\mathrm{winning\ proof}}+C_{\mathrm{admission}},
\qquad k=O(1/\sqrt p).
\]

Unknown success fractions, failed noise-budget branches, parallel quantum
machines, new-tip interruptions and invalidated prepared contexts need explicit
treatment. The DAA model's isolated-rate input `r=0.25` has not been derived from
this complete ledger. Its apparent weight advantage remains conditional, and
`quantum_resource_estimate = null` remains appropriate. The fixed-p0/fresh-m
proposal would require a newly defined full `C_F(m)` and a new chain-quality
analysis; this document supplies neither a quantum lower bound nor activation.

Source anchors for reproduction:

- [W1 constants, domain hashing and bounded noise expansion](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs#L19-L222).
- [Prepared task setup and all transcript prefixes](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59/trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs#L808-L963).
- [Independent complete relation and product corrections](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59/trillionnium/crates/trnm-crypto-primitives/src/pon_work/full_relation.rs#L240-L451).
- [Complete paired-product competitor](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59/trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs).
- [Maintenance prefix competitor](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59/trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_prefix.rs).

## Recorded execution and source limitations

The [small raw evidence archive](../../evidence/pon-pq-native-daa-20261027/README.md)
binds native execution to code commit
`99be553ea80bee137b0bcc3b67d8786348547256`. Unique copied binaries passed M01's
five PQ tests (including 210 pinned Wycheproof cases), the complete M00 lib
suite (39 pass, two original ignored), complete M06 lib suite (78 pass, six
original ignored), and 12 local PQ-owner tests. Other Node/M01 tests remain
filtered. The inherited size-bound constant assertions first failed strict
Clippy at 99be. Test-only commit `215fc89386a6375e8a2663774085c3a11b24e24e`
retains both bounds as compile-time assertions, with no lint suppression.
Workspace/all-target/all-feature strict Clippy, formatting and the exact
affected test in a fresh copied binary then passed; all 1,675 tracked
non-evidence files matched before and after that Clippy run. No full suite
is claimed at 215f. The SQLite physical I/O-boundary UNQUALIFIED warning remains.

The atomic native test wrapper nevertheless refused its final source guard:
old self-generated hex fixtures appeared as untracked files after its copied
binary runs. Its earlier pre-Cargo refusal, original owner RED cases, first
SQLite-full setup failure and earlier fuzz-lock error are retained. Historical
upstream evidence is sparse locally; no whole-repository source-guard success
is claimed. A clean published checkout must pass the original gates. Subsequent
documentation/evidence recording changes no native source or locked dependency.

## Primary research and implementation references

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
- [RustCrypto ML-DSA 0.1.1](https://github.com/RustCrypto/signatures/tree/ml-dsa/v0.1.1/ml-dsa).
- [Duplicate-hint advisory](https://github.com/RustCrypto/signatures/security/advisories/GHSA-5x2r-hc65-25f9).
- [Quantum difficulty-increase analysis](https://arxiv.org/abs/2403.08023).
- [Quantum mining cost and interruption analysis](https://arxiv.org/abs/2110.00878).
- [IOP arguments in QROM](https://eprint.iacr.org/2019/834).
- [FRI Fiat-Shamir analysis](https://eprint.iacr.org/2023/1071).

No STARK implementation, grinding PoW, BLS/pairing wrapper, validator committee
or consensus fallback is introduced by this increment.
