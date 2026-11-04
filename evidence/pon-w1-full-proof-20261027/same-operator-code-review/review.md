# Independent read-only review of the complete W1 zkVM experiment

## Scope and verdict

Reviewed source: `f9994db17eb9ed5fdc0bf080572dd6e0e6d4b198` in
`chain-work/formal/pon-nakamoto-v1/w1_zkvm`, its original native dependencies,
and `docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md`.
The reviewer used source inspection and readback of existing observations only.
No build, Rust test, proving job, native execution or adversarial crash was run
by this review; no root worktree file was edited.

**No omitted native W1 relation check, journal substitution, Fake/dev bypass,
or additional proof-randomness ticket was found in the reviewed call path.**
This is a bounded code-review conclusion, not a proof of the upstream zkVM or
whole-chain security. One concrete pre-verification parser weakness was found
and subsequently fixed in `ce04877b6cab8109fee51c7013bf1c8127978946`.
The original proof measurement remains attached to source
`65c97a95cab4702a368855397c65413e2a754b97`; it must not inherit a successor
decoder's test verdict or be relabeled as a new-source measurement.

## 1. Concrete finding and reviewed correction

### W1-01: recursive rejected receipt types entered the general decoder

At the original source, `host/src/main.rs:28–34` deserializes the full SDK
`Receipt` using bincode before `:45–51` requires a Succinct receipt. A 16 MiB
input limit and bincode byte limit do not provide a recursion-depth limit.
In pinned `risc0-zkvm` 3.0.3, `Receipt.inner` may be Composite, whose
`assumption_receipts: Vec<InnerAssumptionReceipt>` can recursively contain
Composite receipts. An attacker-selected, ultimately forbidden variant can
therefore descend through arbitrary nesting before the application rejects it.
This is a statically identified stack-exhaustion path; no crash was attempted.

The path is a denial-of-service concern for untrusted receipt parsing, not a
way to obtain a valid W1 proof or another lottery ticket. The reviewed program
is an isolated local experiment, so this finding does not establish a currently
exposed Node vulnerability. It is a blocker for reusing that original decoder
at an untrusted native admission boundary.

Exact pinned wire facts were checked in the downloaded dependency sources:

- `risc0-zkvm-3.0.3/src/receipt.rs:116`: fields are `inner`, `journal`, `metadata`.
- The same file at `:308` orders variants Composite=0, Succinct=1, Groth16=2,
  Fake=3. The derived serde representation has no preceding struct tag.
- `bincode-1.3.3/src/ser/mod.rs:206–217` writes the enum index as u32;
  the selected fixed-integer encoding and default little endian make the first
  four bytes of the allowed variant exactly `01 00 00 00`.
- The Succinct branch has no recursive Receipt edge. Its claim has fixed
  nesting; its assumptions are a vector of fixed-shape digest pairs, not nested
  receipts. Journal bytes, seals, strings and Merkle paths remain variable-sized.

Successor `ce04877b6`, `host/src/main.rs:28–43`, now checks the total byte cap
and the exact LE u32 Succinct tag before invoking the existing bounded,
trailing-rejecting decoder. Inspection confirms that this closes the identified
Composite recursion path. The extra in-memory Succinct check and real receipt
verification remain in place.

The committed regression constructs 4,096 nested Composite assumptions as
213,084 bytes and asserts the specific predecode error. It never constructs a
recursive Receipt object or passes that vector to the old decoder. It also
covers prohibited and truncated tags, truncated Succinct data, and the 16 MiB
cap. Existing `/workspace/scratch/56818e4fba76/w1-decoder-tests.log` records two
passing tests run by the root agent. The reviewer inspected this log but did
not rerun those tests. This correction does not prove arbitrary SDK-parser
resource safety or establish a public receiver CPU budget.

## 2. Complete relation and public statement

| Obligation | Reviewed implementation and consequence |
| --- | --- |
| Fixed input and original header | `relation/src/lib.rs:44–49` requires exactly 49,506 bytes and calls the original `Header::decode` on its first 318 bytes. `pon_wire.rs:143–164` requires the exact PNH1 length, magic and version. |
| Challenge binds the full header | `pon_wire.rs:166–170` hashes the exact canonical encoding, including network, parameters, parent, height, timestamp, target, miner, all roots, work task and nonce. There is no separate caller-selected challenge. |
| Original complete W1 verifier | `relation/src/lib.rs:50–54` calls `pon_work::verify`, not a precheck or sampled relation. |
| Canonical A/B/C and task | `pon_work.rs:503–567` enforces PNW1 length/version, nonzero target, each matrix word below q, and the task commitment to exact A/B bytes. C is checked even though the optimized path does not allocate a separate decoded C vector. |
| Ticket | `pon_work.rs:568–574` checks the original hash of challenge and trace with the same byte-array target comparison. The public helper repeats this binding. |
| Noise and complete trace | `pon_work.rs:194–220,693–783` retains four challenge-bound bounded rejection samplers and the original complete prefix order. Batch hashing changes update-call grouping, not transcript bytes. |
| Product | `pon_work.rs:611–639` requires the recomputed trace and the entire reconstructed C to match the submitted bytes before constructing VerifiedWork. |
| Public journal | `relation/src/lib.rs:24–40` emits its 20-byte domain, the full 318-byte header, trace, ticket, existing block identity and all 16,384 product bytes: exactly 16,818 bytes. |
| Public expectation | `relation/src/lib.rs:60–88` requires the caller's entire header to equal the proven journal header and checks ticket, identity and canonical public C after cryptographic verification. |

The scalar reference and default transposed verifier represent the same W1
relation. Their modulo-q arithmetic is ordinary proved guest integer arithmetic:
`q = 2^32 - 5` has not been replaced by the zkVM's internal proof-system field.
The full prefix stream is 32,768 LE32 words. Including the 16-byte trace domain
and 32-byte challenge gives 131,120 streamed bytes, or 2,049 SHA-256 compression
blocks including padding. This is one streamed digest, not 32,768 separately
initialized SHA-256 hashes.

The guest `methods/guest/src/main.rs:10–15` allocates a fixed buffer, reads it,
runs the complete relation and commits only its returned journal. There is no
guest shortcut for the maximum-target fixture and no public path that can
commit an unchecked product.

The guest does not check EOF after the fixed read. Thus private stdin can have
an unread suffix even though the relation consumes exactly one fixed-size
input. This is not an observed W1 forgery or additional ticket: unused suffix
bytes enter neither the public statement nor work identity. If future wire
language promises rejection of surplus private stdin, it needs an explicit
EOF check or wording that distinguishes the consumed statement from the
private transport stream. It is not necessary to alter the currently measured
guest to preserve the present one-work identity.

## 3. Cryptographic binding, fake proofs and work identity

The original `host/src/main.rs:45–53` requires Succinct, invokes
`Receipt::verify(TRNM_W1_FULL_GUEST_ID)`, then checks the exact expected public
header/journal. The pinned SDK's `src/receipt.rs:163–194` verifies integrity and
compares the whole expected successful ReceiptClaim digest. This constrains
the image, `Halted(0)`, journal digest and empty assumptions; it is stronger
than checking seal integrity alone. The guest itself makes no conditional
`env::verify` call.

Both guest and host request `disable-dev-mode`. The host also refuses
RISC0_DEV_MODE and automatic/remote-prover selection variables, requires an
explicit local binary whose SHA-256 matches the pinned release, and has no
fallback success path. The Succinct variant gate independently excludes Fake,
Composite and Groth16. The pinned backend is executable provenance, not an
authority substitute: acceptance still depends on the SDK's cryptographic
verification and the expected guest image.

The only logical identity remains `H("block", header, trace)`; the lottery is
`H("ticket", challenge, trace)`. Receipt bytes, receipt metadata, blinding,
recursive proof choices and their encodings enter neither expression.
Equivalent proofs cannot create distinct logical work or more target trials.
The isolated prototype does not itself add any chainwork, and does not test a
Node deduplication integration; future admission must continue to credit the
existing block identity only once.

`check_public_journal` is publicly callable but expressly documented as a
post-cryptographic binding helper. Its output is not an authority capability.
It cannot independently establish product correctness and must not become a
standalone native verifier.

## 4. Remaining proof-format and qualification boundaries

These are explicit limits or future integration requirements, not additional
observed proof forgeries:

- The SDK default verifier registers Blake2b, Poseidon2 and SHA-256 suites. It
  checks known verifier parameters and a permitted control root; it does not
  restrict the application to one recorded suite name. A deployed proof profile
  needs an exact permitted suite/parameter policy and hostile-input cost bounds.
  The current experiment records the actual suite, and makes no PQ qualification.
- SDK Succinct verification obtains the effective control ID from the seal in
  its callback. The separate `SuccinctReceipt.control_id` field is not compared
  in that verification path. Treat the host's recorded field as observed receipt
  metadata, not an independently authenticated application authorization value.
  This does not change the checked guest/image/journal or allow another ticket.
- A 16 MiB receipt cap is finite but is not a demonstrated public service budget.
  The header/journal size checks currently occur after expensive cryptographic
  verification. Production admission may reject obvious public-format failures
  earlier, while still requiring the full cryptographic check before success.
- The execution-control harness's negative modes produced executor errors with
  guest panic text. It deliberately recorded `guest_rejection_established:false`
  and nonzero process exits. Preserve those raw outcomes; they are not successful
  cryptographic invalid-proof tests. The positive execution observation is also
  explicitly execution-only, not a proof.
- The outer proof observer records timeouts and incomplete attempts. Its wait4
  peak RSS is kernel child rusage, not a measured sum of simultaneous process-tree
  allocations. Its CPU/time/exit observations and the separate resource sampler
  must retain their actual scopes.

## 5. Source-bound measurements and security-language check

The actual proof attempt's `source.json` pins source
`65c97a95cab4702a368855397c65413e2a754b97`, clean tracked source, host SHA-256
`de867e2b77079b8d73b890823d3b3cc23f6b6d810660a5291216b32d886b43d5`, and local
r0vm SHA-256
`2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6`.
Readback during this review confirmed that the on-disk original host binary
still has that digest after the successor decoder test build.

Between 65c97a95 and f9994db17, the main host, relation, guest, both lockfiles,
the observation runner, `pon_work.rs` and `pon_wire.rs` are byte-identical.
The W1 workspace gains only the separate execution-control binary. Other
repository files do change, so this is not a claim of identical complete source
trees or an automatic transfer of compiled-artifact qualification.

The independent native-cost observation uses source
`f6c6380abc1b1a942ad90120f87e44e36b07f83c`, source-bound binary
`b663b1659e4fc4ad22ffb82a34f438bbb933b08140dd07c16f37a558e6c45057`, and the same
49,506-byte input SHA-256
`67b74fa2f417c0240d974e5ecea410d2b68d97d6dde667603aeb4d7ce59036cb`.
Existing readback reports 1,000 complete native verifications, median
693,803.5 ns, observed nearest-rank p99 1,559,635 ns and maximum 6,346,603 ns.
Concurrent proving and separate M06 work are recorded. This reviewer did not
rerun the benchmark. It is one fixed dense maximum-target sample, with fixture
generation and experimental journal construction excluded; it is not the full
mining search distribution, proof benefit, production latency or tail guarantee.

The security contract does **not** claim that trace equality proves useful
training, minimum energy or quantum safety:

- Lines 47–52 retain actual parent, branch target, timestamp, task eligibility,
  transaction, M06 and State/receipt-root validation at the original Node.
- Lines 69–74 explicitly allow structured tasks, preprocessing, amortization,
  reuse of AB, hardware and algorithmic improvements in adversarial cost.
- Lines 79–84 label equal-cost/uniform-lottery reasoning as conditional.
- Lines 96–113 separate computational correctness from fresh training, model
  improvement, energy and sequential hardness, and require additional exact
  quantum random-oracle and per-application hash analysis.
- Lines 153–158 retain independent actual-benefit, native integration, quantum
  soundness, hardness, model-efficacy and WAN gates.

At review handoff the original real proving attempt was still pending. No
receipt-size, proof-generation, verifier-speed, actual-benefit, hardness,
whole-chain PQ, native admission or production activation acceptance is granted
by this review. A later completed proof and a fresh-process verification must
be read as new evidence under their original source identity.
