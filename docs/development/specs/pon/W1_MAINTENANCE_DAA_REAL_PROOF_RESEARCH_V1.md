# W1 maintenance × DAA: exact full-proof branch experiment

Status: **unactivated research, no production authority**. This is a subordinate
M01/M02/M17 engineering experiment to PN1/P1-B. It does not introduce another
consensus profile, activate ASERT, or change historical Q4/Revision12 semantics.

## Why this exists

The prior lease/DAA campaigns include arithmetic time schedules and synthetic
Poisson-mined, assumed-valid blocks. This experiment separately executes the
**unchanged scalar PNW1 relation** using the Revision12 deterministic public
Maintenance A/B matrix recipe and the existing canonical PNH1 318-byte header.
Every success obtains and fully verifies the actual 49,188-byte W1 proof.

It builds two local logical fork branches sharing a first real W1 proof and
using identical mining calculation, attempts and proof validity:

- `honest`: height `h` timestamp `10*h`, no endpoint manipulation.
- `endpoint_push`: heights 2–14 choose `MTP11(parent)+1`, at height 15
  timestamp 600, at height 16 timestamp 601; `logical_now=10000`.

Both are valid under the original `MTP11` and +120s *provided logical
clock*. These are **not** elapsed real-world mining timestamps. The actual
legacy 16-block 15-interval DAA makes the latter branch's next target four
times easier (up to the declared pow_limit), while all complete W1 proofs
remain valid. Chainwork always uses `floor(2^256/(target+1))` from the
expected target; the lower-work branch never wins merely by height or luck.

A separate false-trace candidate uses the same public A/B input and challenge,
zero claimed product and a newly fabricated trace hash. Its cheap Ticket
predicate passes but the complete original W1 verifier rejects `TRANSCRIPT`;
**zero** valid chainwork is credited. CPU timers are single-process observations,
not minimum attack cost or receiver-service resource measurement.

## Reproduce using existing repository modules

From `formal/pon-nakamoto-v1/`:

```sh
python3 -m unittest -v test_w1_maintenance_daa_proof_research.py
python3 w1_maintenance_daa_proof_research.py \
  --output /new/path/w1-daa-report.json \
  --artifact-dir /new/path/w1-pnw1-raw
```

The program uses only the original `contract_wire` / `work_oracle` and the
existing `daa_research_oracle`; neither original module is edited.
The report's reproducible inventory SHA-256 excludes CPU durations; the
raw artifact directory is create-only and holds every complete PNH1 and PNW1
byte sequence. Verify every `<block_id>.pnw1` SHA-256 against the report.
The extra `invalid-claimed-transcript.pnw1` is **not** a valid work proof.

The initial **local isolated** run verified 31 complete PNW1 proofs, actually
attempted 137 candidates, retained 32 full raw proof/header pairs (including
one invalid trace), and passed 7/7 focused Python tests. It used the exact
repository `work_oracle.py` Git blob
`9cbfccd2d50af48fc43522b967ffdfb1f45ec098`. The local runner
reimplemented only the two relevant `contract_wire` byte functions and
reused an earlier local `daa_research_oracle.py` with the same legacy DAA/MTP
and time-check routines. It was **not** an exact-head full-repository run.

Frozen source-only proof inventory digest:

`ecf015e262b03043b8a0395ee78a7cf04889a514dcf74f15c17106203ebfefbc`

## Strict nonclaims and remaining work

- Header transaction, state and receipt commitments are explicitly synthetic;
  they have correct **byte grammar**, not actual M06 signed execution roots.
- The research network and genesis hashes differ from installed Revision12;
  this does **not** supply a native consensus-valid Block or model output.
- The finite idealized clock does not give wall-clock time to mine, adversarial
  effective-work share, profitable attack, physical time drift or double spend.
- No native Rust W1, SQLite, real P2P, independent clients/operators,
  CPU/GPU prover lower bounds, validation-DoS economic bound or WAN response
  envelopes were executed by this Python experiment.
- `hardness_accepted`, `production_candidate`, all public-security acceptance,
  and new-DAA activation remain **false**.

Next strict exits: replay these preserved header/proof bytes in a separately
versioned native test context with real application roots and leases, perform
receiver-side full-cost and honest-service trials on exact source, then obtain
independently administered WAN/physical experiments without changing old Q4,
old W1 proof bytes, Revision12 Genesis Maintenance, or the deployed DAA.
