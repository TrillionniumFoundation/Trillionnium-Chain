# P1 History W1: combine the original CPU account and Host/M06 fence

Status: **DRAFT / SHADOW_ONLY / HOLD_NO_GO**, not production qualification.
Exact source parent: Chain #490 `197ba7a076ea9b89b9644e850341f4a45a3c0c79`;
the candidate is a separate child branch, not a merge to #328 or main.
No W1/PNW1 encoding, TaskId, lottery ticket, target, chainwork, signed
public V3 Cookie, final-use, consensus, state schema or activation changes.

## Concrete remaining P1 bypass at the original parent

Chain #490 already checked the original administrator-owned Host cgroup during
History W1 transcript replay and at M06/BeforeDurableCommit. However it did
not charge each remote History W1 and subsequent M06 operation to the Node's
already shared `ServiceMutationCpuDomain`. Cgroup aggregate CPU bounds are
not the V3 original per-request paid CPU budget. Up to 16 untrusted proofs/page
and 4096 pages/import could contend with actual honest paid mutations.

Chain #437 separately developed original-domain metering, a Node-scoped
zero-credit cold History epoch and durable old-V3-epoch fail-closed checks.
It lacked the newer #490 Host checks **inside** W1 and native M06. Neither
source alone closes both CPU/Host boundaries.

## Composition implemented on the child branch

- `store/operator_continuous_owner.rs::Node::remote_history_cpu_domain`
  uses the same previously bound V3/continuous CPU owner; if none exists it
  checks the durable `ordinary-public-v3-epoch-v1` metadata and refuses a
  leftover active/unclean epoch, then binds one **zero-initial-credit** original
  domain. No caller, peer key, packet or restart gets an independent warm burst.
- `ingress/public_v3/scalar_cpu.rs::cold_remote_history_epoch` reuses the
  original scalar credit/refill and actual same-thread accounting. No change
  to V3 quotas, credits or version signature.
- `ingress.rs::receive_page` reserves/settles an original CPU operation for
  bounded packet decoding, packet IDs/parent linkage, **each** complete
  new W1 + native M06 verification, and final activation. No nesting or
  double billing; already stored exact packets still run original context
  checks. Known budget depletion may wait at most two seconds for original
  refill; exhausted credit is local Busy/Capacity, never consensus Invalid.
- Each W1 callback checks its live original CPU debit. At the original
  bounded Host checkpoint cadence it also checks actual fixed cgroup owner.
  The native `ExecutionControl` combines that same Host check and live CPU
  checkpoint with `operation.worker_accounting()`, so M06 scoped workers,
  state-root work, ledger deltas and BeforeDurableCommit are inside one
  metered cancellation/commit authority. No new block verifier was created.
- Every operation settles even on false Transcript/Product, CPU refusal,
  cancellation and M06 failure. Missing/unknown CPU disables further starts
  without manufacturing a zero charge or rewriting an already durable block.
  Post-commit Host failures likewise refuse **sync completion**, not W1
  mathematical validity or existing persisted state.
- Public `receive_public_page_from` retains #488/#490's strict root-owned
  Host requirement even for loopback proxy sources. Crate-private
  `receive_page_from` retains local development compatibility but still
  charges the **same Node CPU account**. Raw/authenticated/durable/CLI
  History paths continue to call the original Host guarded owner.
- Existing #490 negative tests for W1 tile Host cancellation and
  BeforeDurableCommit M06 Host fault remain untouched.

## Additional native controls (source submitted, execution outstanding)

Under `ingress.rs`:

1. A malformed History packet consumes bounded decode CPU and leaves state unchanged.
2. A correct ticket/transcript with a wrong C receives a late `WORK:Product`
   refusal; the original cold Node account settles with zero inflight.
3. An independently valid W1 packet must still commit under that same account.
4. Two loopback source ports must reuse one CPU domain across a false and
   valid proof; bad duplicate content cannot overwrite the stored accepted byte.
5. Four different forged ticket-valid transcript claims under one exact
   challenge/target each cost a full W1 refusal; no Chainwork or state
   increases, then the honest reference proof still admits normally.
6. A previously active public V3 persistent epoch must prevent creating a
   fresh cold History budget after crash/cold open.
7. An explicitly clean V3 close allows exactly one shared cold account
   with zero initial credit, not a new epoch per lookup.
8. A locally marked unclean public service epoch refuses new CPU credit.

The original #488/#490 native Host W1/M06 failure and legal retry tests
remain required. No new historical timing, native compilation or physical
cgroup/GPU observation is inferred from adding a selector.

## Remaining blockers

- **P1:** A standalone History CPU epoch is still volatile and lacks its
  *own* complete durable operation-ID/debt reconciliation after a standalone
  History process crash. Its existing old-V3 persistent epoch guard does not
  solve every independent History crash. Shared Node `&mut` import holds the
  writer owner across refill wait/W1/M06 and does **not** provide fair
  scheduling against paid honest readers. Loopback relays and other exported
  caller paths require an explicit physical operator deployment contract.
- **P2:** Full original signed-Cookie/native W1 attack costs against the
  cheapest attacker CPU/GPU/ASIC, memory and WAN are unknown. Raising a
  public ticket target or changing signed domains without versioning
  does not solve W1's false-transcript cost gap.
- **P3/P4:** Identity rotation, valid W1/wrong StateRoot, replayed sessions,
  competing honest work, physically measured independent Host cgroups,
  original A03 three hostile modes x three runs x 3/3 timely confirmations
  per run, all failures and unknown samples are unexecuted on this exact
  source. Historic partial passes are not inherited.
- **P5:** W2-A remains sampling-unsound; W2-B full replay is not succinct;
  W2-C receiver-local tickets are only resource admission and remain
  locally cheaper than W1 full reject. No qualified neural-work hardness
  or succinct economical sound proof is available.
- **P6:** Only independent externally authored verification and cryptography
  review with hidden vectors, source/binary/hardware pins, and governed
  activation could close this gate. Internal Rust/Python/Go comparisons
  do not constitute third-party acceptance.

Required source gate: run `bash scripts/project-preflight.sh` from the exact
checked-out repository, followed by real Rust format, complete relevant
test selectors, native negative-campaign, physical cgroup readbacks, and
stored failed observations. No CI wait is needed to continue development,
but source-only changes do not close production admission. No auto-merge,
force update or production activation.
