# W2 formal and admission research consolidation

Status: **committed code has selected-control PASS; audit files are uncommitted;
research remains HOLD_NO_GO**. No remote
branch/ref, production policy or network service was changed in this lane.

The assigned scope is 20 root research tips plus four formal-only transfers,
24 original heads, 95 distinct source variants and 33 historical documentation
variants. The initial selected source is
`11a2cba1953f4aaee97e8ed169fcfd9a1517da23`. The final code checkpoint is
`ae2cba1d5ae22ad55fd44e557313f19961f4697c`; later documentation and this
ledger do not acquire a retrospective test result.

## Concrete changes

The stateful research issuer now has one cumulative epoch issuance counter
and a trusted fixed-bit owner policy. No expiry/spend/identity event refunds
that counter. Existing cost callers configure the owner explicitly. Common
Grant bytes and domains remain unchanged.

Read-only cost analysis now counts reusable preparation once across the
declared shared context, treats missing transport/hardware as UNKNOWN and
refuses known-subtotal overflow. The cost envelope also refuses finite-input
arithmetic overflow. Declared-price and joint triage readers retain their
false activation fields and never attest caller-supplied measurements.

The fa704 shared physical database class now applies its inherited local
minimum-cost policy before storing a paid claim. Its unchanged schema does
**not** persist capacity, lifetime or minimum_bits. A local raised floor is
not restored by reopening; this is not a shared policy migration mechanism.
The selected policy-bound Gate and the held-inode owner remain different
research contracts.

The independent stdlib Go full W1 oracle and bounded bridge are retained.
Two ordinary Go controls and two Python methods include ten complete proof
byte comparisons with full verification in both languages. Historical
forgery/cost-driver tests are not transplanted into the selected Go suite.

## Per-tip disposition

Full original SHAs, source Git blobs, exact selected blobs and semantic
reasons are in [tip-ledger.json](tip-ledger.json); the assigned roster is in
[assigned-tip-snapshot.json](assigned-tip-snapshot.json). “Archived alternate”
means the exact original head and evidence must remain in final Git ancestry
or a durable archive before branch retirement. It does not mean the selected
owner implements every historical capability. Source ports in this lane are
not claims that the entire tip, including Node/CI deltas, has been merged.

| Original tip | Disposition | Specific result |
| --- | --- | --- |
| `fa704e45c1` | Retained + local fix | Held-inode shared DB owner; inherited local floor checked, persisted-policy limits explicit. |
| `9934e70dba` | Archived alternate | WAL paid/clock/policy owner and its exact matched-cost reader; different schema, policy and provisioning. |
| `10429dab61` | Archived alternate | SQLiteSpentOwner and injection contract; selected Gate/common stateless retained. |
| `26dd988a1e` | Archived alternate | Boot-context WAL owner; selected Gate is not an equivalent stored format. |
| `ca2e9d14d5` | Archived alternate | W2ER append-only epoch log; selected SQLite/lease owners do not claim its log contract. |
| `db379fe210` | Retained exact | SQLite epoch fencing and its matched research cost reader. |
| `d575524c95` | Compatible parts integrated | Shared-cost correction, price model and joint triage; distinct prevalidated SQLite injection archived. |
| `c953a86c93` | Retained exact | Exclusive local epoch lease, private identity and weakref fork cleanup. |
| `cab37b3f9e` | Archived alternate | Policy-bound WAL meta/spent and exact-bit injection; no schema mixing with fa704. |
| `093ec49ae5` | Retained exact | Policy-bound full-grant DurableSpendGate and common caller-bound stateless owner. |
| `e19245dd88` | Archived alternate | Distinct signed Grant domain, durable lifecycle and matched historical cost driver. |
| `7573e3ae83` | Corrected continuation | Strict UNKNOWN reader retained, conservative d575 shared-preparation accounting applied. |
| `4bf21e2a1e` | Archived alternate | Shared rotate/join WAL lifecycle; selected b517 remains exclusive-directory ownership. |
| `4f367f106f` | Retained exact research | Full-tile W2-D and W2-E polynomial models, original failure evidence unchanged; no fault drivers rerun. |
| `b517d6f9e1` | Retained exact | Exclusive directory, fresh durable epoch and commit-before-READY owner. |
| `a4f7fd5bda` | Integrated formal scope | Cost envelope plus finite-arithmetic guards; Node deltas remain separately assigned. |
| `51423e1798` | Retained exact research | PND0 product projection and original unqualified observations; no cost driver rerun. |
| `7aa1a1dad7` | Integrated | Cumulative original epoch issuance without refunds, composed with a0 owner bits. |
| `9386ba1462` | Archived alternate | PFD1 tape profile and legacy stateless Grant with paired costs; raw layouts and source-bound timings differ. |
| `658b61cacc` | Compatible oracle integrated | Bounded Go W1 + ordinary controls and full-byte parity; historical W2 comparison/fixture archived; selected W2-B/C retained. |
| `b50018a58a` | Formal transfer closed | Cost envelope integrated; alternate preverified durable fence archived; current caller binding/policy retained. |
| `a0d2b172bb` | Formal transfer closed | Owner bits and cost-caller configuration integrated with quota; proposal-only stateless alternative archived. |
| `e489fa33fe` | Formal transfer closed | Network-bound Offer/token-bucket/PaidReplayOwner module and cost source already exact; separate research profile retained. |
| `fffc600e20` | Formal transfer closed | Same legacy stateless/cost alternative as 938; preserve source and paired measurements, no wire alias. |

## Exact observed validation

| Source checkpoint | Selected scope | Observed result |
| --- | --- | --- |
| `ff7c1ec4f9fed9b3cc9e16e39b9e6cd433f9c375` | Cost readers/envelope plus four stateful owner policy/quota controls | 29 Python methods passed |
| `36ac2df36c3f213c6624d525bd3d09fb743d9e9a` | Standalone Go and optional Python differential | 2 Go functions + 2 Python methods passed; 10 full-byte cases |
| `ae2cba1d5ae22ad55fd44e557313f19961f4697c` | Durable local floor, original-file restart, capacity/expiry and two-instance serialization | 4 Python methods passed |

These are 35 Python test methods and two Go functions, not 47 independent
tests: the ten parity cases are inside one Python test method. All three
receipts verify every tracked source byte before and after their own command.
The complete logs and per-case hashes are retained. The original receipts
referenced by [validation-index.json](validation-index.json) contain their
SHA-256 values and exact source trees. Post-relocation hash recomputation is
pending the root's serialized evidence-sealing step.
No selected method was skipped or ignored. Native chain integration, full
historical research suites and independent operator acceptance were not run
or inferred by this lane.

Initial PATH selection found an unrelated `/usr/bin/go`, and `gofmt` was
absent from that PATH. These were environment-selection failures, not passing
test observations; no saved command receipt exists for those attempts. The
successful offline command records actual Go1.27.4 from the existing toolchain.

## Historical failures and HOLD evidence

The ledger identifies each historical document by original full head, path,
Git blob and SHA-256. In particular, preserve these distinct observations:

- ca2's first combined SIGKILL-readiness failure remains failed even though
  later bounded-readiness runs passed; retain snapshot/unkeyed-log limits.
- c953's original global atfork secret-retention negative remains tied to
  its pre-fix source and does not disappear with weakref cleanup.
- 093/fa704/993/cab37/4bf original copied-state and shared-owner limitations
  remain open; local SQLite serialization does not establish global custody.
- 993/cab37/e192 cost and honest-latency regressions stay paired with their
  original owners, inputs, environments and output schemas.
- The W2-D/E soundness assumptions, historical projection/falsification
  results, late-rejection limits and 938's two local samples remain historical
  research evidence. They are not selected-source physical benchmarks.
- 658's old broader Go suite and W2 comparison/fixtures remain at their
  original source. The new ordinary suite has its own observed counts.

The alternate Grant/Offer schemas, append log, rotate/join mode, boot context
and policy-bound WAL tables were reviewed as concrete incompatible contracts.
No compatibility aliases, new wire identities or schema migrations were added.
Historical vulnerability/falsification/cost workflows were not executed.

## Integration responsibilities

The host exhausted thread resources while starting the final mechanical
ledger calculation (`Resource temporarily unavailable`, OS error 11).
All selected tests had completed earlier. At the root's request, the pending
Git read was stopped and no additional build, test or Git process was started.
The 24-tip semantic ledger and the 95-variant/33-document raw snapshots are
saved here, with exact selected commit/path locators. Final original-head
ancestry coverage and optional selected-blob materialization are explicitly
pending; they are not fabricated as completed calculations.

These audit files and the added/updated explanatory documents are currently
uncommitted. Stage them only in the serialized final integration step. The
three `.log` files are ignored by repository defaults and require an explicit
force-add after their receipt hashes are checked. The optional standalone
`seal_local_evidence.py` performs that read-only integrity/roster check without
starting Git, builds or tests.

Root must preserve all original heads, complete Node/runtime/crypto/CI lane
review and recompute the final source/corpus/CI inventories and pins against
the composed tree. New Go/formal/script sources need those final inventories;
old pins are not patched speculatively here. This ledger and its test receipts
do not establish whole-chain readiness, GPU/ASIC cost, WAN fairness, external
cryptanalysis or independent custody. Existing production HOLD gates remain.
