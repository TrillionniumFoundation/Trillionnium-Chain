# PQ source convergence — HOLD / NO-GO

This candidate continues PR #894 at
`31543fb6dde565b62b47436e0b1d399b6d0bd772`. It brings the reviewed development
account boundary, complete-key TLS checks, live provider-history check, V5
witness components and separate hash-purpose inventory into one source tree.

## Source and retained boundaries

| Component | Reviewed input | Integrated scope |
| --- | --- | --- |
| Authority selectors, complete TLS SPKI, live provider history | #894 / `31543fb6dde565b62b47436e0b1d399b6d0bd772` | Baseline kept |
| V5 typed witness, durable register, exact native rosters | #896 / `32d33bf78ef41136f9e806c8fdc3118c9df53db3` | Forward composed; provider remains its separate V3 consumer |
| Development account boundary | Retained local `077ac4f33206de00a178553d9a0c729a20685088` | Forward ported onto #894, preserving its read-only API error order |
| Hash-purpose contract | Retained local `e2e442f01f84681d1afe81980d079c22bfbe71f7` | 17 uses / 26 unchanged native source paths |
| Current runtime checkpoint | `8add285b6c0a91d8b7812efe2d02c9342f74c91b` / tree `8aaa486aa4ccd4e41e33241fb4e7e273d3c3d5f6` | Source snapshot; not a native execution receipt |

The 44-path authority register changes the executor and Node store pins. The
15-path PQ lifetime lock and 20-path W1 survey change only the store pin. Each
was derived from the exact runtime Git blobs. The 41-path Root register keeps
#894's live provider implementation and tests alongside #896's V5 components.
This is declared source consistency. It is not an authenticated complete
authority/call graph or a bound on all shared cryptographic queries.

The [current lifetime input](lifetime-input.json) and
[report](lifetime-report.json) occupy a new evidence namespace. All previous
lifetime reports remain byte-identical. Unknown query counts, concrete
reductions, custody/freshness assumptions and lifetime failure bounds remain
unknown; all qualification/activation flags remain false.

## Concrete behavior

Account execution, state-root computation and fresh/cold/warm Node ownership
require the existing development-only fields. Missing, null, mistyped or
production-like scope is rejected before state effects. Stranded native PQ
configuration cannot select the classical owner. Explicit PQ failure does not
fall back. An explicitly selected classical development account still has real
test-ledger effects; this change does not migrate all accounts to PQ.

The QROM workflow distinguishes original historical Git source, the current
source mapping and the historical reader's refusal of current bytes. Its
historical and current report scopes are independently checked. The historical
reader and original pins are unchanged. A software mapping is not a QROM
soundness theorem or a quantum mining qualification.

Root V5 still has no installed independent daemon, wire transport or effect
sink. Whole-authority common restore, independent custody, post-restore entropy,
physical power loss and WAN/production adoption remain unqualified. The
provider journal's V3 consumer is not silently converted into a V5 consumer.

## Source and completion gate corrections

The first converged source still accepted six report mutations: historical
Git object ID, historical executable mode, coordinated historical source-row
substitution, current revision, current contract digest and current closure
substitution. The gate now rebuilds the historical report and Git receipt as
well as the current V2 report from actual pinned inputs and compares them in
full. The retained red/green comparison identifies each gate's exact bytes.
It does not prove authenticated execution or cryptographic security.

The original 81 named controls remain unchanged. A separate fixed roster
requires all eight historical and fourteen current controls to register, start
and succeed once, without skips, ignored expected failures or SystemExit(0).
Both the report-scope and final status gates validate the two completion
records. Missing or forged-looking shapes cannot satisfy actual source binding.

The six-grid CodeQL local-SARIF workflow now covers ordinary stacked PR bases
under the original same-repository guard. GitHub default setup remains
configured, so the local lane retains `upload: never`; its artifacts cannot
replace missing exact-source Code Scanning API analyses/checks. No repository
security setting, protected branch policy or exporter criterion is changed.
The inherited #894 original campaign remains a real failed confirmation and
budget-depletion experiment, not an artifact-upload error.

## Validation provenance

Validation records will be retained against the exact committed candidate,
with command arguments, raw streams, outcomes and source/provider readback.
Earlier branch tests are not added to the joint candidate's counts. Original
service budgets and failed campaigns remain in force. This source record does
not claim a hosted CI pass or completion of the full native business campaign.
