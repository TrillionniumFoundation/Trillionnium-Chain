# P1: metered History import at the actual native W1 execution point

**Candidate / not accepted / not activated.** Incremental source parent:
e55107450eb1a1f051a6c98101f3f88b7afa8f91 (Chain draft PR #342).
This is a separate child PR, without mainline activation or changes to the
49,188-byte W1 proof, Header, TaskId, target, ticket, Chainwork, signatures
or canonical arithmetic relation.

## Verified source-level gap

A caller may present remotely obtained bytes as loopback transport through a
local relay. PR #342's 'receive_page_from' binds a supplied source SocketAddr
and checks the original root-owned Host cgroup for nonloopback addresses, but
a local relay can provide a loopback address even when its bytes came from
the WAN. Thus source-address checks ALONE are not a mathematical, physical,
authenticated-origin or CPU-cost proof.

The private 'receive_page' previously called ordinary unmetered
'node.admit(packet, clock)' for each of up to 16 History page members.
The ordinary W1 verifier correctly rejects forged transcripts, yet could
consume materially more CPU than the fake producer spent. Repeating pages,
client names or fake claims could consume CPU independent of V3's in-process
service bucket. Pinned-peer polling has a separate candidate metering patch
in PR #340; this new source covers the generic History importer that is used
by CLI/native/authenticated/remote sources.

## Implementation boundary

- The publicly accessible 'receive_page_from' still checks the original
  host-kernel policy on its declared source before W1 and again after native
  import. It now **also** requires the Node's sole original
  'public_service_cpu_domain()'. If the Node already has a V3 or continuous
  CPU domain, that exact Arc-backed owner is reused.
- If an otherwise-unbound one-shot sync Node needs a first domain, it may
  bind one 'ServiceMutationCpuDomain::process_cold()' **only once** through
  the original 'Node::bind_public_service_cpu_domain'. This has ZERO initial
  CPU credit. The original fixed 100ms start reservation and 250ms CPU
  credit per wall second refill are unchanged. No peer, page, key, process
  restart or signed cookie mints the existing warm two-second burst.
- When the cold account initially lacks 100ms credit, receipt of a History
  page waits at most two seconds for the ORIGINAL shared refill. The
  underlying reserve and in-flight limits are always rechecked; unavailable
  accounting fails closed. There is no infinite waiting or deadline renewal.
- The accepted operation spans **the entire page**: bounded header/packet
  decoding, context/parent checks, W1 transcript replay, M06 real child
  worker CPU through the original 'ExecutionControl', and activation.
  All W1 tile/noise/row checkpoints use the same live shared paid CPU.
- Complete native acceptance still requires the original Node's
  check_admission_context, begin_owner_work, attach_owner_work, private
  VerifiedWork and admit_work_checked_with_control. The exact previously
  accepted packet reuses the existing original native admission fact, not
  another mathematical acceptance cache.
- The original operation.finish runs for success, full invalid transcript,
  partial page, cancellation, parent/context error, or missing bytes.
  Unknown settlement marks existing operator-task authority unavailable
  where applicable and returns a CPU accounting error. A native commit
  already completed before an after-check/accounting fault is NEVER undone,
  downgraded into a false consensus verdict or refunded as fictitious zero.
- A remote History refiller still cannot guarantee anonymous honest-peer
  fairness, and a physically unguarded loopback relay across many
  independent local Node processes can evade global host protection.
  This patch measures and bounds cost per genuine Node owner; proving
  kernel-global ownership remains a separate physical/deployment gate.

## Native negative and positive selectors (new)

In 'ingress.rs':
1. 'loopback_relay_valid_history_uses_original_cold_cpu_and_can_activate'
   builds a genuine full W1 block, imports through public checked History
   entry using loopback-sourced bytes, asserts full activation and an
   original cold CPU flow with initial credit zero, known positive settled
   CPU, zero live owners and conserved budget. Attempted second warm
   Node-domain binding fails with OWNER_PUBLIC_SERVICE_CPU_DOMAIN.
2. 'loopback_relay_false_w1_claim_pays_cpu_without_chainwork' changes
   only the claimed W1 product while preserving exact valid trace and
   ticket. Full verification refuses Product; importing the same packet
   also refuses WORK:Product, leaves active head/stats unchanged, but
   retains a known positive full CPU debit on the very same zero-start
   epoch. No legal work, state or Block ID is minted from the invalid
   mathematical claim.
3. 'four_distinct_ticket_valid_fake_history_traces_each_pay_original_cpu'
   builds four distinct claimed SHA256 traces from the SAME already legal
   Header, challenge, TaskId, target and canonical A/B. It does not copy a
   valid product or transcript into the fake proofs; the fixture's legal
   Header was originally constructed with an actual Node. Every fake
   passes the preliminary ticket precheck yet returns WORK:Transcript
   after complete W1 replay, keeps native state unchanged and increases
   the EXACT SAME cold Node CPU-domain settled-full-cost counter.
   These newly derived samples are not falsely claimed to be the user's
   earlier four raw attack payloads or matching old hardware timings.
4. PR #342's raw/authenticated/durable remote no-Host-negative tests
   remain intact; they must still deny before any source connection and W1.

Tests require a real Rust checkout/toolchain and cannot be declared passed
on the basis of the candidate's source, documentation or Python counterpart.

## P0–P6 status and explicit gaps

| Gate | Status | Missing acceptance evidence |
| --- | --- | --- |
| P0 | Native source test retained, not independently re-run here | Exact original four attack payloads, clocks/resource IDs, original State and full replay receipts |
| P1 | Significant ingress/peer/import remediation drafted | Real physical host cgroup owner including relay and multiple processes, rootless restart, missing clock, cancellation, reorg, CPU starvation and original binaries |
| P2 | Python V3 research, plus PR #339 receiver-local PoW prototype | Actual signed V3 on CPU/GPU/ASIC, whole honest request cost and attacker cost across one comparable hardware budget |
| P3 | Selected original and new native regressions | Authenticated malicious Peer, identity rotations, false StateRoot, mixed valid transactions/reads and full retained false-refusal cohort |
| P4 | Original A03 3 modes x 3 trials x 3 honest confirmations unchanged | Complete fresh source-attested physical (not synthetic) 27 confirmations and 3 pressure modes, proper failure denominator |
| P5 | W2-A/B/C explicit unsound and resource-cost controls | Succinct authenticated complete transcript relation, independent challenge grinding proof and positive utility/cost over best W1 |
| P6 | Go/Rust/Python oracle material available | Independent cryptographic review, blind controls and independently provisioned hosts; internal sources cannot certify themselves |

All changes remain HOLD_NO_GO, no new public consensus or proof profile.
