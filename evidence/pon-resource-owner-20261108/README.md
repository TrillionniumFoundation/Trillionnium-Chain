# Original-owner resource admission continuation

Status: **HOLD_NO_GO**. The component work in this directory does not qualify
whole-ingress resource limits, a positive honest-service bound, proof-backend
economics, or production activation.

## Source and purpose

The real integration base is PR #812 at
`7e044b65454f4c9ea505591727332acffb33e7e5`. The observer CPU envelope is selectively
ported from PR #802 at `cc09d6dc311596a9d9a45c64e9392caff4a75c0b`; #802 is not
represented as an ancestor of #812. Existing r14 signed profile bytes, original
native validation, deadlines and activation gates remain unchanged.

The [local resource owner contract](../../docs/development/specs/pon/RESOURCE_OWNER_ADMISSION_V1.md)
and [machine-readable scope](../../config/pon/local-resource-owner-v1.json)
describe the new explicit finite profile. A fixed journal retains execution and
cleanup reservations, original operation bindings, class allocations and replay
state across process exits. A real local packet observer consumes that account;
it does not silently give the legacy public profile new semantics.

## Execution record

Exact-source compilation, native outcomes and publication readback are appended
after execution. This initial record makes no successful test claim. The local
editing snapshot contains byte-verified selected blobs only and is not the
authoritative upstream Git history. Authoritative validation uses a complete
clone of the actual base on ai395 and a dedicated development branch.

An initial setup preflight on an existing sparse checkout failed because its
preflight script was not materialized. No source edit was performed there.
The subsequent independent complete clone passed both base and development
branch preflight and resolved 181 packages / 26 workspace members with the
unchanged locked offline Cargo graph. Runtime: Rust/Cargo 1.95.0; the observed
system OpenSSL is 3.5.5. These preparation observations are not native test passes.

Preparatory local compilation first refused a missing exact baseline consensus
vector in the partial editing snapshot. The missing bytes were obtained from
the pinned base, not synthesized. A local SQLite loader qualification warning
is retained separately; local component tests cannot certify that environment
as the original native runtime.

## Acceptance limits

- The new observer uses the original native snapshot and packet observation.
  Successful supervisor completion consumes the entire reserved principal; it
  does not report measured child CPU or complete SQLite I/O.
- Unresolved process/cleanup outcomes retain their full original reservation.
  Recovery assertions require trusted local stop, readback and cleanup evidence.
- Only adopted packet-observer entry points enforce this new local account.
  Cookie/PQ, other public and local readers, History, Growth and all host processes
  are not yet jointly qualified by this integration.
- Direct internal workers retain the once-only claim and CPU ceiling, but the
  independent supervisor wall/cleanup contract is not supplied by a worker flag.
- Positive honest service requires actual minimum host supply, bounded admitted
  backlog and bounded nonpreemptible interference. Three accounting allocations
  alone do not establish that supply or implement a cost-fair scheduler.
- The original 0.25 CPU / 2 GiB / zero swap / 256 PID / 4-second / 16-hostile
  acceptance profile is unchanged and is not replaced by these component tests.
