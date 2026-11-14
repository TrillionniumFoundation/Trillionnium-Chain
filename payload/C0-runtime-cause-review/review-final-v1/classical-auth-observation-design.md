# Proposed classic reactor CPU sidecar — design only

Status: **not implemented; not executed; no performance or qualification claim**.

Fixed reviewed source: `1a7afcdb820b051d1e4bfde3d436f96fc050c487`. Its selected runtime blobs equal the tested C0 checkpoint `dc42ce4df5cff79cc61c5addbaf01074b56b06ca`.

## Question the additional measurement would answer

How much actual server reactor thread CPU is spent signing the classical challenge and strictly verifying the classical caller during the unchanged workload? Current C0 observations cover paid body decoding, native dispatch, response signing, selected socket I/O, and client/replay CPU. They explicitly exclude classic reactor authentication CPU. This design fills only the two missing crypto intervals; it does not provide complete whole-reactor or kernel-scheduling attribution.

No existing supported entrypoint already measures those classic server intervals. The existing client CPU wrapper measures the client thread. V5 authenticates caller identity but retains `cpu_includes_reactor_authentication=false`. PQ `AuthenticationBudget::perform` is not reusable as an observation-only classic switch because it changes budget/refusal behavior.

## Smallest intended seam

Use an explicit opt-in observer configuration with two fixed event slots per retained connection:

1. **classic_challenge_sign**: in the existing cookie path, after the original `server_message()` has succeeded, sample around the one original call to `sign_authentication` / classical `identity.sign`.
2. **classic_caller_verify**: after the original caller-message preparation succeeds, sample around the one original classic `verify_hex_strict` expression, including its existing key/signature representation preparation. Do not alter which error occurs first.

The actual classical branches are `ingress/public_v3/pq_identity.rs` 249–276. The challenge callsite is `public_v3.rs` 845–882; the solution transition calls caller verification before spent-cookie reservation. Instrument actual selected callsites or explicitly pass an observation token; do not wrap every sign operation indiscriminately and accidentally count paid response signing again.

A small private optional observed wrapper can preserve existing unobserved helper callsites by passing None. No public name is committed by this design. This is not a proposal to add a general profiler framework.

## Output and strict-reader compatibility

Return a **separate** snapshot/sidecar, with a new explicit schema such as `public-v3-classical-reactor-auth-cpu-observation-v1`. Keep the existing V4 and V5 constructors, snapshots, serialized byte shapes, CPU coverage flags, and original phase reader behavior unchanged. Do not add optional unknown fields to the existing strict input and do not relabel old evidence as newly covering reactor authentication.

The sidecar would bind:

- fixed source/head and observer identity at its producer boundary;
- observer-local connection sequence and original request deadline, without exporting secrets or private key material;
- event identity, entered/returned state, original success/error classification;
- start/end monotonic offsets in the same existing observer clock and checked same-thread CPU delta;
- explicit unavailable, omission, duplicate-entry, counter-overflow and incomplete-event flags;
- all authority/qualification/control-effect flags false.

A numeric zero is permitted only when a valid same-thread clock difference is actually zero. A missing start/end, clock error, migration, rollback, overflow or unfinished event remains unknown; it cannot become zero. An event that was never reached is distinguished from one that started but did not return.

## Preserve primary behavior

At the measurement seam, the conceptual sequence is:

`start optional measurement; result = original operation exactly once; close optional measurement using result; return the original result`.

The diagnostic must not reserve or refund CPU, change listener intake, alter signature bytes or context validation, select a different identity, reset/recompute a deadline, perform an extra cryptographic verification, change cold recovery or durable settlement, or mutate spent-cookie state.

Keep all existing signature checks, including both distinct client cookie and response checks. Keep identity construction in the original fixture, all 16 pressure callers, the 4-second acceptance window, Host profile, and every fresh W1 progress/Host observation. Do not remove or replace any of the original five native controls or the Python confirmation assertion.

Optional observation cannot be strictly timing-neutral: clock reads and record publication cost CPU and may perturb scheduling. The design preserves decisions and primary error precedence at the code level; it must not promise identical scheduling or a passing deadline. A diagnostic run cannot replace the original acceptance run.

## Bounded failure behavior

Reuse the existing observer's bounded connection capacity, without eviction, and allocate at most two fixed event slots per retained connection. A failed capacity check or nonblocking record update marks diagnostic coverage incomplete only. There is no dynamically growing event stream and no retry until a diagnostic lock becomes available.

Use the existing checked `ThreadCpuStamp` convention. Keep measurement publication outside the crypto operation itself. On panic/unwind, retain an entered but not-returned event when possible; never manufacture a returned success. Duplicate entry must be reported as incomplete/invalid evidence instead of overwriting the prior event.

Read the final sidecar only after the original service and worker joins. A live snapshot must remain explicitly incomplete. The two event intervals are disjoint from each other for one connection but may overlap other threads' wall intervals; client/server/Host/dispatch values must not be blindly added.

## Minimum verification needed if implementation is authorized later

These are proposed controls, not tests executed by this review:

- Actual valid and invalid classical sign/verify paths invoke the original operation once and retain its success/error classification and error precedence.
- Missing/invalid/cross-thread clock observations remain unknown without changing the original operation's result.
- Capacity exhaustion, contention, duplicate events and unwind do not grant/refund/complete or turn an unfinished event into success.
- Old V4 and V5 snapshots remain byte-exact, including their false reactor-authentication CPU flag; existing strict phase/report inputs remain valid.
- The original workload and all original controls remain unchanged. Any opt-in diagnostic entry is separate and retains the original deadline, worker count and Host constraints.
- Per-event start/end/deadline records expose tails outside the four-second interval; a report refuses to treat differently scoped totals as one aligned CPU budget.
- Actual complete records include failed attempts as well as successes; omission is visible and cannot improve an apparent cost bound.

Implementation, source-binding updates if required by the repository, selected tests, and any permitted hosted execution would be separate reviewed work. This document authorizes none of them and supplies no measured benefit.
