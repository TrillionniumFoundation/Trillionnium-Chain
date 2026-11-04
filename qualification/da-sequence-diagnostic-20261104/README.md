# Bounded DA sequence exchange diagnosis

This independent branch starts at exact #699 candidate `1bac21f81fc8be67a566dddfed4da6b2fd87ad30`, tree `5dd3781b0d74c91d3bd66872cbaccf8e520b206a`. It does not update the #699 branch, the #688 owner branch, main, or an original qualification workflow.

The original 312 head runtime job 126350991887 ran 174 DA cases and failed one: the two-bootstrap sequence case observed one validated record while the unchanged assertion requires two. Its same-tree prospective-merge job 126350991731 subsequently passed all 174 DA cases, then failed a separate Python schema oracle. The later pass does not erase the head failure or establish its cause. Original logs and exact hashes are recorded in SOURCE_MANIFEST.json.

## Diagnostic change

The test-only Unix transport records the elapsed exchange time, numeric round/connection counters, returned byte count, and the existing fixed error classification. It prints no reply, address, signature, key, request, SQL error, or free-form error text. The original two-record assertion remains exact; its additional failure message contains only numeric discovery counters. The corpus pin follows this exact diagnostic test-source byte change.

Both new transport call sites and the receiving test module are compiled only under `cfg(all(test, unix))`. Unix test builds still incur an Instant read and environment lookup when the diagnostic variable is unset. When enabled, synchronous stderr output occurs after exchange and before the existing receipt-time/wall-clock reads. That I/O has no independent hard deadline and can perturb scheduling or cause an existing remaining deadline to expire. This is deliberately a diagnostic branch, not timing-equivalent qualification source.

## Hosted execution

The push-only, 20-minute workflow runs the original audit preflight, Rust 1.95.0 formatting check, and pinned PQ-provider preparation. It uses an isolated Cargo home and target. It builds the DA library tests with the locked workspace manifest and a package-selected test profile, verifies the exact 174-case registry, runs the complete original module once, then runs the original failing case exactly three more times. All four outcomes must pass for the limited diagnostic result; a later pass never replaces an earlier failure. The full logs, compiler identity, binary hashes, command arguments, source receipts, and outcomes are retained. Eight synthetic parser controls are separate from native case counts.

The 200 ms client request, 250 ms server request, 10 s original overall operation, 30 s record lifetime, and every original assertion remain unchanged. Bounded outer command timeouts terminate only the owned diagnostic child process group. They are not renewed native operation budgets.

This package-selected build does not reproduce the original whole-workspace feature-unification denominator. Extra test instrumentation also changes the executable. A diagnostic pass cannot close the original baseline, Host, 4-second/16-attacker service, 30-second campaign, ARM, or production-activation gate. No local execution environment is available, so local preflight, formatter, parser controls, and native execution are unexecuted at publication. Actual hosted results must supply those facts.
