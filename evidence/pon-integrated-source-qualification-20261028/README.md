# Integrated source qualification, 2026-10-28 UTC

These records bind local committed source `4370f250236d89fb86dab215f862fe7e4d91c648`, tree `b8bdd87dca3cd6288c38f63848b24b1a2df6a09d`. The published API commit `131f673d9563e72aca7139f3239856957d118d49` has the identical tree. The actual PR merge `66634191298767b40691d6b2a298418ec19e3673` has the independently checked base/head parent order and identical computed merge tree.

- Strict locked/offline Clippy checked the full 25-package workspace, all targets and all features with warnings denied. It completed with code 0 in 1.707787714 seconds using a warm cache. This is compilation, not native test execution or isolated performance evidence. The real W1 prover shared the host.
- The phase-host Python controls passed 11/11 and source-integrity controls passed 34/34 on this clean source.
- The repository graph/lockfile/document check passed: 25 packages, 971 Rust files, 1,342 local Markdown links, 19 normal dependency edges. It took 52.087965023 seconds while sharing the host; source remained clean and unchanged.
- An earlier repository-check invocation lost its tool session during user interruption and has no retained terminal result. It receives no pass credit; the bounded recorded rerun above is the stated observation.
- `cargo fmt --all -- --check` passed before the same source was committed. No production behavior was activated.

The old e25 original campaign failed before Host/service measurement, and its failures remain in `../pon-e25-phase-startup-20261028`. This directory does not replace new actual native campaign, PQ authorization, model efficacy or independent WAN acceptance. Every work-package acceptance remains separately gated.
