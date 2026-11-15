# Exact evidence-source validation and publication mapping

Four checks completed on clean local commit
`2a06d2933a466675b081bb3b004a732f676d8028`, tree
`b1b73e10f3e8f4eb152d11bc0278a6a65fc47f9b`: full tracked-source verification,
repository/link audit, existing CI-contract reader and original r1 packet
reconciliation. All returned exit 0. Full-source verification checked 26,323
entries / 2,503,727,712 bytes; it executes no tests.

Published evidence commit `46bcaed1a3c9b8c8e06628936d3d95e1173a7f73`
has that identical tree. It is a different commit because the GitHub connector
sets author/committer metadata. `identity-map.json` preserves both identities;
no checks are relabeled as having run on the connector-created commit.
This follow-up adds only these receipts and documentation. The original tested
research source is still `4716bade250f327b012a098418f4eece6b73fcaa`.

The Mac HeptaRuntime file-info query timed out during publication preparation;
no publication mutation was submitted through that unavailable control route.
Publication uses the user's explicitly authorized GitHub connector fallback,
verified as ProfHepta / 102159240, with only evidence paths, the exact expected
branch head and force=false. The known-terminal native r1 was not resubmitted.

Original r1 is FAILED / exit 2 before setup. Its original command list is
empty; every Rust gate is NOT_RUN. The local wrong-command-path error in the
first packet remains retained, alongside the corrected successful CI command.
Neither local evidence checks nor source hashes supply physical resource,
all-legal-strategy, delivery, CP/CG/CQ or lifetime proofs. All thirteen actual
joint obligations remain open, native risk bounds remain null and qualification
remains HOLD_NO_GO. No main merge or production activation.
