# R1 publication and PR adapter compatibility review

The existing publisher V2, preparer V5 and apply V3 support the reviewed R1 candidate with P1 as the Linux start and N2 as the expected remote head. No script change is required by the identities inspected here. This is a static review, not a publication result or a completed R1 Linux result.

## Identities

| Role | Exact commit |
| --- | --- |
| Candidate R1 | `2a86462a1ab20c68151719ba4635e3c294391e64` |
| Candidate tree | `5c26776f96f15fd131e85a5c2d7c5e895ad7fab4` |
| Expected remote N2 | `096c6b5f9b952c49389fd975515744074ba61317` |
| ROG start P1 | `6a8cd55573065ceb50cdb65a7834615f79b521ae` |
| Previous own publication C0 | `dc42ce4df5cff79cc61c5addbaf01074b56b06ca` |

The publisher checks C0 → N2 → R1 separately from C0 → P1 → R1. It does not require N2 to precede P1. The old history archive and its original 908-name manifest retain their original identity. New archive parents remain the old archive followed by R1.

## Gate and PR behavior

The original seven local gates and complete 18-step Linux lane retain their producer, argv, environment, timeout, raw-output and source-identity checks. The R1 bundle can retain both N and P1 prerequisites: only its advertised HEAD must be exactly R1. The passing P1 result cannot substitute for a R1 receipt.

The body template renders head, tree, archive and current receipts from validated inputs; it does not embed M8 or P1 as the candidate. C0 and 7d8 failures remain explicitly historical. Hosted qualification is not asserted. Apply retains exact original-PR comparison, one metadata edit, verified readback, one ready action if needed, final readback and unchanged source.

## Capacity and remaining inputs

The reported closed stage is 4,340 files / 223,727,993 bytes. The reported in-progress addition would yield 4,847 files / 234,963,272 bytes; that total is a plan, not a completed observation. Both are below the existing 10,000-file / 512 MiB total limits. Individual files remain bounded at 256 MiB. The final manifest, publication terminal summary and other metadata inputs have a separate 8 MiB limit. Their final sizes must be checked from the actual final pins, without changing those bounds.

Root must provide the final R1 spec, completed R1 receipts and frozen payload manifest. The publisher's original fresh PR/ref/tag checks still reject further remote movement. The static review did not execute a helper, command producer, test, Git operation or remote operation; it did not read the running R1 receipt directory or rescan the payload.

The machine-readable review identifies exact source line ranges and limitations. Four copied source inputs are pinned independently; the original scripts and template were not edited.
