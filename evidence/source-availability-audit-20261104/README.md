# Source availability check, 2026-11-04

A fresh snapshot of 630 remote branch heads was checked against its own package
owner inventory. Twenty-four inventory blobs were read; one historical recovery
branch has no inventory and is excluded. Only inventory and Git source-tree
metadata were read. No old evaluation/calibration/consumer task content was used.

Relative to the original baseline tree plus the 161 published candidate blobs,
38 Rust blobs are not covered: declared owners M00=20 and M10=18, M04=0. This is
set difference, not proof that all 38 were created since the previous audit.
Original path filtering leaves five blobs, all M00. No source functions were
parsed, admitted, split, relabeled, or trained here. Cargo manifests were not
re-audited; these are inventory declarations, not accepted new task labels.

This is a blob-availability screen, not a full owner-reassignment audit. Reusing
an existing blob under another path or owner is not evidence of independent
M04 tasks. The existing M04-free probe gate remains unresolved. Increasing M00 material
cannot supply its missing M04 class. No split reroll or new model claim follows.

heads.json.gz freezes exact commit/branch pairs. source-delta.json.gz binds every
uncovered blob to paths, declared modules, source commits and inventory blobs.
The prior source-development-freeze-20261103 package supplies the original
comparison. summary.json records decoded hashes. All inputs are repository
metadata, with no private user data or credentials.

Recheck using a checkout with these historical objects available:

    python evidence/source-availability-audit-20261104/scan.py --output /tmp/chain-source-recheck

The script uses frozen commits, not current branch tips, and reads only source
trees and inventories. Git may retrieve missing objects from the configured
repository. Its source-delta.json must equal the decoded frozen file.
This evidence does not certify independent task labels or model efficacy.
