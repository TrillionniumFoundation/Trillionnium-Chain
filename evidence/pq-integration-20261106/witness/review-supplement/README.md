# Independent publication evidence readbacks

This supplement records integrity and content checks for the c07 witness and
release-root evidence increment. The actual code source is
`c07e8b9cce4621c5ef6f61256482bfe94e5a622f`; the native batch remains exit 1,
with 74 succeeded, one failed and two blocked observations.

The [archive index](../publication/archive-index.json) binds 971 members:
966 selected original files and five generated metadata files. The archive
contains the complete current raw terminal records, independent readbacks,
V6 reports, preserved intermediate failures and explicit recovery provenance.
Its hash-only checks do not execute the evidence or qualify the product.

The selection, finite-pattern scan and collection execution receipts retain
their actual commands, outputs and exit codes. The scan covers exactly 966
selected text files and four fixed credential/PEM/signed-URL patterns. Its
zero findings establish only that bounded result.

The independent archive review is kept in `independent-review/` with its
method, actual execution and explicit handoff. It rechecks member identities,
declared manifest bindings and preservation of the failed native and historical
observations. It does not rerun source gates, Cargo, native controls or old CI.

`supplement-files.json` binds this supplement's files, excluding itself.
The containing publication's seven source-only gates are executed after its
immutable commit exists; their separate actual commit and records are linked
from the maintained section of PR #723. Those gates never convert c07's failed
native batch into a pass. The PR remains Draft / HOLD.
