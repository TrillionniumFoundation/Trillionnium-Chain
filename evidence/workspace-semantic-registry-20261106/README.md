# Original workspace semantic registry correction

[Job 127765650164](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42179526890/job/127765650164)
built the complete workspace at candidate
`0eac6017b1e4087a69bc9c40962b4e216b9c4ee2`, tree
`8b25abdd3c09268d8c68752c56d49d50dafa12be`. Both original library ELFs passed
their hash readback and returned successful native libtest registries. Selection
then failed: the post-write group expected 23 registered tests and found 25.
The semantic execution loop was not reached. This failure is retained verbatim.

The two tests were added by commit
`88b953f0b2b8f9377bb4747e00c4789785ef3718` on 2026-11-05:

- `cached_catalog_statement_reads_current_ddl_and_unversioned_catalog_rows`
- `warm_catalog_statement_never_hides_temp_objects_or_database_attachments`

They ensure prepared catalog statements observe current DDL, unversioned catalog
changes, temporary objects and database attachments. Both also actually ran and
passed in all four retained native logs under
[`authenticated-suite-count-20261106`](../authenticated-suite-count-20261106/README.md).
Those prior executions do not make this failed workspace semantic step pass.

The workflow now selects all 25 post-write tests and preserves its other nine
groups, for 60 unique exact selectors. It still requires the original complete
workspace build, unchanged ELFs, original test profile and resources, one actual
successful execution for every selector, and nonzero exact execution accounting.

The two gzip files losslessly retain the original registry bytes from artifact
13486249758. The small source, exit and failure files are verbatim entries from
that artifact; [`provenance.json`](provenance.json) binds every file to its hash.
`scripts/ci/test_authenticated_suite_count.py` executes the actual workflow reader
against these registries, proves the old 23-count failure, checks all 60 selected
names and the complete 25-test source/prior-execution roster, and rejects empty,
missing, duplicate, extra and wrong-group registry controls. This is reader replay,
not a new native run, full workspace qualification or production acceptance.
