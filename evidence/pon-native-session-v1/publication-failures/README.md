# Retained publication failures

The working-tree prepublication check used the unchanged fbe72b70f runtime with
pending publication files. It was not a clean exact-head qualification. The raw
external-evidence log records the final rejection: the old work-cost inputs no
longer matched. That old report was not rewritten to cover the new source.

After publication commit 5589434f2a5bc6452fd61a0c70e8cb4272c93326, a separate
Git inventory probe found 90 manifested logs present with correct disk hashes but
absent from the committed package due to ignored *.log files. The JSON retains
that exact inventory. Adding original bytes and checking the Git index repairs
publication; it does not rerun those old measurements or create new acceptance.

The current receipt, all historical experiments and native runtime remain unchanged.
Subsequent current-cost collection and clean delivery checks have their own source
identities and must not be inferred from these failed diagnostics.
