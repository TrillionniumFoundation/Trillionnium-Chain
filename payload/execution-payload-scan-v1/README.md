# Fixed execution payload credential-pattern scan

The exact pre-report manifest contains 2,100 files / 150,184,002 bytes. Its SHA-256 is 6869bb859742174128f390f6d868f73c49559f5b8e354425dff5eccf06f762d4. The one approved scanner v2 execution exited 0, checked all declared bytes and observed zero matches in each of the five exact patterns. The retained status is NO_PATTERN_HITS_IN_DECLARED_SCOPE, not a claim that all secrets are absent or a general security qualification.

Patterns are the exact prior driver's AST-extracted byte literals. Each declared file was a canonical regular single-link file, verified through stable file descriptors and SHA-256. The scan read raw bytes only: it did not decompress ZIP/pack/archive members, traverse Git history, run fsck, enumerate extra payload paths, access original origin paths, run tests or use the network. No automatic finding classification occurred.

The scope was frozen BEFORE this result group. These newly archived scanner, scope, terminal, index and report files were not self-scanned by that execution. Their original provenance, byte counts and SHA-256 are preserved separately. A later final publication manifest may include them without changing the earlier scan's scope.

The preparation README retains its original prepare-only wording and is historical context for the actual invocation and terminal saved here. A PTY output file contains the exact combined terminal stream; it is not relabelled as separate stdout/stderr. The freezer terminal likewise preserves the actual completed observation.

All source files were fully read and verified before stage publication; target writes are create-only. The 2,100 preexisting stage file identities are protected before/after. This group has a 4 MiB cap and does not duplicate the large original CI archives or runtime reports. The strict files.json remains external to the payload to avoid self-referential hashing.
