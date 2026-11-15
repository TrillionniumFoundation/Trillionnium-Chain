# Publication inventory scope

This directory is a byte-preserving publication copy of the completed Root
native evidence stage. The native archives, their raw logs and manifests, the
README, validator, and original validation output are unchanged.

Zero-byte .hepta-lock-* files belonged to runtime coordination in the original
staging directory and are excluded from publication. No native observation was
removed or rewritten.

original-stage-file-hashes.json is the unchanged manifest of that earlier
staging directory. It includes its runtime lock entry and excludes itself; it
does not describe the current publication directory. The current file set and
the explicit exclusions are recorded in publication-manifest.json, which
excludes itself to avoid self-reference. The repository's later source binding
can pin that manifest independently.

The archive validator was run again in this publication copy. Its stdout was
byte-identical to the preserved verification.json. This was an archive-only
read, with no Rust, Clippy, provider or external-effect execution. Native
qualification remains scoped to the bac6 commit stated in README.md.
