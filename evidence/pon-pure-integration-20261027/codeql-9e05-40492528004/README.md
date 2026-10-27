# Exact 9e05 CodeQL export: failed with no available selected analyses

[Run 40492528004](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40492528004),
job `122149745072`, failed after the original 1,200-second export deadline.
Its complete decoded log reports: `CodeQL analyses/checks did not complete and
stabilize before the deadline`. The original 16 exporter tests passed, and the
before/after source checks both bound commit
`9e05ad5d237660fb0ea8b40dd5c29af4225551d3`, tree
`952666bff72a49d8bc7693b27ff747f56a56b240`.

This is a failed attempt to export existing analyses, not a completed CodeQL
scan, a clean security result, or permission to remove a required gate.

## Complete retention and readback

The [complete original artifact](complete-original-artifact.zip) is 251,365 bytes,
with SHA256 `f9b1514ae929629b758d8bd0a285008c46e74a3d1e6d8ef94b1ff5413095a2fd`,
matching the GitHub metadata for artifact `12729429089`. All **200 original
members / 1,048,320 uncompressed bytes** remain inside that exact ZIP; the
[member inventory](members.json) records their individual identities. No partial
poll, failure, empty response or original checksum file was discarded.

The [independent readback](independent-readback.json) checks all 198 entries in
the original outer checksum map. The original workflow deliberately excludes
every file named `sha256.json`, including the nested exporter's checksum map;
both excluded manifests are still bound by the complete ZIP digest. The initial
readback's mistaken single-manifest assumption and its correction are recorded.

All 38 retained poll snapshots have empty `analyses-1.json` responses. Every
selection snapshot has empty selected analyses/checks and `ready=false`.
These observations establish what this exact export could retrieve during its
window. They do not establish repository-wide CodeQL configuration, explain all
possible service causes, or prove that no later analysis can exist.

The [full decoded job log](github-job.decoded.log.gz),
[complete jobs/artifact metadata](github-metadata.json), original
[exporter tests](exporter-offline-tests.log), and
[before](exporter-source-before.json)/[after](exporter-source-after.json) source
records are retained separately for direct inspection. The decoded log is not
presented as the original HTTP transfer encoding. Signed download URLs and
credentials are not retained.

No runtime source, CI policy, failure verdict, production flag or required check
was changed by this evidence capture. Source and exporter checks cannot certify
the absent security analysis.
