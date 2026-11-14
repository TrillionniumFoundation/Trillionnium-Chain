# Retained native collector source provenance

This directory records one fixed source-content binding used by the current
read-only W1 native bridge. It does not execute the historical producer or
replace any original native observation.

- Source: e4abb172147e941b62483652b0ceabaae4317624.
- Tree: 016ebf3deeac88d6d7a782edf563f2291ebe17f5.
- Original path: formal/pon-native-fullpath-v1/collect_native.py.
- Original collector: 23,639 bytes; SHA256
  f40c5d621454d0532141920724a3cfd57e240f4a3b061536162313daa676c254;
  Git blob 421b10241820580efcdabc692ccb1f6dd27b6586.

[provenance.json](provenance.json) records the raw commit and three raw tree
objects, their byte counts, SHA256 digests and Git content addresses. Independent
offline review verified SHA1 of type, one space, decimal byte count, a NUL byte
and the raw object body for every object. Parsing the three tree entries links
the commit's tree through formal/pon-native-fullpath-v1/collect_native.py to
the fixed blob. No signature or author-authenticity claim follows from these
content addresses.

The exact producer bytes are kept as
[non-executable data](../../../formal/pon-nakamoto-v1/fixtures/native-collector-e4abb172.py.raw).
The current bridge verifies the fixed source/tree/context-digest tuple and uses
its existing bounded regular-file reader to check the data's size, SHA256 and
Git blob identity. It neither imports this file nor invokes historical Git or
native processes. Other sources keep the existing current-collector semantics.
The current collector retains its later exact-source checks.

The original ZIP, context, saved reports and their native source identities are
unchanged. The original native binary has not been rebuilt, reauthenticated or
rerun by this correction. Service acceptance, quantum security and production
activation remain unqualified.
