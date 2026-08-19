# Retired legacy node configuration markers

These four files are non-operational audit markers. They contain no listener,
RPC, peer, key, executable, or data-directory authority. The active native
workspace has no legacy node package and must reject these marker schemas.

A future native PoCO node configuration needs its own versioned schema,
network magic, chain descriptor, peer authentication, data-directory marker,
and explicit migration rejection tests. These markers cannot be translated
or supplied to that future node.
