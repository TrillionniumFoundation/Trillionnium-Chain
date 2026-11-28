# Bounded positional Activation and Runtime

This explicit private wrapper shares the original composed activation frame:
TAR1 magic, expected raw SHA-256, one immutable JSON value, and the final
32-byte expected checkpoint SHA. It supports the original four bounded
representation combinations: named or positional Activation, with named
or positional Runtime. The newly admitted root tuple has exactly 13
members in frozen Rust `Activation` declaration order. Runtime uses the
existing 16-position declaration order when an array is supplied.

The raw pin is checked first. For an array root, the lexical stage walks
the same held raw bytes, checking the complete array and recording the
first 13 element starts in bounded scratch. It reuses the shared strict
number/string/array parser and the decoded-key/uniqueness object parser.
Only after strict lexical success does the typed stage require the exact
tuple lengths and concrete member types. Then the existing composed
semantic code follows original precedence and emits token count and
decoded hidden bytes only on success.

The cap allows primitive arrays and one object level beneath the
positional root (plus primitive arrays in the object), no arbitrary
deeper nesting; collection, text and raw capacity limits remain private
refusals. The old raw/TAT/named-composed/nested-Runtime wrappers retain
their established representation scope. No observer is invoked, and
there is no IO, real model work, provenance, material authority or live
activation. This is only original bounded byte projection.
