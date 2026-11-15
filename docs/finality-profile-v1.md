# Versioned deterministic finality profile

The original `trnm-committee-finality-v1` remains specified-disabled. It now fixes
exactly four actual manifest members, f=1 and q=3. Five members with the same
three-vote rule are rejected, not accepted merely because n>=3f+1.
The executable successor has a new domain: see
[release finality V2](protocol/release-finality-v2/SPEC.md).

This is a narrow port of the October 14 finality draft into the current native
integration lineage. It does not import the old draft's CI or overwrite newer
node, runtime, storage, learning or recovery code. Both old and new profiles stay
disabled; old finality bytes never become new-profile votes. PoN remains separate.
