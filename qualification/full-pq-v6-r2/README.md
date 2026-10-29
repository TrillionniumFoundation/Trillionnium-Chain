# Full PQ V6 reconstruction and qualification

Status: **HOLD / validation in progress**. This directory records observations;
it does not grant production activation or a security score.

Source checkpoint: `e19bf296a3e85dd15c00e9c6957fc59bfb358249` on
`feature/chain-full-pq-20261028-r2`. This checkpoint deliberately preserves an
unqualified integration candidate before final tests; subsequent fixes and the
final tested source must be identified separately.

- Chain base: `58d533877ccdf56f2fc2b87e0b60c485300955a5`.
- Native account/task source input: `42ab57f1c5065d50f981cc337c417ef0ab7dc096`.
- Hepta base: `bcb8f97164cefe494918fb0efe482029d7dfe6be`.
- Hepta verified retained-lifetime checkpoint: `60e01eb44` (123 ledger tests
  passed, two existing skips; not a full Hepta PQ qualification).

Earlier environment-only sources and tests were unavailable and are not
inherited as successful observations. The first compiler/test failures of this
reconstruction are retained alongside later results. A compile, source check,
fixed vector or independent-provider comparison has its own limited meaning.

The [implementation contract](../../docs/security/PQ_APPLICATION_AUTHORIZATION_V6.md)
records resource bounds, owner composition and remaining gates. The
[development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the only plan. Final results and replay commands are added only after
the actual scoped runs finish.
