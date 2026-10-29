//! Explicit independently anchored import into a new NPQ5 network.
//! Existing NPQ2/3/4/5 networks and stores never opt in through request bytes.
//! Prior PQ registration, source finality and retirement remain external trust
//! premises. Imported accounts remain locked until the ordinary dual-PQ CLAIM.
use super::{
    build_genesis_profile, Arc, Config, GenesisAccount, GenesisProfile, Hash, Result, State,
    TrustedMigrationAnchor,
};

pub const PROFILE: &str = "pon-native-pq-tasks-v5-anchored-migration-v1";

pub fn genesis_with_trusted_migration(
    accounts: &[GenesisAccount],
    timestamp: u64,
    anchor: TrustedMigrationAnchor,
) -> Result<(Config, State, Hash)> {
    build_genesis_profile(
        accounts,
        timestamp,
        Some(Arc::new(anchor)),
        GenesisProfile::AnchoredTasksV5,
    )
}
