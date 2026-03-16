#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MonetaryState {
    pub last_tick_height: u64,
    pub tick_count: u64,
    pub total_minted: u128,
    pub total_burned: u128,
    pub net_issuance: i128,
}
