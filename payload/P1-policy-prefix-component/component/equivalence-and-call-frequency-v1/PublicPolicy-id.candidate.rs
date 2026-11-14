    pub fn id(self) -> Hash {
        hash_public_policy([
            &[self.bits],
            &self.lifetime_ms.to_le_bytes(),
            &MUTATION_CPU_BURST_NS.to_le_bytes(),
            &MUTATION_CPU_REFILL_NS_PER_SECOND.to_le_bytes(),
            &MUTATION_CPU_START_RESERVE_NS.to_le_bytes(),
            &(MUTATION_CPU_WORKERS as u32).to_le_bytes(),
        ])
    }