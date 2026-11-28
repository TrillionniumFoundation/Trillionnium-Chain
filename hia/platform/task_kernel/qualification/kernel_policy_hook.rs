// Appended only to an isolated, byte-prefix-checked copy of original store.rs.
// The wrapper calls private original methods without duplicating their rules.
pub fn qualification_policy(
    operation: u64,
    height: u64,
    bundle: AgentMarketFreshGenesisTrustBundleV1,
    extra: &[u8],
) -> AgentMarketResultV1<Vec<u8>> {
    let mut config=AgentMarketStoreConfigV1{path:PathBuf::new(),store_id:Hash32V1::default(),trust_bundle:bundle};
    match operation {
        0=>{validate_trust_bundle(&config.trust_bundle)?;Ok(Vec::new())},
        1=>{let execution:CommittedExecutionContextV1=strict_decode(extra)?;validate_execution_context_static(&config,&execution)?;Ok(Vec::new())},
        2=>{let command:KernelCommandV1=strict_decode(extra)?;verify_command_envelope(&config,height,&command)?;Ok(Vec::new())},
        3=>{let command:KernelCommandV1=strict_decode(extra)?;verify_authorization_signature(&config,&command)?;Ok(Vec::new())},
        4=>{config.store_id=Hash32V1(extra.try_into().expect("checked frame"));Ok(config.config_hash()?.0.to_vec())},
        _=>unreachable!(),
    }
}
