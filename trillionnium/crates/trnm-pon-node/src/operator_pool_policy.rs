//! Independent finite exact-command permits. Never a partial Work capability.
//! This source is unexecuted; external issuer, latest and request are mandatory.
use super::*;

pub const POOL_SCHEMA: &str = "restricted-owner-pool-command-v1";
const POOL_DOMAIN: &[u8] = b"TRNM-RESTRICTED-NODE-POOL-GRANT1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PoolGrant {
    pub(crate) schema: String,
    pub(crate) context: Context,
    pub(crate) registry_sequence: u64,
    pub(crate) registry_digest: String,
    pub(crate) registry_previous_digest: Option<String>,
    pub(crate) declaration_digest: String,
    pub(crate) registered_task: String,
    pub(crate) lease_sha256: String,
    pub(crate) instance_class: String,
    pub(crate) pool_context: String,
    pub(crate) command: String,
    pub(crate) exact_payload_sha256: String,
    pub(crate) operation_nonce: String,
    pub(crate) operation_id: String,
    pub(crate) expected_generation: u64,
    pub(crate) allocation: Allocation,
    pub(crate) limits: Limits,
    pub(crate) funding_commitment: String,
    pub(crate) funding_evidence: String,
    pub(crate) declared_funding_units: u64,
    pub(crate) not_before_ns: u64,
    pub(crate) expires_ns: u64,
    pub(crate) revoked: bool,
    pub(crate) allowed_task_commands: Vec<String>,
    pub(crate) authorized_retained_groups: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PoolEnvelope {
    body: PoolGrant,
    registry_signature: String,
    task_signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolExternalAuthority {
    pub registry_key: String,
    pub task_key: String,
    pub latest_sequence: u64,
    pub latest_digest: String,
    pub expected_envelope_sha256: String,
    pub expected: PoolGrant,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolExternalPermission {
    pub raw_policy: Vec<u8>,
    pub authority: PoolExternalAuthority,
}

pub(crate) struct VerifiedPoolPolicy {
    pub(super) body: PoolGrant,
    pub(super) envelope_sha256: String,
}
pub(crate) struct PoolFacts {
    pub(crate) parent: String,
    pub(crate) generation: u64,
    pub(crate) pool_context: String,
    pub(crate) registered_task: String,
    pub(crate) lease_sha256: String,
    pub(crate) command: String,
    pub(crate) payload_sha256: String,
}

fn validate_pool(g: &PoolGrant) -> Result<()> {
    require(
        g.schema == POOL_SCHEMA
            && matches!(
                g.command.as_str(),
                "enable-pool" | "reconcile" | "submit-bundle"
            ),
        PolicyError::Input,
    )?;
    for h in [
        &g.context.registry_id,
        &g.context.operator_id,
        &g.context.network,
        &g.context.parameters,
        &g.context.node_policy_source,
        &g.context.registry2_package,
        &g.context.actual_parent,
        &g.registry_digest,
        &g.declaration_digest,
        &g.registered_task,
        &g.lease_sha256,
        &g.pool_context,
        &g.exact_payload_sha256,
        &g.operation_nonce,
        &g.operation_id,
        &g.funding_commitment,
        &g.funding_evidence,
    ] {
        hash_hex(h, 32)?;
    }
    hash_hex(&g.context.source_commit, 20)?;
    if let Some(h) = &g.registry_previous_digest {
        hash_hex(h, 32)?;
    }
    require(
        g.registry_sequence > 0
            && (g.registry_sequence == 1) == g.registry_previous_digest.is_none(),
        PolicyError::Input,
    )?;
    require(
        matches!(g.instance_class.as_str(), "dense" | "structured" | "zero"),
        PolicyError::Input,
    )?;
    validate_allocation(&g.allocation)?;
    validate_allocation(&g.limits.allocation)?;
    require(
        g.limits.operations > 0
            && g.limits.operations <= MAX_FILES as u64
            && within(&g.allocation, &g.limits.allocation)
            && g.declared_funding_units >= g.limits.allocation.funding_units,
        PolicyError::Budget,
    )?;
    let window = g
        .expires_ns
        .checked_sub(g.not_before_ns)
        .ok_or(PolicyError::Window)?;
    require(
        g.not_before_ns > 0 && window > 0 && window <= MAX_WINDOW_NS,
        PolicyError::Window,
    )?;
    require(
        g.allowed_task_commands.len() <= 16
            && g.allowed_task_commands.windows(2).all(|v| v[0] < v[1]),
        PolicyError::Input,
    )?;
    for h in &g.allowed_task_commands {
        hash_hex(h, 32)?;
    }
    require(
        g.authorized_retained_groups.len() <= MAX_FILES
            && g.authorized_retained_groups.windows(2).all(|v| v[0] < v[1]),
        PolicyError::Input,
    )?;
    for h in &g.authorized_retained_groups {
        hash_hex(h, 32)?;
    }
    require(
        g.operation_id == pool_operation_id(g)?,
        PolicyError::NativeBinding,
    )
}
pub fn pool_operation_id(g: &PoolGrant) -> Result<String> {
    let c = &g.context;
    pool_operation_components(
        [&c.registry_id, &c.operator_id, &c.network, &c.parameters],
        [
            &c.actual_parent,
            &g.pool_context,
            &g.exact_payload_sha256,
            &g.operation_nonce,
        ],
        &g.command,
        g.expected_generation,
    )
}
fn pool_operation_components(
    identity: [&str; 4],
    binding: [&str; 4],
    command: &str,
    generation: u64,
) -> Result<String> {
    let mut raw = b"TRNM-RESTRICTED-NODE-POOL-OP1".to_vec();
    for h in identity.into_iter().chain(binding) {
        hash_hex(h, 32)?;
        put_text(&mut raw, h);
    }
    require(
        matches!(command, "enable-pool" | "reconcile" | "submit-bundle"),
        PolicyError::Input,
    )?;
    put_text(&mut raw, command);
    raw.extend_from_slice(&generation.to_le_bytes());
    Ok(sha(&raw))
}
pub(super) fn validate_retained_claim(c: &PoolClaim, identity: &JournalIdentity) -> Result<()> {
    require(
        c.schema == "restricted-node-pool-reservation-v1"
            && c.sequence > 0
            && matches!(c.instance_class.as_str(), "dense" | "structured" | "zero"),
        PolicyError::Journal,
    )?;
    for h in [
        &c.declaration,
        &c.policy_sha256,
        &c.registry_digest,
        &c.native_task,
    ] {
        hash_hex(h, 32)?;
    }
    require(
        c.operation
            == pool_operation_components(
                [
                    &identity.registry,
                    &identity.operator,
                    &identity.network,
                    &identity.parameters,
                ],
                [
                    &c.parent,
                    &c.pool_context,
                    &c.payload_sha256,
                    &c.operation_nonce,
                ],
                &c.command,
                c.generation,
            )?,
        PolicyError::Journal,
    )?;
    validate_allocation(&c.allocation)
}
fn pool_message(g: &PoolGrant, role: u8) -> Vec<u8> {
    let mut out = POOL_DOMAIN.to_vec();
    out.push(role);
    for h in [
        &g.schema,
        &g.context.registry_id,
        &g.context.operator_id,
        &g.context.network,
        &g.context.parameters,
        &g.context.source_commit,
        &g.context.node_policy_source,
        &g.context.registry2_package,
        &g.context.actual_parent,
    ] {
        put_text(&mut out, h);
    }
    out.extend_from_slice(&g.registry_sequence.to_le_bytes());
    put_text(&mut out, &g.registry_digest);
    put_optional(&mut out, &g.registry_previous_digest);
    for h in [
        &g.declaration_digest,
        &g.registered_task,
        &g.lease_sha256,
        &g.instance_class,
        &g.pool_context,
        &g.command,
        &g.exact_payload_sha256,
        &g.operation_nonce,
        &g.operation_id,
    ] {
        put_text(&mut out, h);
    }
    out.extend_from_slice(&g.expected_generation.to_le_bytes());
    put_allocation(&mut out, &g.allocation);
    out.extend_from_slice(&g.limits.operations.to_le_bytes());
    put_allocation(&mut out, &g.limits.allocation);
    put_text(&mut out, &g.funding_commitment);
    put_text(&mut out, &g.funding_evidence);
    for n in [g.declared_funding_units, g.not_before_ns, g.expires_ns] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.push(u8::from(g.revoked));
    out.extend_from_slice(&(g.allowed_task_commands.len() as u32).to_le_bytes());
    for h in &g.allowed_task_commands {
        put_text(&mut out, h);
    }
    out.extend_from_slice(&(g.authorized_retained_groups.len() as u32).to_le_bytes());
    for h in &g.authorized_retained_groups {
        put_text(&mut out, h);
    }
    out
}
pub fn operator_pool_signing_bytes(g: &PoolGrant, role: SigningRole) -> Result<Vec<u8>> {
    validate_pool(g)?;
    Ok(pool_message(
        g,
        match role {
            SigningRole::Registry => 1,
            SigningRole::Task => 2,
        },
    ))
}

pub(crate) fn authenticate_pool(
    permission: &PoolExternalPermission,
    primary: &ExternalAuthority,
    policy: &VerifiedPolicy,
    observed_ns: u64,
) -> Result<VerifiedPoolPolicy> {
    let e = &permission.authority;
    let raw = &permission.raw_policy;
    require(
        !raw.is_empty() && raw.len() <= MAX_POLICY_BYTES,
        PolicyError::Input,
    )?;
    let envelope: PoolEnvelope = serde_json::from_slice(raw).map_err(|_| PolicyError::Input)?;
    let g = &envelope.body;
    validate_pool(g)?;
    validate_pool(&e.expected)?;
    hash_hex(&e.expected_envelope_sha256, 32)?;
    require(
        g == &e.expected
            && sha(raw) == e.expected_envelope_sha256
            && e.registry_key == primary.registry_key
            && e.task_key == primary.task_key
            && e.latest_sequence == primary.latest_sequence
            && e.latest_digest == primary.latest_digest
            && g.context == policy.body.context
            && g.registry_sequence == policy.body.registry_sequence
            && g.registry_digest == policy.body.registry_digest
            && g.registry_previous_digest == policy.body.registry_previous_digest
            && g.declaration_digest == policy.body.declaration_digest
            && g.registered_task == policy.body.task.native_task
            && g.lease_sha256 == policy.body.task.lease_sha256
            && g.instance_class == policy.body.instance_class
            && g.limits == policy.body.limits
            && g.funding_commitment == policy.body.funding_commitment
            && g.funding_evidence == policy.body.funding_evidence
            && g.declared_funding_units == policy.body.declared_funding_units,
        PolicyError::ExternalContext,
    )?;
    require(
        g.not_before_ns <= observed_ns && observed_ns < g.expires_ns,
        PolicyError::Window,
    )?;
    verify_hex_strict(
        &e.registry_key,
        &pool_message(g, 1),
        &envelope.registry_signature,
    )
    .map_err(|_| PolicyError::Signature)?;
    verify_hex_strict(&e.task_key, &pool_message(g, 2), &envelope.task_signature)
        .map_err(|_| PolicyError::Signature)?;
    Ok(VerifiedPoolPolicy {
        body: envelope.body,
        envelope_sha256: sha(raw),
    })
}

/// Ordered whole raw payload; no task ID, proof, matrix or signature cache.
pub fn pool_payload_sha256(command: &str, raws: &[Vec<u8>]) -> Result<String> {
    require(
        matches!(command, "enable-pool" | "reconcile" | "submit-bundle") && raws.len() <= 256,
        PolicyError::Input,
    )?;
    let mut raw = b"TRNM-RESTRICTED-NODE-POOL-PAYLOAD1".to_vec();
    put_text(&mut raw, command);
    raw.extend_from_slice(&(raws.len() as u32).to_le_bytes());
    for value in raws {
        require(!value.is_empty() && value.len() <= 2048, PolicyError::Input)?;
        raw.extend_from_slice(&(value.len() as u32).to_le_bytes());
        raw.extend_from_slice(value);
    }
    Ok(sha(&raw))
}
impl VerifiedPoolPolicy {
    pub(crate) fn same_operation(&self, other: &Self) -> bool {
        self.body.operation_id == other.body.operation_id
    }
    pub(crate) fn matches(&self, command: &str, payload: &str) -> bool {
        self.body.command == command && self.body.exact_payload_sha256 == payload
    }
    pub(crate) fn task(&self) -> &str {
        &self.body.registered_task
    }
    pub(crate) fn check_parent(
        &self,
        parent: &str,
        generation: u64,
        pool_context: &str,
    ) -> Result<()> {
        require(
            parent == self.body.context.actual_parent
                && generation == self.body.expected_generation
                && pool_context == self.body.pool_context,
            PolicyError::NativeBinding,
        )
    }
    pub(crate) fn check(&self, facts: &PoolFacts, observed_ns: u64) -> Result<()> {
        require(!self.body.revoked, PolicyError::Revoked)?;
        require(
            self.body.not_before_ns <= observed_ns && observed_ns < self.body.expires_ns,
            PolicyError::Window,
        )?;
        require(
            facts.parent == self.body.context.actual_parent
                && facts.generation == self.body.expected_generation
                && facts.pool_context == self.body.pool_context
                && facts.registered_task == self.body.registered_task
                && facts.lease_sha256 == self.body.lease_sha256
                && self.matches(&facts.command, &facts.payload_sha256),
            PolicyError::NativeBinding,
        )
    }
    pub(crate) fn check_prefix_commands(&self, raws: &[Vec<u8>]) -> Result<()> {
        for raw in raws {
            let envelope = trnm_protocol::pon_wire::Envelope::decode(raw)
                .map_err(|_| PolicyError::NativeBinding)?;
            require(envelope.tag != 12, PolicyError::NativeBinding)?;
            if matches!(envelope.tag, 13 | 18..=22) {
                require(
                    self.body
                        .allowed_task_commands
                        .binary_search(&sha(raw))
                        .is_ok(),
                    PolicyError::ExternalContext,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PoolClaim {
    pub(super) schema: String,
    pub(super) operation: String,
    pub(super) command: String,
    pub(super) payload_sha256: String,
    pub(super) parent: String,
    pub(super) generation: u64,
    pub(super) pool_context: String,
    pub(super) operation_nonce: String,
    pub(super) declaration: String,
    pub(super) policy_sha256: String,
    pub(super) sequence: u64,
    pub(super) registry_digest: String,
    pub(super) native_task: String,
    pub(super) instance_class: String,
    pub(super) allocation: Allocation,
}
pub(crate) struct PoolReservation {
    pub(super) operation: String,
    pub(super) policy_sha256: String,
    pub(super) sequence: u64,
    pub(super) registry_digest: String,
}

impl Journal {
    #[cfg(test)]
    pub(crate) fn pool_claim_count_for_tests(&self) -> usize {
        self.pool_claims.len()
    }
    pub(crate) fn pool_operation_is_used(&self, policy: &VerifiedPoolPolicy) -> bool {
        self.pool_claims
            .iter()
            .any(|row| row.operation == policy.body.operation_id)
    }
    pub(crate) fn reserve_pool(
        &mut self,
        policy: &VerifiedPoolPolicy,
        facts: &PoolFacts,
        now: u64,
    ) -> Result<PoolReservation> {
        self.ready()?;
        policy.check(facts, now)?;
        require(
            policy.body.registry_sequence == self.anchor_sequence
                && policy.body.registry_digest == self.anchor_digest,
            PolicyError::ExternalContext,
        )?;
        require(!self.pool_operation_is_used(policy), PolicyError::Replay)?;
        require(
            self.claims.len() + self.pool_claims.len() < MAX_FILES,
            PolicyError::Capacity,
        )?;
        let g = &policy.body;
        let mut count = 0u64;
        let mut usage = Allocation {
            cpu_ns: 0,
            material_bytes: 0,
            da_bytes: 0,
            funding_units: 0,
            reuse_uses: 0,
        };
        for (task, class, allocation) in self
            .claims
            .iter()
            .map(|r| (&r.native_task, &r.instance_class, &r.allocation))
            .chain(
                self.pool_claims
                    .iter()
                    .map(|r| (&r.native_task, &r.instance_class, &r.allocation)),
            )
        {
            if task == &g.registered_task && class == &g.instance_class {
                usage = add(&usage, allocation)?;
                count += 1;
            }
        }
        usage = add(&usage, &g.allocation)?;
        require(
            count < g.limits.operations && within(&usage, &g.limits.allocation),
            PolicyError::Budget,
        )?;
        let claim = PoolClaim {
            schema: "restricted-node-pool-reservation-v1".into(),
            operation: g.operation_id.clone(),
            command: g.command.clone(),
            payload_sha256: facts.payload_sha256.clone(),
            parent: facts.parent.clone(),
            generation: facts.generation,
            pool_context: facts.pool_context.clone(),
            operation_nonce: g.operation_nonce.clone(),
            declaration: g.declaration_digest.clone(),
            policy_sha256: policy.envelope_sha256.clone(),
            sequence: g.registry_sequence,
            registry_digest: g.registry_digest.clone(),
            native_task: g.registered_task.clone(),
            instance_class: g.instance_class.clone(),
            allocation: g.allocation.clone(),
        };
        let result = save_new(
            &self
                .pinned()
                .join(format!("pool-claim-{}.json", g.operation_id)),
            &claim,
            &self.directory,
        );
        if result.is_err() {
            self.unavailable = true;
            return Err(PolicyError::Journal);
        }
        self.pool_claims.push(claim);
        Ok(PoolReservation {
            operation: g.operation_id.clone(),
            policy_sha256: policy.envelope_sha256.clone(),
            sequence: g.registry_sequence,
            registry_digest: g.registry_digest.clone(),
        })
    }
    pub(crate) fn recheck_pool(
        &self,
        policy: &VerifiedPoolPolicy,
        reservation: &PoolReservation,
        facts: &PoolFacts,
        now: u64,
    ) -> Result<()> {
        self.ready()?;
        policy.check(facts, now)?;
        require(
            reservation.operation == policy.body.operation_id
                && reservation.policy_sha256 == policy.envelope_sha256
                && reservation.sequence == self.anchor_sequence
                && reservation.registry_digest == self.anchor_digest,
            PolicyError::ExternalContext,
        )
    }
    pub(crate) fn prefix_group_authorized(
        &self,
        policy: &VerifiedPoolPolicy,
        payload: &str,
    ) -> Result<()> {
        self.ready()?;
        // A prior exact admission is required, and a new parent/view must
        // separately permit rechecking that old bundle. New-bundle identity
        // alone never grants authority over all retained prefix groups.
        require(
            policy
                .body
                .authorized_retained_groups
                .binary_search(&payload.to_owned())
                .is_ok()
                && self.pool_claims.iter().any(|r| {
                    r.command == "submit-bundle"
                        && r.payload_sha256 == payload
                        && r.pool_context == policy.body.pool_context
                        && r.native_task == policy.body.registered_task
                        && r.instance_class == policy.body.instance_class
                }),
            PolicyError::ExternalContext,
        )
    }
}

#[cfg(test)]
#[path = "operator_pool_policy_tests.rs"]
pub(crate) mod tests;
