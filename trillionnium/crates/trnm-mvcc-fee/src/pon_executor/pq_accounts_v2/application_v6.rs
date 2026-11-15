//! Explicit full application successor. The configured profile, immutable
//! network identity and original M06 state owner select every authorization path.
use super::*;
use crate::public_evaluation;
use std::sync::atomic::{AtomicUsize, Ordering};

pub const PROFILE: &str = "pon-native-pq-application-v6";
pub const VERIFICATION_FEE_UNITS: u64 = 1_000;

/// Protected genesis input. Evaluator addresses refer to actual seeded PQ
/// accounts; no incoming transaction may replace this roster or model contract.
pub struct ApplicationPolicy {
    pub evaluators: BTreeSet<Hash>,
    pub evaluation_profile: String,
    pub model_profile: String,
}

pub fn enabled(cfg: &Config) -> bool {
    cfg.native_pq_v2
        .as_ref()
        .is_some_and(|p| p.wire_profile == wire::AccountProfile::ApplicationV6)
}

pub fn genesis(
    accounts: &[GenesisAccount],
    timestamp: u64,
    policy: &ApplicationPolicy,
) -> Result<(Config, State, Hash)> {
    build_genesis_profile(
        accounts,
        timestamp,
        None,
        GenesisProfile::Existing(wire::AccountProfile::ApplicationV6),
        Some(policy),
    )
}

pub fn genesis_with_trusted_migration(
    accounts: &[GenesisAccount],
    timestamp: u64,
    anchor: TrustedMigrationAnchor,
    policy: &ApplicationPolicy,
) -> Result<(Config, State, Hash)> {
    build_genesis_profile(
        accounts,
        timestamp,
        Some(Arc::new(anchor)),
        GenesisProfile::Existing(wire::AccountProfile::ApplicationV6),
        Some(policy),
    )
}

pub(super) fn configured(policy: &ApplicationPolicy, seeded: &BTreeSet<Hash>) -> Result<Config> {
    require(
        (2..=16).contains(&policy.evaluators.len()) && policy.evaluators.is_subset(seeded),
        "PQ6_EVALUATOR_PINS",
    )?;
    require(
        matches!(
            policy.evaluation_profile.as_str(),
            public_evaluation::PROFILE | public_evaluation::QUORUM_PROFILE
        ),
        "PQ6_PUBLIC_EVALUATION_REQUIRED",
    )?;
    let mut cfg = Config::installed_with_model_profiles(
        &policy.evaluation_profile,
        crate::continuity_v1::PROFILE,
        &policy.model_profile,
    )?;
    cfg.evaluators = policy.evaluators.iter().map(hex::encode).collect();
    cfg.params["max_transaction_bytes"] = json!(wire::APPLICATION_MAX_BYTES);
    cfg.params["max_transactions"] = json!(wire::APPLICATION_MAX_TRANSACTIONS);
    cfg.params["max_pq_verifications"] = json!(wire::APPLICATION_MAX_VERIFICATIONS);
    cfg.params["max_pq_transaction_total_bytes"] = json!(wire::MAX_TRANSACTION_BYTES);
    cfg.params["pq_verification_fee_units"] = json!(VERIFICATION_FEE_UNITS);
    // These are deterministic accounting units, not a CPU-time measurement.
    for (tag, fee) in cfg.fees.iter_mut().enumerate() {
        let count = match tag {
            11 | 21 | 22 => 2,
            16 => 3,
            _ => 1,
        };
        *fee = fee
            .checked_add(VERIFICATION_FEE_UNITS * count)
            .ok_or("RANGE")?;
    }
    Ok(cfg)
}

pub(super) fn charge(cfg: &Config, budget: &AtomicUsize) -> Result<()> {
    let maximum = account_profile(cfg)?.maximum_verifications();
    budget
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            used.checked_add(1).filter(|next| *next <= maximum)
        })
        .map_err(|_| "PQ_VERIFY_BUDGET")?;
    Ok(())
}

/// Evidence holds two actually verified, nonrecursive commit/reveal statements.
/// There is no public field constructor, deserializer or accepted boolean.
pub(crate) struct VerifiedConflict {
    pub(super) first: Vec<u8>,
    pub(super) second: Vec<u8>,
    pub(super) sender: Hash,
    pub(super) generation: u64,
    pub(super) tag: u8,
    pub(super) first_payload: Vec<u8>,
    pub(super) second_payload: Vec<u8>,
}
impl VerifiedConflict {
    pub(crate) fn raw(&self) -> (&[u8], &[u8]) {
        (&self.first, &self.second)
    }
    pub(crate) fn signer(&self) -> Hash {
        self.sender
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn kind(&self) -> u8 {
        self.tag
    }
    pub(crate) fn payloads(&self) -> (&[u8], &[u8]) {
        (&self.first_payload, &self.second_payload)
    }
}

pub(super) fn conflict_proofs(
    parent: &State,
    tx: &UnverifiedEnvelope<'_>,
    cfg: &Config,
    budget: &AtomicUsize,
) -> Result<Option<VerifiedConflict>> {
    if !enabled(cfg) || tx.kind != 16 {
        return Ok(None);
    }
    let (first, second) =
        wire::conflict_evidence(tx.payload).map_err(|_| "PQ6_CONFLICT_ENCODING")?;
    let a = decode_for_config(first, cfg)?;
    let b = decode_for_config(second, cfg)?;
    require(
        a.common.context == context(cfg)?
            && b.common.context == context(cfg)?
            && a.common.account == b.common.account
            && a.kind == b.kind
            && matches!(a.kind, 14 | 15)
            && a.payload != b.payload,
        "PQ6_CONFLICT_CONTEXT",
    )?;
    let mut view = View::new(parent, None);
    for signed in [&a, &b] {
        require(
            signed.payload[..32] == tx.payload[..32],
            "PQ6_CONFLICT_CONTEXT",
        )?;
        let witness = &signed.witnesses()[0];
        let key = historical_evaluator_key(&mut view, signed, cfg)?;
        charge(cfg, budget)?;
        verify_tpq1(
            witness.frame,
            &PqFrameExpectation {
                purpose: witness.role,
                network: signed.common.context.network,
                owner_context: wire::owner_context_for_profile(
                    account_profile(cfg)?,
                    &signed.common,
                    signed.kind,
                    witness.role,
                )
                .map_err(|_| "PQ6_CONFLICT_CONTEXT")?,
                signer_key_id: witness.key_id,
                owner_generation: witness.generation,
                operation_sequence: signed.common.nonce,
                expires_at: signed.common.expires_at,
                // Historical evidence is admissible after its original spend expiry.
                // It grants no nonce, fee, or execution effect for either inner tx.
                now: 0,
                payload: signed.core(),
            },
            &key,
        )
        .map_err(|_| "PQ6_CONFLICT_SIGNATURE")?;
    }
    Ok(Some(VerifiedConflict {
        first: first.to_vec(),
        second: second.to_vec(),
        sender: a.common.account,
        generation: a.common.generation,
        tag: a.kind,
        first_payload: a.payload.to_vec(),
        second_payload: b.payload.to_vec(),
    }))
}

pub(super) fn apply_model(
    base: &State,
    prepared: &PreparedCommand,
    height: u64,
    cfg: &Config,
    access: Option<&super::super::AccountPointAccess<'_>>,
) -> Result<super::super::Patch> {
    require(
        enabled(cfg) && matches!(prepared.kind, 6..=9 | 14..=17 | 23 | 24),
        "PQ6_MODEL_COMMAND",
    )?;
    // The original application owner consumes a private typed, checked command;
    // this never manufactures an Ed25519 Envelope or a fake signature.
    let command = super::super::ApplicationCommand {
        sender: prepared.common.account,
        nonce: prepared.common.nonce,
        fee_limit: prepared.common.max_fee,
        tag: prepared.kind,
        payload: prepared.payload.clone(),
    };
    let application = super::super::Prepared {
        command,
        legacy: None,
        native_pq: None,
        sender: hex::encode(prepared.common.account),
        encoded_len: prepared.raw.len(),
        transaction_id: prepared.wire_id.to_vec(),
    };
    super::super::apply_authenticated_application(
        base,
        &application,
        height,
        cfg,
        access,
        prepared.conflict.as_ref(),
    )
}

pub(super) fn command_profile(kind: u8, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    require(kind != 7, "PQ6_COMMIT_REVEAL_REQUIRED")?;
    require(
        kind != 6 || !crate::integer_factor_candidate_v2::enabled(cfg),
        "FACTOR_PROFILE",
    )?;
    require(
        kind != 23
            || (crate::integer_factor_candidate_v2::enabled(cfg)
                && !crate::model_evolution_v5::enabled(cfg)),
        "FACTOR_PROFILE",
    )?;
    require(
        kind != 24 || crate::model_evolution_v5::enabled(cfg),
        "EVOLUTION_PROFILE",
    )
}

/// Freeze generations in the same order as the immutable roster. Public keys
/// remain in the original bounded account history, avoiding large duplicated
/// keys in every plan. The round digest commits to these generation pins.
pub(in crate::pon_executor) fn pin_evaluators(
    view: &mut View<'_>,
    contribution: &mut Value,
    cfg: &Config,
) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    let evaluation = &mut contribution["public_evaluation"];
    let roster = evaluation["plan"]["roster"]
        .as_array()
        .ok_or("PQ6_FROZEN_AUTHORITY")?;
    let mut generations = Vec::with_capacity(roster.len());
    for account in roster {
        let account = hash32(account.as_str().ok_or("PQ6_FROZEN_AUTHORITY")?)?;
        generations.push(authorize(view, account)?.generation);
    }
    evaluation["plan"]["pq_generations"] = json!(generations);
    evaluation["round"] = json!(hex::encode(public_evaluation::expected_round(evaluation)?));
    require(
        canonical(contribution)?.len() <= 4096,
        "PUBLIC_EVAL_RECORD_LIMIT",
    )
}

pub(crate) fn frozen_generation(evaluation: &Value, account: Hash) -> Result<u64> {
    require(
        matches!(evaluation["storage_revision"].as_u64(), Some(6 | 7)),
        "PQ6_FROZEN_AUTHORITY",
    )?;
    public_evaluation::round(evaluation)?;
    let roster = evaluation["plan"]["roster"]
        .as_array()
        .ok_or("PQ6_FROZEN_AUTHORITY")?;
    let pins = evaluation["plan"]["pq_generations"]
        .as_array()
        .ok_or("PQ6_FROZEN_AUTHORITY")?;
    require(
        (2..=16).contains(&roster.len()) && pins.len() == roster.len(),
        "PQ6_FROZEN_AUTHORITY",
    )?;
    let name = hex::encode(account);
    let index = roster
        .iter()
        .position(|a| a.as_str() == Some(&name))
        .ok_or("PQ6_FROZEN_AUTHORITY")?;
    let generation = pins[index].as_u64().ok_or("PQ6_FROZEN_AUTHORITY")?;
    require(
        (1..=MAX_GENERATIONS).contains(&generation),
        "PQ6_FROZEN_AUTHORITY",
    )?;
    Ok(generation)
}

/// Historical conflict evidence is bound to the round's original authority.
/// A rotation disables old spending, but cannot erase proof of old equivocation.
pub(super) fn historical_evaluator_key(
    view: &mut View<'_>,
    tx: &UnverifiedEnvelope<'_>,
    cfg: &Config,
) -> Result<Vec<u8>> {
    require(
        enabled(cfg) && matches!(tx.kind, 14 | 15) && tx.witnesses().len() == 1,
        "PQ6_FROZEN_AUTHORITY",
    )?;
    let candidate: Hash = tx.payload[..32]
        .try_into()
        .map_err(|_| "PQ6_FROZEN_AUTHORITY")?;
    let name = hex::encode(candidate);
    let contribution = view
        .get(&format!("contribution:{name}"))
        .or_else(|| view.get(&format!("evaluation-archive:{name}")))
        .ok_or("PQ6_FROZEN_AUTHORITY")?;
    let evaluation = &contribution["public_evaluation"];
    let generation = frozen_generation(evaluation, tx.common.account)?;
    require(
        tx.payload[32..64] == public_evaluation::round(evaluation)?
            && tx.common.generation == generation
            && tx.witnesses()[0].generation == generation,
        "PQ6_FROZEN_AUTHORITY",
    )?;
    let row = view
        .get(&key_key(&hex::encode(tx.common.account), generation))
        .ok_or("PQ6_FROZEN_AUTHORITY")?;
    let (spki, key_id) = decode_spki(&row)?;
    require(key_id == tx.witnesses()[0].key_id, "PQ6_FROZEN_AUTHORITY")?;
    Ok(spki)
}

pub(super) fn validate_frozen_evaluators(state: &State, cfg: &Config) -> Result<()> {
    if !enabled(cfg) {
        return Ok(());
    }
    for (key, contribution) in state
        .iter()
        .filter(|(k, _)| k.starts_with("contribution:") || k.starts_with("evaluation-archive:"))
    {
        let evaluation = &contribution["public_evaluation"];
        require(
            key.split_once(':')
                .is_some_and(|(_, id)| evaluation["plan"]["candidate"] == id),
            "PQ6_FROZEN_AUTHORITY",
        )?;
        let roster = evaluation["plan"]["roster"]
            .as_array()
            .ok_or("PQ6_FROZEN_AUTHORITY")?;
        let mut previous: Option<Hash> = None;
        for account in roster {
            let account = hash32(account.as_str().ok_or("PQ6_FROZEN_AUTHORITY")?)?;
            require(
                previous.is_none_or(|prior| prior < account),
                "PQ6_FROZEN_AUTHORITY",
            )?;
            previous = Some(account);
            let generation = frozen_generation(evaluation, account)?;
            decode_spki(
                state
                    .get(&key_key(&hex::encode(account), generation))
                    .ok_or("PQ6_FROZEN_AUTHORITY")?,
            )?;
        }
    }
    Ok(())
}
