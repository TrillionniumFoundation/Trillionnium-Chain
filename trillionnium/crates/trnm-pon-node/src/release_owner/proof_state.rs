//! Every open/new operation replays actual retained proofs. No permission cache.
use super::bundle_wire::Bundle;
use super::execution_wire::{
    Claim, ConfigurationPolicy, Contract, Installation, LaunchAttempt, MAX_LAUNCH_RECORDS,
};
use super::files::Files;
use super::frontier::{invalid, Digest32, Result, Validity, MAX_INDEX_BYTES};
use super::proof_wire::{signatures, ObservedPublication, Publication};
use super::records::{self, Index, Record};
use super::trust_client::SignedAuthorityClient;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use trnm_release_bundle::pq_release::{
    PqReleaseAuthorityV1, PqReleaseRoleV1 as Role, PqReleaseRootV1,
};

#[derive(Clone)]
pub(super) struct Context {
    pub namespace: Digest32,
    pub configuration_pin: Digest32,
    pub initial_root_file: Digest32,
    pub initial_root_pin: Digest32,
    pub initial_root: PqReleaseRootV1,
    pub service_keys: [Digest32; 3],
    pub required_packages: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Context {
    pub fn from_client(client: &SignedAuthorityClient) -> Self {
        Self {
            namespace: client.config.namespace,
            configuration_pin: client.config_pin(),
            service_keys: [
                client.config.clock.key_id,
                client.config.frontier.key_id,
                client.config.writer_key_id,
            ],
            initial_root_file: client.config.initial_root_file_sha256,
            initial_root_pin: client.config.initial_root_digest,
            initial_root: client.initial_root.clone(),
            required_packages: client
                .config
                .required_packages
                .iter()
                .map(|(name, version)| (name.as_bytes().to_vec(), version.as_bytes().to_vec()))
                .collect(),
        }
    }
}

pub(super) struct State {
    pub index: Index,
    pub authority: PqReleaseAuthorityV1,
    pub bundle: Option<Bundle>,
    pub configuration: Option<ConfigurationPolicy>,
    pub installations: BTreeMap<Digest32, Installation>,
    pub attempts: BTreeMap<Digest32, LaunchAttempt>,
    pub claims: BTreeSet<Digest32>,
    root_expires_at: u64,
    release_expiry: BTreeMap<Role, u64>,
}

impl State {
    pub fn initial(context: &Context, now: u64) -> Result<Self> {
        super::root_separation::require(&context.initial_root, &context.service_keys)?;
        let authority = PqReleaseAuthorityV1::bootstrap_pinned(
            context.initial_root.clone(),
            context.initial_root_pin,
            now,
        )
        .map_err(io::Error::other)?;
        let index = Index {
            schema_version: 1,
            namespace: context.namespace,
            trust_configuration_sha256: context.configuration_pin,
            initial_root_file_sha256: context.initial_root_file,
            initial_root_digest: context.initial_root_pin,
            initialized_at: now,
            records: Vec::new(),
            kernel_checkpoint: authority.checkpoint(),
            time_floor: now,
        };
        Ok(Self {
            index,
            authority,
            bundle: None,
            configuration: None,
            installations: BTreeMap::new(),
            attempts: BTreeMap::new(),
            claims: BTreeSet::new(),
            root_expires_at: context.initial_root.expires_at,
            release_expiry: BTreeMap::new(),
        })
    }

    /// The caller authenticates the entire index through its independent M15
    /// frontier, or checks an append-only pending successor before its CAS.
    pub fn replay(files: &Files, raw: &[u8], context: &Context) -> Result<Self> {
        let index: Index = super::codec::decode(raw, MAX_INDEX_BYTES)?;
        if index.schema_version != 1
            || index.namespace != context.namespace
            || index.trust_configuration_sha256 != context.configuration_pin
            || index.initial_root_file_sha256 != context.initial_root_file
            || index.initial_root_digest != context.initial_root_pin
            || index.records.len() > records::MAX_RECORDS
        {
            return Err(invalid("M15 complete index/provisioning binding"));
        }
        let mut state = Self::initial(context, index.initialized_at)?;
        for digest in &index.records {
            state.append_verified(context, *digest, records::read(files, *digest)?)?;
        }
        if state.index.encode()? != raw {
            return Err(invalid("M15 full replay/index mismatch"));
        }
        Ok(state)
    }

    pub fn append_verified(
        &mut self,
        context: &Context,
        digest: Digest32,
        record: Record,
    ) -> Result<()> {
        if self.index.records.len() >= records::MAX_RECORDS
            || self.index.records.contains(&digest)
            || record.observed_at() < self.index.time_floor
            || record.digest()? != digest
        {
            return Err(invalid(
                "M15 record order, digest, time, or full history bound",
            ));
        }
        let observed_at = record.observed_at();
        match record {
            Record::Publication(value) => self.apply_publication(context, &value)?,
            Record::Installation(value) => self.apply_installation(digest, value)?,
            Record::LaunchAttempt(value) => self.apply_attempt(digest, *value)?,
            Record::Claim(value) => self.apply_claim(value)?,
        }
        self.index.records.push(digest);
        self.index.time_floor = observed_at;
        self.index.kernel_checkpoint = self.authority.checkpoint();
        Ok(())
    }

    fn apply_publication(&mut self, context: &Context, value: &ObservedPublication) -> Result<()> {
        if value.schema_version != 1 {
            return Err(invalid("M15 publication schema"));
        }
        self.verify_publication_material(context, &value.publication, value.observed_at)?;
        if value.resulting_checkpoint != self.authority.checkpoint() {
            return Err(invalid("M15 publication resulting checkpoint"));
        }
        Ok(())
    }

    pub fn prepare_publication(
        &mut self,
        context: &Context,
        publication: Publication,
        now: u64,
    ) -> Result<Record> {
        if now < self.index.time_floor || self.index.records.len() >= records::MAX_RECORDS {
            return Err(invalid("M15 publication clock/history bound"));
        }
        self.verify_publication_material(context, &publication, now)?;
        let record = Record::Publication(ObservedPublication {
            schema_version: 1,
            publication,
            observed_at: now,
            resulting_checkpoint: self.authority.checkpoint(),
        });
        let digest = record.digest()?;
        if self.index.records.contains(&digest) {
            return Err(invalid("M15 duplicate publication"));
        }
        self.index.records.push(digest);
        self.index.kernel_checkpoint = self.authority.checkpoint();
        self.index.time_floor = now;
        Ok(record)
    }

    fn verify_publication_material(
        &mut self,
        context: &Context,
        publication: &Publication,
        now: u64,
    ) -> Result<()> {
        match publication {
            Publication::RootRotation {
                root,
                old_signatures,
                new_signatures,
            } => {
                let successor = root.kernel()?;
                super::root_separation::require(&successor, &context.service_keys)?;
                self.authority
                    .rotate_root(
                        successor,
                        &signatures(old_signatures)?,
                        &signatures(new_signatures)?,
                        now,
                    )
                    .map_err(io::Error::other)?;
                self.root_expires_at = root.expires_at;
            }
            Publication::Release {
                metadata,
                signatures: proof,
                bundle,
                configuration,
            } => {
                let metadata = metadata.kernel()?;
                let proof = signatures(proof)?;
                match metadata.role {
                    Role::NodeSoftware => {
                        let bundle = bundle
                            .as_deref()
                            .ok_or_else(|| invalid("M15 actual full Node bundle required"))?;
                        if configuration.is_some() {
                            return Err(invalid("mixed M15 publication payload"));
                        }
                        self.authority
                            .accept_bundle(
                                &bundle.kernel(),
                                &context.required_packages,
                                &metadata,
                                &proof,
                                now,
                            )
                            .map_err(io::Error::other)?;
                        self.bundle = Some(bundle.clone());
                    }
                    Role::ProtocolConfiguration => {
                        let config = configuration
                            .as_deref()
                            .ok_or_else(|| invalid("M15 complete configuration policy required"))?;
                        if bundle.is_some()
                            || config.digest()? != metadata.content
                            || config.contract.namespace != context.namespace
                            || config.contract.protected_trust_sha256 != context.configuration_pin
                        {
                            return Err(invalid("M15 configuration content/provisioning mismatch"));
                        }
                        self.authority
                            .accept(&metadata, &proof, now)
                            .map_err(io::Error::other)?;
                        self.configuration = Some(config.clone());
                    }
                    _ => {
                        if bundle.is_some() || configuration.is_some() {
                            return Err(invalid("unexpected M15 role payload"));
                        }
                        self.authority
                            .accept(&metadata, &proof, now)
                            .map_err(io::Error::other)?;
                    }
                }
                self.release_expiry
                    .insert(metadata.role, metadata.expires_at);
            }
        }
        Ok(())
    }

    pub fn check_root_time(&self, now: u64) -> Result<Validity> {
        let window = Validity {
            not_before: self.index.time_floor,
            expires_at: self.root_expires_at,
        };
        window.check(now)?;
        Ok(window)
    }

    pub fn record_window(&self, record: &Record, now: u64) -> Result<Validity> {
        let mut window = self.check_root_time(now)?;
        window.not_before = record.observed_at();
        match record {
            Record::Publication(value) => match &value.publication {
                Publication::RootRotation { .. } => {}
                Publication::Release { metadata, .. } => {
                    self.check_role(
                        super::proof_wire::role(metadata.role)?,
                        metadata.content,
                        now,
                    )?;
                    window.expires_at = window.expires_at.min(metadata.expires_at);
                }
            },
            Record::Installation(value) => {
                self.check_role(Role::NodeSoftware, value.bundle, now)?;
                window.expires_at = window.expires_at.min(
                    *self
                        .release_expiry
                        .get(&Role::NodeSoftware)
                        .ok_or_else(|| invalid("M15 installation lifetime"))?,
                );
            }
            Record::LaunchAttempt(value) => {
                window.expires_at = self
                    .current_contract(&value.contract, now)?
                    .expires_at
                    .min(value.expires_at);
            }
            Record::Claim(value) => {
                let attempt = self
                    .attempts
                    .get(&value.attempt)
                    .ok_or_else(|| invalid("M15 claim attempt"))?;
                window.expires_at = self
                    .current_contract(&attempt.contract, now)?
                    .expires_at
                    .min(attempt.expires_at);
            }
        }
        window.check(now)?;
        Ok(window)
    }

    pub fn check_role(&self, role: Role, content: Digest32, now: u64) -> Result<()> {
        if now < self.index.time_floor {
            return Err(invalid("M15 owner trusted clock below retained floor"));
        }
        self.authority
            .check_current(role, content, self.index.kernel_checkpoint, now)
            .map_err(io::Error::other)
    }

    pub fn current_contract(&self, contract: &Contract, now: u64) -> Result<Validity> {
        let policy = self
            .configuration
            .as_ref()
            .ok_or_else(|| invalid("missing M15 current configuration"))?;
        if &policy.contract != contract {
            return Err(invalid("M15 exact current execution contract"));
        }
        let bundle = self
            .bundle
            .as_ref()
            .ok_or_else(|| invalid("M15 full current bundle missing"))?;
        let artifact = bundle
            .artifacts
            .iter()
            .find(|v| v.logical_name == contract.artifact_name)
            .ok_or_else(|| invalid("M15 exact contract artifact missing"))?;
        if bundle.bundle_digest != contract.node_bundle
            || artifact.content_digest != contract.program_sha256
            || artifact.size_bytes != contract.program_size
            || artifact.platform_digest != contract.platform_digest
            || !artifact.executable
        {
            return Err(invalid(
                "M15 bundle/artifact/platform/configuration cross-binding",
            ));
        }
        self.check_role(Role::NodeSoftware, contract.node_bundle, now)?;
        self.check_role(Role::ProtocolConfiguration, policy.digest()?, now)?;
        Ok(Validity {
            not_before: now,
            expires_at: self
                .root_expires_at
                .min(
                    *self
                        .release_expiry
                        .get(&Role::NodeSoftware)
                        .ok_or_else(|| invalid("M15 Node lifetime"))?,
                )
                .min(
                    *self
                        .release_expiry
                        .get(&Role::ProtocolConfiguration)
                        .ok_or_else(|| invalid("M15 configuration lifetime"))?,
                ),
        })
    }

    fn apply_installation(&mut self, digest: Digest32, value: Installation) -> Result<()> {
        self.check_role(Role::NodeSoftware, value.bundle, value.observed_at)?;
        let bundle = self
            .bundle
            .as_ref()
            .ok_or_else(|| invalid("M15 missing installed bundle"))?;
        let artifact = bundle
            .artifacts
            .iter()
            .find(|v| v.logical_name == value.artifact_name)
            .ok_or_else(|| invalid("M15 installed artifact absent from actual bundle"))?;
        if value.schema_version != 1
            || self.installations.len() >= MAX_LAUNCH_RECORDS
            || value.kernel_checkpoint != self.authority.checkpoint()
            || value.bundle != bundle.bundle_digest
            || value.program_sha256 != artifact.content_digest
            || value.source_identity.size != artifact.size_bytes
            || value.source_identity.inode == 0
            || !artifact.executable
        {
            return Err(invalid("M15 installed object/bundle binding"));
        }
        self.installations.insert(digest, value);
        Ok(())
    }

    fn apply_attempt(&mut self, digest: Digest32, value: LaunchAttempt) -> Result<()> {
        value.validate_arguments()?;
        let window = self.current_contract(&value.contract, value.observed_at)?;
        let installation = self
            .installations
            .get(&value.installation)
            .ok_or_else(|| invalid("M15 launch has no retained actual installation"))?;
        if self.attempts.len() >= MAX_LAUNCH_RECORDS
            || value.policy_digest
                != self
                    .configuration
                    .as_ref()
                    .ok_or_else(|| invalid("M15 policy"))?
                    .digest()?
            || value.kernel_checkpoint != self.authority.checkpoint()
            || value.root_digest != self.authority.root_digest()
            || value.root_generation != self.authority.root_generation()
            || value.expires_at > window.expires_at
            || installation.bundle != value.contract.node_bundle
            || installation.program_sha256 != value.contract.program_sha256
            || installation.artifact_name != value.contract.artifact_name
            || self
                .attempts
                .values()
                .any(|old| old.nonce == value.nonce || old.process == value.process)
        {
            return Err(invalid("M15 exact one-shot launch attempt"));
        }
        self.attempts.insert(digest, value);
        Ok(())
    }

    pub fn pending_attempt(&self, digest: Digest32, now: u64) -> Result<&LaunchAttempt> {
        let attempt = self
            .attempts
            .get(&digest)
            .ok_or_else(|| invalid("M15 missing retained launch attempt"))?;
        self.current_contract(&attempt.contract, now)?;
        if self.claims.contains(&digest)
            || now >= attempt.expires_at
            || now < attempt.observed_at
            || attempt.root_digest != self.authority.root_digest()
            || attempt.root_generation != self.authority.root_generation()
            || attempt.kernel_checkpoint != self.authority.checkpoint()
            || self
                .configuration
                .as_ref()
                .ok_or_else(|| invalid("M15 current policy"))?
                .digest()?
                != attempt.policy_digest
        {
            return Err(invalid(
                "M15 launch attempt epoch/expiry/consumption changed",
            ));
        }
        Ok(attempt)
    }

    fn apply_claim(&mut self, value: Claim) -> Result<()> {
        let attempt = self
            .attempts
            .get(&value.attempt)
            .ok_or_else(|| invalid("M15 unknown launch claim"))?;
        self.current_contract(&attempt.contract, value.observed_at)?;
        if value.schema_version != 1
            || value.process != attempt.process
            || value.observed_at >= attempt.expires_at
            || attempt.root_digest != self.authority.root_digest()
            || attempt.root_generation != self.authority.root_generation()
            || attempt.kernel_checkpoint != self.authority.checkpoint()
            || value.kernel_checkpoint != self.authority.checkpoint()
            || self.claims.contains(&value.attempt)
            || self
                .configuration
                .as_ref()
                .ok_or_else(|| invalid("M15 policy"))?
                .digest()?
                != attempt.policy_digest
        {
            return Err(invalid(
                "M15 claim replay, expiry, or current-identity mismatch",
            ));
        }
        // This consumes a reservation before Node open. It never asserts that
        // exec or Node open completed, and cannot authorize another launch.
        self.claims.insert(value.attempt);
        Ok(())
    }
}
