//! Production construction uses only protected pins and authenticated services.
use super::frontier::{hash, invalid, Digest32, ExternalM15Authority, Frontier, Result, Validity};
use super::{proof_wire, protected, trust_wire as wire, unix_transport};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};
use trnm_protocol::pq_frame::ML_DSA_65_SPKI_BYTES;
use trnm_release_bundle::pq_release::PqReleaseRootV1;

const MAX_CONFIGURATION_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Endpoint {
    pub socket: PathBuf,
    pub key_id: Digest32,
    pub spki_hex: String,
}

impl Endpoint {
    fn verifier(&self) -> Result<PqNativeVerifier> {
        if !self.socket.is_absolute() || self.spki_hex.len() != 2 * ML_DSA_65_SPKI_BYTES {
            return Err(invalid("M15 protected endpoint shape"));
        }
        let spki = hex::decode(&self.spki_hex).map_err(io::Error::other)?;
        if hex::encode(&spki) != self.spki_hex {
            return Err(invalid("M15 endpoint key encoding"));
        }
        PqNativeVerifier::from_pinned_spki(&spki, self.key_id).map_err(io::Error::other)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub schema_version: u32,
    pub profile: String,
    pub namespace: Digest32,
    pub initial_root: PathBuf,
    pub initial_root_file_sha256: Digest32,
    pub initial_root_digest: Digest32,
    pub clock: Endpoint,
    pub clock_contract: super::clock_contract::Contract,
    pub frontier: Endpoint,
    pub writer_key_id: Digest32,
    pub writer_seed: PathBuf,
    pub required_packages: Vec<(String, String)>,
}

/// These are live clients, not supplied clock values or cached permissions.
/// Each new owner must construct its own instance from independently pinned
/// configuration. The public entry never accepts a trait object from a caller.
pub(super) struct SignedAuthorityClient {
    pub config: Configuration,
    pub initial_root: PqReleaseRootV1,
    config_pin: Digest32,
    binding: Digest32,
    writer: PqNativeSigningKey,
    clock: PqNativeVerifier,
    frontier: PqNativeVerifier,
    floor: u64,
    last_frontier: Option<Option<Frontier>>,
    unavailable: bool,
    clock_sample: Option<super::clock_contract::Sample>,
}

impl SignedAuthorityClient {
    pub fn from_protected(path: &Path, independent_config_pin: Digest32) -> Result<Self> {
        let raw = protected::read_pinned(path, MAX_CONFIGURATION_BYTES, independent_config_pin)?;
        let config: Configuration = super::codec::decode(&raw, MAX_CONFIGURATION_BYTES)?;
        if config.schema_version != 1
            || config.profile != "trnm-m15-owner-trust-v1"
            || config.namespace == [0; 32]
            || config.initial_root_digest == [0; 32]
            || config.required_packages.is_empty()
            || config.required_packages.len() > trnm_release_bundle::MAX_PACKAGES_V0
        {
            return Err(invalid("M15 complete protected configuration required"));
        }
        for (index, (name, version)) in config.required_packages.iter().enumerate() {
            if name.is_empty()
                || name.len() > trnm_release_bundle::MAX_NAME_BYTES_V0
                || version.is_empty()
                || version.len() > trnm_release_bundle::MAX_VERSION_BYTES_V0
                || !name
                    .bytes()
                    .chain(version.bytes())
                    .all(|b| (0x20..=0x7e).contains(&b))
                || (index > 0
                    && config.required_packages[index - 1] >= config.required_packages[index])
            {
                return Err(invalid(
                    "M15 required package set must be complete, bounded, sorted and unique",
                ));
            }
        }
        config.clock_contract.validate()?;
        let clock = config.clock.verifier()?;
        let frontier = config.frontier.verifier()?;
        if config.clock.key_id == config.frontier.key_id
            || config.writer_key_id == config.clock.key_id
            || config.writer_key_id == config.frontier.key_id
        {
            return Err(invalid(
                "M15 writer, clock and witness keys must be independent",
            ));
        }
        let root_raw = protected::read_pinned(
            &config.initial_root,
            1048576,
            config.initial_root_file_sha256,
        )?;
        let root: proof_wire::Root = serde_json::from_slice(&root_raw).map_err(io::Error::other)?;
        if serde_json::to_vec(&root)
            .map_err(io::Error::other)?
            .as_slice()
            != root_raw.as_slice()
        {
            return Err(invalid("M15 initial root is not canonical"));
        }
        let initial_root = root.kernel()?;
        if initial_root.digest().map_err(io::Error::other)? != config.initial_root_digest
            || initial_root.generation != 1
            || initial_root.previous_root_digest != [0; 32]
        {
            return Err(invalid("M15 independent complete initial root pin"));
        }
        let service_keys = [
            config.clock.key_id,
            config.frontier.key_id,
            config.writer_key_id,
        ];
        super::root_separation::require(&initial_root, &service_keys)?;
        let writer = PqNativeSigningKey::from_owned_seed(
            protected::read_seed(&config.writer_seed)?,
            config.writer_key_id,
        )
        .map_err(io::Error::other)?;
        let binding = hash(
            b"TRNM/M15/ProtectedOwner/Binding/v1\0",
            &wire::canonical(&(
                config.namespace,
                config.initial_root_digest,
                config.clock.key_id,
                config.frontier.key_id,
                config.writer_key_id,
                &config.clock_contract,
            ))?,
        );
        Ok(Self {
            config,
            initial_root,
            config_pin: independent_config_pin,
            binding,
            writer,
            clock,
            frontier,
            floor: 0,
            last_frontier: None,
            unavailable: false,
            clock_sample: None,
        })
    }

    pub fn config_pin(&self) -> Digest32 {
        self.config_pin
    }

    pub fn require_current_window(&mut self, validity: Validity) -> Result<()> {
        if self.unavailable {
            return Err(invalid("M15 signed client is fenced"));
        }
        let result = (|| {
            let sample = self
                .clock_sample
                .as_ref()
                .ok_or_else(|| invalid("M15 fresh signed clock sample missing"))?;
            if sample.floor_seconds() != self.floor {
                return Err(invalid("M15 newer observed floor requires a fresh clock"));
            }
            sample.check(validity)
        })();
        if result.is_err() {
            self.unavailable = true;
        }
        result
    }

    fn call(
        &mut self,
        operation: wire::Operation,
        expected: Option<&Frontier>,
        next: Option<&Frontier>,
        validity: Option<Validity>,
    ) -> Result<wire::Reply> {
        if self.unavailable {
            return Err(invalid("M15 signed client is fenced"));
        }
        let result = self.call_inner(operation, expected, next, validity);
        if result.is_err() {
            self.unavailable = true;
        }
        result
    }

    fn call_inner(
        &mut self,
        operation: wire::Operation,
        expected: Option<&Frontier>,
        next: Option<&Frontier>,
        validity: Option<Validity>,
    ) -> Result<wire::Reply> {
        let until = Instant::now()
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| invalid("M15 service deadline overflow"))?;
        // Start before nonce creation/request signing; the authenticated server
        // sample therefore cannot predate this BOOTTIME lower endpoint.
        let ticket = self.config.clock_contract.begin()?;
        let mut challenge = [0; 32];
        let mut filled = 0;
        while filled < challenge.len() {
            if Instant::now() >= until {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let count = rustix::rand::getrandom(
                &mut challenge[filled..],
                rustix::rand::GetRandomFlags::NONBLOCK,
            )?;
            if count == 0 {
                return Err(invalid("M15 challenge generation failed"));
            }
            filled += count;
        }
        if challenge == [0; 32] {
            return Err(invalid("M15 zero challenge"));
        }
        let request = wire::Request {
            schema_version: 1,
            operation,
            binding: self.binding,
            namespace: self.config.namespace,
            challenge,
            expected: expected.cloned(),
            next: next.cloned(),
            validity,
        };
        let raw = wire::sign(wire::REQUEST, request, &self.writer)?;
        let (endpoint, key, domain) = if operation == wire::Operation::Clock {
            (&self.config.clock.socket, &self.clock, wire::CLOCK_REPLY)
        } else {
            (
                &self.config.frontier.socket,
                &self.frontier,
                wire::FRONTIER_REPLY,
            )
        };
        let answer = unix_transport::exchange(endpoint, &raw, until)?;
        let reply: wire::Reply = wire::verify(domain, &answer, key)?;
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if reply.schema_version != 1
            || reply.request != wire::request_digest(&raw)
            || reply.challenge != challenge
            || reply.operation != operation
            || reply.namespace != self.config.namespace
            || !reply.accepted
            || reply.now_seconds < self.floor
        {
            return Err(invalid(
                "M15 signed response binding, rejection, or clock rollback",
            ));
        }
        if operation == wire::Operation::Clock {
            if reply.frontier.is_some() {
                return Err(invalid("clock response contains a frontier"));
            }
        } else {
            if let Some(value) = &reply.frontier {
                value.validate(self.config.namespace)?;
            }
            if let Some(Some(old)) = &self.last_frontier {
                let current = reply
                    .frontier
                    .as_ref()
                    .ok_or_else(|| invalid("M15 frontier disappeared"))?;
                if current.generation < old.generation
                    || (current.generation == old.generation && current != old)
                {
                    return Err(invalid("M15 external frontier regressed or equivocated"));
                }
            }
            self.last_frontier = Some(reply.frontier.clone());
        }
        let sample = ticket.authenticated(reply.now_seconds);
        sample.check_fresh()?;
        if operation == wire::Operation::Clock {
            self.clock_sample = Some(sample);
        }
        self.floor = reply.now_seconds;
        Ok(reply)
    }
}

impl ExternalM15Authority for SignedAuthorityClient {
    fn now_seconds(&mut self) -> Result<u64> {
        Ok(self
            .call(wire::Operation::Clock, None, None, None)?
            .now_seconds)
    }

    fn load(&mut self, namespace: Digest32) -> Result<Option<Frontier>> {
        if namespace != self.config.namespace {
            return Err(invalid("M15 client namespace mismatch"));
        }
        Ok(self.call(wire::Operation::Load, None, None, None)?.frontier)
    }

    fn compare_and_set(
        &mut self,
        expected: Option<&Frontier>,
        next: &Frontier,
        validity: Validity,
    ) -> Result<()> {
        next.validate(self.config.namespace)?;
        if let Some(old) = expected {
            old.validate(self.config.namespace)?;
        }
        let reply = self.call(
            wire::Operation::CompareAndSet,
            expected,
            Some(next),
            Some(validity),
        )?;
        let result = validity.check(reply.now_seconds).and_then(|_| {
            if reply.frontier.as_ref() != Some(next) {
                Err(invalid("M15 CAS did not return exact proposal"))
            } else {
                Ok(())
            }
        });
        if result.is_err() {
            self.unavailable = true;
        }
        result
    }
}
