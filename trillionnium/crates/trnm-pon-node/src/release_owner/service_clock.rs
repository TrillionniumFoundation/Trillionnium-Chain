//! The service consumes an independently authenticated clock; never SystemTime.
use super::frontier::{invalid, Digest32, Result};
use super::service_configuration::{self, Clock};
use super::trust_wire as wire;
use std::time::Instant;
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};

pub(super) struct ClockClient {
    configuration: Clock,
    namespace: Digest32,
    requester: PqNativeSigningKey,
    verifier: PqNativeVerifier,
    floor: u64,
    contract: super::clock_contract::Contract,
}
impl ClockClient {
    pub fn connect(
        configuration: Clock,
        namespace: Digest32,
        floor: u64,
        contract: super::clock_contract::Contract,
    ) -> Result<Self> {
        contract.validate()?;
        let verifier = service_configuration::verifier(
            &configuration.server_spki_hex,
            configuration.server_key_id,
        )?;
        let requester = PqNativeSigningKey::from_owned_seed(
            super::protected::read_seed(&configuration.requester_seed)?,
            configuration.requester_key_id,
        )
        .map_err(std::io::Error::other)?;
        Ok(Self {
            configuration,
            namespace,
            requester,
            verifier,
            floor,
            contract,
        })
    }
    pub fn now(&mut self, until: Instant) -> Result<super::clock_contract::Sample> {
        let ticket = self.contract.begin()?;
        let mut challenge = [0; 32];
        let mut filled = 0;
        while filled < challenge.len() {
            if Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            let count = rustix::rand::getrandom(
                &mut challenge[filled..],
                rustix::rand::GetRandomFlags::NONBLOCK,
            )?;
            if count == 0 {
                return Err(invalid("M15 service clock challenge unavailable"));
            }
            filled += count;
        }
        if challenge == [0; 32] {
            return Err(invalid("M15 clock challenge zero"));
        }
        let request = wire::Request {
            schema_version: 1,
            operation: wire::Operation::Clock,
            binding: self.configuration.binding,
            namespace: self.namespace,
            challenge,
            expected: None,
            next: None,
            validity: None,
        };
        let raw = wire::sign(wire::REQUEST, request, &self.requester)?;
        let reply = super::unix_transport::exchange(&self.configuration.socket, &raw, until)?;
        let value: wire::Reply = wire::verify(wire::CLOCK_REPLY, &reply, &self.verifier)?;
        if Instant::now() >= until {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        if value.schema_version != 1
            || value.request != wire::request_digest(&raw)
            || value.challenge != challenge
            || value.operation != wire::Operation::Clock
            || value.namespace != self.namespace
            || !value.accepted
            || value.frontier.is_some()
            || value.now_seconds < self.floor
        {
            return Err(invalid("M15 independent signed clock binding/floor"));
        }
        self.floor = value.now_seconds;
        let sample = ticket.authenticated(value.now_seconds);
        sample.check_fresh()?;
        Ok(sample)
    }
}
