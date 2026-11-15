//! Real signed M15 service; storage errors and uncertain replies fence the owner.
use super::frontier::{invalid, Result};
use super::service_clock::ClockClient;
use super::service_configuration::{self, Configuration};
use super::service_store::Store;
use super::trust_wire as wire;
use std::time::{Duration, Instant};
use trnm_crypto_primitives::pq_auth::{PqNativeSigningKey, PqNativeVerifier};

pub(super) struct Service {
    configuration: Configuration,
    store: Store,
    clock: ClockClient,
    owner: PqNativeVerifier,
    signer: PqNativeSigningKey,
    fenced: bool,
}
impl Service {
    pub fn open(initialize: bool) -> Result<Self> {
        let configuration = Configuration::load()?;
        let signer = configuration.signer()?;
        let owner = service_configuration::verifier(
            &configuration.owner_spki_hex,
            configuration.owner_key_id,
        )?;
        let mut clock = ClockClient::connect(
            configuration.clock.clone(),
            configuration.namespace,
            configuration.expected_time_floor,
            configuration.clock_contract.clone(),
        )?;
        let now = clock.now(
            Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or_else(|| invalid("M15 service initialization deadline"))?,
        )?;
        configuration.revalidate()?;
        let store = if initialize {
            Store::initialize(&configuration, now.floor_seconds())?
        } else {
            Store::open(&configuration)?
        };
        let mut service = Self {
            configuration,
            store,
            clock,
            owner,
            signer,
            fenced: false,
        };
        service.store.recheck()?;
        now.check_fresh()?;
        Ok(service)
    }
    pub fn initialization(&self) -> Result<serde_json::Value> {
        let (frontier, time_floor) = self.store.head()?;
        Ok(
            serde_json::json!({"schema":"trnm-m15-independent-service-initialized-v1",
            "namespace":self.configuration.namespace, "frontier":frontier,
            "time_floor":time_floor, "service_binding":self.configuration.core_digest()?,
            "production_qualified":false,"execution_authorized":false}),
        )
    }
    pub fn fence(&mut self) {
        self.fenced = true;
        self.store.fence();
    }
    pub fn answer(&mut self, raw: &[u8], until: Instant) -> Result<Vec<u8>> {
        if self.fenced {
            return Err(invalid("M15 service is fenced"));
        }
        // Unauthenticated garbage cannot mutate/fence durable authority.
        let request: wire::Request = wire::verify(wire::REQUEST, raw, &self.owner)?;
        if request.schema_version != 1
            || request.binding != self.configuration.owner_binding
            || request.namespace != self.configuration.namespace
            || request.challenge == [0; 32]
            || request.operation == wire::Operation::Clock
        {
            return Err(invalid("M15 service exact owner/request domain"));
        }
        let result = (|| {
            if Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            self.configuration.revalidate()?;
            self.store.recheck()?;
            let now = self.clock.now(until)?;
            #[cfg(test)]
            super::service_faults::hit(super::service_faults::Point::Clock)?;
            // Both callbacks above may yield. Recheck provisioning and the exact
            // held local head inside decide before the service CAS decision.
            self.configuration.revalidate()?;
            if Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            let accepted = self
                .store
                .decide(&request, &now, until, || self.configuration.revalidate())?;
            let (frontier, _) = self.store.head()?;
            let reply = wire::Reply {
                schema_version: 1,
                request: wire::request_digest(raw),
                challenge: request.challenge,
                operation: request.operation,
                namespace: self.configuration.namespace,
                now_seconds: now.floor_seconds(),
                accepted,
                frontier,
            };
            let bytes = wire::sign(wire::FRONTIER_REPLY, reply, &self.signer)?;
            self.store.recheck()?;
            self.configuration.revalidate()?;
            if Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            Ok(bytes)
        })();
        if result.is_err() {
            self.fence();
        }
        result
    }
    pub fn serve(mut self) -> Result<()> {
        let socket = super::service_socket::Socket::bind(&self.configuration)?;
        loop {
            let (mut stream, _) = socket.accept()?;
            if rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw()
                != self.configuration.owner_uid
            {
                continue;
            }
            let until = Instant::now()
                .checked_add(Duration::from_secs(2))
                .ok_or_else(|| invalid("M15 service request deadline"))?;
            stream.set_nonblocking(true)?;
            let raw = match super::unix_transport::receive(&mut stream, until) {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let answer = match self.answer(&raw, until) {
                Ok(answer) => answer,
                Err(error) if self.fenced => return Err(error),
                Err(_) => continue,
            };
            socket.revalidate()?;
            if let Err(error) = super::unix_transport::send(&mut stream, &answer, until) {
                self.fence();
                return Err(error);
            }
        }
    }
}
