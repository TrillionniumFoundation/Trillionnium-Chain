//! A separate protected UID/namespace owns this linearizable M15 register.
//! One held file lock serializes CAS; atomically installed/fsynced canonical
//! rows complete a previously admitted decision. Admission is under this same
//! exclusive owner, after preparation and a conservative exact-window check.
//! No response or subsequent request precedes durable completion.
//! On reopen the complete head/floor must match independent pre-stop pins.
use super::files::Files;
use super::frontier::{invalid, Digest32, Frontier, Result};
use super::service_configuration::Configuration;
use super::trust_wire::{Operation, Request};
use serde::{Deserialize, Serialize};

const ROW: &str = "independent-frontier.json";
const MAX_ROW: usize = 65536;
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    schema_version: u32,
    namespace: Digest32,
    service_configuration: Digest32,
    frontier: Option<Frontier>,
    time_floor: u64,
}

pub(super) struct Store {
    files: Files,
    row: Row,
    exact: Vec<u8>,
    fenced: bool,
}
impl Store {
    pub fn initialize(configuration: &Configuration, now: u64) -> Result<Self> {
        if configuration.expected_frontier.is_some() || configuration.expected_time_floor != 0 {
            return Err(invalid(
                "M15 service initialize requires independently new namespace",
            ));
        }
        let files = Files::create(&configuration.directory)?;
        let row = Row {
            schema_version: 1,
            namespace: configuration.namespace,
            service_configuration: configuration.core_digest()?,
            frontier: None,
            time_floor: now,
        };
        let exact = super::codec::encode(&row, MAX_ROW)?;
        files.write(ROW, &exact)?;
        Ok(Self {
            files,
            row,
            exact,
            fenced: false,
        })
    }
    pub fn open(configuration: &Configuration) -> Result<Self> {
        let files = Files::open(&configuration.directory)?;
        let exact = files
            .read(ROW, MAX_ROW)?
            .ok_or_else(|| invalid("M15 service missing existing row"))?;
        let row: Row = super::codec::decode(&exact, MAX_ROW)?;
        if row.schema_version != 1
            || row.namespace != configuration.namespace
            || row.service_configuration != configuration.core_digest()?
            || row.frontier != configuration.expected_frontier
            || row.time_floor != configuration.expected_time_floor
        {
            return Err(invalid("M15 service independent reopen head/floor binding"));
        }
        if let Some(frontier) = &row.frontier {
            frontier.validate(row.namespace)?;
        }
        Ok(Self {
            files,
            row,
            exact,
            fenced: false,
        })
    }
    pub fn fence(&mut self) {
        self.fenced = true;
    }
    pub fn recheck(&mut self) -> Result<()> {
        if self.fenced {
            return Err(invalid("M15 service is fenced"));
        }
        let result = (|| {
            self.files.revalidate()?;
            if self.files.read(ROW, MAX_ROW)?.as_deref() != Some(self.exact.as_slice()) {
                return Err(invalid("M15 service durable head changed"));
            }
            self.files.revalidate()
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
    pub fn head(&self) -> Result<(Option<Frontier>, u64)> {
        if self.fenced {
            return Err(invalid("M15 service is fenced"));
        }
        Ok((self.row.frontier.clone(), self.row.time_floor))
    }

    /// A fresh signed sample is a lower observation, not the decision's time.
    /// Prepare/fsync and every callback precede the final BOOTTIME interval.
    /// Once admitted, completion may cross expiry; uncertainty fences this owner.
    pub fn decide(
        &mut self,
        request: &Request,
        sample: &super::clock_contract::Sample,
        until: std::time::Instant,
        check_provisioning: impl FnOnce() -> Result<()>,
    ) -> Result<bool> {
        self.recheck()?;
        let result = (|| {
            let now = sample.floor_seconds();
            if now < self.row.time_floor || request.namespace != self.row.namespace {
                return Err(invalid("M15 service trusted floor/namespace"));
            }
            let mut next = self.row.clone();
            next.time_floor = now;
            let accepted = match request.operation {
                Operation::Load => {
                    if request.expected.is_some()
                        || request.next.is_some()
                        || request.validity.is_some()
                    {
                        return Err(invalid("M15 load has unexpected mutation fields"));
                    }
                    true
                }
                Operation::CompareAndSet => {
                    let proposal = request
                        .next
                        .as_ref()
                        .ok_or_else(|| invalid("M15 CAS missing proposal"))?;
                    let validity = request
                        .validity
                        .ok_or_else(|| invalid("M15 CAS missing exact window"))?;
                    proposal.validate(self.row.namespace)?;
                    let (generation, previous) = if let Some(old) = &request.expected {
                        old.validate(self.row.namespace)?;
                        (
                            old.generation
                                .checked_add(1)
                                .ok_or_else(|| invalid("M15 service generation exhausted"))?,
                            old.digest()?,
                        )
                    } else {
                        (1, [0; 32])
                    };
                    if proposal.generation != generation || proposal.previous != previous {
                        return Err(invalid("M15 CAS is not the exact immediate successor"));
                    }
                    validity.check(now)?;
                    if request.expected == self.row.frontier {
                        next.frontier = Some(proposal.clone());
                        true
                    } else {
                        false
                    }
                }
                Operation::Clock => {
                    return Err(invalid("M15 frontier service is not a clock authority"))
                }
            };
            let bytes = super::codec::encode(&next, MAX_ROW)?;
            let prepared = self.files.prepare_atomic(ROW, &bytes)?;
            #[cfg(test)]
            super::service_faults::hit(super::service_faults::Point::Prepared)?;
            check_provisioning()?;
            prepared.recheck()?;
            if self.files.read(ROW, MAX_ROW)?.as_deref() != Some(self.exact.as_slice()) {
                return Err(invalid("M15 service old head changed during preparation"));
            }
            self.files.revalidate()?;
            if std::time::Instant::now() >= until {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            if let Some(window) = request.validity {
                sample.check(window)?;
            } else {
                sample.check_fresh()?;
            }
            // Linearization: exact old/proposal and conservative current interval
            // are accepted under the sole owner. No remote call, preparation or
            // arbitrary callback follows; only durable completion below.
            self.fenced = true;
            #[cfg(test)]
            super::service_faults::admitted(
                request.operation == Operation::CompareAndSet && accepted,
            )?;
            prepared.publish_after_admission()?;
            #[cfg(test)]
            super::service_faults::hit(super::service_faults::Point::Published)?;
            self.row = next;
            self.exact = bytes;
            self.fenced = false;
            self.recheck()?;
            Ok(accepted)
        })();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }
}
