//! Exact, opt-in funded service contract bytes. These are signed commitments to
//! terms, not proof of independent customers, useful outputs or fair arbitration.
//! The output specification is known at reservation; the actual output is bound
//! only by the later provider receipt and, when needed, the frozen arbiter.
use crate::pon_wire::{hash, Hash, WireError};
use serde::{Deserialize, Serialize};

pub const RESERVATION_MAGIC: [u8; 4] = *b"TSC1";
pub const DECISION_MAGIC: [u8; 4] = *b"TSD1";
pub const RESERVATION_BYTES: usize = 380;
pub const DECISION_BYTES: usize = 133;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundedServiceContractV1 {
    pub request: Hash,
    pub provider: Hash,
    pub model: Hash,
    pub input: Hash,
    pub output_spec: Hash,
    pub qualified_work: Hash,
    pub evaluation_protocol: Hash,
    pub fee_schedule: Hash,
    pub dispute_policy: Hash,
    pub arbitrator: Hash,
    pub budget: u64,
    /// Provider receipts are permitted through this height, inclusive.
    pub delivery_deadline: u64,
    /// Decisions and customer acceptance must precede this height. The existing
    /// mandatory expiry owner returns any unresolved escrow at this height.
    pub dispute_deadline: u64,
}

impl FundedServiceContractV1 {
    fn commitments(&self) -> [Hash; 10] {
        [
            self.request,
            self.provider,
            self.model,
            self.input,
            self.output_spec,
            self.qualified_work,
            self.evaluation_protocol,
            self.fee_schedule,
            self.dispute_policy,
            self.arbitrator,
        ]
    }

    pub fn validate(&self) -> Result<(), WireError> {
        if self.commitments().contains(&[0; 32])
            || self.budget == 0
            || self.delivery_deadline == 0
            || self.dispute_deadline <= self.delivery_deadline
            || self.arbitrator == self.provider
        {
            return Err(WireError::Noncanonical);
        }
        Ok(())
    }

    fn terms_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(344);
        for value in self.commitments() {
            bytes.extend(value);
        }
        bytes.extend(self.budget.to_le_bytes());
        bytes.extend(self.delivery_deadline.to_le_bytes());
        bytes.extend(self.dispute_deadline.to_le_bytes());
        bytes
    }

    pub fn digest(&self, network: Hash, parameters: Hash, payer: Hash) -> Hash {
        hash(
            b"funded-service-contract-v1",
            &[&network, &parameters, &payer, &self.terms_bytes()],
        )
    }

    pub fn task_id(&self, network: Hash, parameters: Hash, payer: Hash, nonce: u64) -> Hash {
        hash(
            b"funded-service-task-instance-v1",
            &[
                &network,
                &parameters,
                &payer,
                &nonce.to_le_bytes(),
                &self.digest(network, parameters, payer),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedServiceReservationV1 {
    pub task: Hash,
    pub contract: FundedServiceContractV1,
}

impl FundedServiceReservationV1 {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        self.contract.validate()?;
        if self.task == [0; 32] {
            return Err(WireError::Noncanonical);
        }
        let mut bytes = Vec::with_capacity(RESERVATION_BYTES);
        bytes.extend(RESERVATION_MAGIC);
        bytes.extend(self.task);
        bytes.extend(self.contract.terms_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != RESERVATION_BYTES {
            return Err(WireError::Length);
        }
        let mut reader = Reader { bytes, pos: 0 };
        if reader.take::<4>()? != RESERVATION_MAGIC {
            return Err(WireError::Version);
        }
        let value = Self {
            task: reader.take()?,
            contract: FundedServiceContractV1 {
                request: reader.take()?,
                provider: reader.take()?,
                model: reader.take()?,
                input: reader.take()?,
                output_spec: reader.take()?,
                qualified_work: reader.take()?,
                evaluation_protocol: reader.take()?,
                fee_schedule: reader.take()?,
                dispute_policy: reader.take()?,
                arbitrator: reader.take()?,
                budget: reader.number()?,
                delivery_deadline: reader.number()?,
                dispute_deadline: reader.number()?,
            },
        };
        value.contract.validate()?;
        if value.task == [0; 32] {
            return Err(WireError::Noncanonical);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundedServiceVerdictV1 {
    PayProvider,
    RefundPayer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedServiceDecisionV1 {
    pub task: Hash,
    pub contract_digest: Hash,
    /// Zero is permitted only for a refund before any provider receipt.
    pub output: Hash,
    pub evidence: Hash,
    pub verdict: FundedServiceVerdictV1,
}

impl FundedServiceDecisionV1 {
    fn validate(&self) -> Result<(), WireError> {
        if self.task == [0; 32]
            || self.contract_digest == [0; 32]
            || self.evidence == [0; 32]
            || (self.verdict == FundedServiceVerdictV1::PayProvider && self.output == [0; 32])
        {
            return Err(WireError::Noncanonical);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(DECISION_BYTES);
        bytes.extend(DECISION_MAGIC);
        for value in [self.task, self.contract_digest, self.output, self.evidence] {
            bytes.extend(value);
        }
        bytes.push(match self.verdict {
            FundedServiceVerdictV1::PayProvider => 1,
            FundedServiceVerdictV1::RefundPayer => 2,
        });
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != DECISION_BYTES {
            return Err(WireError::Length);
        }
        let mut reader = Reader { bytes, pos: 0 };
        if reader.take::<4>()? != DECISION_MAGIC {
            return Err(WireError::Version);
        }
        let value = Self {
            task: reader.take()?,
            contract_digest: reader.take()?,
            output: reader.take()?,
            evidence: reader.take()?,
            verdict: match reader.take::<1>()?[0] {
                1 => FundedServiceVerdictV1::PayProvider,
                2 => FundedServiceVerdictV1::RefundPayer,
                _ => return Err(WireError::Noncanonical),
            },
        };
        value.validate()?;
        Ok(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self.pos.checked_add(N).ok_or(WireError::Length)?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(WireError::Length)?
            .try_into()
            .map_err(|_| WireError::Length)?;
        self.pos = end;
        Ok(value)
    }
    fn number(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> FundedServiceContractV1 {
        FundedServiceContractV1 {
            request: [1; 32],
            provider: [2; 32],
            model: [3; 32],
            input: [4; 32],
            output_spec: [5; 32],
            qualified_work: [6; 32],
            evaluation_protocol: [7; 32],
            fee_schedule: [8; 32],
            dispute_policy: [9; 32],
            arbitrator: [10; 32],
            budget: 2_000,
            delivery_deadline: 12,
            dispute_deadline: 20,
        }
    }

    #[test]
    fn exact_reservation_bytes_and_every_term_binding() {
        let contract = contract();
        let context = ([20; 32], [21; 32], [22; 32]);
        let task = contract.task_id(context.0, context.1, context.2, 1);
        assert_eq!(
            hex::encode(contract.digest(context.0, context.1, context.2)),
            "665bae88cf42e5a697ad91c84678cb439771d9b9eb9bf5524e8d85e46d805277"
        );
        assert_eq!(
            hex::encode(task),
            "4892e76755db0d7e0b4769dc52c8d8f70d641aa2450fb072676cb843f158acec"
        );
        let reservation = FundedServiceReservationV1 { task, contract };
        let encoded = reservation.encode().unwrap();
        {
            use sha2::{Digest, Sha256};
            assert_eq!(
                hex::encode(Sha256::digest(&encoded)),
                "fed2bf65bf4b6711f5cc1974b48943b14a97116a2f1c1bd45c134e536bf53953"
            );
        }
        assert_eq!(encoded.len(), RESERVATION_BYTES);
        assert_eq!(
            FundedServiceReservationV1::decode(&encoded).unwrap(),
            reservation
        );
        assert_eq!(&encoded[..4], b"TSC1");
        assert_eq!(&encoded[4..36], &task);
        assert_eq!(&encoded[356..364], &2_000_u64.to_le_bytes());
        for offset in (36..356).step_by(32).chain([356, 364, 372]) {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            let changed = FundedServiceReservationV1::decode(&changed).unwrap();
            assert_ne!(
                changed.contract.task_id(context.0, context.1, context.2, 1),
                task
            );
        }
        for (network, parameters, payer, nonce) in [
            ([23; 32], context.1, context.2, 1),
            (context.0, [23; 32], context.2, 1),
            (context.0, context.1, [23; 32], 1),
            (context.0, context.1, context.2, 2),
        ] {
            assert_ne!(
                reservation
                    .contract
                    .task_id(network, parameters, payer, nonce),
                task
            );
        }
        for len in [0, 80, RESERVATION_BYTES - 1, RESERVATION_BYTES + 1] {
            assert_eq!(
                FundedServiceReservationV1::decode(&vec![0; len]),
                Err(WireError::Length)
            );
        }
        let mut bad = encoded;
        bad[0] = b'X';
        assert_eq!(
            FundedServiceReservationV1::decode(&bad),
            Err(WireError::Version)
        );
    }

    #[test]
    fn decisions_have_no_ambiguous_verdict_or_predicted_output() {
        let mut decision = FundedServiceDecisionV1 {
            task: [1; 32],
            contract_digest: [2; 32],
            output: [3; 32],
            evidence: [4; 32],
            verdict: FundedServiceVerdictV1::PayProvider,
        };
        let bytes = decision.encode().unwrap();
        assert_eq!(bytes.len(), DECISION_BYTES);
        assert_eq!(FundedServiceDecisionV1::decode(&bytes).unwrap(), decision);
        let mut bad = bytes.clone();
        bad[132] = 0;
        assert_eq!(
            FundedServiceDecisionV1::decode(&bad),
            Err(WireError::Noncanonical)
        );
        bad = bytes;
        bad.push(0);
        assert_eq!(
            FundedServiceDecisionV1::decode(&bad),
            Err(WireError::Length)
        );
        decision.output = [0; 32];
        assert_eq!(decision.encode(), Err(WireError::Noncanonical));
        decision.verdict = FundedServiceVerdictV1::RefundPayer;
        assert_eq!(
            FundedServiceDecisionV1::decode(&decision.encode().unwrap()).unwrap(),
            decision
        );
        decision.evidence = [0; 32];
        assert_eq!(decision.encode(), Err(WireError::Noncanonical));
    }

    #[test]
    fn every_native_pq_profile_keeps_its_original_task_grammar() {
        use crate::pq_native_accounts_v2::{
            encode_for_profile, AccountProfile, ChainContext, Common, Error,
        };
        let common = Common {
            context: ChainContext {
                network: [20; 32],
                parameters: [21; 32],
                genesis: [22; 32],
            },
            account: [23; 32],
            nonce: 1,
            expires_at: 100,
            max_fee: 10_000,
            generation: 1,
        };
        let reserve = FundedServiceReservationV1 {
            task: [30; 32],
            contract: contract(),
        }
        .encode()
        .unwrap();
        let decision = FundedServiceDecisionV1 {
            task: [30; 32],
            contract_digest: [31; 32],
            output: [32; 32],
            evidence: [33; 32],
            verdict: FundedServiceVerdictV1::PayProvider,
        }
        .encode()
        .unwrap();
        for profile in [
            AccountProfile::AccountsV2,
            AccountProfile::QuotaV3,
            AccountProfile::TasksV4,
            AccountProfile::TasksV5,
            AccountProfile::ApplicationV6,
        ] {
            for (tag, payload) in [(2, reserve.as_slice()), (5, decision.as_slice())] {
                // Rejection occurs in the selected payload grammar before the
                // missing witness list could be interpreted as authorization.
                assert_eq!(
                    encode_for_profile(profile, &common, tag, payload, &[], &[]),
                    Err(Error::Length),
                );
                // An old-size payload passes that grammar and reaches the
                // missing-witness rejection, which has a different error.
                assert_eq!(
                    encode_for_profile(
                        profile,
                        &common,
                        tag,
                        &vec![1; if tag == 2 { 80 } else { 64 }],
                        &[],
                        &[],
                    ),
                    Err(Error::Encoding),
                );
            }
        }
    }
}
