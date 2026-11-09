//! Typed native anchor protocol. Both directions require separate pinned quorums.
use super::{
    digest, map_error, require, JournalEnrollmentV3, JournalHeadV3, OwnerBudgetV3,
    RootOwnerResultV3,
};
use trnm_crypto_primitives::pq_root_v3::{DualFamilyRosterV3, RootSignatureV3};

const WRITER_DOMAIN: &[u8] = b"TRNM/RootOwner/AnchorWriter/v3\0";
const REQUEST_DOMAIN: &[u8] = b"TRNM/RootOwner/AnchorRequestDigest/v3\0";
const RECEIPT_DOMAIN: &[u8] = b"TRNM/RootOwner/AnchorReceipt/v3\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorOutcomeV3 {
    Current,
    Advanced,
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRequestV3 {
    pub scope: [u8; 64],
    pub challenge: [u8; 32],
    pub expected: Option<JournalHeadV3>,
    pub target: Option<JournalHeadV3>,
}
impl AnchorRequestV3 {
    fn fresh(
        scope: [u8; 64],
        expected: Option<JournalHeadV3>,
        target: Option<JournalHeadV3>,
    ) -> RootOwnerResultV3<Self> {
        let mut challenge = [0; 32];
        let filled =
            rustix::rand::getrandom(&mut challenge, rustix::rand::GetRandomFlags::NONBLOCK)?;
        require(
            filled == challenge.len(),
            "ROOT_ANCHOR_CHALLENGE_UNAVAILABLE",
        )?;
        let request = Self {
            scope,
            challenge,
            expected,
            target,
        };
        request.message()?;
        Ok(request)
    }
    pub fn message(&self) -> RootOwnerResultV3<Vec<u8>> {
        require(
            self.scope != [0; 64] && self.challenge != [0; 32],
            "ROOT_ANCHOR_REQUEST_IDENTITY",
        )?;
        let mut bytes = WRITER_DOMAIN.to_vec();
        bytes.extend(self.scope);
        bytes.extend(self.challenge);
        match (self.expected, self.target) {
            (None, None) => bytes.push(0),
            (Some(expected), Some(target)) => {
                expected.validate()?;
                target.validate()?;
                require(
                    expected.version.checked_add(1) == Some(target.version),
                    "ROOT_ANCHOR_REQUEST_SEQUENCE",
                )?;
                bytes.push(1);
                bytes.extend(expected.bytes());
                bytes.extend(target.bytes());
            }
            _ => return Err(super::rejected("ROOT_ANCHOR_REQUEST_SHAPE")),
        }
        Ok(bytes)
    }
    pub fn digest(&self) -> RootOwnerResultV3<[u8; 64]> {
        Ok(digest(REQUEST_DOMAIN, &[&self.message()?]))
    }
}

pub struct AnchorEnvelopeV3 {
    pub request: AnchorRequestV3,
    pub writer_approvals: Vec<RootSignatureV3>,
}
impl AnchorEnvelopeV3 {
    /// Anchor-side authentication. The expected scope and writer roster are
    /// provisioned out of band, never read from the request or caller journal.
    pub fn verify_writer(
        &self,
        expected_scope: [u8; 64],
        writer: &DualFamilyRosterV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        budget.check()?;
        require(
            self.request.scope == expected_scope,
            "ROOT_ANCHOR_WRITER_SCOPE",
        )?;
        writer
            .verify_quorum(
                &self.request.message()?,
                &self.writer_approvals,
                budget.verification(),
            )
            .map_err(map_error)?;
        budget.check()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorReceiptV3 {
    pub scope: [u8; 64],
    pub challenge: [u8; 32],
    pub request_digest: [u8; 64],
    pub head: JournalHeadV3,
    pub outcome: AnchorOutcomeV3,
}
impl AnchorReceiptV3 {
    /// Construct message contents only. This does not sign or authenticate them.
    pub fn for_request(
        request: &AnchorRequestV3,
        head: JournalHeadV3,
        outcome: AnchorOutcomeV3,
    ) -> RootOwnerResultV3<Self> {
        let value = Self {
            scope: request.scope,
            challenge: request.challenge,
            request_digest: request.digest()?,
            head,
            outcome,
        };
        value.message()?;
        Ok(value)
    }
    pub fn message(&self) -> RootOwnerResultV3<Vec<u8>> {
        self.head.validate()?;
        require(
            self.scope != [0; 64] && self.challenge != [0; 32] && self.request_digest != [0; 64],
            "ROOT_ANCHOR_RECEIPT_IDENTITY",
        )?;
        let mut bytes = RECEIPT_DOMAIN.to_vec();
        bytes.extend(self.scope);
        bytes.extend(self.challenge);
        bytes.extend(self.request_digest);
        bytes.extend(self.head.bytes());
        bytes.push(match self.outcome {
            AnchorOutcomeV3::Current => 0,
            AnchorOutcomeV3::Advanced => 1,
            AnchorOutcomeV3::Mismatch => 2,
        });
        Ok(bytes)
    }
}

pub struct SignedAnchorReceiptV3 {
    pub receipt: AnchorReceiptV3,
    pub approvals: Vec<RootSignatureV3>,
}

/// Private signing keys remain outside the journal. The owner independently
/// verifies this callback's signatures before invoking the transport.
pub trait RootWriterSignerV3 {
    fn sign(
        &mut self,
        message: &[u8],
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<Vec<RootSignatureV3>>;
}
pub trait RootAnchorTransportV3 {
    fn exchange(
        &mut self,
        request: AnchorEnvelopeV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<SignedAnchorReceiptV3>;
}

pub(super) struct AnchorClientV3 {
    scope: [u8; 64],
    writer_roster: DualFamilyRosterV3,
    anchor_roster: DualFamilyRosterV3,
    writer: Box<dyn RootWriterSignerV3>,
    transport: Box<dyn RootAnchorTransportV3>,
}
impl AnchorClientV3 {
    pub(super) fn new(
        enrollment: &JournalEnrollmentV3,
        writer: impl RootWriterSignerV3 + 'static,
        transport: impl RootAnchorTransportV3 + 'static,
    ) -> Self {
        Self {
            scope: enrollment.scope,
            writer_roster: enrollment.writer.clone(),
            anchor_roster: enrollment.anchor.clone(),
            writer: Box::new(writer),
            transport: Box::new(transport),
        }
    }
    fn exchange(
        &mut self,
        request: AnchorRequestV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<AnchorReceiptV3> {
        budget.check()?;
        let original_budget = budget.identity.clone();
        let message = request.message()?;
        let approvals = self.writer.sign(&message, budget)?;
        budget.check_identity(&original_budget)?;
        self.writer_roster
            .verify_quorum(&message, &approvals, budget.verification())
            .map_err(map_error)?;
        budget.check()?;
        let response = self.transport.exchange(
            AnchorEnvelopeV3 {
                request: request.clone(),
                writer_approvals: approvals,
            },
            budget,
        )?;
        budget.check_identity(&original_budget)?;
        let receipt = response.receipt;
        require(
            receipt.scope == self.scope
                && receipt.challenge == request.challenge
                && receipt.request_digest == request.digest()?,
            "ROOT_ANCHOR_COMPLETE_REQUEST_BINDING",
        )?;
        self.anchor_roster
            .verify_quorum(
                &receipt.message()?,
                &response.approvals,
                budget.verification(),
            )
            .map_err(map_error)?;
        budget.check()?;
        Ok(receipt)
    }
    pub(super) fn current(
        &mut self,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<JournalHeadV3> {
        let receipt = self.exchange(AnchorRequestV3::fresh(self.scope, None, None)?, budget)?;
        require(
            receipt.outcome == AnchorOutcomeV3::Current,
            "ROOT_ANCHOR_CURRENT_OUTCOME",
        )?;
        Ok(receipt.head)
    }
    pub(super) fn advance(
        &mut self,
        expected: JournalHeadV3,
        target: JournalHeadV3,
        budget: &mut OwnerBudgetV3,
    ) -> RootOwnerResultV3<()> {
        let receipt = self.exchange(
            AnchorRequestV3::fresh(self.scope, Some(expected), Some(target))?,
            budget,
        )?;
        require(
            receipt.outcome == AnchorOutcomeV3::Advanced && receipt.head == target,
            "ROOT_ANCHOR_CAS_REFUSED",
        )
    }
}
