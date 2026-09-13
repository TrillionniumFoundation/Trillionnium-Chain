use crate::{
    error::{error, NativeBoundaryErrorCodeV0, NativeBoundaryResultV0},
    primitives::Hash32V0,
};

pub const MAX_EVENT_KIND_BYTES_V0: usize = u32::MAX as usize;
pub const MAX_EVENT_ATTRIBUTE_KEY_BYTES_V0: usize = u32::MAX as usize;
pub const MAX_EVENT_ATTRIBUTE_VALUE_BYTES_V0: usize = u32::MAX as usize;
pub const MAX_EVENT_ATTRIBUTES_V0: usize = u32::MAX as usize;
pub const MAX_EVENTS_PER_RECEIPT_V0: usize = u32::MAX as usize;

fn validate_exact_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> NativeBoundaryResultV0<()> {
    if value.len() > maximum {
        return Err(error(NativeBoundaryErrorCodeV0::TooLong, field));
    }
    Ok(())
}

/// One exact, raw-key-ordered application event attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEventAttributeV0 {
    key: String,
    value: String,
}

impl NativeEventAttributeV0 {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> NativeBoundaryResultV0<Self> {
        let key = key.into();
        let value = value.into();
        validate_exact_text(
            &key,
            MAX_EVENT_ATTRIBUTE_KEY_BYTES_V0,
            "event_attribute.key",
        )?;
        validate_exact_text(
            &value,
            MAX_EVENT_ATTRIBUTE_VALUE_BYTES_V0,
            "event_attribute.value",
        )?;
        Ok(Self { key, value })
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

/// One deterministic application event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEventV0 {
    kind: String,
    attributes: Vec<NativeEventAttributeV0>,
}

impl NativeEventV0 {
    pub fn new(
        kind: impl Into<String>,
        attributes: Vec<NativeEventAttributeV0>,
    ) -> NativeBoundaryResultV0<Self> {
        let kind = kind.into();
        validate_exact_text(&kind, MAX_EVENT_KIND_BYTES_V0, "event.kind")?;
        if attributes.len() > MAX_EVENT_ATTRIBUTES_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "event.attributes",
            ));
        }
        if attributes
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(error(
                NativeBoundaryErrorCodeV0::NotCanonical,
                "event.attributes",
            ));
        }
        Ok(Self { kind, attributes })
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn attributes(&self) -> &[NativeEventAttributeV0] {
        &self.attributes
    }
}

/// Runtime-derived receipt for one successfully applied transaction.
///
/// Deterministically invalid blocks do not carry receipts. The commitment is
/// supplied by the native receipt encoder and is never inferred from a host
/// transport representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExecutionReceiptV0 {
    transaction_index: u32,
    transaction_digest: Hash32V0,
    gas_used: u64,
    fee_charged: u128,
    events: Vec<NativeEventV0>,
    commitment: Hash32V0,
}

impl NativeExecutionReceiptV0 {
    pub fn new(
        transaction_index: u32,
        transaction_digest: Hash32V0,
        gas_used: u64,
        fee_charged: u128,
        events: Vec<NativeEventV0>,
        commitment: Hash32V0,
    ) -> NativeBoundaryResultV0<Self> {
        let transaction_digest =
            transaction_digest.require_nonzero("execution_receipt.transaction_digest")?;
        let commitment = commitment.require_nonzero("execution_receipt.commitment")?;
        if events.len() > MAX_EVENTS_PER_RECEIPT_V0 {
            return Err(error(
                NativeBoundaryErrorCodeV0::TooMany,
                "execution_receipt.events",
            ));
        }
        Ok(Self {
            transaction_index,
            transaction_digest,
            gas_used,
            fee_charged,
            events,
            commitment,
        })
    }

    pub const fn transaction_index(&self) -> u32 {
        self.transaction_index
    }

    pub const fn transaction_digest(&self) -> Hash32V0 {
        self.transaction_digest
    }

    pub const fn gas_used(&self) -> u64 {
        self.gas_used
    }

    pub const fn fee_charged(&self) -> u128 {
        self.fee_charged
    }

    pub fn events(&self) -> &[NativeEventV0] {
        &self.events
    }

    pub const fn commitment(&self) -> Hash32V0 {
        self.commitment
    }
}
