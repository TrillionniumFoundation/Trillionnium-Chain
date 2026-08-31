use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use trnm_consensus_types::{
    ApplicationPayloadV0, ExecutionEventAttributeV0, ExecutionEventV0,
    ExecutionReceiptCommitmentV0, ExecutionReceiptsV0, Height, PayloadDigest, ReceiptsRoot,
    StateRoot,
};
use trnm_finality_types::hash_domain;
use trnm_runtime::RuntimeReceipt;

const NATIVE_CHECKPOINT_EXECUTION_AUTHORIZATION_DOMAIN_V0: &str =
    "trnm.poco-bft.authorized-native-checkpoint-execution.v0";

/// Runtime-authorized receipt facts before they are bound to one exact
/// transaction position in a native PoCO application payload.
///
/// This value is deliberately independent from ABCI `ExecTxResult`: the
/// transport projection cannot represent the exact `u128` fee and is not an
/// authority source for native header commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeTransactionReceiptFactsV0 {
    gas_used: u64,
    fee_charged: u128,
    events: Vec<ExecutionEventV0>,
}

impl NativeTransactionReceiptFactsV0 {
    pub(crate) fn try_from_runtime_receipt(receipt: &RuntimeReceipt) -> Result<Self> {
        let events = receipt
            .events
            .iter()
            .map(runtime_event_to_native_v0)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            gas_used: receipt.gas_used,
            fee_charged: receipt.fee_charged,
            events,
        })
    }

    /// App-internal operations do not execute the fee-charging runtime. Their
    /// frozen native receipt is exactly empty and never caller-supplied.
    pub(crate) const fn internal_operation() -> Self {
        Self {
            gas_used: 0,
            fee_charged: 0,
            events: Vec::new(),
        }
    }

    fn bind_to_transaction(
        self,
        payload: &ApplicationPayloadV0,
        transaction_index: u32,
    ) -> Result<ExecutionReceiptCommitmentV0> {
        ExecutionReceiptCommitmentV0::for_transaction(
            payload,
            transaction_index,
            self.gas_used,
            self.fee_charged,
            self.events,
        )
        .map_err(|error| anyhow!("bind native execution receipt to payload: {error:?}"))
    }
}

/// Exact transaction bytes and runtime-derived native receipt commitments for
/// one deterministically executed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeBlockExecutionV0 {
    application_payload: ApplicationPayloadV0,
    execution_receipts: ExecutionReceiptsV0,
}

impl NativeBlockExecutionV0 {
    pub(crate) fn try_new(
        transactions: &[Bytes],
        receipt_facts: Vec<NativeTransactionReceiptFactsV0>,
    ) -> Result<Self> {
        let application_payload = ApplicationPayloadV0::new(
            transactions
                .iter()
                .map(|transaction| transaction.to_vec())
                .collect(),
        )
        .map_err(|error| anyhow!("construct native application payload: {error:?}"))?;
        let execution_receipts = receipt_facts
            .into_iter()
            .enumerate()
            .map(|(index, facts)| {
                let index = u32::try_from(index).context("native receipt index exceeds u32")?;
                facts.bind_to_transaction(&application_payload, index)
            })
            .collect::<Result<Vec<_>>>()?;
        let execution_receipts = ExecutionReceiptsV0::new(&application_payload, execution_receipts)
            .map_err(|error| anyhow!("construct native execution receipts: {error:?}"))?;
        Ok(Self {
            application_payload,
            execution_receipts,
        })
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self::try_new(&[], Vec::new()).expect("empty native block execution is valid")
    }

    pub(crate) const fn application_payload(&self) -> &ApplicationPayloadV0 {
        &self.application_payload
    }

    pub(crate) const fn execution_receipts(&self) -> &ExecutionReceiptsV0 {
        &self.execution_receipts
    }
}

/// Opaque application authority for one exact deterministic native execution
/// between an authenticated parent state and its immediately following state.
///
/// Unlike [`NativeBlockExecutionV0`], this value is not merely a payload and
/// receipt shape container. Its private authorization seal commits to the
/// authenticated source/target state transition and to the exact CEV0 payload
/// and receipt bytes. ABCI `ExecTxResult` and caller-supplied header roots are
/// deliberately absent from this authority surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedNativeCheckpointExecutionV0 {
    parent_height: Height,
    parent_state_root: StateRoot,
    target_height: Height,
    post_state_root: StateRoot,
    execution: NativeBlockExecutionV0,
    authorization_id: [u8; 32],
}

impl AuthorizedNativeCheckpointExecutionV0 {
    pub(crate) const fn parent_height(&self) -> Height {
        self.parent_height
    }

    pub(crate) const fn parent_state_root(&self) -> StateRoot {
        self.parent_state_root
    }

    pub(crate) const fn target_height(&self) -> Height {
        self.target_height
    }

    pub(crate) const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    pub(crate) const fn execution(&self) -> &NativeBlockExecutionV0 {
        &self.execution
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}

/// Binds the locally produced native execution to the authenticated
/// application transition. Production calls this only after the state-tree
/// update has derived the target root.
pub(crate) fn authorize_native_checkpoint_execution_v0(
    execution: NativeBlockExecutionV0,
    parent_height: Height,
    parent_state_root: StateRoot,
    target_height: Height,
    post_state_root: StateRoot,
) -> Result<AuthorizedNativeCheckpointExecutionV0> {
    let expected_target = parent_height
        .checked_next()
        .map_err(|error| anyhow!("native execution target-height overflow: {error:?}"))?;
    if target_height != expected_target {
        return Err(anyhow!(
            "native execution target height is not immediately after authenticated parent"
        ));
    }
    if parent_state_root.is_zero() {
        return Err(anyhow!(
            "zero authenticated native execution parent state root"
        ));
    }
    if post_state_root.is_zero() {
        return Err(anyhow!("zero authorized native execution post-state root"));
    }

    execution
        .execution_receipts()
        .validate_for_payload(execution.application_payload())
        .map_err(|error| anyhow!("native receipt/payload relation: {error:?}"))?;
    let payload_root = execution
        .application_payload()
        .payload_root()
        .map_err(|error| anyhow!("compute authorized native payload root: {error:?}"))?;
    let receipts_root = execution
        .execution_receipts()
        .receipts_root()
        .map_err(|error| anyhow!("compute authorized native receipts root: {error:?}"))?;
    let payload_bytes = execution
        .application_payload()
        .try_cev0_bytes()
        .map_err(|error| anyhow!("encode authorized native payload: {error:?}"))?;
    let receipts_bytes = execution
        .execution_receipts()
        .try_cev0_bytes()
        .map_err(|error| anyhow!("encode authorized native receipts: {error:?}"))?;
    let authorization_id = native_checkpoint_execution_authorization_id_v0(
        parent_height,
        parent_state_root,
        target_height,
        post_state_root,
        payload_root,
        receipts_root,
        &payload_bytes,
        &receipts_bytes,
    );

    Ok(AuthorizedNativeCheckpointExecutionV0 {
        parent_height,
        parent_state_root,
        target_height,
        post_state_root,
        execution,
        authorization_id,
    })
}

/// Recomputes the private native-execution seal from the exact canonical
/// inputs retained by the live authority and durable replay paths. The digest
/// is inert comparison material and cannot construct execution authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn native_checkpoint_execution_authorization_id_v0(
    parent_height: Height,
    parent_state_root: StateRoot,
    target_height: Height,
    post_state_root: StateRoot,
    payload_root: PayloadDigest,
    receipts_root: ReceiptsRoot,
    payload_cev0: &[u8],
    receipts_cev0: &[u8],
) -> [u8; 32] {
    hash_domain(
        NATIVE_CHECKPOINT_EXECUTION_AUTHORIZATION_DOMAIN_V0,
        &[
            &parent_height.get().to_be_bytes(),
            parent_state_root.as_bytes(),
            &target_height.get().to_be_bytes(),
            post_state_root.as_bytes(),
            payload_root.as_bytes(),
            receipts_root.as_bytes(),
            payload_cev0,
            receipts_cev0,
        ],
    )
}

fn runtime_event_to_native_v0(event: &trnm_runtime::RuntimeEvent) -> Result<ExecutionEventV0> {
    let mut attributes = event
        .attributes
        .iter()
        .map(|(key, value)| {
            ExecutionEventAttributeV0::new(key.as_bytes().to_vec(), value.as_bytes().to_vec())
                .map_err(|error| anyhow!("construct native execution-event attribute: {error:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    // Runtime attributes originate in a BTreeMap<String, String>, but sort on
    // the frozen raw UTF-8 bytes explicitly so this adapter owns the protocol
    // ordering rule rather than inheriting a container implementation detail.
    attributes.sort_by(|left, right| left.key().cmp(right.key()));
    ExecutionEventV0::new(event.kind.as_bytes().to_vec(), attributes)
        .map_err(|error| anyhow!("construct native execution event: {error:?}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use trnm_runtime::{RuntimeEvent, RuntimeMutation};

    #[test]
    fn runtime_receipts_bind_exact_transactions_fee_and_event_order() {
        let receipt = RuntimeReceipt {
            gas_used: u64::MAX,
            fee_charged: (u128::from(u64::MAX) << 32) + 17,
            events: vec![
                RuntimeEvent {
                    kind: "first".to_string(),
                    attributes: BTreeMap::from([
                        ("z".to_string(), "last".to_string()),
                        ("aa".to_string(), "first".to_string()),
                    ]),
                },
                RuntimeEvent {
                    kind: "second".to_string(),
                    attributes: BTreeMap::new(),
                },
            ],
            mutations: vec![RuntimeMutation {
                object_key_hex: "00".to_string(),
                object_type: "ignored-by-receipt-commitment".to_string(),
                expected_version: None,
                next_version: 1,
                value_bytes: vec![1],
            }],
        };
        let internal = NativeTransactionReceiptFactsV0::internal_operation();
        let native = NativeBlockExecutionV0::try_new(
            &[
                Bytes::from_static(&[0, 255]),
                Bytes::from_static(b"internal"),
            ],
            vec![
                NativeTransactionReceiptFactsV0::try_from_runtime_receipt(&receipt).unwrap(),
                internal,
            ],
        )
        .unwrap();

        assert_eq!(
            native.application_payload().transactions(),
            &[vec![0, 255], b"internal".to_vec()]
        );
        let receipts = native.execution_receipts().receipts();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].transaction_index(), 0);
        assert_eq!(receipts[0].gas_used(), u64::MAX);
        assert_eq!(receipts[0].fee_charged(), receipt.fee_charged);
        assert_eq!(receipts[0].events()[0].kind(), b"first");
        assert_eq!(receipts[0].events()[1].kind(), b"second");
        assert_eq!(receipts[0].events()[0].attributes()[0].key(), b"aa");
        assert_eq!(receipts[0].events()[0].attributes()[1].key(), b"z");
        assert_eq!(receipts[1].transaction_index(), 1);
        assert_eq!(receipts[1].gas_used(), 0);
        assert_eq!(receipts[1].fee_charged(), 0);
        assert!(receipts[1].events().is_empty());
        assert!(native.application_payload().payload_root().is_ok());
        assert!(native.execution_receipts().receipts_root().is_ok());
    }

    #[test]
    fn missing_runtime_receipt_rejects_the_whole_native_block_mapping() {
        let error =
            NativeBlockExecutionV0::try_new(&[Bytes::from_static(b"tx")], Vec::new()).unwrap_err();
        assert!(format!("{error:#}").contains("exactly one receipt per transaction"));
    }

    #[test]
    fn empty_block_has_exact_empty_payload_and_receipts() {
        let native = NativeBlockExecutionV0::empty();
        assert!(native.application_payload().transactions().is_empty());
        assert!(native.execution_receipts().receipts().is_empty());
    }

    #[test]
    fn authorized_native_execution_binds_exact_state_transition_and_bytes() {
        let execution = NativeBlockExecutionV0::try_new(
            &[Bytes::from_static(b"checkpoint")],
            vec![NativeTransactionReceiptFactsV0::internal_operation()],
        )
        .unwrap();
        let authorized = authorize_native_checkpoint_execution_v0(
            execution.clone(),
            Height::new(27),
            StateRoot::new([1; 32]),
            Height::new(28),
            StateRoot::new([2; 32]),
        )
        .unwrap();

        assert_eq!(authorized.parent_height(), Height::new(27));
        assert_eq!(authorized.parent_state_root(), StateRoot::new([1; 32]));
        assert_eq!(authorized.target_height(), Height::new(28));
        assert_eq!(authorized.post_state_root(), StateRoot::new([2; 32]));
        assert_eq!(authorized.execution(), &execution);
        assert_ne!(authorized.authorization_id(), [0; 32]);

        let parent_root_splice = authorize_native_checkpoint_execution_v0(
            execution.clone(),
            Height::new(27),
            StateRoot::new([3; 32]),
            Height::new(28),
            StateRoot::new([2; 32]),
        )
        .unwrap();
        let post_root_splice = authorize_native_checkpoint_execution_v0(
            execution,
            Height::new(27),
            StateRoot::new([1; 32]),
            Height::new(28),
            StateRoot::new([4; 32]),
        )
        .unwrap();
        let payload_splice = authorize_native_checkpoint_execution_v0(
            NativeBlockExecutionV0::try_new(
                &[Bytes::from_static(b"checkpoint-splice")],
                vec![NativeTransactionReceiptFactsV0::internal_operation()],
            )
            .unwrap(),
            Height::new(27),
            StateRoot::new([1; 32]),
            Height::new(28),
            StateRoot::new([2; 32]),
        )
        .unwrap();
        assert_ne!(
            parent_root_splice.authorization_id(),
            authorized.authorization_id()
        );
        assert_ne!(
            post_root_splice.authorization_id(),
            authorized.authorization_id()
        );
        assert_ne!(
            payload_splice.authorization_id(),
            authorized.authorization_id()
        );
    }

    #[test]
    fn authorized_native_execution_rejects_height_and_zero_root_splices() {
        let attempt = |parent_height, parent_root, target_height, post_root| {
            authorize_native_checkpoint_execution_v0(
                NativeBlockExecutionV0::empty(),
                Height::new(parent_height),
                StateRoot::new(parent_root),
                Height::new(target_height),
                StateRoot::new(post_root),
            )
        };

        assert!(attempt(27, [1; 32], 27, [2; 32])
            .unwrap_err()
            .to_string()
            .contains("target height"));
        assert!(attempt(27, [1; 32], 29, [2; 32])
            .unwrap_err()
            .to_string()
            .contains("target height"));
        assert!(attempt(27, [0; 32], 28, [2; 32])
            .unwrap_err()
            .to_string()
            .contains("parent state root"));
        assert!(attempt(27, [1; 32], 28, [0; 32])
            .unwrap_err()
            .to_string()
            .contains("post-state root"));
        assert!(attempt(u64::MAX, [1; 32], 0, [2; 32])
            .unwrap_err()
            .to_string()
            .contains("overflow"));
    }
}
