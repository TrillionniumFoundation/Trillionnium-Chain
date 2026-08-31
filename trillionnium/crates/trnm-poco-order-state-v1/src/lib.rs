//! Candidate authoritative local writer for registered v1 Order-state tag 50.
//!
//! The write permit cannot be forged or cloned in a normal build:
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::OrderStateWritePermitV1;
//! let _forged = OrderStateWritePermitV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::OrderStateWritePermitV1;
//! fn duplicate(value: OrderStateWritePermitV1) { let _copy = value.clone(); }
//! ```
//!
//! A successful materialization keeps the terminal owner linear:
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::MaterializedOrderStateOwnerV1;
//! let _forged = MaterializedOrderStateOwnerV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::MaterializedOrderStateOwnerV1;
//! fn duplicate(value: MaterializedOrderStateOwnerV1) { let _copy = value.clone(); }
//! ```
//!
//! Raw bytes cannot be passed to the writer:
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::PocoOrderStateStoreV1;
//! fn raw(store: &PocoOrderStateStoreV1, bytes: Vec<u8>) {
//!     let _ = store.materialize_global_execution_binding_v1(bytes);
//! }
//! ```
//!
//! The finalized canonical permit is likewise private, linear authority:
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::CanonicalFinalizedOrderApplyPermitV1;
//! let _forged = CanonicalFinalizedOrderApplyPermitV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::CanonicalFinalizedOrderApplyPermitV1;
//! fn duplicate(value: CanonicalFinalizedOrderApplyPermitV1) { let _copy = value.clone(); }
//! ```
//!
//! Fresh recovery still returns private, non-Clone linear authority:
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::AppliedFinalizedOrderStateOwnerV1;
//! let _forged = AppliedFinalizedOrderStateOwnerV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::AppliedFinalizedOrderStateOwnerV1;
//! fn duplicate(value: AppliedFinalizedOrderStateOwnerV1) { let _copy = value.clone(); }
//! ```
//!
//! An inert prepared plan cannot be substituted for that authority:
//!
//! ```compile_fail
//! use trnm_poco_order_application_v1::PreparedOrderBlockV1;
//! use trnm_poco_order_state_v1::PocoCanonicalOrderStateStoreV1;
//! fn raw(store: &PocoCanonicalOrderStateStoreV1, prepared: PreparedOrderBlockV1) {
//!     let _ = store.apply_finalized_prepared_order_block_v1(prepared);
//! }
//! ```
//!
//! The fresh-audited durable parent owner is also private and non-Clone:
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::RecoveredCanonicalOrderApplicationParentV1;
//! let _forged = RecoveredCanonicalOrderApplicationParentV1 {};
//! ```
//!
//! ```compile_fail
//! use trnm_poco_order_state_v1::RecoveredCanonicalOrderApplicationParentV1;
//! fn duplicate(value: RecoveredCanonicalOrderApplicationParentV1) {
//!     let _copy = value.clone();
//! }
//! ```

#![forbid(unsafe_code)]

mod canonical;
mod error;
mod store;

pub use canonical::{
    AppliedFinalizedOrderStateOwnerV1, CanonicalFinalizedOrderApplyAttemptV1,
    CanonicalFinalizedOrderApplyFailureV1, CanonicalFinalizedOrderApplyPermitV1,
    CanonicalFinalizedOrderApplyReceiptV1, CanonicalOrderStateHeadPinV1,
    PocoCanonicalOrderStateStoreV1, RecoveredCanonicalOrderApplicationParentV1,
};
pub use error::{OrderStateErrorCodeV1, OrderStateErrorV1, OrderStateResultV1};
pub use store::{
    empty_order_state_root_v1, issue_order_state_write_permit_v1,
    verify_order_state_membership_proof_v1, MaterializedOrderStateOwnerV1, OrderStateHeadPinV1,
    OrderStateMembershipProofV1, OrderStateWriteAttemptV1, OrderStateWriteFailureV1,
    OrderStateWritePermitV1, OrderStateWriteReceiptV1, PocoOrderStateStoreV1,
    VerifiedMaterializedOrderStateOwnerV1,
};

#[cfg(any(test, feature = "test-support"))]
pub use store::{issue_test_order_state_write_permit_v1, TestOrderStateWritePermitV1};

#[cfg(test)]
mod tests;
