use super::{find_numeric_field, find_token_field, verify_bound_envelope};
use crate::verification::VerificationResult;
use trnm_types::{ProofType, TaskObject, TaskStatus};

mod fraud;
mod zk;
mod tee;
mod payload;
mod scanner;
mod numeric;
mod token;
mod envelope;
