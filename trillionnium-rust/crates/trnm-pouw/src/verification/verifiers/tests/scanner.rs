use super::*;

#[path = "scanner/scanner_task_id_duplicates.rs"]
mod scanner_task_id_duplicates;
mod scanner_worker_duplicates;
#[path = "scanner/scanner_result_hash_duplicates.rs"]
mod scanner_result_hash_duplicates;
mod scanner_proof_type_duplicates;
mod scanner_numeric_guards;
mod scanner_identifier_spoofing;
mod scanner_missing_context;
mod scanner_fullwidth_separators;
