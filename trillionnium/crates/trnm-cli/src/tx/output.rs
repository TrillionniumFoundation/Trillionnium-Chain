use super::*;

pub(crate) fn format_tx_hash_line(tx_hash: &str) -> String {
    format!("tx_hash=\"{}\"", tx_hash)
}

pub(crate) fn format_tx_hash_alias_line(tx_hash: &str) -> String {
    format!("txhash={}", tx_hash)
}

pub(crate) fn format_transaction_hash_alias_line(tx_hash: &str) -> String {
    format!("transaction_hash={}", tx_hash)
}

pub(crate) fn format_transaction_hash_camel_alias_line(tx_hash: &str) -> String {
    format!("transactionHash={}", tx_hash)
}

pub(crate) fn format_tx_hash_hyphen_alias_line(tx_hash: &str) -> String {
    format!("tx-hash={}", tx_hash)
}

pub(crate) fn format_transaction_hash_hyphen_alias_line(tx_hash: &str) -> String {
    format!("transaction-hash={}", tx_hash)
}

pub(crate) fn format_transaction_hash_spaced_alias_line(tx_hash: &str) -> String {
    format!("transaction hash={}", tx_hash)
}

pub(crate) fn format_tx_hash_spaced_alias_line(tx_hash: &str) -> String {
    format!("tx hash={}", tx_hash)
}

pub(crate) fn emit_tx_hash_lines(tx_hash: &str) {
    println!("{}", format_tx_hash_line(tx_hash));
    println!("{}", format_tx_hash_alias_line(tx_hash));
    println!("{}", format_transaction_hash_alias_line(tx_hash));
    println!("{}", format_transaction_hash_camel_alias_line(tx_hash));
    println!("{}", format_tx_hash_hyphen_alias_line(tx_hash));
    println!("{}", format_tx_hash_spaced_alias_line(tx_hash));
    println!("{}", format_transaction_hash_hyphen_alias_line(tx_hash));
    println!("{}", format_transaction_hash_spaced_alias_line(tx_hash));
}

pub(crate) fn emit_pending_tx_hash(tx_hash: &str) -> Result<()> {
    persist_local_pending_tx(tx_hash)?;
    emit_tx_hash_lines(tx_hash);
    Ok(())
}
