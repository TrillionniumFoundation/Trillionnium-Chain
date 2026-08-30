#!/usr/bin/env python3
"""Finalize the candidate-only transaction-admission tombstone GC slice.

This script is intentionally one-shot. The verification workflow removes it
and itself before publishing the exact tested candidate.
"""

from pathlib import Path


SOURCE = Path("trillionnium/crates/trnm-poco-node/src/tx_admission_wal.rs")
INC = Path(
    "trillionnium/crates/trnm-poco-node/src/tx_admission_wal_tombstone_gc_v1.inc"
)
CARGO = Path("trillionnium/crates/trnm-poco-node/Cargo.toml")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} drift: expected exactly one marker, got {count}")
    return text.replace(old, new)


def finalize_source() -> None:
    text = SOURCE.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "const SCHEMA_VERSION_V0: i64 = 1;",
        "const SCHEMA_VERSION_V0: i64 = 2;",
        "schema version",
    )

    ddl = "\n".join(
        [
            "    UNIQUE(namespace, tx_digest)",
            ");",
            "CREATE TABLE tx_admission_tombstone_v1 (",
            "    namespace BLOB NOT NULL CHECK(length(namespace) = 32),",
            "    signer BLOB NOT NULL CHECK(length(signer) = 32),",
            "    nonce BLOB NOT NULL CHECK(length(nonce) = 8),",
            "    tx_digest BLOB NOT NULL CHECK(length(tx_digest) = 32),",
            "    terminal_state INTEGER NOT NULL CHECK(terminal_state IN (2, 3)),",
            "    terminal_height BLOB NOT NULL CHECK(length(terminal_height) = 8),",
            "    receipt_commitment BLOB NOT NULL CHECK(length(receipt_commitment) = 32),",
            "    tombstone_digest BLOB NOT NULL CHECK(length(tombstone_digest) = 32),",
            "    PRIMARY KEY(namespace, signer, nonce),",
            "    UNIQUE(namespace, tx_digest),",
            "    UNIQUE(namespace, tombstone_digest)",
            ");",
            '"#;',
        ]
    )
    text = replace_once(
        text,
        "    UNIQUE(namespace, tx_digest)\n);\n\"#;",
        ddl,
        "tombstone DDL insertion",
    )
    text = replace_once(
        text,
        'execute_batch("PRAGMA user_version = 1;")',
        'execute_batch("PRAGMA user_version = 2;")',
        "SQLite user_version",
    )
    text = replace_once(
        text,
        "        validate_pending_rows_v0(&connection, namespace)?;\n"
        "        validate_receipt_rows_v0(&connection, namespace)?;",
        "        validate_pending_rows_v0(&connection, namespace)?;\n"
        "        validate_receipt_rows_v0(&connection, namespace)?;\n"
        "        validate_tombstone_rows_v1(&connection, namespace)?;",
        "tombstone validation hook",
    )

    count_sql = "SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1"
    query_count = text.count(count_sql)
    if query_count != 4:
        raise SystemExit(
            f"bounded inventory query drift: expected four markers, got {query_count}"
        )
    text = text.replace(
        count_sql,
        "SELECT (SELECT COUNT(*) FROM pending_nonce WHERE namespace = ?1) + "
        "(SELECT COUNT(*) FROM tx_admission_tombstone_v1 WHERE namespace = ?1)",
    )

    reserve_start = text.index("    fn reserve_record<E: ?Sized>(")
    insertion_marker = "        if let Some((existing, state)) = read_row_v0("
    insertion = text.index(insertion_marker, reserve_start)
    guard = "\n".join(
        [
            "        if tombstone_exists_by_nonce_or_digest_v1(",
            "            &transaction,",
            "            self.namespace,",
            "            expected.signer,",
            "            expected.nonce,",
            "            expected.digest,",
            "        )? {",
            "            return Err(TxAdmissionWalErrorV0::Replay);",
            "        }",
            "",
        ]
    )
    text = text[:insertion] + guard + text[insertion:]

    include_marker = "#[cfg(test)]\nmod tests {"
    text = replace_once(
        text,
        include_marker,
        'include!("tx_admission_wal_tombstone_gc_v1.inc");\n\n'
        "#[cfg(test)]\nmod tests {",
        "tombstone implementation include",
    )
    SOURCE.write_text(text, encoding="utf-8")


def finalize_candidate_contract() -> None:
    text = INC.read_text(encoding="utf-8")
    constants_marker = "\n".join(
        [
            "/// Neither compaction nor purge activates production transaction admission.",
            "pub const TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1: bool = false;",
            "",
            "const TOMBSTONE_DIGEST_DOMAIN_V1",
        ]
    )
    constants_replacement = "\n".join(
        [
            "/// Neither compaction nor purge activates production transaction admission.",
            "pub const TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1: bool = false;",
            "",
            "const fn tombstone_gc_candidate_contract_v1() -> bool {",
            "    TX_ADMISSION_TOMBSTONE_COMPACTION_V1",
            "        && TX_ADMISSION_TOMBSTONE_AUTHENTICATED_PURGE_V1",
            "        && !TX_ADMISSION_TOMBSTONE_PRODUCTION_ACTIVATION_V1",
            "}",
            "",
            "const TOMBSTONE_DIGEST_DOMAIN_V1",
        ]
    )
    text = replace_once(
        text,
        constants_marker,
        constants_replacement,
        "candidate truth contract",
    )

    compact_marker = "\n".join(
        [
            "    pub fn compact_terminal_rows_v1(",
            "        &mut self,",
            "        max_rows: usize,",
            "    ) -> Result<TxAdmissionTombstoneGcResultV1, TxAdmissionWalErrorV0> {",
            "        if max_rows == 0 || max_rows > MAX_TOMBSTONE_BATCH_V1 {",
        ]
    )
    compact_replacement = "\n".join(
        [
            "    pub fn compact_terminal_rows_v1(",
            "        &mut self,",
            "        max_rows: usize,",
            "    ) -> Result<TxAdmissionTombstoneGcResultV1, TxAdmissionWalErrorV0> {",
            "        if !tombstone_gc_candidate_contract_v1() {",
            "            return Err(TxAdmissionWalErrorV0::Malformed);",
            "        }",
            "        if max_rows == 0 || max_rows > MAX_TOMBSTONE_BATCH_V1 {",
        ]
    )
    text = replace_once(
        text,
        compact_marker,
        compact_replacement,
        "compact_terminal_rows_v1 entry",
    )
    INC.write_text(text, encoding="utf-8")


def finalize_metadata() -> None:
    text = CARGO.read_text(encoding="utf-8")
    replacement = "\n".join(
        [
            "tx_admission_tombstone_gc = true",
            "tx_admission_tombstone_compaction = true",
            "tx_admission_tombstone_authenticated_purge = true",
            "tx_admission_tombstone_gc_production = false",
            "tx_admission_replay_floor_native_integration = false",
        ]
    )
    text = replace_once(
        text,
        "tx_admission_tombstone_gc = false",
        replacement,
        "Cargo tombstone metadata",
    )
    CARGO.write_text(text, encoding="utf-8")


def main() -> None:
    finalize_source()
    finalize_candidate_contract()
    finalize_metadata()


if __name__ == "__main__":
    main()
