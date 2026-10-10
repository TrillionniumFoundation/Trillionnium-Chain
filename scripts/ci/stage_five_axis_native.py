#!/usr/bin/env python3
"""Isolated authoring transport; never included in the product candidate."""
from pathlib import Path
import argparse
import subprocess

ROOT = Path('trillionnium/crates/trnm-pon-node')
STORE = ROOT / 'src/store.rs'
TESTS = ROOT / 'src/native_account_query_tests.rs'
PIPE = ROOT / 'examples/continuous_pipeline.rs'
DOC = Path('docs/protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md')

READ_TESTS = r'''

#[test]
fn native_account_query_final_callback_write_is_rejected_and_rolled_back() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let owners = [development_public(0).unwrap()];
    let before = logical_rows(&node.db);
    let expected = node.authenticated_account_multiproof(settings.genesis(), &owners).unwrap();
    let touched = Cell::new(false);
    let result = node.authenticated_account_multiproof_with_progress(
        settings.genesis(), &owners, &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                touched.set(true);
                node.db.execute("UPDATE active SET generation=generation+1", [])?;
            }
            Ok(())
        },
    );
    assert!(touched.get());
    assert!(result.is_err(), "a read-only proof must not commit callback writes");
    let error = result.unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_PROOF_WRITE");
    assert!(error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
    assert_eq!(node.authenticated_account_multiproof(settings.genesis(), &owners).unwrap().1.encode().unwrap(), expected.1.encode().unwrap());
    drop(node);
    let node = open(directory.path(), settings, true);
    assert_eq!(logical_rows(&node.db), before);
}

#[test]
fn native_account_query_write_then_restore_still_has_no_commit_authority() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let before = logical_rows(&node.db);
    let error = node.authenticated_account_multiproof_with_progress(
        settings.genesis(), &[development_public(0).unwrap()], &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                node.db.execute("UPDATE active SET generation=generation+1", [])?;
                node.db.execute("UPDATE active SET generation=generation-1", [])?;
            }
            Ok(())
        },
    ).unwrap_err();
    assert_eq!(error.to_string(), "NATIVE_ACCOUNT_PROOF_WRITE");
    assert!(error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
}

#[test]
fn native_account_query_cancel_after_write_keeps_original_error_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), settings.clone(), true);
    let before = logical_rows(&node.db);
    let error = node.authenticated_account_multiproof_with_progress(
        settings.genesis(), &[development_public(0).unwrap()], &|point| {
            if point == NativeAccountProofProgress::BeforeOutput {
                node.db.execute("UPDATE active SET generation=generation+1", [])?;
                return Err(Error::new(ErrorCode::PublicRequestCancelled));
            }
            Ok(())
        },
    ).unwrap_err();
    assert_eq!(error.code(), Some(ErrorCode::PublicRequestCancelled));
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert!(!error.requires_owner_stop());
    assert!(node.db.is_autocommit());
    assert_eq!(logical_rows(&node.db), before);
}
'''

BATCH_TESTS = r'''

#[test]
fn native_nonce_batch_dimensions_precede_database_and_preserve_single_reads() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings, authenticated);
        let senders = [development_public(0).unwrap(), development_public(7).unwrap(), development_public(777).unwrap()];
        let expected: Vec<_> = senders.iter().map(|sender| node.next_nonce(*sender).unwrap()).collect();
        let before = logical_rows(&node.db);
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        node.db.execute_batch("BEGIN IMMEDIATE; DELETE FROM kv;").unwrap();
        assert_eq!(node.next_nonces(&[]).unwrap_err().to_string(), "NONCE_QUERY_LIMIT");
        assert_eq!(node.next_nonces(&vec![[0; 32]; 257]).unwrap_err().to_string(), "NONCE_QUERY_LIMIT");
        assert_eq!(node.next_nonces(&[senders[0], senders[0]]).unwrap_err().to_string(), "DUPLICATE_NONCE_QUERY");
        node.db.execute_batch("ROLLBACK").unwrap();
        assert_eq!(logical_rows(&node.db), before);
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        assert!(node.db.is_autocommit());
    }
}

#[test]
fn native_nonce_batch_rechecks_actual_state_and_reopens_without_a_verdict_cache() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), settings.clone(), authenticated);
        let senders = [development_public(0).unwrap(), development_public(7).unwrap()];
        let expected = node.next_nonces(&senders).unwrap();
        let before = logical_rows(&node.db);
        let other = rusqlite::Connection::open(node.directory.join("native.sqlite")).unwrap();
        let key = format!("account:{}", hex::encode(senders[0]));
        let slot = node.slot().unwrap();
        let raw: Vec<u8> = other.query_row("SELECT value FROM kv WHERE slot=? AND key=?", params![slot, &key], |row| row.get(0)).unwrap();
        other.execute("UPDATE kv SET value=X'00' WHERE slot=? AND key=?", params![slot, &key]).unwrap();
        let error = node.next_nonces(&senders).unwrap_err();
        assert!(error.requires_owner_stop());
        assert!(node.db.is_autocommit());
        other.execute("UPDATE kv SET value=? WHERE slot=? AND key=?", params![raw, slot, key]).unwrap();
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        assert_eq!(logical_rows(&node.db), before);
        drop(other);
        drop(node);
        let node = open(directory.path(), settings, authenticated);
        assert_eq!(node.next_nonces(&senders).unwrap(), expected);
        assert_eq!(logical_rows(&node.db), before);
    }
}

#[test]
fn native_nonce_batch_arithmetic_retains_absence_bad_nonce_and_overflow_rules() {
    let sender = development_public(0).unwrap();
    let key = format!("account:{}", hex::encode(sender));
    let mut state = State::new();
    assert_eq!(next_nonce_from_state(&state, sender).unwrap(), 1);
    for value in [serde_json::json!(null), serde_json::json!({"nonce":-1}), serde_json::json!({"nonce":"1"})] {
        state.insert(key.clone(), value);
        assert_eq!(next_nonce_from_state(&state, sender).unwrap_err().to_string(), "STATE_NONCE");
    }
    state.insert(key, serde_json::json!({"nonce":u64::MAX}));
    assert_eq!(next_nonce_from_state(&state, sender).unwrap_err().to_string(), "NONCE_OVERFLOW");
}
'''

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError(f'expected one source anchor, found {text.count(old)}: {old[:100]!r}')
    return text.replace(old, new, 1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['negative', 'repair'])
    args = parser.parse_args()
    if args.phase == 'negative':
        original = TESTS.read_text()
        assert 'native_account_query_final_callback_write_is_rejected' not in original
        TESTS.write_text(original + READ_TESTS)
        return
    source = STORE.read_text()
    start = source.index('    pub fn authenticated_account_multiproof_with_progress(')
    end = source.index('\n    }', start) + len('\n    }')
    body = source[start:end]
    body = replace_once(body, '        let tx = self.db.unchecked_transaction()?;\n', '        let tx = self.db.unchecked_transaction()?;\n        let read_changes = tx.total_changes();\n')
    body = replace_once(body, '        progress(NativeAccountProofProgress::BeforeOutput)?;\n        tx.commit()?;\n', '''        progress(NativeAccountProofProgress::BeforeOutput)?;
        // A completed read has no write authority. Count same-connection row
        // writes, including a write that a callback subsequently restores.
        // This is a local ownership fence, not an external-writer attestation.
        if tx.total_changes() != read_changes {
            self.invalidate_commitment();
            return Err(Error::from("NATIVE_ACCOUNT_PROOF_WRITE").local_integrity());
        }
        // Never commit a query transaction (including uncounted schema changes).
        tx.rollback()?;
''')
    source = source[:start] + body + source[end:]
    old = '''    pub fn next_nonce(&self, sender: Hash) -> Result<u64> {
        let state = self.state_at(self.active()?.0)?;
        let key = format!("account:{}", hex::encode(sender));
        let current = match state.get(&key) {
            None => 0,
            Some(account) => account
                .get("nonce")
                .and_then(serde_json::Value::as_u64)
                .ok_or("STATE_NONCE")?,
        };
        current
            .checked_add(1)
            .ok_or_else(|| "NONCE_OVERFLOW".into())
    }
'''
    new = '''    pub fn next_nonce(&self, sender: Hash) -> Result<u64> {
        let state = self.state_at(self.active()?.0)?;
        next_nonce_from_state(&state, sender)
    }
    /// Read up to 256 distinct senders from ONE fully checked SQLite snapshot.
    /// Results preserve input order and reserve no nonce or execution authority.
    /// The legacy singleton path is unchanged; no successful verdict survives a call.
    pub fn next_nonces(&self, senders: &[Hash]) -> Result<Vec<u64>> {
        ensure((1..=256).contains(&senders.len()), "NONCE_QUERY_LIMIT")?;
        let unique: std::collections::BTreeSet<_> = senders.iter().collect();
        ensure(unique.len() == senders.len(), "DUPLICATE_NONCE_QUERY")?;
        self.namespace()?;
        let tx = self.db.unchecked_transaction()?;
        self.storage_context()?;
        let state = self.state_at(self.active()?.0)?;
        let values = senders
            .iter()
            .map(|sender| next_nonce_from_state(&state, *sender))
            .collect::<Result<Vec<_>>>()?;
        tx.rollback()?;
        Ok(values)
    }
'''
    source = replace_once(source, old, new)
    helper = '''// The same checked successor arithmetic serves singleton and batched reads.
fn next_nonce_from_state(state: &State, sender: Hash) -> Result<u64> {
    let key = format!("account:{}", hex::encode(sender));
    let current = match state.get(&key) {
        None => 0,
        Some(account) => account
            .get("nonce")
            .and_then(serde_json::Value::as_u64)
            .ok_or("STATE_NONCE")?,
    };
    current.checked_add(1).ok_or_else(|| "NONCE_OVERFLOW".into())
}

'''
    source = replace_once(source, '/// One private native namespace; no reference subprocess or remote state setter exists.\n', helper + '/// One private native namespace; no reference subprocess or remote state setter exists.\n')
    STORE.write_text(source)
    TESTS.write_text(TESTS.read_text() + BATCH_TESTS)
    pipeline = PIPE.read_text()
    pipeline = replace_once(pipeline, '''                first_intake.get_or_insert(intake);
                for offset in 0..batch {
''', '''                first_intake.get_or_insert(intake);
                let sender_count = if pattern == "hot" { 1 } else { batch.min(4) };
                let senders = (0..sender_count)
                    .map(|index| development_public(index as u64))
                    .collect::<Result<Vec<_>>>()?;
                let nonces = producer.next_nonces(&senders)?;
                for (index, nonce) in nonces.into_iter().enumerate() {
                    next.insert(index as u64, nonce);
                }
                for offset in 0..batch {
''')
    pipeline = replace_once(pipeline, '''                    // One owner read per sender and block. An eager or_insert argument
                    // rereads the entire authenticated state for every transfer.
                    let nonce = match next.entry(sender_index) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(producer.next_nonce(sender)?)
                        }
                        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    };
''', '''                    // All senders share one checked snapshot, not one full
                    // state read per sender. The existing signed nonce rules remain.
                    let nonce = next.get_mut(&sender_index).ok_or("NONCE_QUERY_RESULT")?;
''')
    PIPE.write_text(pipeline)
    DOC.write_text(DOC.read_text() + '''\n\n## Read-only proof completion and batched nonce observations\n\nThe account multiproof reader retains its complete state, record, node, root and\ncallback checks. After the final callback it rejects same-connection row writes\nwith local `NATIVE_ACCOUNT_PROOF_WRITE`, including write-then-restore. Successful\nreads end by rollback, never commit. Existing cancellation keeps its original\nidentity and rolls back; this is a local ownership fence, not a sandbox for an\narbitrary callback or proof against a privileged writer. No schema or consensus\nbytes change. The original mutation/cancellation tests remain.\n\n`Node::next_nonces` accepts 1..256 distinct senders, rejects malformed dimensions\nbefore storage, and returns results in input order from one current, complete\nchecked SQLite snapshot. It shares exact absence/nonce/overflow arithmetic with\n`next_nonce`, without changing the singleton's existing I/O path. The snapshot\nends by rollback and stores no nonce reservation. The next call rereads actual\nstate; a returned nonce is not a signing or final-use capability.\n\nThe existing continuous pipeline now obtains its one-to-four sender nonces in\none call per business block instead of one complete state read per sender.\nAll mining, admission, activation, TCP, membership and confirmation stages\nremain. This removes repeated full-state acquisition within this specific caller;\nfull state/root/account verification and full retained history costs remain.\nNo constant-time state, throughput multiplier, saturated TPS, independent WAN,\nphysical power-loss or public work qualification follows from the source change.\n''')
    subprocess.run(['git', 'diff', '--check'], check=True)

if __name__ == '__main__':
    main()
