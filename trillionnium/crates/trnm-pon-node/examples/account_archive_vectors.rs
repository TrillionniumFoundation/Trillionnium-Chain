//! Actual bounded archive observations for a separately implemented Python oracle.
//! Usage: account_archive_vectors NEW_OUTPUT_DIRECTORY
#[path = "support/account_archive_artifact.rs"]
mod account_archive_artifact;
use account_archive_artifact::finish_archive_artifact;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_mvcc_fee::{continuity_v1, pon_executor};
use trnm_pon_node::{
    account_archive_prototype::{
        Account, AccountArchive, ArchiveError, CheckedAccounts, Checkpoint, Context, Limits,
        ResearchUpdate, Witness,
    },
    development_public, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Envelope, Hash};

fn owner(n: u64) -> Hash {
    let mut out = [0; 32];
    out[..8].copy_from_slice(&n.to_le_bytes());
    out
}
fn rows(path: &Path) -> Value {
    let db = Connection::open(path).unwrap();
    let nodes: Vec<Value> = db.prepare("SELECT id,data FROM archive_nodes ORDER BY id").unwrap().query_map([], |row| Ok(json!({"id":hex::encode(row.get::<_,Vec<u8>>(0)?),"data":hex::encode(row.get::<_,Vec<u8>>(1)?)}))).unwrap().map(|r| r.unwrap()).collect();
    let checkpoints: Vec<Value> = db.prepare("SELECT id,branch,data FROM archive_checkpoints ORDER BY id").unwrap().query_map([], |row| Ok(json!({"id":hex::encode(row.get::<_,Vec<u8>>(0)?),"branch":hex::encode(row.get::<_,Vec<u8>>(1)?),"data":hex::encode(row.get::<_,Vec<u8>>(2)?)}))).unwrap().map(|r| r.unwrap()).collect();
    let active: Vec<Value> = db.prepare("SELECT singleton,checkpoint,generation FROM archive_active ORDER BY singleton").unwrap().query_map([], |row| Ok(json!({"singleton":row.get::<_,u64>(0)?,"checkpoint":hex::encode(row.get::<_,Vec<u8>>(1)?),"generation":row.get::<_,u64>(2)?}))).unwrap().map(|r| r.unwrap()).collect();
    let meta: Vec<Value> = db
        .prepare("SELECT key,value FROM archive_meta ORDER BY key")
        .unwrap()
        .query_map([], |row| {
            Ok(json!({"key":row.get::<_,String>(0)?,"value":hex::encode(row.get::<_,Vec<u8>>(1)?)}))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    json!({"archive_nodes":nodes,"archive_checkpoints":checkpoints,"archive_active":active,"archive_meta":meta})
}
fn snapshot(
    archive: &AccountArchive,
    label: &str,
    checkpoint: &Checkpoint,
    values: &BTreeMap<Hash, Account>,
    state: Option<&pon_executor::State>,
    owners: &[Hash],
) -> Value {
    let queries: Vec<_> = owners.iter().map(|&owner| {
        let (witness, node_reads) = archive.witness(checkpoint.id(), owner).unwrap();
        let bytes = witness.encode().unwrap();
        json!({"owner":owner,"witness":witness,"node_reads":node_reads,"binary_hex":hex::encode(bytes)})
    }).collect();
    let accounts: Vec<_> = values
        .iter()
        .map(|(&owner, &account)| json!({"owner":owner,"account":account}))
        .collect();
    json!({"label":label,"source_kind":if state.is_some(){"native-node-admitted-state"}else{"synthetic-account-space"},"state":state,"accounts":accounts,"checkpoint":checkpoint,"queries":queries})
}
fn extract(state: &pon_executor::State) -> BTreeMap<Hash, Account> {
    state
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("account:").map(|owner| {
                (
                    hex::decode(owner).unwrap().try_into().unwrap(),
                    serde_json::from_value(value.clone()).unwrap(),
                )
            })
        })
        .collect()
}
fn operation(
    archive: &mut AccountArchive,
    path: &Path,
    kind: &str,
    input: Value,
    action: impl FnOnce(&mut AccountArchive) -> trnm_pon_node::account_archive_prototype::Result<Value>,
) -> Value {
    let before_active = archive.active().unwrap();
    let before_storage = archive.observation().unwrap();
    let before_rows = rows(path);
    let result = action(archive);
    let (outcome, output) = match result {
        Ok(value) => ("PASS".to_owned(), value),
        Err(error) => (format!("{error:?}"), Value::Null),
    };
    json!({"kind":kind,"input":input,"outcome":outcome,"output":output,"before_active":before_active,"after_active":archive.active().unwrap(),"before_storage":before_storage,"after_storage":archive.observation().unwrap(),"before_rows":before_rows,"after_rows":rows(path)})
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        2,
        "usage: account_archive_vectors NEW_OUTPUT_DIRECTORY"
    );
    let output = std::path::PathBuf::from(&args[1]);
    fs::create_dir(&output).expect("output directory must not already exist");
    let path = output.join("archive.sqlite");
    let settings = Settings::development_with_profiles(
        Some(1),
        "native-public-evaluation-dev-v1",
        continuity_v1::PROFILE,
    )
    .unwrap();
    let context = Context {
        network: settings.network(),
        parameters: settings.parameters(),
        genesis: settings.genesis(),
    };
    let mut archive = AccountArchive::open(&path, context, Limits::default()).unwrap();
    let mut snapshots = Vec::new();
    let mut operations = Vec::new();
    let empty_values = BTreeMap::new();
    let empty = archive
        .seed_research_accounts([4; 32], &empty_values, &mut || Ok(()))
        .unwrap();
    snapshots.push(snapshot(
        &archive,
        "synthetic-empty",
        &empty,
        &empty_values,
        None,
        &[owner(1), owner(3800)],
    ));
    let single_values = BTreeMap::from([(
        owner(1),
        Account {
            balance: 10,
            nonce: 7,
        },
    )]);
    let single = archive
        .seed_research_accounts([5; 32], &single_values, &mut || Ok(()))
        .unwrap();
    snapshots.push(snapshot(
        &archive,
        "synthetic-single",
        &single,
        &single_values,
        None,
        &[owner(1), owner(3800)],
    ));
    let deep_update = ResearchUpdate {
        owner: owner(3800),
        before: None,
        after: Account {
            balance: 3,
            nonce: 0,
        },
    };
    let mut deep = None;
    operations.push(operation(
        &mut archive,
        &path,
        "research-update",
        json!({"parent":single.id(),"branch":vec![6u8;32],"updates":[deep_update]}),
        |archive| {
            let result =
                archive.research_successor(single.id(), [6; 32], &[deep_update], &mut || Ok(()))?;
            deep = Some(result.clone());
            Ok(json!(result))
        },
    ));
    let deep = deep.unwrap();
    let mut deep_values = single_values.clone();
    deep_values.insert(deep_update.owner, deep_update.after);
    snapshots.push(snapshot(
        &archive,
        "synthetic-deep",
        &deep,
        &deep_values,
        None,
        &[owner(1), owner(3800), owner(99)],
    ));
    let branch_update = ResearchUpdate {
        owner: owner(1),
        before: single_values.get(&owner(1)).copied(),
        after: Account {
            balance: 0,
            nonce: 8,
        },
    };
    let mut branch = None;
    operations.push(operation(
        &mut archive,
        &path,
        "research-update",
        json!({"parent":single.id(),"branch":vec![7u8;32],"updates":[branch_update]}),
        |archive| {
            let result =
                archive
                    .research_successor(single.id(), [7; 32], &[branch_update], &mut || Ok(()))?;
            branch = Some(result.clone());
            Ok(json!(result))
        },
    ));
    let branch = branch.unwrap();
    let branch_values = BTreeMap::from([(owner(1), branch_update.after)]);
    snapshots.push(snapshot(
        &archive,
        "synthetic-branch",
        &branch,
        &branch_values,
        None,
        &[owner(1), owner(3800)],
    ));
    operations.push(operation(
        &mut archive,
        &path,
        "activate",
        json!({"expected":null,"checkpoint":deep.id()}),
        |archive| Ok(json!(archive.activate(None, deep.id(), &mut || Ok(()))?)),
    ));
    let selected = archive.active().unwrap();
    let cancel_update = ResearchUpdate {
        owner: owner(3800),
        before: Some(deep_update.after),
        after: Account {
            balance: 0,
            nonce: 1,
        },
    };
    operations.push(operation(&mut archive, &path, "cancel-research-update", json!({"parent":deep.id(),"branch":vec![8u8;32],"updates":[cancel_update],"cancel_at_progress_call":3}), |archive| {
        let mut calls = 0; let result = archive.research_successor(deep.id(), [8; 32], &[cancel_update], &mut || { calls += 1; if calls == 3 { Err(ArchiveError::Cancelled) } else { Ok(()) } });
        assert_eq!(calls, 3); result.map(|value| json!(value))
    }));
    operations.push(operation(
        &mut archive,
        &path,
        "cancel-activate",
        json!({"expected":selected,"checkpoint":branch.id()}),
        |archive| {
            Ok(json!(archive.activate(
                selected,
                branch.id(),
                &mut || Err(ArchiveError::Cancelled)
            )?))
        },
    ));
    operations.push(operation(
        &mut archive,
        &path,
        "stale-activate",
        json!({"expected":null,"checkpoint":branch.id()}),
        |archive| {
            Ok(json!(archive.activate(
                None,
                branch.id(),
                &mut || Ok(())
            )?))
        },
    ));
    let old_witness = archive.witness(single.id(), owner(1)).unwrap().0;
    operations.push(operation(
        &mut archive,
        &path,
        "old-branch-witness",
        json!({"expected_checkpoint":deep.id(),"requested":[owner(1)],"witnesses":[old_witness]}),
        |_| {
            CheckedAccounts::verify(
                context,
                &deep,
                &[owner(1)],
                std::slice::from_ref(&old_witness),
            )?;
            Ok(json!(true))
        },
    ));
    let rewind = ResearchUpdate {
        owner: owner(1),
        before: Some(branch_update.after),
        after: Account {
            balance: 1,
            nonce: 0,
        },
    };
    operations.push(operation(
        &mut archive,
        &path,
        "nonce-rewind",
        json!({"parent":branch.id(),"branch":vec![9u8;32],"updates":[rewind]}),
        |archive| {
            Ok(json!(archive.research_successor(
                branch.id(),
                [9; 32],
                &[rewind],
                &mut || Ok(())
            )?))
        },
    ));
    let live_witness = archive.witness(deep.id(), owner(1)).unwrap().0;
    let correct = live_witness.encode().unwrap();
    for (case, bytes) in [
        ("wrong-magic", {
            let mut b = correct.clone();
            b[0] ^= 1;
            b
        }),
        ("invalid-presence", {
            let mut b = correct.clone();
            b[68] = 2;
            b
        }),
        ("truncated", correct[..correct.len() - 1].to_vec()),
        ("trailing", {
            let mut b = correct.clone();
            b.push(0);
            b
        }),
    ] {
        operations.push(operation(
            &mut archive,
            &path,
            "decode-witness",
            json!({"case":case,"binary_hex":hex::encode(&bytes)}),
            |_| Ok(json!(Witness::decode(&bytes)?)),
        ));
    }
    let mut wrong_sibling = live_witness.clone();
    wrong_sibling.siblings[12][0] ^= 1;
    let encoded = wrong_sibling.encode().unwrap();
    operations.push(operation(&mut archive, &path, "verify-witness", json!({"case":"wrong-sibling","expected_checkpoint":deep.id(),"requested":[owner(1)],"binary_hex":hex::encode(&encoded)}), |_| {
        let decoded = Witness::decode(&encoded)?; CheckedAccounts::verify(context, &deep, &[owner(1)], &[decoded])?; Ok(json!(true))
    }));
    let db = Connection::open(&path).unwrap();
    let (leaf_id, original): (Vec<u8>,Vec<u8>) = db.query_row("SELECT id,data FROM archive_nodes WHERE length(data)=49 AND substr(data,2,32)=? AND substr(data,34,8)=?", params![owner(1).as_slice(),10u64.to_le_bytes().as_slice()], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    for kind in ["missing-node", "corrupt-node"] {
        let mut replacement = original.clone();
        replacement[40] ^= 1;
        let input = json!({"checkpoint":deep.id(),"owner":owner(1),"row_id":hex::encode(&leaf_id),"original_hex":hex::encode(&original),"replacement_hex":if kind=="corrupt-node" {Some(hex::encode(&replacement))}else{None}});
        operations.push(operation(&mut archive, &path, kind, input, |archive| {
            if kind == "missing-node" { db.execute("DELETE FROM archive_nodes WHERE id=?", [&leaf_id]).unwrap(); }
            else { db.execute("UPDATE archive_nodes SET data=? WHERE id=?", params![replacement,&leaf_id]).unwrap(); }
            let observed = archive.witness(deep.id(), owner(1));
            db.execute("INSERT INTO archive_nodes(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", params![&leaf_id,&original]).unwrap();
            observed.map(|(witness,reads)| json!({"witness":witness,"node_reads":reads}))
        }));
    }
    drop(db);
    // Actual native genesis and one admitted block, signed bytes and full State.
    let mut node = Node::open(&output.join("native-node"), settings.clone(), 1).unwrap();
    let genesis = node.read_active().unwrap();
    let native_initial = archive
        .project_initial(&genesis.2, pon_executor::root(&genesis.2).unwrap())
        .unwrap();
    snapshots.push(snapshot(
        &archive,
        "projection-genesis",
        &native_initial,
        &extract(&genesis.2),
        Some(&genesis.2),
        &[
            development_public(0).unwrap(),
            development_public(10).unwrap(),
        ],
    ));
    let mut payload = development_public(10).unwrap().to_vec();
    payload.extend(500u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce: 1,
        expiry: 2000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0u64.to_le_bytes()]))).unwrap();
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    let signed = envelope.encode().unwrap();
    let packet = node
        .make_consensus_maintenance(
            genesis.0,
            vec![signed.clone()],
            development_public(0).unwrap(),
            11,
            4096,
        )
        .unwrap();
    let id = node.admit(&packet, 100_000).unwrap();
    node.activate(id).unwrap();
    let next_state = node.read_active().unwrap().2;
    let mut native_next = None;
    operations.push(operation(&mut archive, &path, "project-successor", json!({"parent":native_initial.id(),"branch":id,"height":1,"before_state":genesis.2,"after_state":next_state,"signed_transactions_hex":[hex::encode(&signed)],"native_packet_hex":hex::encode(packet.encode().unwrap())}), |archive| {
        let result = archive.project_successor(native_initial.id(), &genesis.2, &next_state, id, 1, &mut || Ok(()))?; native_next = Some(result.clone()); Ok(json!(result))
    }));
    let native_next = native_next.unwrap();
    snapshots.push(snapshot(
        &archive,
        "projection-next",
        &native_next,
        &extract(&next_state),
        Some(&next_state),
        &[
            development_public(0).unwrap(),
            development_public(10).unwrap(),
        ],
    ));
    let expected = archive.active().unwrap();
    operations.push(operation(
        &mut archive,
        &path,
        "activate",
        json!({"expected":expected,"checkpoint":native_next.id()}),
        |archive| {
            Ok(json!(archive.activate(
                expected,
                native_next.id(),
                &mut || Ok(())
            )?))
        },
    ));
    let final_active = archive.active().unwrap();
    let final_storage = archive.observation().unwrap();
    let final_rows = rows(&path);
    drop(node);
    drop(archive);
    let reopened = AccountArchive::open(&path, context, Limits::default()).unwrap();
    assert_eq!(reopened.active().unwrap(), final_active);
    assert_eq!(reopened.observation().unwrap(), final_storage);
    assert_eq!(rows(&path), final_rows);
    drop(reopened);
    let control = Connection::open(&path).unwrap();
    let checkpoint_rows: u64 = control
        .query_row("SELECT COUNT(*) FROM archive_checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(checkpoint_rows, final_storage.checkpoint_rows);
    let finalization = finish_archive_artifact(control, &path, &output).unwrap();
    let observed = json!({"schema":"pon-account-archive-native-observation-v1","context":context,"snapshots":snapshots,"operations":operations,"final_active":final_active,"final_storage":final_storage,"final_rows":final_rows,"database":path,"finalization":finalization,"reopened":true,"archive_used_for_native_execution":false,"protocol_capacity_changed":false,"public_data_availability_accepted":false});
    let bytes = serde_json::to_vec(&observed).unwrap();
    fs::write(output.join("observation.json"), &bytes).unwrap();
    println!("{}", String::from_utf8(bytes).unwrap());
}
