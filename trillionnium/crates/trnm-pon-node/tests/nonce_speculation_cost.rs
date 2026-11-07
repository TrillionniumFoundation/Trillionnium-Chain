//! Complete native-operation comparison across exact pre/post executables.
//! No production legacy-executor selector or synthetic throughput is exposed.
//! The retained negative experiment does not enable mixed-sender skipping in the
//! final production executor. Each observed binary must bind its own exact source.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Write,
    path::Path,
    time::Instant,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_pon_node::{development_public, Node, Settings};
use trnm_protocol::pon_wire::{hash, Envelope};
mod compiled_source {
    include!("../examples/support/distributed_source_inventory.rs");
}

fn transactions(settings: &Settings, senders: u64) -> Vec<Vec<u8>> {
    (0..256)
        .map(|index| {
            let sender = index % senders;
            let key = signing_key_from_hex(&hex::encode(hash(
                b"DEV-ONLY-KEY",
                &[&sender.to_le_bytes()],
            )))
            .unwrap();
            let mut payload = development_public(2).unwrap().to_vec();
            payload.extend(1_u64.to_le_bytes());
            let mut tx = Envelope {
                network: settings.network(),
                sender: development_public(sender).unwrap(),
                nonce: index / senders + 1,
                expiry: 10_000,
                fee_limit: 1000,
                tag: 1,
                payload,
                signature: [0; 64],
            };
            tx.signature = hex::decode(sign_hex(&key, &tx.signing_digest().unwrap()))
                .unwrap()
                .try_into()
                .unwrap();
            tx.encode().unwrap()
        })
        .collect()
}
fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directory_bytes(&entry.path())
            } else {
                entry.metadata().unwrap().len()
            }
        })
        .sum()
}
fn emit(log: &mut File, row: Value) {
    writeln!(log, "{row}").unwrap();
    log.flush().unwrap();
    println!("{row}");
}

#[test]
#[ignore = "exact pre/post binary complete actual256signed-tx native make/admit/activate/reopen comparison; new output directory required"]
fn complete_native_repeated_sender_operation_cost() {
    let out = std::env::var_os("TRNM_NONCE_SPECULATION_COST_DIRECTORY")
        .expect("new outside-checkout output directory required");
    let out = Path::new(&out);
    fs::create_dir(out).unwrap();
    let mut log = File::create(out.join("native-operation-cost.jsonl")).unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    emit(
        &mut log,
        json!({"schema":"native-repeated-sender-cost-source-v1","source_files":compiled_source::FILES.iter().map(|(path,bytes)|json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes))})).collect::<Vec<_>>(),"binary_sha256":hex::encode(Sha256::digest(fs::read(std::env::current_exe().unwrap()).unwrap())),"architecture":std::env::consts::ARCH,"os":std::env::consts::OS,"build_profile":if cfg!(debug_assertions){"debug"}else{"release"},"builder_commit_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_COMMIT"),"builder_tree_claim":option_env!("TRNM_DISTRIBUTED_SOURCE_TREE"),"timed_scope":"complete actual Node.make, complete packet.encode, Node.admit, Node.activate and Packet release; fresh Node.open, transaction construction/copy, full byte/state/root comparison and cold reopen outside clock","comparison_scope":"actual separate pre/post executables and source tuples; no production reference switch","concurrent_context":std::env::var("TRNM_NONCE_CONCURRENT_CONTEXT").ok(),"workers":4,"logical_timestamp":11,"logical_verification_clock":1_000_000,"sample_count_per_case":32,"public_network_ready":false,"production_activation":false,"wan_tps":null,"process_rss":null}),
    );
    let mut samples = 0;
    for (case, senders) in [
        ("mixed_repeated_two_senders", 2),
        ("same_sender_existing_serial_control", 1),
    ] {
        let raws = transactions(&settings, senders);
        let input_hash = hex::encode(hash(
            b"nonce-speculation-cost-input-v1",
            &raws.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        ));
        let mut expected = None;
        for sample in 0..32 {
            let path = out.join(format!("{case}-{sample:02}"));
            let mut node = Node::open(&path, settings.clone(), 4).unwrap();
            let input = raws.clone();
            let started = Instant::now();
            let packet = node
                .make(
                    settings.genesis(),
                    input,
                    development_public(3).unwrap(),
                    11,
                    4096,
                )
                .unwrap();
            let bytes = packet.encode().unwrap();
            let packet_root = packet.header.state;
            let id = node.admit(&packet, 1_000_000).unwrap();
            node.activate(id).unwrap();
            drop(packet);
            let elapsed = started.elapsed().as_nanos();
            let complete = node.read_active().unwrap();
            assert_eq!(complete.0, id);
            assert_eq!(
                trnm_mvcc_fee::pon_executor::root(&complete.2).unwrap(),
                packet_root
            );
            let packet_hash = hex::encode(Sha256::digest(&bytes));
            let state_bytes = serde_json::to_vec(&complete.2).unwrap();
            let state_hash = hex::encode(Sha256::digest(&state_bytes));
            let identity = (packet_hash.clone(), state_hash.clone(), complete.clone());
            if let Some(expected) = &expected {
                assert_eq!(&identity, expected);
            } else {
                fs::write(out.join(format!("{case}-packet.bin")), &bytes).unwrap();
                fs::write(out.join(format!("{case}-state.json")), &state_bytes).unwrap();
                expected = Some(identity);
            }
            let logical_bytes = directory_bytes(&path);
            drop(node);
            let started = Instant::now();
            let reopened = Node::open(&path, settings.clone(), 4).unwrap();
            assert_eq!(reopened.read_active().unwrap(), complete);
            let reopen_ns = started.elapsed().as_nanos();
            emit(
                &mut log,
                json!({"schema":"native-repeated-sender-cost-sample-v1","case":case,"sample":sample,"elapsed_ns":elapsed,"complete_cold_reopen_state_ns":reopen_ns,"input_hash":input_hash,"packet_sha256":packet_hash,"packet_bytes":bytes.len(),"active":hex::encode(id),"generation":complete.1,"state_sha256":state_hash,"actual_state_keys":complete.2.len(),"root":hex::encode(packet_root),"actual_signed_transactions":256,"complete_response_state_root_equal":true,"logical_directory_bytes_while_owner_open":logical_bytes,"disk_scope":"logical database/WAL/SHM files, not physical allocation or permanent retention"}),
            );
            samples += 1;
        }
    }
    emit(
        &mut log,
        json!({"schema":"native-repeated-sender-cost-result-v1","complete":true,"samples":samples,"actual_admitted_activated_blocks":samples,"actual_signed_transactions":samples*256,"single_writer":true,"complete_packet_state_root_reopen_checks":true,"independent_accepted":false,"public_network_ready":false,"production_activation":false,"wan_tps":null}),
    );
}
