struct NativeCampaignTestSigner {
    id: String,
    public: String,
    key: SigningKey,
}
impl trnm_application_tx_builder_v0::ApplicationSignerV0 for NativeCampaignTestSigner {
    fn signer_id(&self) -> &str {
        &self.id
    }
    fn signer_role(&self) -> &str {
        "operator"
    }
    fn public_key_hex(&self) -> &str {
        &self.public
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer;
        Ok(self.key.sign(bytes).to_bytes())
    }
}
fn native_socket_exchange(
    runtime: &mut crate::native_client_runtime::NativeClientRuntimeV1,
    path: &Path,
    parent: u64,
    finalized: u64,
    request: serde_json::Value,
) -> serde_json::Value {
    use std::io::{Read, Write};
    let mut socket = std::os::unix::net::UnixStream::connect(path).unwrap();
    let bytes = serde_json::to_vec(&request).unwrap();
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    socket.write_all(&bytes).unwrap();
    socket.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut response = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "actual native socket reply timed out"
        );
        runtime.poll_v1(parent, finalized).unwrap();
        let mut buffer = [0u8; 64 * 1024];
        match socket.read(&mut buffer) {
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("native socket read: {e}"),
        }
        if response.len() >= 4 {
            let n = u32::from_be_bytes(response[..4].try_into().unwrap()) as usize;
            if response.len() == n + 4 {
                return serde_json::from_slice(&response[4..]).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn observe_native_test_finality_v1(
    client: &mut crate::native_client_runtime::NativeClientRuntimeV1,
    authority: &ContinuousValidatorAuthorityV0,
    headers: &std::collections::BTreeMap<
        trnm_consensus_types::BlockId,
        trnm_consensus_types::BlockHeader,
    >,
) -> Result<()> {
    if authority.facts_v0()?.finalized_height_v0() < 4 {
        return Ok(());
    }
    let query = authority.native_finalized_query_v1()?;
    let parent = headers
        .get(
            &query
                .proof_v0()
                .proof_v0()
                .finalized_block()
                .header()
                .parent_id(),
        )
        .unwrap();
    client.observe_finality_v1(authority, parent)
}

#[test]
fn actual_native_socket_submit_wal_consensus_commit_and_historical_proof_v1() {
    run_native_socket_finality_case_v1(false);
}
#[test]
fn native_delayed_multi_height_archive_commits_real_historical_business_v1() {
    run_native_socket_finality_case_v1(true);
}
fn run_native_socket_finality_case_v1(defer_archive: bool) {
    on_bounded_takeover_owner_stack_v0(move || {
        use trnm_application_tx_builder_v0::{
            build_signed_canonical_tx_v0, CanonicalTxBuildContextV0, TxBuilderLimitsV0,
        };
        let temp = private_temp_v0();
        let (set, parameters, keys) = fixture_validator_set_v0(4);
        let mut profile = crate::native_client_profile::generate_isolated_native_client_profile_v1(
            &temp.path().join("client-keys"),
            set.chain_id().as_str(),
        )
        .unwrap();
        crate::bootstrap_material::write_native_client_test_bootstrap_v1(
            temp.path(),
            set.clone(),
            parameters,
            keys.clone(),
            &profile,
        )
        .unwrap();
        let lifetime =
            ContinuousSignerLifetimeBoundsV0::from_exact_test_bounds_v0(4, 0, 4, 0).unwrap();
        let mut authorities = Vec::new();
        let mut headers = std::collections::BTreeMap::new();
        let mut sync_proofs = std::collections::BTreeMap::new();
        for (index, validator) in set.validators().iter().enumerate() {
            let core =
                CoreConfig::new(validator.id(), set.clone(), parameters, 0, 64, 1_024).unwrap();
            let app = NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
                CanonicalLabNativeApplicationConfigInputsV0::new(
                    "native-client-real-e2e",
                    [0x81; 32],
                    [0x82; 32],
                    [0x83; 32],
                    [0x84; 32],
                    validator.id(),
                    set.clone(),
                    parameters,
                    profile.authorized_signers_v1().unwrap(),
                    profile.governance_signer_id.clone(),
                )
                .unwrap(),
            )
            .unwrap();
            let verified =
                crate::bootstrap_material::verify_public_native_bootstrap_with_policy_v1(
                    temp.path(),
                    &set,
                    &parameters,
                    profile.authorized_signers_v1().unwrap(),
                    &profile.governance_signer_id,
                )
                .unwrap();
            let (proposals, proof) = verified.into_node_parts_v1();
            sync_proofs.insert(1, proof.clone());
            for p in &proposals {
                headers.insert(p.block().id(), p.block().header().clone());
            }
            let bootstrap = trnm_poco_node::PocoNodeDeployedLabBootstrapV0::admit_exact_v0(
                &core, &app, proposals, proof,
            )
            .unwrap();
            let root = temp.path().join(format!("owner-{index}"));
            create_private_directory_v0(&root).unwrap();
            let runtime = trnm_poco_node::commission_deployed_lab_ordinary_runtime_v0(
                root,
                core,
                app,
                bootstrap,
                |path| LabFileWatermark::open(path),
            )
            .unwrap();
            authorities.push(
                ContinuousValidatorAuthorityV0::from_takeover_parts_v0(
                    validator.id(),
                    set.clone(),
                    parameters,
                    keys[index].clone(),
                    4,
                    runtime,
                    lifetime,
                )
                .unwrap(),
            );
        }
        // Publish one agreed fresh wall-clock epoch before the public socket
        // opens. The canonical chain prefix/genesis remains timestamp 0.
        profile.wall_clock_epoch_ms =
            crate::native_client_profile::unix_now_ms_v1().unwrap() - 4_000;
        let view = authorities[0].facts_v0().unwrap().current_view_v0();
        let leader = leader_for(&set, view);
        let leader_index = set
            .validators()
            .iter()
            .position(|v| v.id() == leader)
            .unwrap();
        let client_root = temp.path().join("client-node");
        create_private_directory_v0(&client_root).unwrap();
        let mut clients = crate::native_client_runtime::NativeClientRuntimeV1::open_parts_v1(
            &client_root,
            &set,
            leader,
            profile.clone(),
        )
        .unwrap();
        let socket = client_root
            .join("native-client-v1")
            .join(&profile.socket_basename);
        let seed = hex::decode(
            std::fs::read_to_string(temp.path().join("client-keys/operator.key")).unwrap(),
        )
        .unwrap();
        let signer = NativeCampaignTestSigner {
            id: profile.signers[0].signer_id.clone(),
            public: profile.signers[0].public_key_hex.clone(),
            key: SigningKey::from_bytes(&seed.try_into().unwrap()),
        };
        let now = profile.chain_now_ms_v1().unwrap();
        let tx = build_signed_canonical_tx_v0(
            CanonicalTxBuildContextV0 {
                chain_id: set.chain_id().as_str().to_owned(),
                sender: signer.id.clone(),
                command_id: None,
                transaction_sequence: 1,
                issued_at_unix_ms: now,
                expires_at_unix_ms: now + 300_000,
                max_gas: 100_000,
                fee_limit: 1_000_000,
                limits: TxBuilderLimitsV0::candidate_v0(),
            },
            trnm_protocol::CanonicalCommandV1::CreditAccount {
                account: profile.signers[1].signer_id.clone(),
                amount: 1_000_000,
            },
            &signer,
        )
        .unwrap();
        let hash = tx.envelope().tx_hash().unwrap();
        let request = serde_json::json!({"schema":"trnm.native-client.request.v1","request_id":"e2e-submit","op":"submit","data":{"signed_outer_hex":hex::encode(tx.exact_outer_bytes())}});
        let first = native_socket_exchange(&mut clients, &socket, 3_000, 1, request.clone());
        assert_eq!(first["ok"], true, "real signed submit rejected: {first}");
        assert_eq!(first["data"]["status"], "pending");
        assert_eq!(first["data"]["receive_sequence"], "1");
        assert_eq!(
            native_socket_exchange(&mut clients, &socket, 3_000, 1, request.clone()),
            first
        );
        let proposal = clients
            .maybe_proposal_v1(
                &mut authorities[leader_index],
                true,
                parameters.max_block_time_step_ms(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(proposal.block().header().height().get(), 4);
        let business_id = proposal.block().id();
        headers.insert(proposal.block().id(), proposal.block().header().clone());
        drive_parallel_deployed_authority_round_v0(&mut authorities, proposal).unwrap();
        let sync_query = authorities[leader_index].native_finalized_query_v1().unwrap();
        sync_proofs.insert(sync_query.proof_v0().proof_v0().finalized_block().header().height().get(), sync_query.proof_v0().proof_v0().clone());
        observe_native_test_finality_v1(&mut clients, &authorities[leader_index], &headers)
            .unwrap();
        if !defer_archive {
            clients.cut_after_next_durable_proof_v1();
        }
        let mut deferred = Vec::new();
        let mut observed_cut = false;
        for _ in 0..3 {
            let facts = authorities[0].facts_v0().unwrap();
            let leader = leader_for(&set, facts.current_view_v0());
            let index = set
                .validators()
                .iter()
                .position(|v| v.id() == leader)
                .unwrap();
            let timestamp = authorities[index].native_parent_timestamp_v1().unwrap() + 1;
            let proposal = authorities[index]
                .signed_native_proposal_v1(Vec::new(), timestamp)
                .unwrap();
            headers.insert(proposal.block().id(), proposal.block().header().clone());
            drive_parallel_deployed_authority_round_v0(&mut authorities, proposal).unwrap();
            let sync_query = authorities[leader_index].native_finalized_query_v1().unwrap();
            sync_proofs.insert(sync_query.proof_v0().proof_v0().finalized_block().header().height().get(), sync_query.proof_v0().proof_v0().clone());
            if defer_archive {
                if authorities[leader_index]
                    .facts_v0()
                    .unwrap()
                    .finalized_height_v0()
                    >= 4
                {
                    let query = authorities[leader_index]
                        .native_finalized_query_v1()
                        .unwrap();
                    let proof = query.proof_v0().proof_v0().clone();
                    let parent = headers[&proof.finalized_block().header().parent_id()].clone();
                    deferred.push((proof, parent));
                }
                continue;
            }
            if let Err(error) =
                observe_native_test_finality_v1(&mut clients, &authorities[leader_index], &headers)
            {
                assert!(error.to_string().contains("test cut after durable proof"));
                observed_cut = true;
                drop(clients);
                assert!(
                    crate::native_client_runtime::NativeClientRuntimeV1::open_parts_v1(
                        &client_root,
                        &set,
                        set.validators()[leader_index].id(),
                        profile.clone()
                    )
                    .is_err()
                );
                clients=crate::native_client_runtime::NativeClientRuntimeV1::open_parts_with_recovery_v1(&client_root,&set,set.validators()[leader_index].id(),profile.clone(),Some(&authorities[leader_index])).unwrap();
            }
        }
        if defer_archive {
            assert_eq!(deferred.len(), 2);
            assert_eq!(clients.last_archived_finalized_height_v1(), 0);
            for (proof, parent) in deferred {
                clients
                    .observe_finality_evidence_v1(&authorities[leader_index], &proof, &parent)
                    .unwrap();
            }
        } else {
            assert!(observed_cut, "native proof/WAL crash cut was not reached");
        }
        let facts = authorities[leader_index].facts_v0().unwrap();
        assert!(facts.finalized_height_v0() > 4);
        let committed = native_socket_exchange(
            &mut clients,
            &socket,
            now + 10,
            facts.finalized_height_v0(),
            request,
        );
        assert_eq!(committed["data"]["status"], "committed");
        assert_eq!(committed["data"]["receive_sequence"], "1");
        let proof = native_socket_exchange(
            &mut clients,
            &socket,
            now + 10,
            facts.finalized_height_v0(),
            serde_json::json!({"schema":"trnm.native-client.request.v1","request_id":"proof-old-tip","op":"proof","data":{"native_tx_hash":hex::encode(hash)}}),
        );
        assert_eq!(proof["ok"], true, "historical proof unavailable: {proof}");
        assert_eq!(proof["data"]["proof_verified"], true);
        assert_eq!(proof["data"]["m05_intent_binding"], false);
        let encoded = hex::decode(proof["data"]["package_hex"].as_str().unwrap()).unwrap();
        let package =
            trnm_tx_lifecycle_v0::NativeTxProofPackageV1::decode_exact(&encoded, 4 * 1024 * 1024)
                .unwrap();
        assert_eq!(package.transaction, tx.exact_outer_bytes());
        let parent_bytes =
            hex::decode(proof["data"]["parent_header_hex"].as_str().unwrap()).unwrap();
        let independent = trnm_tx_lifecycle_v0::verify_native_tx_inclusion_with_parent_header_v1(
            &encoded,
            &parent_bytes,
            trnm_tx_lifecycle_v0::NativeTxParentHeaderContextV1 {
                trusted_validator_set: &set,
                trusted_parameters: &parameters,
                maximum_transactions: 64,
                maximum_proof_bytes: 4 * 1024 * 1024,
            },
            &mut trnm_consensus_types::Cev0AdmissionBudgetV0::for_validator_set(&parameters, &set),
        )
        .unwrap();
        assert_eq!(
            independent.native_transaction_bytes(),
            tx.exact_outer_bytes()
        );

        assert_eq!(
            trnm_consensus_types::decode_block_header_v0_exact(&package.target_header)
                .unwrap()
                .id(),
            business_id
        );
        clients.persist_sync_bootstrap_v1(&[sync_proofs[&1].clone(), sync_proofs[&2].clone(), sync_proofs[&3].clone()]).unwrap();
        if defer_archive {
            verify_actual_native_replay_sync_v1(&temp, &mut clients, &socket, &set, &profile, facts.finalized_height_v0(), tx.exact_outer_bytes());
        }
        assert!(clients.drained_v1(facts.finalized_height_v0()));
        drop(clients);
        let mut reopened = crate::native_client_runtime::NativeClientRuntimeV1::open_parts_v1(
            &client_root,
            &set,
            set.validators()[leader_index].id(),
            profile,
        )
        .unwrap();
        let status = native_socket_exchange(
            &mut reopened,
            &socket,
            now + 10,
            facts.finalized_height_v0(),
            serde_json::json!({"schema":"trnm.native-client.request.v1","request_id":"after-reopen","op":"transaction","data":{"native_tx_hash":hex::encode(hash)}}),
        );
        assert_eq!(status["data"]["status"], "committed");
    });
}

#[test]
fn native_socket_rejects_duplicate_unknown_uppercase_and_noncanonical_requests_v1() {
    use std::io::{Read, Write};
    let temp = private_temp_v0();
    let (set, _, _) = fixture_validator_set_v0(4);
    let profile = crate::native_client_profile::generate_isolated_native_client_profile_v1(
        &temp.path().join("keys"),
        set.chain_id().as_str(),
    )
    .unwrap();
    let mut owner = crate::native_client_runtime::NativeClientRuntimeV1::open_parts_v1(
        temp.path(),
        &set,
        set.validators()[0].id(),
        profile.clone(),
    )
    .unwrap();
    let socket = temp
        .path()
        .join("native-client-v1")
        .join(&profile.socket_basename);
    for request in [
        r#"{"schema":"trnm.native-client.request.v1","request_id":"x","op":"submit","data":{"signed_outer_hex":"aa","signed_outer_hex":"aa"}}"#,
        r#"{"schema":"trnm.native-client.request.v1","request_id":"x","op":"status","data":{},"surprise":1}"#,
        r#"{"schema":"trnm.native-client.request.v1","request_id":"x","op":"submit","data":{"signed_outer_hex":"AA"}}"#,
        r#"{"schema":"trnm.native-client.request.v1","request_id":"x","request_id":"y","op":"status","data":{}}"#,
    ] {
        let mut peer = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        peer.write_all(&(request.len() as u32).to_be_bytes())
            .unwrap();
        peer.write_all(request.as_bytes()).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        peer.set_nonblocking(true).unwrap();
        let mut reply = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < deadline);
            owner.poll_v1(3_000, 1).unwrap();
            let mut buffer = [0u8; 4_096];
            match peer.read(&mut buffer) {
                Ok(n) => reply.extend_from_slice(&buffer[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            };
            if reply.len() >= 4
                && reply.len() == 4 + u32::from_be_bytes(reply[..4].try_into().unwrap()) as usize
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let response: serde_json::Value = serde_json::from_slice(&reply[4..]).unwrap();
        assert_eq!(response["ok"], false, "unexpected acceptance {request}");
        assert_eq!(response["error"]["code"], "invalid_request");
    }
    // A second live owner cannot remove or steal the first owner's socket.
    assert!(
        crate::native_client_runtime::NativeClientRuntimeV1::open_parts_v1(
            temp.path(),
            &set,
            set.validators()[0].id(),
            profile
        )
        .is_err()
    );
    let status = native_socket_exchange(
        &mut owner,
        &socket,
        3_000,
        1,
        serde_json::json!({"schema":"trnm.native-client.request.v1","request_id":"still-alive","op":"status","data":{}}),
    );
    assert_eq!(status["ok"], true);
}

fn verify_actual_native_replay_sync_v1(
    temp: &tempfile::TempDir, client: &mut crate::native_client_runtime::NativeClientRuntimeV1,
    socket: &Path, set: &ValidatorSet,
    profile: &crate::native_client_profile::NativeClientProfileV1, target: u64, outer: &[u8],
) {
    use crate::native_replay_sync_v1::{NativeReplayReceiverV1, ReplayManifestV1, CHUNK_BYTES};
    let parameters = ConsensusParametersV0::reference_shadow_v0();
    let config = || NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
        CanonicalLabNativeApplicationConfigInputsV0::new("native-replay-receiver", [0x91;32],[0x92;32],[0x93;32],[0x94;32],set.validators()[0].id(),set.clone(),parameters,profile.authorized_signers_v1().unwrap(),profile.governance_signer_id.clone()).unwrap()
    ).unwrap();
    let response = native_socket_exchange(client,socket,10_000,target,serde_json::json!({"schema":"trnm.native-client.request.v1","request_id":"sync-manifest","op":"sync_manifest","data":{"target_height":target}}));
    assert_eq!(response["ok"],true,"sync manifest missing: {response}");
    let manifest: ReplayManifestV1=serde_json::from_value(response["data"].clone()).unwrap();
    let root=temp.path().join("sync-receiver");
    let profile_hash=profile.digest_v1().unwrap();
    let mut receiver=NativeReplayReceiverV1::open(&root,config(),profile_hash,target,manifest.clone()).unwrap();
    let application_path=receiver.application_path();
    assert!(NativeReplayReceiverV1::open(&root,config(),profile_hash,target,manifest.clone()).is_err());
    let mut transferred=Vec::new();
    for (offset,record) in manifest.records.iter().enumerate() {
        let height=offset as u64+1;
        for index in 0..(record.bytes as usize).div_ceil(CHUNK_BYTES) {
            let response=native_socket_exchange(client,socket,10_000,target,serde_json::json!({"schema":"trnm.native-client.request.v1","request_id":format!("sync-{height}-{index}"),"op":"sync_chunk","data":{"height":height,"index":index,"record_sha256":record.sha256}}));
            assert_eq!(response["ok"],true,"sync chunk missing: {response}");
            let bytes=hex::decode(response["data"]["bytes_hex"].as_str().unwrap()).unwrap();
            if height<=3 {
                let mut poison = bytes.clone(); poison[0] ^= 1;
                assert!(receiver.accept_chunk(height,index,&poison).is_err());
                assert!(!receiver.has_chunk(height,index).unwrap());
                receiver.accept_chunk(height,index,&bytes).unwrap();
            }
            transferred.push((height,index,bytes));
        }
    }
    assert!(receiver.replay_and_publish(config()).is_err(),"incomplete transfer must not publish");
    assert!(!root.join("CURRENT").exists()); drop(receiver);
    let app=trnm_native_execution_v0::DurableNativeApplicationV0::open(application_path.clone(),config()).unwrap();
    assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(),3); drop(app);
    let mut receiver=NativeReplayReceiverV1::open(&root,config(),profile_hash,target,manifest.clone()).unwrap();
    for (height,index,bytes) in &transferred {
        receiver.accept_chunk(*height,*index,bytes).unwrap();
        let mut wrong=bytes.clone(); wrong[0]^=1;
        assert!(receiver.accept_chunk(*height,*index,&wrong).is_err(),"persisted chunk substitution must reject");
    }
    let head=receiver.replay_and_publish(config()).unwrap();
    assert_eq!(head.height().get(),target);
    assert_eq!(hex::encode(head.block_id().as_bytes()),manifest.target_block_id);
    assert!(root.join("CURRENT").is_file()); drop(receiver);
    let mut retry=NativeReplayReceiverV1::open(&root,config(),profile_hash,target,manifest.clone()).unwrap();
    assert_eq!(retry.replay_and_publish(config()).unwrap(),head); drop(retry);
    let app=trnm_native_execution_v0::DurableNativeApplicationV0::open(application_path.clone(),config()).unwrap();
    let business=app.read_finalized_by_height_v0(trnm_native_application::HeightV0::new(4)).unwrap();
    assert_eq!(business.executed_v0().request().transactions(), &[outer.to_vec()]);
    // Replay protection is derived by execution, never supplied by the peer.
    let parent_time=app.read_finalized_by_height_v0(trnm_native_application::HeightV0::new(target)).unwrap().executed_v0().request().timestamp_ms();
    let preview=|transactions| trnm_native_execution_v0::NativeBlockPreviewRequestV0::new(
        trnm_native_application::ChainIdV0::new(set.chain_id().as_str()).unwrap(),
        trnm_native_application::GenesisHashV0::new(*set.genesis_hash().as_bytes()).unwrap(),
        head.clone(),trnm_native_application::HeightV0::new(target+1),parent_time+1,
        trnm_native_application::ValidatorSetIdV0::new(*set.id().as_bytes()).unwrap(),transactions,
    ).unwrap();
    assert!(app.preview_block_v0(&preview(Vec::new())).is_ok());
    let duplicate=app.preview_block_v0(&preview(vec![outer.to_vec()])).unwrap_err();
    assert_eq!(duplicate.code(),trnm_native_execution_v0::NativeApplicationExecutionErrorCodeV0::DeterministicallyInvalid);
    assert_eq!(app.confirmed_committed_head_v0().unwrap(),head);
    drop(app);
    assert!(NativeReplayReceiverV1::open(&temp.path().join("wrong-profile"),config(),[0x55;32],target,manifest.clone()).is_err());
    assert!(NativeReplayReceiverV1::open(&temp.path().join("wrong-target"),config(),profile_hash,target-1,manifest.clone()).is_err());
    // A process-local lock cannot survive namespace substitution unnoticed.
    let swapped=temp.path().join("sync-root-swap");
    let held=NativeReplayReceiverV1::open(&swapped,config(),profile_hash,target,manifest.clone()).unwrap();
    std::fs::rename(&swapped,temp.path().join("sync-root-displaced")).unwrap();
    create_private_directory_v0(&swapped).unwrap();
    assert!(held.accept_chunk(transferred[0].0,transferred[0].1,&transferred[0].2).is_err()); drop(held);
    let symlink=temp.path().join("sync-root-alias");
    std::os::unix::fs::symlink(&root,&symlink).unwrap();
    assert!(NativeReplayReceiverV1::open(&symlink,config(),profile_hash,target,manifest.clone()).is_err());
    // Re-hashing an invalid signature still cannot authenticate a source.
    let mut corrupt_manifest=manifest.clone();
    let mut corrupt=transferred.clone();
    let (_,_,first)=&mut corrupt[0];
    let mut record:crate::native_replay_sync_v1::ReplayRecordV1=serde_json::from_slice(first).unwrap();
    let last=record.finality_hex.len()-2; let changed=if &record.finality_hex[last..]=="00" {"01"} else {"00"};
    record.finality_hex.replace_range(last..,changed);
    *first=serde_json::to_vec(&record).unwrap();
    corrupt_manifest.records[0].sha256=hex::encode(sha2::Sha256::digest(&*first));
    corrupt_manifest.records[0].chunk_sha256=first.chunks(CHUNK_BYTES).map(|bytes|hex::encode(sha2::Sha256::digest(bytes))).collect();
    let badproof_root=temp.path().join("sync-bad-proof");
    let mut badproof=NativeReplayReceiverV1::open(&badproof_root,config(),profile_hash,target,corrupt_manifest).unwrap();
    for (height,index,bytes) in &corrupt {badproof.accept_chunk(*height,*index,bytes).unwrap();}
    assert!(badproof.replay_and_publish(config()).is_err());
    assert!(!badproof_root.join("CURRENT").exists());
    drop(badproof);
    let mut honest_retry=NativeReplayReceiverV1::open(&badproof_root,config(),profile_hash,target,manifest.clone()).unwrap();
    for (height,index,bytes) in &transferred {honest_retry.accept_chunk(*height,*index,bytes).unwrap();}
    assert_eq!(honest_retry.replay_and_publish(config()).unwrap(),head);
    assert!(badproof_root.join("CURRENT").exists());

    // Same byte lengths and a matching attacker-chosen transfer hash do not
    // authenticate altered proof/body data: actual execution remains decisive.
    let mut malicious=manifest.clone();
    let mut changed=transferred.clone();
    for (height,index,bytes) in &mut changed {
        if *height==4 && *index==0 {
            let mut record:crate::native_replay_sync_v1::ReplayRecordV1=serde_json::from_slice(bytes).unwrap();
            record.transactions_hex[0].replace_range(0..2,"00");
            *bytes=serde_json::to_vec(&record).unwrap();
            malicious.records[3].sha256=hex::encode(sha2::Sha256::digest(&*bytes));
            malicious.records[3].chunk_sha256=bytes.chunks(CHUNK_BYTES).map(|part|hex::encode(sha2::Sha256::digest(part))).collect();
        }
    }
    let badroot=temp.path().join("sync-bad-body");
    let mut bad=NativeReplayReceiverV1::open(&badroot,config(),profile_hash,target,malicious).unwrap();
    for (height,index,bytes) in &changed {bad.accept_chunk(*height,*index,bytes).unwrap();}
    assert!(bad.replay_and_publish(config()).is_err());
    assert!(!badroot.join("CURRENT").exists());
}
