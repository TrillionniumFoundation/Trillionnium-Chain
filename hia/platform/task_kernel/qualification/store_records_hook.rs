// This adapter is appended to the exact original store.rs only in an isolated
// oracle. Every semantic decision below invokes the unchanged private method.
pub fn qualification_records_object<B, S>(method:u64,config:AgentMarketStoreConfigV1,kind:ObjectKindV1,id:[u8;32],expected:u64,successor:u64,body:&[u8],state:&[u8])->AgentMarketResultV1<Vec<u8>>
where B:BorshSerialize+BorshDeserialize,S:BorshSerialize+BorshDeserialize {
    let decoded=if method==0{None}else{Some((strict_decode::<B>(body)?,strict_decode::<S>(state)?))};
    let mut connection=open_rw_raw(&config.path,false)?;
    let transaction=connection.transaction()?;
    let out=match method{
        0=>{let (body,state)=load_object::<B,S>(&transaction,kind,&id)?;let body=canonical_bytes(&body)?;let state=canonical_bytes(&state)?;let mut out=(body.len() as u64).to_le_bytes().to_vec();out.extend_from_slice(&(state.len() as u64).to_le_bytes());out.extend_from_slice(&body);out.extend_from_slice(&state);out},
        1=>{let (body,state)=decoded.as_ref().unwrap();insert_object(&transaction,kind,&id,expected,body,state)?;Vec::new()},
        2=>{let (body,state)=decoded.as_ref().unwrap();update_object(&transaction,kind,&id,expected,successor,body,state)?;Vec::new()},
        _=>unreachable!(),
    };
    transaction.commit()?;Ok(out)
}
pub fn qualification_records_operation(method:u64,config:AgentMarketStoreConfigV1,id:[u8;32],body:&[u8],state:&[u8],command_bytes:&[u8])->AgentMarketResultV1<Vec<u8>>{
    let decoded=if method==3{Some((strict_decode::<KernelCommandV1>(body)?,strict_decode::<KernelTransitionReceiptV1>(state)?))}else{None};
    let mut connection=open_rw_raw(&config.path,false)?;
    let transaction=connection.transaction()?;
    let out=if let Some((command,receipt))=decoded{insert_operation(&transaction,&command,command_bytes,&receipt)?;Vec::new()}else{match load_operation(&transaction,KernelOperationIdV1(id),command_bytes)?{Some(receipt)=>canonical_bytes(&receipt)?,None=>Vec::new()}};
    transaction.commit()?;Ok(out)
}
pub fn qualification_records_progress(method:u64,config:AgentMarketStoreConfigV1,id:[u8;32],source:u64,target:u64,body:&[u8],state:&[u8])->AgentMarketResultV1<Vec<u8>>{
    fn n(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
    fn h(s:&[u8],p:usize)->Hash32V1{Hash32V1(s[p..p+32].try_into().unwrap())}
    fn pack(m:CommittedBlockMarkerV1)->Vec<u8>{let mut out=Vec::new();out.extend_from_slice(&m.marker_sequence.to_le_bytes());out.extend_from_slice(&m.order_height.to_le_bytes());out.extend_from_slice(&m.order_block_id.0);out.extend_from_slice(&m.parent_order_height.to_le_bytes());out.extend_from_slice(&m.parent_order_block_id.0);out.extend_from_slice(&m.source_operation_sequence.to_le_bytes());out.extend_from_slice(&m.target_operation_sequence.to_le_bytes());out.extend_from_slice(&m.source_state_root.0);out.extend_from_slice(&m.target_state_root.0);out.extend_from_slice(&m.source_operation_root.0);out.extend_from_slice(&m.target_operation_root.0);out.extend_from_slice(&m.previous_marker_checksum.0);out.extend_from_slice(&m.row_checksum.0);out}
    let execution=if method==7{Some(strict_decode::<CommittedExecutionContextV1>(body)?)}else{None};
    let mut connection=open_rw_raw(&config.path,false)?;
    let transaction=connection.transaction()?;
    let out=match method{
        5=>{update_metadata_progress(&transaction,&config,source,target,Hash32V1(id),h(body,0),h(body,32),state[0]!=0)?;Vec::new()},
        6=>{let marker=CommittedBlockMarkerV1{marker_sequence:n(body,0),order_height:n(body,8),order_block_id:h(body,16),parent_order_height:n(body,48),parent_order_block_id:h(body,56),source_operation_sequence:n(body,88),target_operation_sequence:n(body,96),source_state_root:h(body,104),target_state_root:h(body,136),source_operation_root:h(body,168),target_operation_root:h(body,200),previous_marker_checksum:h(body,232),row_checksum:h(body,264)};pack(insert_committed_block_marker(&transaction,&config,marker)?)},
        7=>{advance_committed_block_marker(&transaction,&config,execution.as_ref().unwrap(),source,target,h(state,0),h(state,32),h(state,64),h(state,96))?;Vec::new()},
        8=>{insert_anchor_committed_block_marker(&transaction,&config,h(body,0),h(body,32))?;Vec::new()},
        _=>unreachable!(),
    };
    transaction.commit()?;Ok(out)
}
pub fn qualification_records_bootstrap(method:u64,config:AgentMarketStoreConfigV1,body:&[u8])->AgentMarketResultV1<Vec<u8>>{
    if method==9{let connection=open_rw_raw(&config.path,true)?;create_schema(&connection,&config)?;return Ok(Vec::new());}
    let body:NonceLaneKeyBodyV1=strict_decode(body)?;
    let mut connection=open_rw_raw(&config.path,false)?;let transaction=connection.transaction()?;
    insert_nonce_lane(&transaction,&body)?;transaction.commit()?;Ok(Vec::new())
}
pub fn qualification_records_verified(method:u64,config:AgentMarketStoreConfigV1,kind:u64,id:[u8;32],body:&[u8])->AgentMarketResultV1<Vec<u8>>{
    if method==13{return TaskKernelStoreV1::open_existing(config).map(|_|Vec::new());}
    if method==14{return TaskKernelStoreV1::open(config).map(|_|Vec::new());}
    let store=TaskKernelStoreV1{config};
    Ok(match method{
        11=>{let _connection=store.open_ro_verified()?;Vec::new()},
        12=>{let _connection=store.open_rw_verified()?;Vec::new()},
        15=>match kind{
            2=>canonical_bytes(&store.capability_state(CapabilityIdV1(id))?)?,
            3=>canonical_bytes(&store.session_state(SessionKeyGrantIdV1(id))?)?,
            4=>canonical_bytes(&store.task_state(TaskIdV1(id))?)?,
            5=>canonical_bytes(&store.bid_state(BidIdV1(id))?)?,
            6=>canonical_bytes(&store.lease_state(LeaseIdV1(id))?)?,
            7=>canonical_bytes(&store.escrow_state(EscrowIdV1(id))?)?,
            44=>canonical_bytes(&store.nonce_lane_state(NonceLaneIdV1(id))?)?,
            45=>canonical_bytes(&store.account_state(AccountIdV1(id))?)?,
            47=>canonical_bytes(&store.bond_state(BondIdV1(id))?)?,
            _=>unreachable!(),
        },
        16=>{let v=store.fresh_readback()?;let mut out=canonical_bytes(v.context())?;out.extend_from_slice(&v.store_schema_version().to_le_bytes());out.extend_from_slice(&v.store_id().0);out.extend_from_slice(&v.sequence().to_le_bytes());out.extend_from_slice(&v.order_height().to_le_bytes());out.extend_from_slice(&v.order_block_id().0);out.extend_from_slice(&v.durable_state_root().0);out.extend_from_slice(&v.durable_journal_root().0);out.extend_from_slice(&v.durable_committed_block_root().0);out},
        17=>{let receipt:KernelTransitionReceiptV1=strict_decode(body)?;canonical_bytes(store.confirm_receipt(&receipt)?.receipt())?},
        18=>store.logical_row_inventory_digest_v1()?.0.to_vec(),
        _=>unreachable!(),
    })
}
pub fn qualification_records_grant(config:AgentMarketStoreConfigV1,height:u64,raw:&[u8])->AgentMarketResultV1<Vec<u8>>{
    let command:KernelCommandV1=strict_decode(raw)?;
    let mut connection=open_rw_raw(&config.path,false)?;
    let transaction=connection.transaction()?;
    apply_command(&transaction,&config,height,&command)?;
    transaction.commit()?;Ok(Vec::new())
}
pub fn qualification_records_budget(height:u64,body:&[u8],state:&[u8],charge:&[u8])->AgentMarketResultV1<Vec<u8>>{
    let body:CapabilityGrantBodyV1=strict_decode(body)?;
    let mut state:CapabilityStateV1=strict_decode(state)?;
    let charge:KernelResourceChargeV1=strict_decode(charge)?;
    apply_budget(height,&body,&mut state,&charge)?;
    canonical_bytes(&state)
}
pub fn qualification_records_authorize(method:u64,config:AgentMarketStoreConfigV1,height:u64,body:&[u8],raw:&[u8])->AgentMarketResultV1<Vec<u8>>{
    let capability=if method==22{Some(strict_decode::<CapabilityGrantBodyV1>(body)?)}else{None};
    let command:KernelCommandV1=strict_decode(if method==21||method==23{body}else{raw})?;
    let mut connection=open_rw_raw(&config.path,false)?;let transaction=connection.transaction()?;
    let mut out=Vec::new();
    if let Some(capability)=capability{validate_operation_scope(&transaction,&capability,&command)?;}
    else{
        let snapshot=authorize(&transaction,&config,height,&command)?;
        if method==23{consume_authorization(&transaction,&config,height,&command,snapshot)?;transaction.commit()?;return Ok(out);}
        let mut values=vec![canonical_bytes(&snapshot.lane_body)?,canonical_bytes(&snapshot.lane_state)?];
        let flag=if let (Some((cb,cs)),Some((sb,ss)))=(snapshot.capability,snapshot.session){values.extend([canonical_bytes(&cb)?,canonical_bytes(&cs)?,canonical_bytes(&sb)?,canonical_bytes(&ss)?]);1u64}else{values.extend([Vec::new(),Vec::new(),Vec::new(),Vec::new()]);0u64};
        out.extend_from_slice(&flag.to_le_bytes());for value in values{out.extend_from_slice(&(value.len() as u64).to_le_bytes());out.extend_from_slice(&value);}
    }
    transaction.commit()?;Ok(out)
}

pub fn qualification_records_execution(method:u64,config:AgentMarketStoreConfigV1,fault:u64,execution:&[u8],command:&[u8])->AgentMarketResultV1<Vec<u8>>{
    let execution:CommittedExecutionContextV1=strict_decode(execution)?;
    let store=TaskKernelStoreV1{config};
    if method==25{
        let v=store.advance_empty_committed_execution_v1(&execution)?;
        let mut out=canonical_bytes(v.context())?;out.extend_from_slice(&v.store_schema_version().to_le_bytes());out.extend_from_slice(&v.store_id().0);out.extend_from_slice(&v.sequence().to_le_bytes());out.extend_from_slice(&v.order_height().to_le_bytes());out.extend_from_slice(&v.order_block_id().0);out.extend_from_slice(&v.durable_state_root().0);out.extend_from_slice(&v.durable_journal_root().0);out.extend_from_slice(&v.durable_committed_block_root().0);return Ok(out);
    }
    let command:KernelCommandV1=strict_decode(command)?;
    let fault=match fault{0=>CommitFaultInternalV1::None,1=>CommitFaultInternalV1::NotAppliedAckLost,2=>CommitFaultInternalV1::AppliedAckLost,3=>CommitFaultInternalV1::ThirdState,_=>unreachable!()};
    let outcome=store.execute_inner(&execution,&command,fault)?;
    let mut out=vec![u8::from(outcome.is_replay())];out.extend_from_slice(&canonical_bytes(outcome.receipt())?);Ok(out)
}

// Private value-level qualification only. Public owners must obtain the opaque
// expected-parent value from fresh_readback; this fixture is not an SDK mint API.
pub fn qualification_records_preview(config:AgentMarketStoreConfigV1,height:u64,expected:&[u8],commands:&[u8],block:&[u8])->AgentMarketResultV1<Vec<u8>>{
    fn n(s:&[u8],p:usize)->u64{u64::from_le_bytes(s[p..p+8].try_into().unwrap())}
    fn h(s:&[u8],p:usize)->Hash32V1{Hash32V1(s[p..p+32].try_into().unwrap())}
    let context_size=expected.len()-178;let context:ProtocolContextV1=strict_decode(&expected[..context_size])?;let tail=&expected[context_size..];
    let parent=AgentMarketFreshReadbackV1{context,store_schema_version:u16::from_le_bytes(tail[..2].try_into().unwrap()),store_id:h(tail,2),sequence:n(tail,34),order_height:n(tail,42),order_block_id:h(tail,50),durable_state_root:h(tail,82),durable_journal_root:h(tail,114),durable_committed_block_root:h(tail,146)};
    let commands:Vec<KernelCommandV1>=strict_decode(commands)?;
    let store=TaskKernelStoreV1{config};let preview=store.preview_before_vote_v1(&parent,height,h(block,0),&commands)?;
    let mut out=preview.source_sequence().to_le_bytes().to_vec();out.extend_from_slice(&preview.source_state_root().0);out.extend_from_slice(&preview.source_journal_root().0);out.extend_from_slice(&preview.candidate_post_state_root().0);out.extend_from_slice(&(preview.candidate_receipts().len() as u64).to_le_bytes());for receipt in preview.candidate_receipts(){out.extend_from_slice(&canonical_bytes(receipt)?);}out.extend_from_slice(&preview.unchanged_row_inventory_digest().0);Ok(out)
}
