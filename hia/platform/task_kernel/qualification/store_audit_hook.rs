// Appended only to the exact original store.rs prefix in the isolated oracle.
pub fn qualification_store_audit(method:u64,maximum:u64,config:AgentMarketStoreConfigV1)->AgentMarketResultV1<Vec<u8>>{
    let connection=open_ro_raw(&config.path)?;
    Ok(match method {
        0=>compute_state_root(&connection)?.0.to_vec(),
        1=>compute_operation_journal_root_through(&connection,maximum)?.0.to_vec(),
        2=>load_sequence(&connection)?.to_le_bytes().to_vec(),
        3=>{let (height,block)=load_order_tip(&connection)?;let mut v=height.to_le_bytes().to_vec();v.extend_from_slice(&block.0);v},
        4=>load_durable_state_root(&connection)?.0.to_vec(),
        5=>load_durable_journal_root(&connection)?.0.to_vec(),
        6=>{verify_schema(&connection)?;Vec::new()},
        7=>{verify_metadata(&connection,&config)?;Vec::new()},
        8=>{audit_objects(&connection,&config)?;Vec::new()},
        9=>{audit_operations(&connection,&config)?;Vec::new()},
        10=>{audit_operation_tail_root(&connection)?;Vec::new()},
        11=>{let markers=load_committed_block_markers(&connection,&config)?;let mut out=(markers.len() as u64).to_le_bytes().to_vec();for m in markers {out.extend_from_slice(&m.marker_sequence.to_le_bytes());out.extend_from_slice(&m.order_height.to_le_bytes());out.extend_from_slice(&m.order_block_id.0);out.extend_from_slice(&m.parent_order_height.to_le_bytes());out.extend_from_slice(&m.parent_order_block_id.0);out.extend_from_slice(&m.source_operation_sequence.to_le_bytes());out.extend_from_slice(&m.target_operation_sequence.to_le_bytes());out.extend_from_slice(&m.source_state_root.0);out.extend_from_slice(&m.target_state_root.0);out.extend_from_slice(&m.source_operation_root.0);out.extend_from_slice(&m.target_operation_root.0);out.extend_from_slice(&m.previous_marker_checksum.0);out.extend_from_slice(&m.row_checksum.0);}out},
        12=>{audit_committed_block_journal(&connection,&config)?;Vec::new()},
        13=>committed_block_journal_root(&connection,&config)?.0.to_vec(),
        14=>{audit_store(&connection,&config)?;Vec::new()},
        _=>unreachable!(),
    })
}
// Fixture preparation invokes original constructors and checksum calculation.
pub fn qualification_create(config:AgentMarketStoreConfigV1)->AgentMarketResultV1<()>{TaskKernelStoreV1::open(config).map(|_|())}
pub fn qualification_reseal_metadata(config:AgentMarketStoreConfigV1)->AgentMarketResultV1<()>{
    let connection=open_rw_raw(&config.path,false)?;
    let record:MetadataRecordV1=connection.query_row("SELECT schema_version,store_id,config_hash,sequence,order_height,order_block_id,durable_state_root,durable_journal_root,fenced,row_checksum FROM agent_market_metadata_v1 WHERE singleton=1",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)))?;
    let sum=checksum(&[&record.0.to_le_bytes(),&record.1,&record.2,&record.3,&record.4,&record.5,&record.6,&record.7,&[record.8]]);
    connection.execute("UPDATE agent_market_metadata_v1 SET row_checksum=?1 WHERE singleton=1",params![&sum.0[..]])?;
    Ok(())
}
pub fn qualification_reseal_objects(config:AgentMarketStoreConfigV1)->AgentMarketResultV1<()>{
    let connection=open_rw_raw(&config.path,false)?;
    let mut statement=connection.prepare("SELECT rowid,object_kind,object_id,object_version,immutable_body,mutable_state FROM agent_market_objects_v1")?;
    let rows=statement.query_map([],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,u16>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?)))?.collect::<Result<Vec<_>,_>>()?;
    for (row,kind,id,version,body,state) in rows {
        let sum=checksum(&[&kind.to_le_bytes(),&id,&version,&body,&state]);
        connection.execute("UPDATE agent_market_objects_v1 SET row_checksum=?1 WHERE rowid=?2",params![&sum.0[..],row])?;
    }
    Ok(())
}
pub fn qualification_object_fixture(kind:u16,body:&[u8],state:&[u8],funding:u128,normalization:u8)->AgentMarketResultV1<Vec<u8>>{
    fn pack(kind:u16,id:[u8;32],body:Vec<u8>,state:Vec<u8>)->Vec<u8>{
        let version=0u64.to_le_bytes();let sum=checksum(&[&kind.to_le_bytes(),&id,&version,&body,&state]);
        let mut out=kind.to_le_bytes().to_vec();out.extend_from_slice(&id);out.extend_from_slice(&version);out.extend_from_slice(&(body.len() as u64).to_le_bytes());out.extend_from_slice(&(state.len() as u64).to_le_bytes());out.extend_from_slice(&body);out.extend_from_slice(&state);out.extend_from_slice(&sum.0);out
    }
    macro_rules! make {($body:ty,$state:ty,$id_method:ident,$id:ident,$version:ident)=>{{
        let body:$body=strict_decode(body)?;let mut state:$state=strict_decode(state)?;let id=body.$id_method()?;state.$id=id;state.$version=0;
        Ok(pack(kind,id.0,canonical_bytes(&body)?,canonical_bytes(&state)?))
    }};}
    match kind {
        2=>make!(CapabilityGrantBodyV1,CapabilityStateV1,capability_id,capability_id,state_version),
        3=>make!(SessionKeyGrantBodyV1,SessionKeyGrantStateV1,session_key_grant_id,session_key_grant_id,state_version),
        4=>make!(TaskOfferBodyV1,TaskStateV1,task_id,task_id,revision),
        5=>make!(BidBodyV1,BidStateV1,bid_id,bid_id,state_version),
        6=>make!(TaskLeaseBodyV1,TaskLeaseStateV1,lease_id,lease_id,revision),
        44=>make!(NonceLaneKeyBodyV1,NonceLaneStateV1,nonce_lane_id,nonce_lane_id,state_version),
        45=>make!(AccountBodyV1,AccountStateV1,account_id,account_id,version),
        7=>{let body:EscrowBodyV1=strict_decode(body)?;let mut state:EscrowStateV1=strict_decode(state)?;let id=body.escrow_id()?;state.escrow_id=id;state.version=0;
            if normalization!=0 {state.available=body.funded_amount;state.reserved=0;state.disbursed=0;state.refunded=0;state.forfeited=0;state.active_reservations.clear();
                if normalization==2 {state.available=body.funded_amount.checked_sub(3).expect("fixture funded amount");state.reserved=3;for amount in [1,2]{state.active_reservations.push(EscrowReservationEntryV1{reservation_kind:0,source_object_kind:0,source_object_id:Hash32V1::default(),asset_id:Hash32V1::default(),amount,created_height:0,release_condition_hash:Hash32V1::default()});}}
                state.active_reservation_root=digest_value("trnm.portable.v2.escrow-active-reservations-root.v1",&state.active_reservations)?;
            }
            Ok(pack(kind,id.0,canonical_bytes(&body)?,canonical_bytes(&state)?))},
        47=>{let body:BondBodyV1=strict_decode(body)?;let mut state:BondStateV1=strict_decode(state)?;let id=body.bond_id()?;state.bond_id=id;state.version=0;if normalization!=0{state.available=funding;state.held=0;state.released=0;state.slashed=0;}Ok(pack(kind,id.0,canonical_bytes(&body)?,canonical_bytes(&state)?))},
        _=>unreachable!(),
    }
}
pub fn qualification_reseal_operations(config:AgentMarketStoreConfigV1)->AgentMarketResultV1<()>{
    let connection=open_rw_raw(&config.path,false)?;
    let mut statement=connection.prepare("SELECT rowid,operation_id,sequence,operation_kind,command,receipt FROM agent_market_operations_v1")?;
    let rows=statement.query_map([],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,u16>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,Vec<u8>>(5)?)))?.collect::<Result<Vec<_>,_>>()?;
    for (row,id,sequence,kind,command,receipt) in rows {
        let sum=checksum(&[&id,&sequence,&kind.to_le_bytes(),&command,&receipt]);
        connection.execute("UPDATE agent_market_operations_v1 SET row_checksum=?1 WHERE rowid=?2",params![&sum.0[..],row])?;
    }
    Ok(())
}
pub fn qualification_operation_fixture(command:&[u8],sequence:u64,height:u64,block:[u8;32],root:[u8;32])->AgentMarketResultV1<Vec<u8>>{
    let command:KernelCommandV1=strict_decode(command)?;let id=command.operation_id()?;let kind=command.operation_kind();
    let receipt=KernelTransitionReceiptV1{schema_version:SCHEMA_VERSION_V1,store_id:Hash32V1([9;32]),sequence,operation_id:id,operation_kind:kind,operation_digest:command.operation_digest()?,order_height:height,order_block_id:Hash32V1(block),post_state_root:Hash32V1(root)};
    let command=canonical_bytes(&command)?;let receipt=canonical_bytes(&receipt)?;let seq=sequence.to_le_bytes();let sum=checksum(&[&id.0,&seq,&kind.to_le_bytes(),&command,&receipt]);
    let mut out=kind.to_le_bytes().to_vec();out.extend_from_slice(&id.0);out.extend_from_slice(&seq);out.extend_from_slice(&(command.len() as u64).to_le_bytes());out.extend_from_slice(&(receipt.len() as u64).to_le_bytes());out.extend_from_slice(&command);out.extend_from_slice(&receipt);out.extend_from_slice(&sum.0);Ok(out)
}
pub fn qualification_reseal_markers(config:AgentMarketStoreConfigV1)->AgentMarketResultV1<()>{
    let connection=open_rw_raw(&config.path,false)?;
    let mut statement=connection.prepare("SELECT rowid,marker_sequence,order_height,order_block_id,parent_order_height,parent_order_block_id,source_operation_sequence,target_operation_sequence,source_state_root,target_state_root,source_operation_root,target_operation_root,previous_marker_checksum,row_checksum FROM agent_market_committed_blocks_v1")?;
    let rows=statement.query_map([],|row|{let id=row.get::<_,i64>(0)?;let mut values=Vec::new();for i in 1..14{values.push(row.get::<_,Vec<u8>>(i)?);}Ok((id,values))})?.collect::<Result<Vec<_>,_>>()?;
    for (row,v) in rows {
        let marker=CommittedBlockMarkerV1{marker_sequence:decode_u64(&v[0],"fixture marker sequence")?,order_height:decode_u64(&v[1],"fixture marker height")?,order_block_id:decode_marker_hash(v[2].clone(),"fixture marker block")?,parent_order_height:decode_u64(&v[3],"fixture marker parent height")?,parent_order_block_id:decode_marker_hash(v[4].clone(),"fixture marker parent block")?,source_operation_sequence:decode_u64(&v[5],"fixture source sequence")?,target_operation_sequence:decode_u64(&v[6],"fixture target sequence")?,source_state_root:decode_marker_hash(v[7].clone(),"fixture source root")?,target_state_root:decode_marker_hash(v[8].clone(),"fixture target root")?,source_operation_root:decode_marker_hash(v[9].clone(),"fixture source operation root")?,target_operation_root:decode_marker_hash(v[10].clone(),"fixture target operation root")?,previous_marker_checksum:decode_marker_hash(v[11].clone(),"fixture previous checksum")?,row_checksum:Hash32V1::default()};
        let sum=committed_block_marker_checksum(&config,&marker)?;
        connection.execute("UPDATE agent_market_committed_blocks_v1 SET row_checksum=?1 WHERE rowid=?2",params![&sum.0[..],row])?;
    }
    Ok(())
}
pub fn qualification_empty_blocks(config:AgentMarketStoreConfigV1,count:u64)->AgentMarketResultV1<()>{
    assert!(count<=16,"bounded fixture preparation");
    let store=TaskKernelStoreV1::open_existing(config.clone())?;
    for i in 0..count {
        let head=store.fresh_readback()?;
        let execution=CommittedExecutionContextV1{schema_version:SCHEMA_VERSION_V1,context:config.trust_bundle.context.clone(),expected_order_height:head.order_height,expected_order_block_id:head.order_block_id,order_height:head.order_height.checked_add(1).expect("fixture height"),order_block_id:Hash32V1([100+i as u8;32])};
        store.advance_empty_committed_execution_v1(&execution)?;
    }
    Ok(())
}
