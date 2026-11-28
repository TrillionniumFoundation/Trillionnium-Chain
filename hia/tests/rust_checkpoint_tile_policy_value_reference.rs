use std::io::{self,Write};
use trnm_mvcc_fee::{checkpoint_tile_policy_v1::CheckpointTilePolicySpecV1 as Policy,
                   checkpoint_tile_material_v1::policy_id};

fn fixture(size: u64) -> Policy {
    let mut material = String::new();
    for b in policy_id() { material.push_str(&format!("{b:02x}")); }
    Policy { schema:"checkpoint-tile-context-free-policy-v1".into(), material_policy:material,
        checkpoint_sha256:"01".repeat(32), checkpoint_bytes:size,
        activation_sha256:"02".repeat(32), a_sha256:"a3".repeat(32),
        b_sha256:"b4".repeat(32),model:"55".repeat(32),input:"66".repeat(32),
        matrix_task:"77".repeat(32),maintenance_only:true,useful_output_limit:0,
        chain_authority:false,hardness_accepted:false,genuine_demand_verified:false,
        full_forward_verified:false,marginal_contribution_accepted:false,public_network_ready:false }
}

fn emit(out: &mut impl Write, p: &Policy) {
    let mut frame=b"TPV1\0\0\0\0".to_vec();
    let flags=[p.maintenance_only,p.chain_authority,p.hardness_accepted,p.genuine_demand_verified,
        p.full_forward_verified,p.marginal_contribution_accepted,p.public_network_ready]
        .into_iter().enumerate().fold(0u64,|b,(i,flag)| b|((flag as u64)<<i));
    for x in [p.checkpoint_bytes,p.useful_output_limit,flags] {
        frame.extend_from_slice(&x.to_le_bytes());
    }
    for s in [&p.schema,&p.material_policy,&p.checkpoint_sha256,&p.activation_sha256,
        &p.a_sha256,&p.b_sha256,&p.model,&p.input,&p.matrix_task] {
        frame.extend_from_slice(s.as_bytes());
    }
    assert_eq!(frame.len(),582);
    let (status,digest,bytes)=match p.canonical() {
        Ok(bytes)=>(0u32,p.id().unwrap(),bytes),
        Err(e)=>{
            assert_eq!(p.id(),Err(e));
            (match e {
                "CHECKPOINT_POLICY"=>1, "CHECKPOINT_POLICY_SIZE"=>2,
                "CHECKPOINT_POLICY_ID"=>3, "CHECKPOINT_POLICY_ACCEPTANCE"=>4,
                x=>panic!("unexpected original result {x}"),
             },[0;32],Vec::new())
        }
    };
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&frame).unwrap();
    out.write_all(&digest).unwrap();
    out.write_all(&bytes).unwrap();
}

fn main(){
    let mut out=io::stdout().lock();
    for n in [10,65537,536870912] { emit(&mut out,&fixture(n)); }
    let mut scope=fixture(11);
    scope.input="00".repeat(31)+"01";
    emit(&mut out,&scope);
    let mut p=fixture(9); p.model="00".repeat(32); p.chain_authority=true;
    p.schema.replace_range(..1,"X"); emit(&mut out,&p);
    p.schema.replace_range(..1,"c"); emit(&mut out,&p);
    p.checkpoint_bytes=10; emit(&mut out,&p);
    p.model="05".repeat(32); emit(&mut out,&p);
    p.chain_authority=false; p.useful_output_limit=1; emit(&mut out,&p);
    let mut p=fixture(536870913); emit(&mut out,&p);
    p.checkpoint_bytes=11; p.a_sha256="AF".repeat(32); emit(&mut out,&p);
    p.a_sha256="af".repeat(32); p.material_policy.replace_range(..1,"0");
    emit(&mut out,&p);
}
