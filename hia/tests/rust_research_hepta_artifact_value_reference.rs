//! Public original Hepta artifact value methods only; never validates or signs.
use std::io::{self,Write};
use trnm_research_protocol::HeptaArtifactAdmissionV1 as V;
use trnm_research_protocol::ExternalKey;

fn row(out:&mut impl Write, present:bool, nums:[u64;4], seed:u8) {
    let d = |j:u8| -> [u8;32] {
        std::array::from_fn(|i| seed.wrapping_mul(11).wrapping_add(j.wrapping_mul(31))
                                  .wrapping_add((i as u8).wrapping_mul(7)))
    };
    let record=V {
        operation_id:ExternalKey::from_bytes(d(0)),
        artifact_digest:d(1),owner_admission_digest:d(2),family_digest:d(3),
        source_digest_profile_digest:d(4),
        parent_artifact_digest:present.then(||d(5)),generation:nums[0],
        withdrawal_scope_digest:d(6),withdrawal_head_digest:d(7),registry_head_digest:d(8),
        evaluation_plan_digest:d(9),task_scope_digest:d(10),export_permission_digest:d(11),
        payload_digest:d(12),payload_len:nums[1],created_at_unix_s:nums[2],expires_at_unix_s:nums[3],
    };
    out.write_all(b"HAV1").unwrap();
    out.write_all(&[u8::from(present),0,0,0]).unwrap();
    for n in nums { out.write_all(&n.to_le_bytes()).unwrap(); }
    for j in 0..13 {out.write_all(&if j==5 && !present {[0;32]}else{d(j)}).unwrap();}
    let cbor=record.canonical_bytes();
    out.write_all(&record.admission_digest()).unwrap();
    out.write_all(&(cbor.len() as u64).to_le_bytes()).unwrap();
    out.write_all(&cbor).unwrap();
}
fn main(){
    let mut out=io::stdout().lock();
    // Inert normal and width-edge typed records; never passed to validate.
    row(&mut out,false,[1,23,1885,1886],7);
    row(&mut out,true,[2,24,1885,1886],7);
    row(&mut out,true,[23,24,255,256],11);
    row(&mut out,true,[255,256,65535,65536],34);
    row(&mut out,true,[65535,65536,u32::MAX as u64,u32::MAX as u64+1],128);
    row(&mut out,true,[u32::MAX as u64,u32::MAX as u64+1,u64::MAX-1,u64::MAX],240);
    row(&mut out,true,[u64::MAX;4],18);
    row(&mut out,false,[1,23,1885,1887],7);
    row(&mut out,false,[1,23,1885,1886],8);
}
