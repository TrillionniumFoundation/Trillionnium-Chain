//! Public original offline typed status, no envelope or signature.
use std::io::{self,Write};
use trnm_research_protocol::{ExternalKey,HeptaArtifactAdmissionV1 as V,HeptaHandoffError as E};
const FIELDS:[&str;18]=[
    "operation_id","artifact_digest","owner_admission_digest","family_digest",
    "source_digest_profile_digest","withdrawal_scope_digest","withdrawal_head_digest",
    "registry_head_digest","evaluation_plan_digest","task_scope_digest",
    "export_permission_digest","payload_digest","generation","generation_one_parent",
    "missing_parent_artifact","parent_artifact_digest","payload_len","created_at_unix_s",
];
const DIGESTS:[usize;12]=[40,72,104,136,168,232,264,296,328,360,392,424];

fn n(b:&[u8],a:usize)->u64 {u64::from_le_bytes(b[a..a+8].try_into().unwrap())}
fn d(b:&[u8],a:usize)->[u8;32] {b[a..a+32].try_into().unwrap()}
fn put(b:&mut [u8],a:usize,v:u64) {b[a..a+8].copy_from_slice(&v.to_le_bytes());}

fn row(out:&mut impl Write, packet:&[u8], now:Option<u64>, encode:bool) {
    let now=if encode {Some(now.unwrap_or(255))} else {now};
    let v=V {
        operation_id:ExternalKey::from_bytes(d(packet,40)),artifact_digest:d(packet,72),
        owner_admission_digest:d(packet,104),family_digest:d(packet,136),
        source_digest_profile_digest:d(packet,168),
        parent_artifact_digest:(packet[4]==1).then(||d(packet,200)),generation:n(packet,8),
        withdrawal_scope_digest:d(packet,232),withdrawal_head_digest:d(packet,264),
        registry_head_digest:d(packet,296),evaluation_plan_digest:d(packet,328),
        task_scope_digest:d(packet,360),export_permission_digest:d(packet,392),
        payload_digest:d(packet,424),payload_len:n(packet,16),
        created_at_unix_s:n(packet,24),expires_at_unix_s:n(packet,32),
    };
    let status=match now.map_or_else(||v.validate(),|time|v.validate_at(time)) {
        Ok(())=>0u32,
        Err(E::InvalidAdmission(name))=>1+FIELDS.iter().position(|v|*v==name).unwrap() as u32,
        Err(E::AdmissionNotYetValid)=>19,
        Err(E::AdmissionExpired)=>20,
        Err(other)=>panic!("Unexpected original check: {other:?}"),
    };
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(456u32+if now.is_some(){8}else{0}).to_le_bytes()).unwrap();
    out.write_all(packet).unwrap();
    if let Some(time)=now {out.write_all(&time.to_le_bytes()).unwrap();}
    if encode && status==0 {
        let cbor=v.canonical_bytes();
        out.write_all(&v.admission_digest()).unwrap();
        out.write_all(&(cbor.len() as u64).to_le_bytes()).unwrap();
        out.write_all(&cbor).unwrap();
    }
}

pub fn run(encode:bool){
    let out=&mut io::stdout().lock();
    let mut normal=[0x4a;456];
    normal[..8].copy_from_slice(b"HAV1\0\0\0\0");
    put(&mut normal,8,1); put(&mut normal,16,1);
    put(&mut normal,24,255); put(&mut normal,32,256);
    row(out,&normal,None,encode);
    for time in [254,255,256,257] {row(out,&normal,Some(time),encode);}
    for (i,at) in DIGESTS.iter().enumerate() {
        let mut bad=normal; bad[*at..*at+32].fill(0);
        row(out,&bad,None,encode);
        let mut competing=bad;
        if let Some(later)=DIGESTS.get(i+1) {
            competing[*later..*later+32].fill(0);
        } else {
            put(&mut competing,8,0);
        }
        row(out,&competing,Some(257),encode);
    }
    let mut hi=normal; put(&mut hi,8,0); hi[4]=1;
    row(out,&hi,None,encode);
    put(&mut hi,8,1); put(&mut hi,16,0); row(out,&hi,None,encode);
    put(&mut hi,8,2); hi[4]=0; row(out,&hi,None,encode);
    hi[4]=1; hi[200..232].fill(0); row(out,&hi,None,encode);
    hi[200]=1; put(&mut hi,24,0); row(out,&hi,Some(999),encode);
    put(&mut hi,16,67108865); row(out,&hi,None,encode);
    put(&mut hi,16,67108864); row(out,&hi,None,encode);
    put(&mut hi,24,257); row(out,&hi,Some(1),encode);
    put(&mut hi,24,256); put(&mut hi,32,256); row(out,&hi,Some(256),encode);
    put(&mut hi,24,u64::MAX); put(&mut hi,32,u64::MAX);
    row(out,&hi,Some(u64::MAX-1),encode); row(out,&hi,Some(u64::MAX),encode);
    put(&mut hi,32,0); row(out,&hi,None,encode);
}

fn main(){run(false);}
