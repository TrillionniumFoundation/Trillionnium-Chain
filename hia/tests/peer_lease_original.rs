//! Test transport for the complete unchanged original trnm-peer-lease crate.
//! Every constructor, value operation, digest and projection decoder calls its
//! actual public API. The object table only supplies private receiver lifetimes.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use trnm_peer_lease::*;

const MAX_TEST_INPUT: u64 = 64 * 1024 * 1024;
type Failure = (u64, Vec<u8>);
type Answer<T> = Result<T, Failure>;

struct Reader<'a> { bytes: &'a [u8], at: usize }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, at: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        let end = self.at.checked_add(n).ok_or(())?;
        let value = self.bytes.get(self.at..end).ok_or(())?;
        self.at = end;
        Ok(value)
    }
    fn word(&mut self) -> Result<u64, ()> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| ())?))
    }
    fn digest(&mut self) -> Result<[u8; 32], ()> { self.take(32)?.try_into().map_err(|_| ()) }
    fn byte_word(&mut self) -> Result<u8, ()> { u8::try_from(self.word()?).map_err(|_| ()) }
    fn u32_word(&mut self) -> Result<u32, ()> { u32::try_from(self.word()?).map_err(|_| ()) }
    fn direction(&mut self) -> Result<PeerLeaseDirectionV1, ()> {
        match self.word()? { 1 => Ok(PeerLeaseDirectionV1::Outbound), 2 => Ok(PeerLeaseDirectionV1::Inbound), _ => Err(()) }
    }
    fn finish(self) -> Result<(), ()> { if self.at == self.bytes.len() { Ok(()) } else { Err(()) } }
}

#[derive(Clone, PartialEq, Eq)]
enum Value {
    Scope(PeerLeaseScopeV1), Token(PeerLeaseTokenV1), Namespace(PayloadReplayNamespaceV1),
    Frame(PayloadReplayFrameV1), Target(PayloadReplayRecoveryTargetV1),
    Ack(PayloadReplayCoreAcknowledgementV1), Status(PayloadReplayRecoveryStatusV1),
    Projection(PayloadReplayRecoveryStatusProjectionV1),
}
impl Value {
    fn kind(&self) -> u64 {
        match self { Self::Scope(_) => 1, Self::Token(_) => 2, Self::Namespace(_) => 3,
            Self::Frame(_) => 4, Self::Target(_) => 5, Self::Ack(_) => 6,
            Self::Status(_) => 7, Self::Projection(_) => 8 }
    }
}

fn word(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn protocol(error: ProtocolErrorV1) -> Failure {
    let code = match error { ProtocolErrorV1::ZeroIdentity => 1, ProtocolErrorV1::SelfPeer => 2,
        ProtocolErrorV1::ZeroSession => 3, ProtocolErrorV1::ZeroGeneration => 4, ProtocolErrorV1::ZeroRecordHash => 5 };
    (code, error.to_string().into_bytes())
}
fn payload(error: PayloadReplayErrorV1) -> Failure {
    let code = match error { PayloadReplayErrorV1::InvalidRequest(_) => 10,
        PayloadReplayErrorV1::TooLarge => 11, _ => panic!("unexpected pure-value error: {error}") };
    (code, error.to_string().into_bytes())
}
fn recovery(error: PayloadReplayRecoveryErrorV1) -> Failure {
    match error { PayloadReplayRecoveryErrorV1::InvalidRequest(_) => (20, error.to_string().into_bytes()),
        _ => panic!("unexpected projection/constructor error: {error}") }
}
fn lookup(values: &BTreeMap<u64, Value>, handle: u64) -> Answer<&Value> {
    values.get(&handle).ok_or((64, Vec::new()))
}
fn scope(values: &BTreeMap<u64, Value>, handle: u64) -> Answer<PeerLeaseScopeV1> {
    match lookup(values, handle)? { Value::Scope(value) => Ok(*value), _ => Err((65, Vec::new())) }
}
fn namespace(values: &BTreeMap<u64, Value>, handle: u64) -> Answer<PayloadReplayNamespaceV1> {
    match lookup(values, handle)? { Value::Namespace(value) => Ok(*value), _ => Err((65, Vec::new())) }
}
fn target(values: &BTreeMap<u64, Value>, handle: u64) -> Answer<PayloadReplayRecoveryTargetV1> {
    match lookup(values, handle)? { Value::Target(value) => Ok(*value), _ => Err((65, Vec::new())) }
}
fn insert(values: &mut BTreeMap<u64, Value>, next: &mut u64, value: Value) -> Vec<u8> {
    let handle = *next;
    *next = next.checked_add(1).expect("bounded driver handle count");
    assert!(values.insert(handle, value).is_none());
    handle.to_le_bytes().to_vec()
}

fn encode_scope(out: &mut Vec<u8>, value: PeerLeaseScopeV1) {
    out.extend_from_slice(&value.local_id()); out.extend_from_slice(&value.remote_id());
    out.extend_from_slice(&value.peer_scope_id()); word(out, value.direction() as u64); word(out, value.epoch());
}
fn encode_target(out: &mut Vec<u8>, value: PayloadReplayRecoveryTargetV1) {
    word(out, value.record_index()); out.extend_from_slice(&value.record_hash());
    out.extend_from_slice(&value.remote_id()); word(out, value.direction() as u64);
    out.extend_from_slice(&value.session_id()); word(out, value.generation()); word(out, value.sequence());
    word(out, value.frame_kind().into()); word(out, value.payload_len().into());
    out.extend_from_slice(&value.frame_fingerprint());
}
fn encode_status(out: &mut Vec<u8>, value: PayloadReplayRecoveryStatusV1) {
    match value {
        PayloadReplayRecoveryStatusV1::RecoverableHeadLag { payload_record_count, payload_head_count, retained_temporary_count } => {
            word(out,1);word(out,payload_record_count);word(out,payload_head_count);word(out,retained_temporary_count.into());
        }
        PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries { payload_record_count, retained_temporary_count } => {
            word(out,2);word(out,payload_record_count);word(out,retained_temporary_count.into());
        }
        PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { payload_record_count, payload_head_hash } => {
            word(out,3);word(out,payload_record_count);out.extend_from_slice(&payload_head_hash);
        }
        PayloadReplayRecoveryStatusV1::CoreAcknowledged { payload_record_count, payload_head_hash,
            core_safety_revision, core_ack_digest, acknowledgement_hash } => {
            word(out,4);word(out,payload_record_count);out.extend_from_slice(&payload_head_hash);
            word(out,core_safety_revision);out.extend_from_slice(&core_ack_digest);out.extend_from_slice(&acknowledgement_hash);
        }
    }
    word(out,value.payload_publication_recoverable().into());word(out,value.core_acknowledged().into());
    word(out,value.kind().len() as u64);out.extend_from_slice(value.kind().as_bytes());
}
fn snapshot(value: &Value) -> Vec<u8> {
    let mut out = Vec::new(); word(&mut out, value.kind());
    match value {
        Value::Scope(value) => encode_scope(&mut out,*value),
        Value::Token(value) => {
            encode_scope(&mut out,value.scope());out.extend_from_slice(&value.session_id());
            word(&mut out,value.generation());word(&mut out,value.expires_at_ms());out.extend_from_slice(&value.record_hash());
        }
        Value::Namespace(value) => {
            out.extend_from_slice(&value.local_id());out.extend_from_slice(&value.peer_scope_id());
            out.extend_from_slice(&value.run_id_hash());out.extend_from_slice(&value.network_context_hash());word(&mut out,value.epoch());
        }
        Value::Frame(value) => {
            encode_scope(&mut out,value.scope());out.extend_from_slice(&value.run_id_hash());out.extend_from_slice(&value.network_context_hash());
            out.extend_from_slice(&value.session_id());word(&mut out,value.generation());word(&mut out,value.sequence());
            word(&mut out,value.frame_kind().into());word(&mut out,value.payload_len().into());out.extend_from_slice(&value.frame_fingerprint());
        }
        Value::Target(value) => encode_target(&mut out,*value),
        Value::Ack(value) => {
            encode_target(&mut out,value.target());word(&mut out,value.core_safety_revision());out.extend_from_slice(&value.core_ack_digest());
        }
        Value::Status(value) => encode_status(&mut out,*value),
        Value::Projection(value) => {
            let bytes=value.canonical_bytes();word(&mut out,bytes.len() as u64);out.extend_from_slice(&bytes);
            out.extend_from_slice(&value.namespace_digest());out.extend_from_slice(&value.projection_digest());
            encode_target(&mut out,value.target());encode_status(&mut out,value.status());
            assert_eq!(value.status_kind(),value.status().kind());
            assert_eq!(value.payload_publication_recoverable(),value.status().payload_publication_recoverable());
            assert_eq!(value.core_acknowledged(),value.status().core_acknowledged());
            for bit in [value.candidate_only(),value.production_activation(),value.atomic_with_core(),value.is_self_consistent()] {
                word(&mut out,bit.into());
            }
        }
    }
    out
}

fn parse_status(r: &mut Reader<'_>) -> Result<PayloadReplayRecoveryStatusV1, ()> {
    Ok(match r.word()? {
        1 => PayloadReplayRecoveryStatusV1::RecoverableHeadLag { payload_record_count:r.word()?,payload_head_count:r.word()?,retained_temporary_count:r.u32_word()? },
        2 => PayloadReplayRecoveryStatusV1::RecoverableResidualTemporaries { payload_record_count:r.word()?,retained_temporary_count:r.u32_word()? },
        3 => PayloadReplayRecoveryStatusV1::AdmittedUnacknowledged { payload_record_count:r.word()?,payload_head_hash:r.digest()? },
        4 => PayloadReplayRecoveryStatusV1::CoreAcknowledged { payload_record_count:r.word()?,payload_head_hash:r.digest()?,core_safety_revision:r.word()?,core_ack_digest:r.digest()?,acknowledgement_hash:r.digest()? },
        _ => return Err(()),
    })
}

fn typed(op: u64, bytes: &[u8]) -> Result<(), ()> {
    let mut r=Reader::new(bytes);
    match op {
        0 => { r.take(96)?; r.direction()?;r.word()?; }
        1 => { r.take(88)?; }
        2 => { r.take(136)?; }
        3 => { r.take(40)?;r.direction()?; }
        4 => { r.take(120)?;r.byte_word()?;r.word()?;r.digest()?; }
        5 => { r.take(72)?;r.direction()?;r.take(48)?;r.byte_word()?;r.u32_word()?;r.digest()?; }
        6 => { r.take(48)?; }
        7 => { parse_status(&mut r)?; }
        8 | 10 => { r.take(bytes.len())?; }
        9 => { std::str::from_utf8(r.take(bytes.len())?).map_err(|_| ())?; }
        11..=13 => { r.word()?; }
        14..=15 => { r.word()?;r.word()?; }
        _ => return Err(()),
    }
    r.finish()
}

fn command(op:u64, bytes:&[u8], values:&mut BTreeMap<u64,Value>, next:&mut u64) -> Answer<Vec<u8>> {
    let mut r=Reader::new(bytes);
    // The whole frame has already admitted these exact typed bytes.
    let value=match op {
        0 => {
            let local=r.digest().unwrap();let remote=r.digest().unwrap();let peer=r.digest().unwrap();
            let direction=r.direction().unwrap();let epoch=r.word().unwrap();
            Value::Scope(PeerLeaseScopeV1::new(local,remote,direction,epoch,peer).map_err(protocol)?)
        }
        1 => {
            let receiver=scope(values,r.word().unwrap())?;let session=r.digest().unwrap();
            let generation=r.word().unwrap();let expiry=r.word().unwrap();let hash=r.digest().unwrap();
            Value::Token(PeerLeaseTokenV1::from_parts(receiver,session,generation,expiry,hash).map_err(protocol)?)
        }
        2 => {
            let local=r.digest().unwrap();let peer=r.digest().unwrap();let run=r.digest().unwrap();let context=r.digest().unwrap();let epoch=r.word().unwrap();
            Value::Namespace(PayloadReplayNamespaceV1::new(local,epoch,peer,run,context).map_err(payload)?)
        }
        3 => {
            let receiver=namespace(values,r.word().unwrap())?;let remote=r.digest().unwrap();let direction=r.direction().unwrap();
            Value::Scope(receiver.scope_for(remote,direction).map_err(payload)?)
        }
        4 => {
            let receiver=scope(values,r.word().unwrap())?;let run=r.digest().unwrap();let context=r.digest().unwrap();let session=r.digest().unwrap();
            let generation=r.word().unwrap();let sequence=r.word().unwrap();let kind=r.byte_word().unwrap();let length=r.word().unwrap() as usize;let hash=r.digest().unwrap();
            Value::Frame(PayloadReplayFrameV1::new(receiver,run,context,session,generation,sequence,kind,length,hash).map_err(payload)?)
        }
        5 => {
            let record=r.word().unwrap();let hash=r.digest().unwrap();let remote=r.digest().unwrap();let direction=r.direction().unwrap();let session=r.digest().unwrap();
            let generation=r.word().unwrap();let sequence=r.word().unwrap();let kind=r.byte_word().unwrap();let length=r.u32_word().unwrap();let fingerprint=r.digest().unwrap();
            Value::Target(PayloadReplayRecoveryTargetV1::new(record,hash,remote,direction,session,generation,sequence,kind,length,fingerprint).map_err(recovery)?)
        }
        6 => {
            let receiver=target(values,r.word().unwrap())?;let revision=r.word().unwrap();let digest=r.digest().unwrap();
            Value::Ack(PayloadReplayCoreAcknowledgementV1::new(receiver,revision,digest).map_err(recovery)?)
        }
        7 => Value::Status(parse_status(&mut r).unwrap()),
        8 => Value::Projection(PayloadReplayRecoveryStatusProjectionV1::from_canonical_bytes(bytes).map_err(recovery)?),
        9 => return Ok(payload_replay_run_id_hash_v1(std::str::from_utf8(bytes).unwrap()).to_vec()),
        10 => {
            let free=payload_replay_body_digest_v1(bytes).map_err(payload)?;
            let alias=PayloadReplayBodyStoreV1::body_digest(bytes).map_err(payload)?;
            assert_eq!(free,alias);
            return Ok(free.to_vec());
        }
        11 => return Ok(snapshot(lookup(values,r.word().unwrap())?)),
        12 => lookup(values,r.word().unwrap())?.clone(),
        13 => {
            let handle=r.word().unwrap();lookup(values,handle)?;values.remove(&handle).unwrap();return Ok(Vec::new());
        }
        14 => {
            let first=lookup(values,r.word().unwrap())?;let second=lookup(values,r.word().unwrap())?;
            if first.kind()!=second.kind() { return Err((65,Vec::new())); }
            return Ok(u64::from(first==second).to_le_bytes().to_vec());
        }
        15 => {
            let first=scope(values,r.word().unwrap())?;let second=scope(values,r.word().unwrap())?;
            let order=match first.cmp(&second) {std::cmp::Ordering::Less=>0u64,std::cmp::Ordering::Equal=>1,std::cmp::Ordering::Greater=>2};
            return Ok(order.to_le_bytes().to_vec());
        }
        _ => unreachable!(),
    };
    Ok(insert(values,next,value))
}

fn execute(bytes:&[u8]) -> Result<Vec<u8>, ()> {
    let mut r=Reader::new(bytes);
    if r.take(8)?!=b"PLV10001" { return Err(()); }
    let count=usize::try_from(r.word()?).map_err(|_| ())?;
    if count>(bytes.len()-16)/16 { return Err(()); }
    let mut commands=Vec::with_capacity(count);
    for _ in 0..count {
        let op=r.word()?;let size=usize::try_from(r.word()?).map_err(|_| ())?;let data=r.take(size)?;
        typed(op,data)?;commands.push((op,data));
    }
    r.finish()?;
    let mut values=BTreeMap::new();let mut next=1u64;
    let mut out=Vec::from(&b"PLR10001"[..]);word(&mut out,count as u64);word(&mut out,0);word(&mut out,0);
    for (op,data) in commands {
        let (status,output)=match command(op,data,&mut values,&mut next) { Ok(data)=>(0,data),Err(error)=>error };
        word(&mut out,op);word(&mut out,status);word(&mut out,output.len() as u64);out.extend_from_slice(&output);
    }
    let length=out.len() as u64;out[16..24].copy_from_slice(&length.to_le_bytes());Ok(out)
}

fn main() {
    let mut raw=Vec::new();std::io::stdin().take(MAX_TEST_INPUT+1).read_to_end(&mut raw).unwrap();
    let result=if raw.len() as u64>MAX_TEST_INPUT {Err(())} else {execute(&raw)};
    let mut output=std::io::stdout().lock();
    match result {Ok(bytes)=>{output.write_all(&0u64.to_le_bytes()).unwrap();output.write_all(&bytes).unwrap();},
        Err(())=>output.write_all(&100u64.to_le_bytes()).unwrap()}
}
