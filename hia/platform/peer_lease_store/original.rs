//! Transport-only observer of the complete unchanged original store/protocol.
//! The crate-private apply API is accessed by including the original modules
//! into this observer's crate. No original statement is edited or replaced.
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
#[allow(dead_code)]
mod protocol { include!(concat!(env!("ORIGINAL_PEER_SOURCE"), "/src/protocol.rs")); }
#[allow(dead_code)]
mod store { include!(concat!(env!("ORIGINAL_PEER_SOURCE"), "/src/store.rs")); }
pub use protocol::PeerLeaseErrorV1;
use protocol::{LeaseOperationV1, LeaseRequestV1, PeerLeaseDirectionV1, PeerLeaseScopeV1, PeerLeaseTokenV1};
use store::PeerLeaseStoreV1;

fn word(raw: &[u8], p: usize) -> u64 { u64::from_le_bytes(raw[p..p+8].try_into().unwrap()) }
fn put(out: &mut Vec<u8>, value: u64) { out.extend_from_slice(&value.to_le_bytes()); }
fn take(input: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; n]; input.read_exact(&mut bytes)?; Ok(bytes)
}
fn response(output: &mut impl Write, cmd: u64, cat: u64, code: u64, body: &[u8]) -> io::Result<()> {
    let mut bytes = b"PLSR0001".to_vec();
    for value in [cmd, cat, code, body.len() as u64] { put(&mut bytes, value); }
    bytes.extend_from_slice(body); output.write_all(&bytes)?; output.flush()
}
fn scope(raw: &[u8]) -> Result<PeerLeaseScopeV1, ()> {
    if raw.len() != 105 { return Err(()); }
    let direction = match raw[64] { 1 => PeerLeaseDirectionV1::Outbound, 2 => PeerLeaseDirectionV1::Inbound, _ => return Err(()) };
    PeerLeaseScopeV1::new(raw[..32].try_into().unwrap(), raw[32..64].try_into().unwrap(), direction,
                        word(raw,65), raw[73..105].try_into().unwrap()).map_err(|_| ())
}
fn encode_scope(out: &mut Vec<u8>, scope: PeerLeaseScopeV1) {
    out.extend_from_slice(&scope.local_id()); out.extend_from_slice(&scope.remote_id());
    out.push(scope.direction() as u8); put(out, scope.epoch()); out.extend_from_slice(&scope.peer_scope_id());
}
fn token(value: PeerLeaseTokenV1) -> Vec<u8> {
    let mut out=Vec::with_capacity(185); encode_scope(&mut out,value.scope());
    out.extend_from_slice(&value.session_id()); put(&mut out,value.generation());
    put(&mut out,value.expires_at_ms()); out.extend_from_slice(&value.record_hash()); out
}
fn error(error: PeerLeaseErrorV1) -> (u64,u64) {
    eprintln!("original store error: {error:?}; Display={error}");
    match error {
        PeerLeaseErrorV1::Rejected(code) => (4,code as u64),
        PeerLeaseErrorV1::InvalidRequest(message) => (1,match message {
            "journal path must be absolute"=>1,
            "journal parent"=>2,
            "journal anchor filename"=>3,
            "journal parent must be a directory"=>4,
            "journal parent must have private mode 0700"=>5,
            "journal parent must be owned by the effective user"=>6,
            "journal parent must not be a symlink alias"=>7,
            "journal parent ancestry must not be group/world writable"=>8,
            "journal parent ancestry must be root- or owner-controlled"=>9,
            "invalid lease identity"=>10,
            "lease generation must be positive"=>11,
            "lease TTL is outside the bounded profile"=>12,
            "lease TTL overflow"=>13,
            "journal parent must be a real directory"=>14,
            "journal parent has no existing ancestor"=>15,
            "journal authority file must be a private regular file"=>16,
            "journal anchor descriptor/path identity changed"=>17,
            _=>panic!("unmapped actual InvalidRequest: {message}"),
        }),
        PeerLeaseErrorV1::Io(error) => {
            if let Some(errno) = error.raw_os_error() { return (2, errno as u64); }
            let text=error.to_string();
            let code=match text.as_str() {
                "failed to write whole buffer"=>4096,
                "journal anchor descriptor/path identity changed"=>4097,
                "journal authority file must be a private regular file"=>4112,
                "file name contained an unexpected NUL byte"=>22,
                _=> {
                    // The original deliberately converts a metadata error in
                    // the new-anchor admission into io::Error::other(Display).
                    let prefix="peer lease I/O error: ";
                    if text.starts_with(prefix) && text.ends_with(')') {
                        text.rsplit_once("(os error ").and_then(|(_,x)|x.strip_suffix(')'))
                            .and_then(|x|x.parse::<u64>().ok()).map(|n|8192+n)
                            .unwrap_or_else(||panic!("unmapped actual io::Error::other: {text}"))
                    } else { panic!("unmapped actual io::Error without errno: {text}"); }
                }
            };
            (2,code)
        }
        PeerLeaseErrorV1::Protocol(message)=>panic!("unexpected store Protocol error: {message}"),
    }
}
fn run() -> io::Result<()> {
    let mut input=io::stdin().lock(); let mut output=io::stdout().lock();
    let header=take(&mut input,32)?;
    if &header[..8]!=b"PLSTO001" || word(&header,16)!=u64::MAX || word(&header,24)!=u64::MAX {
        return Err(io::Error::other("observer bootstrap; diagnostic gates are native-only observations"));
    }
    let length=word(&header,8);
    if length>4095 { response(&mut output,u64::MAX,2,36,&[])?; return Ok(()); }
    let path=PathBuf::from(OsString::from_vec(take(&mut input,length as usize)?));
    let mut owner=match PeerLeaseStoreV1::open(&path) {
        Ok(owner)=>Some(owner),
        Err(failure)=>{let (a,b)=error(failure); response(&mut output,u64::MAX,a,b,&[])?;return Ok(());}
    };
    response(&mut output,u64::MAX,0,0,&[])?;
    loop {
        let header=take(&mut input,16)?;
        if &header[..8]!=b"PLSC0001" { return Err(io::Error::other("observer command magic")); }
        let cmd=word(&header,8);
        if cmd==0 { drop(owner.take()); response(&mut output,cmd,0,0,&[])?; return Ok(()); }
        let store=owner.as_mut().unwrap();
        let mut result=Vec::new(); let mut status=(0,0);
        match cmd {
            1=>{put(&mut result,store.last_now_ms()); result.extend_from_slice(&store.last_hash());},
            2|3=>{
                let bytes=take(&mut input,105)?;
                match scope(&bytes) {
                    Err(())=>status=(100,0),
                    Ok(scope)=>if cmd==3 { put(&mut result,store.latest_generation(scope)); }
                        else if let Some(value)=store.active_lease(scope) {
                            put(&mut result,1);result.extend_from_slice(&token(value));
                        } else { put(&mut result,0); }
                }
            },
            4=>{
                let bytes=take(&mut input,209)?;
                let operation=match word(&bytes,0) { 1=>Some(LeaseOperationV1::Acquire),2=>Some(LeaseOperationV1::Renew),3=>Some(LeaseOperationV1::Revalidate),4=>Some(LeaseOperationV1::Release),_=>None };
                match (operation,scope(&bytes[16..121])) {
                    (Some(operation),Ok(scope))=>{
                        let request=LeaseRequestV1 {operation,scope,session_id:bytes[121..153].try_into().unwrap(),
                            generation:word(&bytes,153),expires_at_ms:word(&bytes,161),ttl_ms:word(&bytes,169),
                            record_hash:bytes[177..209].try_into().unwrap()};
                        match store.apply(request,word(&bytes,8)) {
                            Ok(value)=>result=token(value),Err(failure)=>status=error(failure)
                        }
                    },
                    _=>status=(100,0),
                }
            },
            5=>result.extend_from_slice(store.path().as_os_str().as_bytes()),
            _=>return Err(io::Error::other("observer command operation")),
        }
        response(&mut output,cmd,status.0,status.1,&result)?;
    }
}
fn main() {
    if let Err(error)=run() { eprintln!("original transport I/O: {error}");std::process::exit(70); }
}
