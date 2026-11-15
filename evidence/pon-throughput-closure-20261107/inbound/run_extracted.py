import hashlib,json,pathlib,subprocess,os
root=pathlib.Path('/workspace/scratch/ae364bcbabfb/chain-throughput')
out=pathlib.Path('/workspace/scratch/ae364bcbabfb/inbound-checks')
source='trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs'
base=subprocess.check_output(['git','show','e70f13448aad715286fb8eb56fc802b09db643a3:'+source],cwd=root,text=True)
new=(root/source).read_text()

def function(src,start,end):
 return src[src.index(start):src.index(end,src.index(start))]

def module(src,name):
 request=function(src,'#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]','pub const PROFILE:')
 constants=function(src,'pub const PROFILE:','#[derive(Default)]\nstruct MutationCpuMeasurement')
 helpers=function(src,'fn request_op(','#[derive(Clone, Copy)]\nstruct Hello')
 canonical=function(src,'/// Streaming canonical equality','struct BufferPermit')
 read=function(src,'fn read_available(','fn write_available(')
 tests=(root/'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/input_decode_tests.rs').read_text()
 return f'''#[allow(dead_code)]\nmod {name} {{
use super::*;
{request}\n{constants}\n{helpers}\n{canonical}\n{read}
#[cfg(test)]\nmod input_decode_tests {{\n{tests}\n}}
pub fn decode(raw: &[u8],op:u8) {{ std::hint::black_box(canonical_request(std::hint::black_box(raw),op).unwrap()); }}
pub fn idle(socket: &mut TcpStream,bytes: &mut Vec<u8>) {{ assert!(!read_available(socket,bytes,108).unwrap()); }}
}}
'''
header='''use serde::{Deserialize,Serialize};
use std::{io::{Read,Write},net::{TcpStream,TcpListener},thread,time::{Duration,Instant}};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(ok:bool,msg:&str)->Result<()> { if ok {Ok(())} else {Err(msg.into())} }
'''
bench='''fn main() {
for op in [1u8,6,7] {
let name = match op {1=>"submit",6=>"growth_submit_v1",_=>"growth_packet_status_v1"};
for size in [64usize,49_603,1_048_576] {
let raw=format!("{{\\\"op\\\":\\\"{}\\\",\\\"packet\\\":\\\"{}\\\"}}",name,"ac".repeat(size)).into_bytes();
let count= (16_777_216usize/raw.len()).max(4);
for arm in [0,1,1,0] {
let started=Instant::now();
for _ in 0..count { if arm==0 {baseline::decode(&raw,op)} else {candidate::decode(&raw,op)} }
println!("{{\\\"kind\\\":\\\"canonical_decode\\\",\\\"op\\\":{},\\\"packet_bytes\\\":{},\\\"calls\\\":{},\\\"arm\\\":{},\\\"wall_ns\\\":{}}}",op,size,count,arm,started.elapsed().as_nanos());
}
}
}
let listener=TcpListener::bind("127.0.0.1:0").unwrap();
let _sender=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
let (mut receiver,_)=listener.accept().unwrap(); receiver.set_nonblocking(true).unwrap();
for arm in [0,1,1,0] {
let mut bytes=Vec::with_capacity(108); let started=Instant::now();
for _ in 0..100_000 { if arm==0 {baseline::idle(&mut receiver,&mut bytes)} else {candidate::idle(&mut receiver,&mut bytes)} }
println!("{{\\\"kind\\\":\\\"idle_hello_socket\\\",\\\"calls\\\":100000,\\\"arm\\\":{},\\\"wall_ns\\\":{}}}",arm,started.elapsed().as_nanos());
}
}
'''
text=header+module(base,'baseline')+module(new,'candidate')+bench
(out/'extracted.rs').write_text(text)
meta={'baseline_commit':'e70f13448aad715286fb8eb56fc802b09db643a3','source_path':source,'baseline_source_sha256':hashlib.sha256(base.encode()).hexdigest(),'candidate_source_sha256':hashlib.sha256(new.encode()).hexdigest(),'harness_sha256':hashlib.sha256(text.encode()).hexdigest(),'scope':'exact extracted component functions; debug-profile serde dependency reuse; not whole-node, WAN, throughput or original gate qualification'}
(out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n')
deps=pathlib.Path('/workspace/scratch/ae364bcbabfb/target/debug/deps')
common=['rustc','--edition=2021',str(out/'extracted.rs'),'-L','dependency='+str(deps),'--extern','serde='+str(next(deps.glob('libserde-*.rlib'))),'--extern','serde_json='+str(next(deps.glob('libserde_json-*.rlib')))]
for typ,extra in [('tests',['--test']),('bench',['-O'])]:
 cmd=common+extra+['-o',str(out/typ)]
 log=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 (out/(typ+'-build.log')).write_text(log.stdout)
 if log.returncode:
  print(log.stdout); raise SystemExit(log.returncode)
args=[str(out/'tests'),'--test-threads=1','--nocapture']
run=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
(out/'tests.log').write_text(run.stdout);print(run.stdout)
if run.returncode: raise SystemExit(run.returncode)
run=subprocess.run([str(out/'bench')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
(out/'abba.jsonl').write_text(run.stdout);print(run.stdout)
raise SystemExit(run.returncode)
