use std::io::{self,BufRead};
use std::os::unix::ffi::{OsStrExt,OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::ffi::{OsStr,OsString};
use std::path::Path;
fn num(s:&[u8],p:usize)->Option<u64>{Some(u64::from_le_bytes(s.get(p..p+8)?.try_into().ok()?))}
fn put(v:&mut Vec<u8>,x:u64){v.extend_from_slice(&x.to_le_bytes());}
fn response(payload:&[u8])->Vec<u8>{let mut v=Vec::new();put(&mut v,payload.len() as u64);v.extend_from_slice(payload);v}
fn fs_response(code:u64,msg:&[u8],errno:u64,mode:u64,size:u64,payload:&[u8])->Vec<u8>{
 let mut v=Vec::new();for x in [code,msg.len() as u64,errno,mode,size,payload.len() as u64]{put(&mut v,x);}v.extend_from_slice(msg);v.extend_from_slice(payload);v
}
fn err(e:io::Error,status:u64,ignore:bool,raw_only:bool)->Vec<u8>{
 let n=e.raw_os_error().unwrap_or(0) as u64;
 if ignore || (raw_only&&e.raw_os_error().is_some()){fs_response(0,b"",n,0,0,b"")}
 else{fs_response(status,e.to_string().as_bytes(),n,0,0,b"")}
}
fn run(s:&[u8])->Option<Vec<u8>>{
 if s.get(..8)?==b"TKPF0001"{
  let op=num(s,8)?;let a=usize::try_from(num(s,16)?).ok()?;let b=usize::try_from(num(s,24)?).ok()?;
  if a>s.len().checked_sub(32)?||b!=s.len()-32-a{return None;}
  let x=&s[32..32+a];let y=&s[32+a..];let mut p=Vec::new();
  match op{
   0=>{match Path::new(OsStr::from_bytes(x)).parent(){None=>put(&mut p,u64::MAX),Some(v)=>{let z=v.as_os_str().as_bytes();put(&mut p,z.len() as u64);p.extend_from_slice(z);}}}
   1=>p.extend_from_slice(String::from_utf8_lossy(x).as_bytes()),
   2=>{let x=std::str::from_utf8(x).ok()?;let y=std::str::from_utf8(y).ok()?;if !y.is_ascii(){return None;}
       let nx:String=x.chars().filter(|c|!c.is_whitespace()).flat_map(char::to_lowercase).collect();
       let ny:String=y.chars().filter(|c|!c.is_whitespace()).flat_map(char::to_lowercase).collect();put(&mut p,(nx==ny) as u64);}
   3=>{if a!=8||b!=0{return None;}let c=char::from_u32(u32::try_from(num(x,0)?).ok()?)?;put(&mut p,c.is_whitespace() as u64);}
   _=>return None
  }return Some(response(&p));
 }
 if s.get(..8)?!=b"TKFS0001"||s.len()<48{return None;}
 let op=num(s,8)?;let n=usize::try_from(num(s,16)?).ok()?;let a=num(s,24)?;let b=num(s,32)?;let m=usize::try_from(num(s,40)?).ok()?;
 if n>s.len()-48||m!=s.len()-48-n{return None;}
 let first=OsString::from_vec(s[48..48+n].to_vec());let second=OsString::from_vec(s[48+n..].to_vec());
 let path=Path::new(&first);let target=Path::new(&second);
 let ok=||fs_response(0,b"",0,0,0,b"");
 Some(match op{
  0=>match std::fs::create_dir_all(path){Ok(())=>ok(),Err(e)=>err(e,22,false,false)},
  3=>match std::fs::File::open(path).and_then(|f|f.sync_all()){Ok(())=>ok(),Err(e)=>err(e,a,false,false)},
  6=>match std::fs::symlink_metadata(path){Ok(m)=>fs_response(0,b"",0,m.mode() as u64,m.len(),b""),Err(e)=>err(e,22,false,true)},
  7=>match std::fs::remove_file(path){Ok(())=>ok(),Err(e)=>err(e,a,b==1,false)},
  8=>match std::fs::hard_link(path,target){Ok(())=>ok(),Err(e)=>err(e,22,false,true)},
  9=>{let n=i32::try_from(a).ok()?;fs_response(b,io::Error::from_raw_os_error(n).to_string().as_bytes(),a,0,0,b"")}
  _=>return None
 })
}
fn unhex(s:&[u8])->Option<Vec<u8>>{if s.len()%2!=0{return None;}s.chunks_exact(2).map(|x|{let a=(x[0] as char).to_digit(16)?;let b=(x[1] as char).to_digit(16)?;Some((a*16+b) as u8)}).collect()}
fn hex(s:&[u8])->String{s.iter().map(|x|format!("{x:02x}")).collect()}
fn main(){let mut input=io::stdin().lock();loop{let mut line=Vec::new();let n=input.read_until(b'\n',&mut line).unwrap();if n==0{break;}if line.last()==Some(&b'\n'){line.pop();}let result=unhex(&line).and_then(|x|run(&x));match result{Some(v)=>println!("0|{}",hex(&v)),None=>println!("100|")}}}
