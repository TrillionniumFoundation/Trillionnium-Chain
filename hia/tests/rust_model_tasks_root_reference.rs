//! Original immutable model task roots from inert known content only.
use std::io::{self,Write};
use trnm_mvcc_fee::model_task_windows_v1::{source_revision,tasks_root,TaskInput};

const DIGESTS: [&str;8]=["4b288b2349b2985083936ff5ee010210f36dfca8e037e69e4f30f1474aab2ffe","b1b4e64852ac465c9990fa668562daa8d5743f43c0eb909faba25c68d5ca51b7","c0e85661496edbc112b3ea9234b1a4ef91a2c2ca573910bb1400e04d35f83cbf","84f6403853b3b7247c504cf7bcd143890d8007b4affff1129f662d73b522f5f3","e8870fb7d518630fadca6b7d15446a1f1e2770378bcd9d81191ba3745c38ab13","1e0c8d98a47d7b6d1c5f678e76d4746d687b9c2f5dc960454b2e0d754aaa09da","18f8d2eb4a387bbc1e37ec099a7326805739bc9c99ecf0f14b808a5bcb65bf49","dfc72234825ec30d61309658da06e827eedc6887578c0566d8820891173684aa"];
fn content(i:usize)->Vec<u8>{
    match i {
        0=>b"ABC abc _foo_123 0123retained M00 m04 M10 trnm_AB trn lowercase".to_vec(),
        1=>b"a a a a a a a a a a b C C C c c c c ___ ___ ___ ___ z".to_vec(),
        2=>b"TRNM__ M00 m04 M10 123 ;.;".to_vec(),
        3=>b"token _ ".repeat(1024),
        4=>b"ab ".repeat(1025),
        5=>b"AB ".repeat(1023),
        6=>b"xxxxxxxx".repeat(1024),
        _=>b"b B b b b b b b b B\nfoo/bar".to_vec(),
    }
}
fn input(i:usize, label:u8)->TaskInput{
    let mut hex=String::new();
    for b in content(i){hex.push_str(&format!("{b:02x}"));}
    TaskInput{source_path:format!("{i}/synthetic-{}.txt",if i==3 {"\""} else { "a" }),
        content_sha256:DIGESTS[i].to_owned(), content_utf8_hex:hex, label}
}
fn emit(out:&mut impl Write, family:[u8;32],repo:&str,rows:&[TaskInput],wrong:bool){
    let mut rev=source_revision(repo,rows).unwrap_or([0;32]);
    if wrong {rev[31]^=1;}
    let mut f=b"MSR1\0\0\0\0".to_vec();
    for x in [repo.len() as u64,rows.len() as u64]{f.extend_from_slice(&x.to_le_bytes());}
    f.extend_from_slice(repo.as_bytes());
    for r in rows{
        let data=[&r.source_path,&r.content_sha256,&r.content_utf8_hex];
        for v in data{f.extend_from_slice(&(v.len() as u64).to_le_bytes());}
        f.extend_from_slice(&u64::from(r.label).to_le_bytes());
        for v in data{f.extend_from_slice(v.as_bytes());}
    }
    f.extend_from_slice(&family);
    f.extend_from_slice(&rev);
    let (status,hash)=match tasks_root(family,repo,rev,rows){
        Ok(x)=>(0u32,x), Err(e)=>(match e{
            "TASK_WINDOW_SOURCE"=>1,"TASK_WINDOW_COUNT"=>2,"TASK_WINDOW_ORDER"=>3,
            "TASK_WINDOW_CONTENT"=>4,"TASK_WINDOW_HASH"=>5,"TASK_WINDOW_CONTENT_HASH"=>6,
            "TASK_WINDOW_SOURCE_REVISION"=>7,"TASK_WINDOW_TASK_ALIAS"=>8,"TASK_WINDOW_CLASSES"=>9,
            x=>panic!("unexpected original result {x}"),
        },[0;32]),
    };
    out.write_all(&status.to_le_bytes()).unwrap();
    out.write_all(&(f.len() as u32).to_le_bytes()).unwrap();
    out.write_all(&f).unwrap();
    out.write_all(&hash).unwrap();
}
fn main(){
    let mut out=io::stdout().lock();
    let family=[7;32];
    let rows=(0..8).map(|i|input(i,(i%3) as u8)).collect::<Vec<_>>();
    emit(&mut out,family,"synthetic-local",&rows[..3],false);
    emit(&mut out,family,"synthetic-local",&rows[..4],false);
    emit(&mut out,family,"synthetic-local",&rows,false);
    emit(&mut out,[9;32],"synthetic-local",&rows,false);
    emit(&mut out,family,"synthetic\"local",&rows,false);
    emit(&mut out,family,"synthetic-local",&rows[..3],true);
    emit(&mut out,family,"",&rows[..2],true);
    emit(&mut out,family,"synthetic-local",&rows[..2],false);
    let mut changed=rows[..3].to_vec(); changed.swap(0,1);
    emit(&mut out,family,"synthetic-local",&changed,true);
    let mut changed=rows[..3].to_vec();changed[1].content_utf8_hex="00".into();
    emit(&mut out,family,"synthetic-local",&changed,true);
    let mut changed=rows[..3].to_vec();changed[1].content_sha256="bad".into();
    emit(&mut out,family,"synthetic-local",&changed,true);
    let mut changed=rows[..3].to_vec();changed[1].content_sha256="00".repeat(32);
    emit(&mut out,family,"synthetic-local",&changed,true);
    let mut changed=rows[..3].to_vec();changed[1].label=255;
    emit(&mut out,family,"synthetic-local",&changed,false);
    emit(&mut out,family,"synthetic-local",&changed,true);
    let mut changed=rows[..3].to_vec();changed[2].label=0;
    emit(&mut out,family,"synthetic-local",&changed,false);
    changed[2].content_utf8_hex=changed[0].content_utf8_hex.clone();
    changed[2].content_sha256=changed[0].content_sha256.clone();
    emit(&mut out,family,"synthetic-local",&changed,false);
    let mut changed=rows[..3].to_vec(); changed[0].label=2;changed[2].label=0;
    emit(&mut out,family,"synthetic-local",&changed,false);
}
