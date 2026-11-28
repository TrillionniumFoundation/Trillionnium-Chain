//! Public original in-memory source snapshot identity; all paths/content are inert.
use std::io::{self, Write};
use trnm_mvcc_fee::model_task_windows_v1::{source_revision, TaskInput};

fn fixture(path: &str, label: u8) -> TaskInput {
    TaskInput { source_path:path.into(), label, content_utf8_hex:"61".into(),
        content_sha256:"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb".into() }
}
fn emit(w: &mut impl Write, repo: &str, inputs: &[TaskInput]) {
    let mut buf=b"MSR1\0\0\0\0".to_vec();
    buf.extend_from_slice(&(repo.len() as u64).to_le_bytes());
    buf.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
    buf.extend_from_slice(repo.as_bytes());
    for t in inputs {
        let fields=[&t.source_path,&t.content_sha256,&t.content_utf8_hex];
        for s in fields {buf.extend_from_slice(&(s.len() as u64).to_le_bytes());}
        buf.extend_from_slice(&u64::from(t.label).to_le_bytes());
        for s in fields {buf.extend_from_slice(s.as_bytes());}
    }
    let (s,h)=match source_revision(repo,inputs) {
        Ok(h)=>(0u32,h),
        Err(e)=>(match e {
            "TASK_WINDOW_SOURCE"=>1,"TASK_WINDOW_COUNT"=>2,"TASK_WINDOW_ORDER"=>3,
            "TASK_WINDOW_CONTENT"=>4,"TASK_WINDOW_HASH"=>5,"TASK_WINDOW_CONTENT_HASH"=>6,
            x=>panic!("unexpected original result {x}"),
        },[0;32]),
    };
    w.write_all(&s.to_le_bytes()).unwrap();
    w.write_all(&(buf.len() as u32).to_le_bytes()).unwrap();
    w.write_all(&buf).unwrap();
    w.write_all(&h).unwrap();
}
fn main() {
    let mut out=io::stdout().lock();
    let clean=vec![fixture("A",0),fixture("A/quoted\".txt",1),fixture("nested/a",255)];
    emit(&mut out,"synthetic", &clean);
    let mut labels=clean.clone();
    for t in &mut labels {t.label ^= 255;}
    emit(&mut out,"synthetic", &labels);
    emit(&mut out,"synthetic\n\"local", &clean);
    emit(&mut out,"", &clean[..2]);
    emit(&mut out,"source-λ", &clean);
    emit(&mut out,"synthetic", &clean[..2]);
    let mut changed=clean.clone();
    changed[0].source_path="A//empty-component".into();
    changed[0].content_sha256="X".into();
    changed[0].content_utf8_hex="A".into();
    emit(&mut out,"synthetic", &changed);
    changed[0].source_path="A".into();
    emit(&mut out,"synthetic", &changed);
    changed[0].content_utf8_hex="00".into();
    emit(&mut out,"synthetic", &changed);
    changed[0].content_utf8_hex="ff".into();
    emit(&mut out,"synthetic", &changed);
    changed[0].content_utf8_hex="61".into();
    emit(&mut out,"synthetic", &changed);
    changed[0].content_sha256="00".repeat(32);
    emit(&mut out,"synthetic", &changed);
    changed=clean.clone();
    changed[1].source_path=changed[0].source_path.clone();
    emit(&mut out,"synthetic", &changed);
    changed=clean.clone();
    changed.swap(1,2);
    emit(&mut out,"synthetic", &changed);
    changed=clean.clone();
    changed[1].content_sha256="00".repeat(31)+"0A";
    emit(&mut out,"synthetic", &changed);
    let large=(0..8).map(|i| {
        let path=format!("{i}{}", "\t".repeat(255));
        let mut row=fixture(&path,i as u8);
        row.content_utf8_hex="78".repeat(8192);
        row.content_sha256="18f8d2eb4a387bbc1e37ec099a7326805739bc9c99ecf0f14b808a5bcb65bf49".into();
        row
    }).collect::<Vec<_>>();
    emit(&mut out,&"\t".repeat(256), &large);
}
