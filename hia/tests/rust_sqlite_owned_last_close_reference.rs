//! Real last-close witness using only the original public owned SQLite API.
#![forbid(unsafe_code)]
#[allow(dead_code)]
#[path="rust_sqlite_real_vfs_receipt_reference.rs"]
mod stream;
use rusqlite::OpenFlags;
use std::{io::{self,Write},os::unix::fs::MetadataExt,path::{Path,PathBuf}};
use trnm_sqlite_io_boundary::{registered_receipt,NativeIoLease,NativeIoOwner,RootReceipt,ROOT_COUNT};

fn words(w:&mut impl Write,n:&[u64]) {for x in n {w.write_all(&x.to_le_bytes()).unwrap();}}
const NAMES:[&str;3]=["native.sqlite","native.sqlite-wal","native.sqlite-shm"];
fn snap(lease:&NativeIoLease)->(RootReceipt,u64,u64,Vec<[u64;14]>) {
    let r=lease.receipt().unwrap();
    assert!(r.lifecycle_complete && !r.failed && r.denied_operations==0 && r.quarantined_actual_states==0);
    assert_eq!((r.root_device,r.root_inode),lease.identity());
    assert_eq!(r.owner_pid,std::process::id());
    assert_eq!(serde_json::to_vec(&r).unwrap(),serde_json::to_vec(&registered_receipt(lease.vfs_name()).unwrap()).unwrap());
    let mut p=0;let mut q=0;let mut rows=Vec::new();
    for (i,name) in NAMES.iter().enumerate() {
        let mut found=r.objects.iter().filter(|o|o.basename==*name);
        let object=found.next();
        assert!(found.next().is_none());
        if object.is_some(){q|=1<<i;}
        match std::fs::symlink_metadata(lease.directory().join(name)) {
            Ok(m) => {
                p|=1<<i;let o=object.unwrap();
                assert!(m.is_file() && m.nlink()==1 && o.linked && !o.reserved_pending_open);
                assert_eq!((o.device,o.inode),(Some(m.dev()),Some(m.ino())));
                assert_eq!((o.actual_last_bytes,o.actual_last_allocated_blocks_512),(m.size(),m.blocks()));
                rows.push([o.generation,m.dev(),m.ino(),m.size(),m.blocks(),o.device.unwrap(),o.inode.unwrap(),
                    o.actual_last_bytes,o.actual_last_allocated_blocks_512,o.high_water_bytes,
                    o.handles.into(),o.pending_opens.into(),o.shm_references.into(),o.linked.into()]);
            }
            Err(e) => {assert_eq!(e.kind(),io::ErrorKind::NotFound);assert!(object.is_none());}
        }
    }
    assert_eq!(rows.len(),r.objects.len());
    (r,p,q,rows)
}
fn main() {
    let a:Vec<_>=std::env::args_os().collect();
    assert_eq!(a.len(),3);
    let top=Path::new(&a[1]);let p:u64=a[2].to_str().unwrap().parse().unwrap();
    assert!([1,2].contains(&p));
    let roots:[PathBuf;ROOT_COUNT]=std::array::from_fn(|i|top.join(format!("root-{i}")));
    let owner=if p==1 {NativeIoOwner::create(roots)} else {NativeIoOwner::create_with_reservation_v2(roots)}.unwrap();
    let lease=owner.lease(0).unwrap();
    let db=lease.open(&lease.directory().join(NAMES[0]),OpenFlags::SQLITE_OPEN_READ_WRITE
        |OpenFlags::SQLITE_OPEN_CREATE|OpenFlags::SQLITE_OPEN_NO_MUTEX).unwrap();
    assert_eq!(db.query_row("PRAGMA journal_mode=WAL",[],|r|r.get::<_,String>(0)).unwrap(),"wal");
    db.execute_batch("CREATE TABLE sample(k INTEGER PRIMARY KEY,v TEXT);
        INSERT INTO sample VALUES(1,'one');").unwrap();
    assert_eq!(db.query_row("SELECT v FROM sample",[],|r|r.get::<_,String>(0)).unwrap(),"one");
    let (before,pm,rm,prior)=snap(&lease);
    assert_eq!((pm,rm),(7,7));
    drop(db);
    let (after,pn,rn,last)=snap(&lease);
    assert_eq!((pn,rn),(1,1));
    assert_eq!((before.root_device,before.root_inode),(after.root_device,after.root_inode));
    assert_eq!(before.growth_reservation_quantum_bytes,(p==2).then_some(65536));
    assert_eq!(before.growth_reservation_quantum_bytes,after.growth_reservation_quantum_bytes);
    assert!(last[0][3]>prior[0][3]);
    assert_eq!(prior[0][..3],last[0][..3]);
    for (old,now) in [(&before.lifecycle,&after.lifecycle),(&before.cleanup_lifecycle,&after.cleanup_lifecycle)] {
        assert!(now.len()>=old.len());
        assert_eq!(serde_json::to_vec(old).unwrap(),serde_json::to_vec(&now[..old.len()]).unwrap());
    }
    let ord=&after.lifecycle[before.lifecycle.len()..];
    let clean=&after.cleanup_lifecycle[before.cleanup_lifecycle.len()..];
    assert_eq!(ord.len(),usize::from(p==1));
    if p==1 {assert_eq!(ord[0].action,"reserve-growth");}
    assert_eq!(clean.iter().map(|e|e.action).collect::<Vec<_>>(),
        ["unlinked","underlying-shm-unmap","underlying-close","unlinked","underlying-close"]);
    let base=before.lifecycle.len()+before.cleanup_lifecycle.len();
    let mut total=0;let mut tail=Vec::new();
    for (i,ev) in ord.iter().chain(clean).enumerate() {
        assert_eq!(ev.sequence,(base+i) as u64);
        total+=serde_json::to_vec(ev).unwrap().len() as u64;
        stream::typed(&mut tail,ev,i<ord.len());
    }
    assert_eq!(total,(after.lifecycle_serialized_bytes-before.lifecycle_serialized_bytes) as u64);
    let mut out=io::stdout().lock();
    words(&mut out,&[p,before.root_device,before.root_inode,after.root_device,after.root_inode,
        before.lifecycle.len() as u64,before.cleanup_lifecycle.len() as u64,before.lifecycle_serialized_bytes as u64,
        after.lifecycle.len() as u64,after.cleanup_lifecycle.len() as u64,after.lifecycle_serialized_bytes as u64,pm,pn,rm,rn]);
    for row in prior.iter().chain(last.iter()) {words(&mut out,row);}
    out.write_all(&tail).unwrap();
    words(&mut out,&[(after.lifecycle.len()+after.cleanup_lifecycle.len()) as u64,
        total,last[0][9],prior[1][9]+prior[2][9],last[0][0],last[0][1],last[0][2]]);
}
