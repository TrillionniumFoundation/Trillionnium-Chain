//! Three dormant, independent metadata observations on one actual owned WAL.
#![forbid(unsafe_code)]
use rusqlite::OpenFlags;
use std::io::{self,Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path,PathBuf};
use trnm_sqlite_io_boundary::{NativeIoLease,NativeIoOwner,ROOT_COUNT};

fn sample(lease:&NativeIoLease,policy:u64) -> [u64;18] {
    let receipt=lease.receipt().unwrap();
    assert!(receipt.lifecycle_complete && !receipt.failed && receipt.denied_operations==0);
    assert_eq!(receipt.owner_pid,std::process::id());
    assert_eq!((receipt.root_device,receipt.root_inode),lease.identity());
    assert_eq!(receipt.growth_reservation_quantum_bytes,(policy==2).then_some(65536));
    let mut wal=receipt.objects.iter().filter(|o|o.basename=="native.sqlite-wal");
    let object=wal.next().unwrap();
    assert!(wal.next().is_none() && object.linked && !object.reserved_pending_open);
    // Single fixture process, with SQLite quiescent at the phase boundary.
    // No extra FD, no write, and no claim of a path/descriptor race guarantee.
    let measured=std::fs::symlink_metadata(lease.directory().join("native.sqlite-wal")).unwrap();
    assert!(measured.is_file() && measured.nlink()==1);
    assert_eq!((object.device,object.inode),(Some(measured.dev()),Some(measured.ino())));
    assert_eq!((object.actual_last_bytes,object.actual_last_allocated_blocks_512),(measured.size(),measured.blocks()));
    let counter = |names:&[&str]| receipt.lifecycle.iter()
        .filter(|e|e.generation==object.generation && e.basename==object.basename && names.contains(&e.action))
        .count() as u64;
    [receipt.root_device,receipt.root_inode,object.generation,measured.dev(),measured.ino(),
     measured.size(),measured.blocks(),object.device.unwrap(),object.inode.unwrap(),
     object.actual_last_bytes,object.actual_last_allocated_blocks_512,object.high_water_bytes,
     receipt.lifecycle.len() as u64,receipt.cleanup_lifecycle.len() as u64,receipt.callback_operations,
     counter(&["bind-real-inode","bind-existing-before-io-v2"]),counter(&["reserve-growth"]),1]
}

fn main() {
    let args:Vec<_>=std::env::args_os().collect();
    assert_eq!(args.len(),3);
    let top=Path::new(&args[1]);
    let policy:u64=args[2].to_str().unwrap().parse().unwrap();
    assert!([1,2].contains(&policy));
    let dirs:[PathBuf;ROOT_COUNT]=std::array::from_fn(|i|top.join(format!("root-{i}")));
    let owner=if policy==1 {NativeIoOwner::create(dirs)} else {NativeIoOwner::create_with_reservation_v2(dirs)}.unwrap();
    let lease=owner.lease(0).unwrap();
    let flags=OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_CREATE|OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let writer=lease.open(&lease.directory().join("native.sqlite"),flags).unwrap();
    assert_eq!(writer.query_row("PRAGMA journal_mode=WAL",[],|r|r.get::<_,String>(0)).unwrap(),"wal");
    writer.execute_batch("CREATE TABLE sample(k INTEGER PRIMARY KEY,v TEXT NOT NULL);
        INSERT INTO sample VALUES(1,'first');").unwrap();
    let a=sample(&lease,policy);
    writer.execute("UPDATE sample SET v='second' WHERE k=1",[]).unwrap();
    assert_eq!(writer.query_row("SELECT v FROM sample",[],|r|r.get::<_,String>(0)).unwrap(),"second");
    let b=sample(&lease,policy);
    writer.execute("UPDATE sample SET v='third' WHERE k=1",[]).unwrap();
    assert_eq!(writer.query_row("SELECT v FROM sample",[],|r|r.get::<_,String>(0)).unwrap(),"third");
    let c=sample(&lease,policy);
    for (x,y) in [(&a,&b),(&b,&c)] {
        assert_eq!(x[..5],y[..5]);
        assert!(x[5]<y[5] && x[14]<y[14] && x[12]<=y[12] && x[13]<=y[13]);
        assert_eq!(x[15],y[15]); // No new bind receipt even while observed size changes.
        if policy==2 {assert_eq!((x[11],x[16]),(y[11],y[16]));}
        else {assert!(x[11]<y[11] && x[16]<y[16]);}
    }
    let mut out=io::stdout().lock();
    for n in [policy].into_iter().chain(a).chain(b).chain(c) {out.write_all(&n.to_le_bytes()).unwrap();}
    for n in [a[2],a[3],a[4],a[5],b[5],c[5],a[6],b[6],c[6],a[11],b[11],c[11],c[16]-a[16],c[14]-a[14]] {
        out.write_all(&n.to_le_bytes()).unwrap();
    }
    drop(writer);
}
