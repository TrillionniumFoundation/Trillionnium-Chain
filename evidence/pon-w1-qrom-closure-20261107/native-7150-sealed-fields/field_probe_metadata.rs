use rustix::fs::{fchmod, fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, Mode, SealFlags};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::thread;
use std::time::Duration;

const BYTES: &[u8] = b"original authenticated bytes";

fn snapshot(stage: &str, file: &File) {
    let m = file.metadata().unwrap();
    let seals = fcntl_get_seals(file).unwrap().bits();
    let mut bytes = [0u8; 64];
    let length = file.read_at(&mut bytes, 0).unwrap();
    println!("{{\"kind\":\"snapshot\",\"stage\":\"{}\",\"device\":{},\"inode\":{},\"size\":{},\"uid\":{},\"gid\":{},\"mode\":{},\"mtime\":{},\"mtime_nsec\":{},\"ctime\":{},\"ctime_nsec\":{},\"seals\":{},\"bytes_equal\":{}}}",
        stage,m.dev(),m.ino(),m.len(),m.uid(),m.gid(),m.mode(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec(),seals,&bytes[..length]==BYTES);
}

fn operation(name: &str, result: io::Result<()>) {
    let (ok, errno) = match result {
        Ok(()) => (true, "null".to_owned()),
        Err(error) => (false,error.raw_os_error().map(|v| v.to_string()).unwrap_or_else(|| "null".to_owned()))
    };
    println!("{{\"kind\":\"operation\",\"name\":\"{}\",\"ok\":{},\"errno\":{}}}",name,ok,errno);
}

fn main() {
    let flags=MemfdFlags::CLOEXEC|MemfdFlags::ALLOW_SEALING|MemfdFlags::NOEXEC_SEAL;
    let required=SealFlags::WRITE|SealFlags::SHRINK|SealFlags::GROW|SealFlags::SEAL|SealFlags::EXEC;
    let mut file=File::from(memfd_create("trnm-m15-fields-diagnostic",flags).unwrap());
    file.write_all(BYTES).unwrap();
    fchmod(&file,Mode::RUSR).unwrap();
    fcntl_add_seals(&file,required).unwrap();
    println!("{{\"kind\":\"profile\",\"memfd_flags\":{},\"required_seals\":{},\"pause_ms_between_operations\":5}}",flags.bits(),required.bits());
    snapshot("validated",&file);
    thread::sleep(Duration::from_millis(5));
    operation("write_at",file.write_at(b"bad",0).map(|_|()));
    snapshot("after_write_at",&file);
    thread::sleep(Duration::from_millis(5));
    operation("shrink",file.set_len(1));
    snapshot("after_shrink",&file);
    thread::sleep(Duration::from_millis(5));
    operation("grow",file.set_len(100));
    snapshot("after_grow",&file);
    thread::sleep(Duration::from_millis(5));
    operation("chmod_add_exec",file.set_permissions(std::fs::Permissions::from_mode(0o700)));
    snapshot("after_chmod_add_exec",&file);
    thread::sleep(Duration::from_millis(5));
    operation("chmod_same_mode",file.set_permissions(std::fs::Permissions::from_mode(0o400)));
    snapshot("after_chmod_same_mode",&file);
    thread::sleep(Duration::from_millis(5));
    operation("set_modified",file.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1)));
    snapshot("after_set_modified",&file);
    thread::sleep(Duration::from_millis(5));
    operation("chmod_nonexec_mode",file.set_permissions(std::fs::Permissions::from_mode(0o600)));
    snapshot("after_chmod_nonexec_mode",&file);
}
