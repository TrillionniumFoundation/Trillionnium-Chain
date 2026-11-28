// Private test child of the complete original relative_tests module.
// Production host_kernel_parent.rs remains byte-for-byte unchanged.
// Only fixture paths and the actual fixture UID replace production authority.
use super::*;
use serde_json::{json, Value};
use std::{cell::Cell, io::BufRead, rc::Rc};

const MARKER: &str = "HIA_HOST_CHECKPOINT_ORACLE:";
const DEFAULTS: [(&str, &[u8]); 5] = [
    ("cpu.max", b"25000 100000\n"), ("cpu.max.burst", b"0\n"),
    ("memory.max", b"2147483648\n"), ("memory.swap.max", b"0\n"),
    ("pids.max", b"256\n"),
];

fn decoded(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes().chunks_exact(2).map(|pair| {
        let raw = std::str::from_utf8(pair).unwrap();
        u8::from_str_radix(raw, 16).unwrap()
    }).collect()
}

fn parent_path(root: &Path) -> PathBuf { root.join("sys/fs/cgroup/trnmponpublic.slice") }

fn selected(root: &Path, spelling: &str) -> PathBuf {
    if spelling == "parent" { return parent_path(root); }
    if let Some(child) = spelling.strip_prefix("parent/") {
        assert!(DEFAULTS.iter().any(|(name, _)| *name == child));
        return parent_path(root).join(child);
    }
    assert!(matches!(spelling, "boot" | "membership" | "controllers" | "sys" | "sys/fs" | "sys/fs/cgroup"));
    root.join(spelling)
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file(), "replacement corpus must contain regular limits");
        fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
    }
}

fn apply(root: &Path, actions: &[Value]) {
    let parent = parent_path(root);
    for action in actions {
        match action["op"].as_str().unwrap() {
            "replace-parent" => {
                let detached = parent.with_file_name("trnmponpublic.slice.detached");
                fs::rename(&parent, &detached).unwrap();
                copy_directory(&detached, &parent);
            }
            "chmod" => fs::set_permissions(&parent,
                fs::Permissions::from_mode(u32::try_from(action["mode"].as_u64().unwrap()).unwrap())).unwrap(),
            "parent-file" => {
                fs::remove_dir_all(&parent).unwrap(); fs::write(&parent, b"not directory").unwrap();
            }
            op => {
                let path = selected(root, action["path"].as_str().unwrap());
                match op {
                    "write" => fs::write(path, decoded(action["hex"].as_str().unwrap())).unwrap(),
                    "remove" => fs::remove_file(path).unwrap(),
                    "symlink" => {
                        let name = format!("{}.target", path.file_name().unwrap().to_str().unwrap());
                        let target = path.with_file_name(&name);
                        fs::rename(&path, target).unwrap(); std::os::unix::fs::symlink(name, path).unwrap();
                    }
                    "directory" => { fs::remove_file(&path).unwrap(); fs::create_dir(path).unwrap(); }
                    "fifo" => {
                        fs::remove_file(&path).unwrap();
                        rustix::fs::mkfifoat(rustix::fs::CWD, &path,
                            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
                    }
                    _ => panic!("unexpected private fixture action {op}"),
                }
            }
        }
    }
}

fn fixture(root: &Path) {
    let parent = parent_path(root);
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("controllers"), b"cpu memory pids\n").unwrap();
    fs::write(root.join("boot"), b"boot-identity\n").unwrap();
    fs::write(root.join("membership"), b"0::/trnmponpublic.slice\n").unwrap();
    for (name, value) in DEFAULTS { fs::write(parent.join(name), value).unwrap(); }
}

fn error_code(result: &Result<()>) -> (u64, Option<String>) {
    let Err(error) = result else { return (0, None); };
    let text = error.to_string();
    let code = match text.as_str() {
        "PUBLIC_HOST_KERNEL_PARENT" => 1,
        "PUBLIC_HOST_KERNEL_UNSUPPORTED" => 2,
        "PUBLIC_HOST_KERNEL_CONTEXT" => 3,
        "PUBLIC_HOST_KERNEL_REPLACED" => 4,
        "PUBLIC_HOST_KERNEL_UNAVAILABLE" => 5,
        "PUBLIC_HOST_KERNEL_LIMITS" => 6,
        "PUBLIC_HOST_KERNEL_LIMITS_CHANGED" => 7,
        _ => 12,
    };
    (code, Some(text))
}

struct FixtureAcquisition {
    root: PathBuf,
    parent: PathBuf,
    identity: (u64, u64, u32),
    boot: String,
    limits: Limits,
}

impl FixtureAcquisition {
    fn acquire(root: &Path) -> Result<Self> {
        let user_path = parent_path(root);
        // This fixture relationship is not approved_parent_path authority.
        let parent = fs::canonicalize(&user_path)
            .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_PARENT"))?;
        if parent != user_path { return Err("PUBLIC_HOST_KERNEL_PARENT".into()); }
        if !root.join("controllers").is_file() { return Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into()); }
        let metadata = fs::symlink_metadata(&parent)?;
        let fixture_uid = rustix::process::getuid().as_raw();
        if !metadata.is_dir() || metadata.uid() != fixture_uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err("PUBLIC_HOST_KERNEL_PARENT".into());
        }
        let boot = fs::read_to_string(root.join("boot"))
            .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
        let identity = (metadata.dev(), metadata.ino(), fixture_uid);
        let limits = {
            let opened = ScopedParentDirectory::from_file(open_current_parent(&parent)?, identity)?;
            opened.read_limits()?
        };
        Ok(Self { root: root.into(), parent, identity, boot: boot.trim().into(), limits })
    }

    fn check(&self, gate: u64, mutations: &[Value], gate_ran: Rc<Cell<bool>>) -> Result<()> {
        let mut boot_bytes = [0; CONTEXT_STACK_BYTES + 1];
        let current_boot = read_context(&self.root.join("boot"), &mut boot_bytes)?;
        if current_boot.trim() != self.boot { return Err("PUBLIC_HOST_KERNEL_REPLACED".into()); }
        if gate == 1 { apply(&self.root, mutations); gate_ran.set(true); }
        let directory = ScopedParentDirectory::from_file(open_current_parent(&self.parent)?, self.identity)?;
        if gate == 2 { apply(&self.root, mutations); gate_ran.set(true); }
        let mut member_bytes = [0; CONTEXT_STACK_BYTES + 1];
        let membership = read_context(&self.root.join("membership"), &mut member_bytes)?;
        if !cgroup_within_parent(&membership, PARENT_NAME)? { return Err("PUBLIC_HOST_KERNEL_CONTEXT".into()); }
        if gate == 3 {
            let root = self.root.clone(); let changes = mutations.to_vec();
            super::with_after_last_limit_read(
                move || { assert!(!gate_ran.replace(true)); apply(&root, &changes); },
                || directory.verify_limits(&self.parent, self.limits),
            )
        } else {
            directory.verify_limits(&self.parent, self.limits)
        }
    }
}

#[test]
fn evaluate() {
    let corpus = std::env::var_os("TRNM_HIA_HOST_CHECKPOINT_CORPUS")
        .expect("the mandatory original driver must supply the exact native corpus");
    let input = fs::File::open(corpus).unwrap();
    for line in io::BufReader::new(input).lines() {
        let case: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path(); fixture(root);
        apply(root, case["before"].as_array().unwrap());
        let mut codes = Vec::new(); let mut texts = Vec::new(); let mut full_checks = 0u64;
        let acquired = FixtureAcquisition::acquire(root);
        let mut gate_observed = false;
        match acquired {
            Err(error) => {
                let (code, text) = error_code(&Err(error)); codes.push(code); texts.push(text);
            }
            Ok(owner) => {
                let initial = owner.check(0, &[], Rc::new(Cell::new(false)));
                let (code, text) = error_code(&initial); codes.push(code); texts.push(text);
                if initial.is_ok() {
                    full_checks += 1;
                    apply(root, case["after"].as_array().unwrap());
                    let gate = case["gate"].as_u64().unwrap();
                    assert!(gate <= 3);
                    let count = case["count"].as_u64().unwrap();
                    assert!((1..=1_000_000).contains(&count));
                    let gate_ran = Rc::new(Cell::new(false));
                    let mut final_result = Ok(());
                    for _ in 0..count {
                        final_result = owner.check(gate, case["mutate"].as_array().unwrap(), gate_ran.clone());
                        if final_result.is_err() { break; }
                        full_checks += 1;
                    }
                    gate_observed = gate_ran.get();
                    let (code, text) = error_code(&final_result); codes.push(code); texts.push(text);
                    if !case["second_error"].is_null() {
                        assert!(final_result.is_ok());
                        let second = owner.check(0, &[], Rc::new(Cell::new(false)));
                        if second.is_ok() { full_checks += 1; }
                        let (code, text) = error_code(&second); codes.push(code); texts.push(text);
                    }
                }
            }
        }
        println!("{MARKER}{}", json!({"name":case["name"],"codes":codes,
            "error_texts":texts,"full_checks":full_checks,"gate_observed":gate_observed,
            "private_file_fixture_only":true,"production_parent_authority":false}));
    }
}
