// Private cfg(test) child of the complete original resource_tests include.
// Production host_kernel_parent.rs is never edited, including in the test copy.
// Only private paths and the actual fixture UID differ from production authority.
use super::*;
use serde_json::{json, Value};
use std::io::BufRead;

const MARKER: &str = "HIA_HOST_RESOURCE_ORACLE:";
const DEFAULTS: [(&str, &[u8]); 8] = [
    ("cpu.max", b"25000 100000\n"), ("cpu.max.burst", b"0\n"),
    ("memory.max", b"2147483648\n"), ("memory.swap.max", b"0\n"),
    ("pids.max", b"256\n"),
    ("cpu.stat", b"usage_usec 10\nnr_periods 20\nnr_throttled 3\nthrottled_usec 40\n"),
    ("memory.current", b"64\n"), ("pids.current", b"2\n"),
];

fn decoded(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

fn parent_path(root: &Path) -> PathBuf { root.join("sys/fs/cgroup/trnmponpublic.slice") }

fn selected(root: &Path, target: &str) -> PathBuf {
    if matches!(target, "boot" | "membership" | "controllers") { return root.join(target); }
    assert!(DEFAULTS.iter().any(|(name, _)| *name == target));
    parent_path(root).join(target)
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
    }
}

fn apply(root: &Path, actions: &[Value]) {
    let parent = parent_path(root);
    for action in actions {
        let kind = action["kind"].as_str().unwrap();
        match kind {
            "replace_parent" | "rename_parent" | "symlink_parent" => {
                let detached = root.join("detached-parent");
                fs::rename(&parent, &detached).unwrap();
                if kind == "replace_parent" { copy_directory(&detached, &parent); }
                if kind == "symlink_parent" { std::os::unix::fs::symlink(&detached, &parent).unwrap(); }
            }
            "chmod_parent" => fs::set_permissions(&parent,
                fs::Permissions::from_mode(u32::try_from(action["mode"].as_u64().unwrap()).unwrap())).unwrap(),
            _ => {
                let path = selected(root, action["target"].as_str().unwrap());
                match kind {
                    "write" => fs::write(path, decoded(action["hex"].as_str().unwrap())).unwrap(),
                    "replace_counter" => {
                        let replacement = path.with_file_name("counter.replacement");
                        fs::write(&replacement, decoded(action["hex"].as_str().unwrap())).unwrap();
                        fs::rename(replacement, path).unwrap();
                    }
                    "remove" => fs::remove_file(path).unwrap(),
                    "symlink" => {
                        let saved = path.with_file_name("counter.saved");
                        fs::rename(&path, &saved).unwrap();
                        std::os::unix::fs::symlink(saved, path).unwrap();
                    }
                    "directory" => { fs::remove_file(&path).unwrap(); fs::create_dir(path).unwrap(); }
                    "fifo" => {
                        fs::remove_file(&path).unwrap();
                        rustix::fs::mkfifoat(rustix::fs::CWD, &path,
                            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
                    }
                    "socket" => {
                        fs::remove_file(&path).unwrap();
                        // Both sides create a real filesystem socket inode;
                        // only regular-file refusal, not peer I/O, is compared.
                        let endpoint = std::os::unix::net::UnixListener::bind(path).unwrap();
                        drop(endpoint);
                    }
                    _ => panic!("unknown private resource action {kind}"),
                }
            }
        }
    }
}

fn provision(root: &Path) {
    let parent = parent_path(root);
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(root.join("controllers"), b"cpu memory pids\n").unwrap();
    fs::write(root.join("boot"), b"boot-identity\n").unwrap();
    fs::write(root.join("membership"), b"0::/trnmponpublic.slice\n").unwrap();
    for (name, raw) in DEFAULTS { fs::write(parent.join(name), raw).unwrap(); }
}

struct FixtureOwner {
    root: PathBuf,
    parent: PathBuf,
    identity: (u64, u64, u32),
    boot: String,
    limits: Limits,
}

impl FixtureOwner {
    fn acquire(root: &Path) -> Result<Self> {
        let spelling = parent_path(root);
        let parent = fs::canonicalize(&spelling)
            .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_PARENT"))?;
        if parent != spelling { return Err("PUBLIC_HOST_KERNEL_PARENT".into()); }
        if !root.join("controllers").is_file() { return Err("PUBLIC_HOST_KERNEL_UNSUPPORTED".into()); }
        let metadata = fs::symlink_metadata(&parent)?;
        let uid = rustix::process::getuid().as_raw();
        if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o022 != 0 {
            return Err("PUBLIC_HOST_KERNEL_PARENT".into());
        }
        let boot = fs::read_to_string(root.join("boot"))
            .map_err(|_| crate::Error::from("PUBLIC_HOST_KERNEL_CONTEXT"))?;
        let identity = (metadata.dev(), metadata.ino(), uid);
        let limits = {
            let current = ScopedParentDirectory::from_file(open_current_parent(&parent)?, identity)?;
            current.read_limits()?
        };
        Ok(Self { root: root.into(), parent, identity, boot: boot.trim().into(), limits })
    }

    fn checked(&self) -> Result<ScopedParentDirectory> {
        let mut boot = [0; CONTEXT_STACK_BYTES + 1];
        if read_context(&self.root.join("boot"), &mut boot)?.trim() != self.boot {
            return Err("PUBLIC_HOST_KERNEL_REPLACED".into());
        }
        let current = ScopedParentDirectory::from_file(open_current_parent(&self.parent)?, self.identity)?;
        let mut member = [0; CONTEXT_STACK_BYTES + 1];
        let text = read_context(&self.root.join("membership"), &mut member)?;
        if !cgroup_within_parent(&text, PARENT_NAME)? {
            return Err("PUBLIC_HOST_KERNEL_CONTEXT".into());
        }
        current.verify_limits(&self.parent, self.limits)?;
        Ok(current)
    }

    fn sample(&self, gate: u64, changes: &[Value], checks: &Cell<u64>, ran: &Cell<bool>)
        -> Result<KernelResourceSample>
    {
        if matches!(gate, 0 | 5 | 8) {
            let attempts = Cell::new(0u64);
            // This executes the unchanged original sample_counters helper.
            return sample_counters(|| {
                let attempt = attempts.get(); attempts.set(attempt + 1);
                if gate == 8 && attempt == 1 { apply(&self.root, changes); ran.set(true); }
                let current = self.checked()?;
                checks.set(checks.get() + 1);
                if gate == 5 && attempt == 0 { apply(&self.root, changes); ran.set(true); }
                Ok(current)
            });
        }
        assert!(matches!(gate, 6 | 7));
        // These two explicit private sequencing fixtures place mutations at
        // boundaries that the unmodified sample_counters API does not expose.
        // They still call the actual original readers and parser; no parser
        // or counter value is replaced by a reference implementation.
        let result = {
            let current = self.checked()?;
            checks.set(checks.get() + 1);
            if gate == 6 {
                let mut cpu = [0; MAX_CPU_COUNTER_BYTES + 1];
                let mut memory = [0; MAX_SCALAR_COUNTER_BYTES + 1];
                let mut tasks = [0; MAX_SCALAR_COUNTER_BYTES + 1];
                let cpu_text = current.read_counter(c"cpu.stat", &mut cpu)?;
                let memory_text = current.read_counter(c"memory.current", &mut memory)?;
                let task_text = current.read_counter(c"pids.current", &mut tasks)?;
                apply(&self.root, changes); ran.set(true);
                resource_sample(cpu_text, memory_text, task_text)?
            } else {
                let result = current.read_counters()?;
                apply(&self.root, changes); ran.set(true);
                result
            }
        };
        self.checked()?;
        checks.set(checks.get() + 1);
        Ok(result)
    }
}

fn error_code(error: &crate::Error) -> u64 {
    match error.to_string().as_str() {
        "PUBLIC_HOST_KERNEL_PARENT" => 1, "PUBLIC_HOST_KERNEL_UNSUPPORTED" => 2,
        "PUBLIC_HOST_KERNEL_CONTEXT" => 3, "PUBLIC_HOST_KERNEL_REPLACED" => 4,
        "PUBLIC_HOST_KERNEL_UNAVAILABLE" => 5, "PUBLIC_HOST_KERNEL_LIMITS" => 6,
        "PUBLIC_HOST_KERNEL_LIMITS_CHANGED" => 7, "PUBLIC_HOST_KERNEL_COUNTERS" => 13,
        "PUBLIC_HOST_KERNEL_COUNTER_REWIND" => 14,
        _ => 12,
    }
}

fn values(sample: KernelResourceSample) -> [u64; 6] {
    [sample.cpu_usage_usec, sample.cpu_nr_periods, sample.cpu_nr_throttled,
     sample.cpu_throttled_usec, sample.memory_current_bytes, sample.pids_current]
}

#[test]
fn evaluate() {
    let input = std::env::var_os("TRNM_HIA_HOST_RESOURCE_CORPUS")
        .expect("mandatory driver must provide the exact physical native corpus");
    for line in io::BufReader::new(fs::File::open(input).unwrap()).lines() {
        let case: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path(); provision(root);
        let owner = FixtureOwner::acquire(root).unwrap();
        drop(owner.checked().unwrap());
        let mut baseline = None;
        let mut observations = Vec::new();
        let mut error_texts = Vec::new();
        let mut methods = Vec::new();
        for instruction in case["steps"].as_array().unwrap() {
            apply(root, instruction["before"].as_array().unwrap());
            let operation = instruction["operation"].as_u64().unwrap();
            assert!(matches!(operation, 1 | 2));
            if operation == 2 && baseline.is_none() {
                let zero_values = [0_u64; 6]; let zero_delta = [0_u64; 4];
                observations.push(json!({"error":15,"values":zero_values,"delta":zero_delta,"checks":0}));
                error_texts.push(Some("private baseline unavailable".to_string()));
                methods.push("private protocol baseline refusal");
                break;
            }
            let gate = instruction["gate"].as_u64().unwrap();
            let checks = Cell::new(0u64); let ran = Cell::new(false);
            let observed = owner.sample(gate, instruction["mutation"].as_array().unwrap(), &checks, &ran);
            assert_eq!(ran.get(), gate != 0, "requested physical boundary must execute");
            let mut error = 0; let mut text = None; let mut numbers = [0;6]; let mut deltas = [0;4];
            match observed {
                Err(value) => { error = error_code(&value); text = Some(value.to_string()); }
                Ok(sample) => {
                    if operation == 2 {
                        match sample.cpu_delta_since(baseline.unwrap()) {
                            Err(value) => { error = error_code(&value); text = Some(value.to_string()); }
                            Ok(delta) => {
                                deltas = [delta.usage_usec, delta.nr_periods, delta.nr_throttled, delta.throttled_usec];
                            }
                        }
                    }
                    if error == 0 { numbers = values(sample); baseline = Some(sample); }
                }
            }
            observations.push(json!({"error":error,"values":numbers,"delta":deltas,"checks":checks.get()}));
            error_texts.push(text);
            methods.push(if matches!(gate, 0 | 5 | 8) { "original sample_counters" }
                         else { "original readers/parser with private phase fixture" });
            if error != 0 { break; }
        }
        println!("{MARKER}{}", json!({"name":case["name"],"comparison":observations,
            "error_texts":error_texts,"methods":methods,"private_file_fixture_only":true,
            "production_fixed_parent_authority":false}));
    }
}
