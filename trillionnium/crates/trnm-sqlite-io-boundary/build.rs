//! Fail-closed build fence for the exact private Unix layout witness.
mod build_loader_paths;

use build_loader_paths::{canonical_directory, LoaderPaths};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const AMALGAMATION_SHA256: &str =
    "9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5";
const UPSTREAM_BUILD_SHA256: &str =
    "239297962bfdc78cd420b44142ee6801d2fc9375bf8470207669f416446ebb9e";
const BUILD_FENCE: &str = "sqlite-3.51.3-normal-native-linux-layout-v3";
const NM_OUTPUT_BYTES: usize = 16 * 1024;
const NM_TIMEOUT: Duration = Duration::from_secs(20);
const WITNESS_GLOBALS: [&str; 4] = [
    "trnm_io_witness_compileoption",
    "trnm_io_witness_layout",
    "trnm_io_witness_source_id",
    "trnm_io_witness_version",
];

fn read_nm_pipe<R: Read + Send + 'static>(
    reader: R,
) -> mpsc::Receiver<Result<(Vec<u8>, bool), String>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut output = Vec::new();
        let result = reader
            .take(NM_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut output)
            .map_err(|_| "could not read bounded nm output".to_string())
            .map(|_| {
                let overflow = output.len() > NM_OUTPUT_BYTES;
                output.truncate(NM_OUTPUT_BYTES);
                (output, overflow)
            });
        let _ = sender.send(result);
    });
    receiver
}

fn verify_witness_symbols(out_dir: &Path) -> Result<(), String> {
    let archive = out_dir.join("libtrnm_sqlite_layout_witness.a");
    let metadata = fs::metadata(&archive).map_err(|_| "missing compiled witness archive")?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err("compiled witness archive is not a nonempty regular file".into());
    }
    // The build trust boundary supplies ordinary native nm in PATH. No shell,
    // nm override, target wrapper, SQLite API, or witness code is executed.
    let mut child = Command::new("nm")
        .args(["-g", "--defined-only"])
        .arg(&archive)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "trusted native nm is unavailable; witness symbols are unqualified")?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("nm stdout pipe unavailable".into());
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("nm stderr pipe unavailable".into());
    };
    let stdout = read_nm_pipe(stdout);
    let stderr = read_nm_pipe(stderr);
    let deadline = Instant::now() + NM_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("nm exceeded its 20-second qualification bound".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("could not obtain nm process terminal status".into());
            }
        }
    };
    // Ordinary trusted nm leaves no descendants holding its pipes. A missing
    // EOF still refuses qualification without an unbounded thread join.
    let (stdout, stdout_overflow) = stdout
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "nm stdout did not close within the qualification bound")??;
    let (stderr, stderr_overflow) = stderr
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "nm stderr did not close within the qualification bound")??;
    fs::write(out_dir.join("trnm-witness-symbols.stdout"), &stdout)
        .map_err(|_| "could not preserve bounded nm stdout")?;
    fs::write(out_dir.join("trnm-witness-symbols.stderr"), &stderr)
        .map_err(|_| "could not preserve bounded nm stderr")?;
    if stdout_overflow || stderr_overflow {
        return Err("nm exceeded its fixed 16 KiB per-stream output bound".into());
    }
    if !status.success() || !stderr.is_empty() {
        return Err("nm failed or emitted diagnostics; witness symbols are unqualified".into());
    }
    let text = std::str::from_utf8(&stdout).map_err(|_| "unknown non-UTF-8 nm format")?;
    let mut symbols = Vec::new();
    let mut object_headers = 0;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        // Accept only an ordinary single-object archive member heading and
        // exact address/type/name rows. Unknown formats are never guessed.
        if line.ends_with(".o:")
            && !line.bytes().any(|byte| byte.is_ascii_whitespace())
            && !line.starts_with('-')
        {
            object_headers += 1;
            continue;
        }
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 3
            || fields[0].is_empty()
            || !fields[0].bytes().all(|byte| byte.is_ascii_hexdigit())
            || fields[1] != "T"
            || !WITNESS_GLOBALS.contains(&fields[2])
        {
            return Err(
                "unexpected defined global or unknown nm symbol format; witness is unqualified"
                    .into(),
            );
        }
        symbols.push(fields[2]);
    }
    symbols.sort_unstable();
    if object_headers != 1 || symbols.as_slice() != WITNESS_GLOBALS.as_slice() {
        return Err(
            "witness must define exactly four unique approved globals in one object".into(),
        );
    }
    Ok(())
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing {name}"))
}

fn pin_text(path: &Path, expected_bytes: u64, expected_sha256: &str) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|_| "missing dependency source")?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err("dependency source length/type mismatch".into());
    }
    let bytes = fs::read(path).map_err(|_| "unreadable dependency source")?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected_sha256 {
        return Err("dependency source digest mismatch".into());
    }
    println!("cargo:rerun-if-changed={}", path.display());
    Ok(())
}

// Cargo 1.95 injects loader paths into build-script processes even when the
// parent variable is absent. Require the exact three observed normal
// directories derived from this real OUT_DIR and the actual RUSTC binary,
// and admit only the optional base profile output Cargo adds for build/test.
// This is a path constraint, not a magic qualification token or a claim that
// this process can recover the parent's original environment provenance.
fn validate_cargo_loader_paths() -> Result<LoaderPaths, String> {
    let target = env::var_os("CARGO_TARGET_DIR");
    let mut paths = LoaderPaths::capture(target.as_deref())?;
    let out = paths.out_directory(Path::new(&required("OUT_DIR")?))?;
    if out.file_name() != Some(OsStr::new("out")) {
        return Err("unexpected Cargo OUT_DIR leaf".into());
    }
    let unit = out.parent().ok_or("missing Cargo unit directory")?;
    let unit_name = unit
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or("non-UTF8 Cargo unit")?;
    let hash = unit_name
        .strip_prefix("trnm-sqlite-io-boundary-")
        .ok_or("foreign Cargo unit directory")?;
    if hash.len() != 16
        || !hash
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("unexpected Cargo unit hash".into());
    }
    let build = unit.parent().ok_or("missing Cargo build directory")?;
    if build.file_name() != Some(OsStr::new("build")) {
        return Err("unexpected Cargo build layout".into());
    }
    let profile = build.parent().ok_or("missing Cargo profile directory")?;
    let profile_name = required("PROFILE")?;
    if !matches!(profile_name.as_str(), "debug" | "release")
        || profile.file_name() != Some(OsStr::new(&profile_name))
    {
        return Err("only normal observed Cargo debug/release layouts are admitted".into());
    }
    let rustc_input = PathBuf::from(required("RUSTC")?);
    if !rustc_input.is_absolute() {
        return Err("RUSTC must be absolute".into());
    }
    let rustc = rustc_input
        .canonicalize()
        .map_err(|_| "RUSTC binary missing")?;
    if rustc != rustc_input || !rustc.is_file() || rustc.file_name() != Some(OsStr::new("rustc")) {
        return Err("RUSTC must name the canonical real compiler binary".into());
    }
    let bin = rustc.parent().ok_or("missing compiler bin")?;
    if bin.file_name() != Some(OsStr::new("bin")) {
        return Err("unexpected compiler layout".into());
    }
    let toolchain = bin.parent().ok_or("missing compiler toolchain root")?;
    let target_deps = paths.target_directory(&profile.join("deps"))?;
    let required: BTreeSet<PathBuf> = [
        target_deps.clone(),
        canonical_directory(
            &toolchain
                .join("lib")
                .join("rustlib")
                .join(required("HOST")?)
                .join("lib"),
        )?,
        canonical_directory(&toolchain.join("lib"))?,
    ]
    .into_iter()
    .collect();
    if required.len() != 3 {
        return Err("loader directory identities overlap".into());
    }
    // Cargo's base profile output is an actual observed fourth directory in
    // build/test mode. This is one exact derived path, not any target subtree
    // or arbitrary native dependency build output.
    let mut allowed = required.clone();
    let target_profile = paths.target_directory(profile)?;
    if !allowed.insert(target_profile.clone()) {
        return Err("base profile directory overlaps required loader set".into());
    }
    let value = env::var_os("LD_LIBRARY_PATH").ok_or("missing normal Cargo loader paths")?;
    let mut seen = BTreeSet::new();
    for path in env::split_paths(&value) {
        if seen.len() == 4 {
            return Err(format!(
                "extra Cargo loader directory: observed={path:?}; derived_normal={allowed:?}"
            ));
        }
        let path = match canonical_directory(&path) {
            Ok(canonical) => canonical,
            Err(canonical_error) => {
                let canonical = paths
                    .target_alias_directory(&path)
                    .map_err(|_| canonical_error)?;
                if canonical != target_deps && canonical != target_profile {
                    return Err(
                        "held loader alias is not the exact profile or deps directory".into(),
                    );
                }
                canonical
            }
        };
        if !allowed.contains(&path) || !seen.insert(path.clone()) {
            return Err(format!("unknown or duplicate Cargo loader directory: observed={path:?}; derived_normal={allowed:?}"));
        }
    }
    if !required.is_subset(&seen) {
        return Err("normal Cargo loader directory set incomplete".into());
    }
    paths.validate()?;
    Ok(paths)
}

fn reject_external_overrides() -> Result<LoaderPaths, String> {
    let paths = validate_cargo_loader_paths()?;
    // cc's unqualified, HOST_/TARGET_, and target-qualified flag/tool inputs
    // are all rejected. A normal Cargo jobserver/OPT_LEVEL/DEBUG is retained.
    // Empty variables do not add flags. pkg-config's literal zero is the
    // upstream documented way of not requesting the linked-library route.
    for (name, value) in env::vars_os() {
        let Some(name) = name.to_str() else {
            return Err("non-UTF-8 environment variable name".into());
        };
        let upper = name.to_ascii_uppercase();
        if upper == "LD_LIBRARY_PATH" {
            continue;
        } // Exact required set plus optional canonical base checked above.

        let tool_override = [
            "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "ARFLAGS",
        ]
        .iter()
        .any(|key| {
            upper == *key
                || upper.starts_with(&format!("{key}_"))
                || upper.ends_with(&format!("_{key}"))
        });
        let native_override = matches!(
            upper.as_str(),
            "CRATE_CC_NO_DEFAULTS"
                | "CC_FORCE_DISABLE"
                | "CC_KNOWN_WRAPPER_CUSTOM"
                | "RUSTC_WRAPPER"
                | "CC_SHELL_ESCAPED_FLAGS"
                | "CPATH"
                | "C_INCLUDE_PATH"
                | "CPLUS_INCLUDE_PATH"
                | "OBJC_INCLUDE_PATH"
                | "LIBRARY_PATH"
                | "GCC_EXEC_PREFIX"
                | "COMPILER_PATH"
                | "LD_PRELOAD"
                | "LD_LIBRARY_PATH"
                | "DYLD_INSERT_LIBRARIES"
                | "SDKROOT"
                | "RUSTFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
                | "LIBSQLITE3_FLAGS"
                | "SQLITE_MAX_VARIABLE_NUMBER"
                | "SQLITE_MAX_EXPR_DEPTH"
                | "SQLITE_MAX_COLUMN"
                | "SQLITE3_LIB_DIR"
                | "SQLITE3_INCLUDE_DIR"
                | "SQLITE3_STATIC"
        ) || upper.starts_with("SQLCIPHER_")
            || upper.contains("SQLITE_SHM_DIRECTORY")
            || (upper.starts_with("CARGO_TARGET_")
                && (upper.ends_with("_LINKER") || upper.ends_with("_RUSTFLAGS")));
        if tool_override || native_override || upper == "LIBSQLITE3_SYS_USE_PKG_CONFIG" {
            println!("cargo:rerun-if-env-changed={name}");
            if !(value.is_empty() || upper == "LIBSQLITE3_SYS_USE_PKG_CONFIG" && value == "0") {
                return Err(format!("external native build override {name}"));
            }
        }
    }
    // Also watch absent common variables. This does not replace the owner
    // requirement to use a fresh controlled build rather than a cached build
    // whose dependency was compiled under a different environment.
    for name in [
        "LIBSQLITE3_SYS_USE_PKG_CONFIG",
        "RUSTC_WRAPPER",
        "RUSTC",
        "OUT_DIR",
        "CARGO_TARGET_DIR",
        "PROFILE",
        "LIBSQLITE3_FLAGS",
        "CC",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "AR",
        "ARFLAGS",
        "CPATH",
        "C_INCLUDE_PATH",
        "LIBRARY_PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "SQLITE_MAX_VARIABLE_NUMBER",
        "SQLITE_MAX_EXPR_DEPTH",
        "SQLITE_MAX_COLUMN",
        "SQLITE3_LIB_DIR",
        "SQLITE3_INCLUDE_DIR",
        "SQLITE3_STATIC",
        "CRATE_CC_NO_DEFAULTS",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    paths.validate()?;
    Ok(paths)
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(trnm_sqlite_layout_witness)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_loader_paths.rs");
    println!("cargo:rerun-if-changed=unix_layout_witness.c");
    println!("cargo:rerun-if-env-changed=DEP_SQLITE3_INCLUDE");
    println!("cargo:rerun-if-env-changed=HOST");
    println!("cargo:rerun-if-env-changed=TARGET");
    if let Err(reason) = qualify_build() {
        // The crate is a default dependency of Node. An unqualified optional
        // boundary must not prevent an ordinary/default Node from building.
        // There is no C witness/extern reference in this configuration, and
        // attempting the bounded API returns an explicit unsupported error.
        println!("cargo:warning=trnm SQLite I/O boundary UNQUALIFIED: {reason}");
        println!("cargo:rustc-env=TRNM_SQLITE3_UNQUALIFIED_REASON={reason}");
    }
}

fn qualify_build() -> Result<(), String> {
    let target = required("TARGET")?;
    if required("HOST")? != target
        || !matches!(
            target.as_str(),
            "x86_64-unknown-linux-gnu"
                | "aarch64-unknown-linux-gnu"
                | "x86_64-unknown-linux-musl"
                | "aarch64-unknown-linux-musl"
        )
        || required("CARGO_CFG_TARGET_OS")? != "linux"
        || required("CARGO_CFG_TARGET_POINTER_WIDTH")? != "64"
        || required("CARGO_CFG_TARGET_ENDIAN")? != "little"
    {
        return Err(
            "only native little-endian Linux x86_64/aarch64 GNU or musl builds are admitted".into(),
        );
    }
    let loader_paths = reject_external_overrides()?;
    let include = PathBuf::from(required("DEP_SQLITE3_INCLUDE")?)
        .canonicalize()
        .map_err(|_| "dependency did not expose a real bundled include directory")?;
    if include.file_name().and_then(|n| n.to_str()) != Some("sqlite3") {
        return Err(
            "SQLCipher, pkg-config, and foreign include directories are unsupported".into(),
        );
    }
    let dependency = include.parent().ok_or("missing dependency root")?;
    if dependency.file_name().and_then(|n| n.to_str()) != Some("libsqlite3-sys-0.37.0") {
        return Err("expected the exact registry libsqlite3-sys-0.37.0 bundled source".into());
    }
    let amalgamation = include.join("sqlite3.c");
    pin_text(&amalgamation, 9_390_466, AMALGAMATION_SHA256)?;
    pin_text(&dependency.join("build.rs"), 33_727, UPSTREAM_BUILD_SHA256)?;
    let source = amalgamation.to_str().ok_or("non-UTF-8 source path")?;
    if source
        .bytes()
        .any(|b| matches!(b, b'"' | b'\\' | b'\n' | b'\r'))
    {
        return Err("source path cannot be represented as a controlled C include".into());
    }
    let quoted_source = format!("\"{source}\"");
    let mut cfg = cc::Build::new();
    cfg.file("unix_layout_witness.c")
        .include(&include)
        .define("TRNM_SQLITE_AMALGAMATION", Some(quoted_source.as_str()))
        // Exact normal bundled flags: upstream libsqlite3-sys-0.37.0 build.rs:125-143.
        .flag("-DSQLITE_CORE")
        .flag("-DSQLITE_DEFAULT_FOREIGN_KEYS=1")
        .flag("-DSQLITE_ENABLE_API_ARMOR")
        .flag("-DSQLITE_ENABLE_COLUMN_METADATA")
        .flag("-DSQLITE_ENABLE_DBSTAT_VTAB")
        .flag("-DSQLITE_ENABLE_FTS3")
        .flag("-DSQLITE_ENABLE_FTS3_PARENTHESIS")
        .flag("-DSQLITE_ENABLE_FTS5")
        .flag("-DSQLITE_ENABLE_JSON1")
        .flag("-DSQLITE_ENABLE_LOAD_EXTENSION=1")
        .flag("-DSQLITE_ENABLE_MEMORY_MANAGEMENT")
        .flag("-DSQLITE_ENABLE_RTREE")
        .flag("-DSQLITE_ENABLE_STAT4")
        .flag("-DSQLITE_SOUNDEX")
        .flag("-DSQLITE_THREADSAFE=1")
        .flag("-DSQLITE_USE_URI")
        .flag("-DHAVE_USLEEP=1")
        .flag("-DHAVE_ISNAN")
        .flag("-D_POSIX_THREAD_SAFE_FUNCTIONS")
        // Upstream libsqlite3-sys-0.37.0 build.rs:249-250: every admitted target is not Windows.
        .flag("-DHAVE_LOCALTIME_R")
        // The witness API exposes compile-time layout/constants only.
        // Static SQLite functions/state have no external entry points.
        .opt_level(2)
        .warnings(false);
    let compiler = cfg
        .try_get_compiler()
        .map_err(|_| "native C compiler unavailable")?;
    if !(compiler.is_like_gnu() || compiler.is_like_clang()) {
        return Err("only the normal GNU/Clang native C ABI is admitted".into());
    }
    loader_paths.validate()?;
    cfg.try_compile("trnm_sqlite_layout_witness").map_err(|_| {
        "the exact C layout witness did not compile; bounded API remains unsupported"
    })?;
    loader_paths.validate()?;
    pin_text(&amalgamation, 9_390_466, AMALGAMATION_SHA256)?;
    pin_text(&dependency.join("build.rs"), 33_727, UPSTREAM_BUILD_SHA256)?;
    loader_paths.validate()?;
    verify_witness_symbols(&PathBuf::from(required("OUT_DIR")?))?;
    // Retain and revalidate the capability through C compile and nm; publish no
    // qualifying cfg/fence until all original checks and this final check pass.
    loader_paths.validate()?;
    println!("cargo:rustc-cfg=trnm_sqlite_layout_witness");
    println!("cargo:rustc-env=TRNM_SQLITE3_BUILD_FENCE={BUILD_FENCE}");
    println!("cargo:rustc-env=TRNM_SQLITE3_AMALGAMATION_SHA256={AMALGAMATION_SHA256}");
    Ok(())
}
