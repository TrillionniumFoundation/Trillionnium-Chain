use sha2::{Digest as _, Sha256};
use std::{env, fs, io::Write, path::PathBuf};

const RETAINED_BYTES: usize = 375_928;
const RETAINED_SHA256: &str = "25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f";
const RETAINED_IMAGE: [u32; 8] = [
    1958252411, 3287394615, 1805488136, 1516578702, 78549041, 790278610, 301018785, 4279049364,
];

fn retained_guest() {
    assert!(
        env::var_os("RISC0_SKIP_BUILD").is_none(),
        "retained-v2-guest cannot be combined with RISC0_SKIP_BUILD"
    );
    let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("../../../../evidence/pon-w1-full-v2-20261105/guest.bin");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-env-changed=RISC0_SKIP_BUILD");
    let metadata = fs::symlink_metadata(&source).expect("retained original v2 guest is required");
    assert!(metadata.is_file(), "retained guest must be a regular file");
    assert_eq!(
        metadata.len(),
        RETAINED_BYTES as u64,
        "retained guest length"
    );
    let bytes = fs::read(&source).expect("read retained original v2 guest");
    assert_eq!(bytes.len(), RETAINED_BYTES, "retained guest read length");
    let digest = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(digest, RETAINED_SHA256, "retained guest SHA-256 changed");
    // This is the original complete SDK ProgramBinary (R0BF), containing user
    // and kernel ELF bytes. It is not a newly compiled guest or an empty stub.
    let image = risc0_binfmt::compute_image_id(&bytes).expect("SDK guest image computation");
    assert_eq!(
        image.as_words(),
        RETAINED_IMAGE.as_slice(),
        "retained guest image changed"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let verified = out.join("retained-v2-guest.bin");
    let mut file = fs::File::create(&verified).expect("verified guest output");
    file.write_all(&bytes).expect("write verified guest");
    file.sync_all().expect("sync verified guest");
    assert_eq!(fs::read(&verified).expect("verified guest readback"), bytes);
    let methods = format!(
        "pub const TRNM_W1_FULL_GUEST_V2_ELF: &[u8] = include_bytes!({path:?});\n\
         pub const TRNM_W1_FULL_GUEST_V2_PATH: &str = {path:?};\n\
         pub const TRNM_W1_FULL_GUEST_V2_ID: [u32; 8] = {RETAINED_IMAGE:?};\n\
         pub const TRNM_W1_GUEST_BUILD_MODE: &str = \"retained-v2-guest\";\n",
        path = verified.to_str().expect("UTF-8 verified guest path"),
    );
    fs::write(out.join("methods.rs"), methods).expect("write retained method constants");
    let provenance = format!(
        "{{\"schema\":\"TRNM-W1-GUEST-BUILD1\",\"mode\":\"retained-v2-guest\",\"guest_format\":\"R0BF ProgramBinary\",\"source_artifact\":\"evidence/pon-w1-full-v2-20261105/guest.bin\",\"bytes\":{RETAINED_BYTES},\"sha256\":\"{RETAINED_SHA256}\",\"image_id\":{RETAINED_IMAGE:?},\"sdk_image_checked\":true,\"guest_compilation_performed\":false}}\n"
    );
    fs::write(out.join("guest-build-provenance.json"), provenance)
        .expect("write retained guest provenance");
    println!("cargo:warning=retained-v2-guest: exact original bytes and SDK image verified; no guest compilation performed");
}

fn main() {
    // Keep the original normal SDK cross-compiler path. A host rustc/clippy
    // wrapper must not intercept the SDK's nested guest compilation.
    env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    env::remove_var("RUSTC_WRAPPER");
    env::set_var("RISC0_BUILD_LOCKED", "1");
    if env::var_os("CARGO_FEATURE_RETAINED_V2_GUEST").is_some() {
        retained_guest();
    } else {
        risc0_build::embed_methods();
        let out = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
        writeln!(
            fs::OpenOptions::new()
                .append(true)
                .open(out.join("methods.rs"))
                .expect("SDK method constants"),
            "pub const TRNM_W1_GUEST_BUILD_MODE: &str = \"sdk-embed-methods\";"
        )
        .expect("append explicit normal build mode");
        fs::write(
            out.join("guest-build-provenance.json"),
            b"{\"schema\":\"TRNM-W1-GUEST-BUILD1\",\"mode\":\"sdk-embed-methods\",\"guest_compilation_freshness\":\"not established by build-mode label\"}\n",
        ).expect("write normal guest build provenance");
    }
}
