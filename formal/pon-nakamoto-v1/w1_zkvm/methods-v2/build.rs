fn main() {
    // The guest must use the pinned RISC Zero cross compiler selected by
    // risc0-build, including while Clippy checks this native workspace.
    // A host rustc/clippy wrapper otherwise intercepts the nested guest build
    // and selects a host sysroot that has no risc0 target core library.
    // This does not skip guest compilation or substitute an empty image.
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");
    // The nested SDK cargo command sanitizes CARGO_* variables. Require its
    // own locked mode so a host --locked build also freezes guest dependencies.
    std::env::set_var("RISC0_BUILD_LOCKED", "1");
    risc0_build::embed_methods();
}
