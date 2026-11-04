fn main() {
    // The guest must use the pinned RISC Zero cross compiler selected by
    // risc0-build, including while Clippy checks this native workspace.
    // A host rustc/clippy wrapper otherwise intercepts the nested guest build
    // and selects a host sysroot that has no risc0 target core library.
    // This does not skip guest compilation or substitute an empty image.
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");
    risc0_build::embed_methods();
}
