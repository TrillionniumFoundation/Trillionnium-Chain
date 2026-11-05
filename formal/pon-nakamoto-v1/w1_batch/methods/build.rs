fn main() {
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");
    std::env::remove_var("RUSTC_WRAPPER");
    // The image is compiled from this guest, never accepted from a manifest.
    risc0_build::embed_methods();
}
