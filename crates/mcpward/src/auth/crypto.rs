/// Makes sure jsonwebtoken has a process-wide crypto provider.
///
/// jsonwebtoken picks its provider from crate features and panics at first use when it
/// can't decide, which happens when both `aws-lc-rs` and `rust-crypto` are enabled (for
/// example with `cargo test --all-features`). mcpward calls this before every sign or verify
/// setup; it installs aws-lc-rs when both are on and does nothing otherwise. Safe to call
/// any number of times.
pub fn ensure_crypto_provider() {
    #[cfg(all(feature = "aws-lc-rs", feature = "rust-crypto"))]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ =
                jsonwebtoken::crypto::CryptoProvider::install_default(&jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER);
        });
    }
}
