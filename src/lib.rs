pub mod common;
pub mod slicesubsequence;
pub mod stanzafilter;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "outgoing")]
pub mod outgoing;

#[cfg(any(feature = "s2s-incoming", feature = "outgoing"))]
pub mod srv;

#[cfg(feature = "websocket")]
pub mod websocket;

#[cfg(feature = "webtransport")]
pub mod webtransport;

#[cfg(any(feature = "s2s-incoming", feature = "outgoing"))]
pub mod verify;

#[cfg(all(feature = "nix", not(target_os = "windows")))]
pub mod systemd;

pub mod context;
pub mod in_out;

#[cfg(feature = "rustls")]
pub fn install_default_rustls_provider() -> Result<(), std::sync::Arc<rustls::crypto::CryptoProvider>> {
    // set up default crypto provider, only one of these can be called
    #[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
    use rustls::crypto::aws_lc_rs as provider;
    #[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
    use rustls::crypto::ring as provider;

    #[cfg(not(any(feature = "tls-ring", feature = "tls-aws-lc-rs")))]
    compile_error!("one of features `tls-aws-lc-rs` and `tls-ring` must be chosen");

    #[cfg(all(feature = "tls-ring", feature = "tls-aws-lc-rs"))]
    compile_error!("features `tls-aws-lc-rs` and `tls-ring` are mutually exclusive");

    provider::default_provider().install_default()
}
