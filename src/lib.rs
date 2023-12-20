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
