use std::net::SocketAddr;

use crate::{
    common::outgoing::OutgoingVerifierConfig,
    in_out::{StanzaRead, StanzaWrite},
};
use anyhow::Result;
use log::trace;

pub async fn quic_connect(target: SocketAddr, server_name: &str, config: OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let client_cfg = config.config_alpn;

    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(client_cfg));

    // connect to server
    let connection = endpoint.connect(target, server_name)?.await?;
    trace!("quic connected: addr={}", connection.remote_address());

    let (wrt, rd) = connection.open_bi().await?;
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}
