use std::net::SocketAddr;

use crate::{
    common::outgoing::OutgoingVerifierConfig,
    in_out::{StanzaRead, StanzaWrite},
};
use anyhow::Result;
use log::trace;
use reqwest::Url;

pub async fn webtransport_connect(target: SocketAddr, server_name: &str, url: &Url, config: &OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let bind_addr = "0.0.0.0:0".parse().unwrap();

    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(config.config_webtransport_alpn.clone()));

    // connect to server
    let connection = endpoint.connect(target, server_name)?.await?;
    trace!("quic pre-wt connected: addr={}", connection.remote_address());

    let connection = webtransport_quinn::connect_with(connection, url).await?;
    trace!("webtransport connected: addr={}", connection.remote_address());

    let (wrt, rd) = connection.open_bi().await?;
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}
