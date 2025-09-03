use crate::{
    common::outgoing::OutgoingVerifierConfig,
    in_out::{StanzaRead, StanzaWrite},
};
use anyhow::Result;
use log::trace;
use quinn::crypto::rustls::QuicClientConfig;
use reqwest::Url;
use std::{net::SocketAddr, sync::Arc};

impl OutgoingVerifierConfig {
    // fix this mess when implementing proper error types
    fn wte(&self) -> Result<quinn::Endpoint, anyhow::Error> {
        let bind_addr = "0.0.0.0:0".parse()?;
        // same config as quic, but different alpn
        let mut client_cfg = self.config_alpn.as_ref().clone();
        client_cfg.alpn_protocols.clear();
        client_cfg.alpn_protocols.push(web_transport_quinn::ALPN.as_bytes().to_vec());

        let suite = crate::quic::initial_suite_from_provider()?;
        let client_cfg = Arc::new(QuicClientConfig::with_initial(client_cfg.into(), suite)?);

        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(client_cfg));

        Ok(endpoint)
    }

    pub fn webtransport_endpoint(&self) -> &Result<quinn::Endpoint, String> {
        self.webtransport_endpoint.get_or_init(|| self.wte().map_err(|e: anyhow::Error| format!("{e}")))
    }
}

pub async fn webtransport_connect(target: SocketAddr, server_name: &str, url: Url, config: &OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let endpoint = config.webtransport_endpoint().as_ref().map_err(|e| anyhow::anyhow!("webtransport endpoint error: {e}"))?;

    // connect to server
    let connection = endpoint.connect(target, server_name)?.await?;
    trace!("quic pre-wt connected: addr={}", connection.remote_address());

    let connection = web_transport_quinn::Session::connect(connection, url).await?;
    trace!("webtransport connected: addr={}", connection.remote_address());

    let (wrt, rd) = connection.open_bi().await?;
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}
