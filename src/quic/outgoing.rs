use crate::{
    common::outgoing::OutgoingVerifierConfig,
    in_out::{StanzaRead, StanzaWrite},
    quic::initial_suite_from_provider,
};
use log::trace;
use quinn::crypto::rustls::QuicClientConfig;
use std::{net::SocketAddr, sync::Arc};

impl OutgoingVerifierConfig {
    // fix this mess when implementing proper error types
    fn qe(&self) -> Result<quinn::Endpoint, anyhow::Error> {
        let bind_addr = "0.0.0.0:0".parse()?;
        let client_cfg = self.config_alpn.clone();
        let suite = initial_suite_from_provider()?;
        let client_cfg = Arc::new(QuicClientConfig::with_initial(client_cfg, suite)?);
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(client_cfg));
        Ok(endpoint)
    }

    pub fn quic_endpoint(&self) -> &Result<quinn::Endpoint, String> {
        self.quic_endpoint.get_or_init(|| self.qe().map_err(|e: anyhow::Error| format!("{e}")))
    }
}

pub async fn quic_connect(target: SocketAddr, server_name: &str, config: &OutgoingVerifierConfig) -> anyhow::Result<(StanzaWrite, StanzaRead)> {
    let endpoint = config.quic_endpoint().as_ref().map_err(|e| anyhow::anyhow!("quic endpoint error: {e}"))?;

    // connect to server
    let connection = endpoint.connect(target, server_name)?.await?;
    trace!("quic connected: addr={}", connection.remote_address());

    let (wrt, rd) = connection.open_bi().await?;
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}
