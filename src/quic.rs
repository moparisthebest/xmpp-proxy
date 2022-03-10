use crate::*;
use futures::StreamExt;
use quinn::{ServerConfig, TransportConfig};
use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;

#[cfg(feature = "outgoing")]
pub async fn quic_connect(target: SocketAddr, server_name: &str, config: OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let client_cfg = config.config_alpn;

    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(client_cfg));

    // connect to server
    let quinn::NewConnection { connection, .. } = endpoint.connect(target, server_name)?.await?;
    trace!("quic connected: addr={}", connection.remote_address());

    let (wrt, rd) = connection.open_bi().await?;
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}

#[cfg(feature = "incoming")]
impl Config {
    pub fn quic_server_config(&self, cert_key: Arc<CertsKey>) -> Result<ServerConfig> {
        let transport_config = TransportConfig::default();
        // todo: configure transport_config here if needed
        let server_config = self.server_config(cert_key)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_config));
        server_config.transport = Arc::new(transport_config);

        Ok(server_config)
    }
}

#[cfg(feature = "incoming")]
pub fn spawn_quic_listener(local_addr: SocketAddr, config: CloneableConfig, server_config: ServerConfig) -> JoinHandle<Result<()>> {
    let (_endpoint, mut incoming) = quinn::Endpoint::server(server_config, local_addr).die("cannot listen on port/interface");
    tokio::spawn(async move {
        // when could this return None, do we quit?
        while let Some(incoming_conn) = incoming.next().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(mut new_conn) = incoming_conn.await {
                    let client_addr = crate::Context::new("quic-in", new_conn.connection.remote_address());
                    let server_certs = ServerCerts::Quic(new_conn.connection);
                    info!("{} connected new connection", client_addr.log_from());

                    while let Some(Ok((wrt, rd))) = new_conn.bi_streams.next().await {
                        let config = config.clone();
                        let mut client_addr = client_addr.clone();
                        let server_certs = server_certs.clone();
                        info!("{} connected new stream", client_addr.log_from());
                        tokio::spawn(async move {
                            if let Err(e) = shuffle_rd_wr(StanzaRead::new(rd), StanzaWrite::new(wrt), config, server_certs, local_addr, &mut client_addr).await {
                                error!("{} {}", client_addr.log_from(), e);
                            }
                        });
                    }
                }
            });
        }
        error!("quic listener shutting down, should never happen????");
        Ok(())
    })
}
