use crate::{
    common::incoming::{shuffle_rd_wr, CloneableConfig, ServerCerts},
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
};
use anyhow::Result;
use die::Die;
use futures::StreamExt;
use log::{error, info};
use quinn::ServerConfig;
use std::{net::SocketAddr, sync::Arc};
use tokio::task::JoinHandle;

pub fn spawn_quic_listener(local_addr: SocketAddr, config: CloneableConfig, server_config: ServerConfig) -> JoinHandle<Result<()>> {
    let (_endpoint, mut incoming) = quinn::Endpoint::server(server_config, local_addr).die("cannot listen on port/interface");
    tokio::spawn(async move {
        // when could this return None, do we quit?
        while let Some(incoming_conn) = incoming.next().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(mut new_conn) = incoming_conn.await {
                    let client_addr = Context::new("quic-in", new_conn.connection.remote_address());

                    #[cfg(feature = "s2s-incoming")]
                    let server_certs = ServerCerts::Quic(new_conn.connection);
                    #[cfg(not(feature = "s2s-incoming"))]
                    let server_certs = ();

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

pub fn quic_server_config(server_config: rustls::ServerConfig) -> ServerConfig {
    let transport_config = quinn::TransportConfig::default();
    // todo: configure transport_config here if needed
    let mut server_config = ServerConfig::with_crypto(Arc::new(server_config));
    server_config.transport = Arc::new(transport_config);

    server_config
}
