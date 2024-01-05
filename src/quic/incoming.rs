use crate::{
    common::incoming::{shuffle_rd_wr, IncomingConfig, ServerCerts},
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
};
use anyhow::Result;
use die::Die;
use log::{error, info};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};
use tokio::task::JoinHandle;

#[cfg(not(target_os = "windows"))]
pub fn spawn_quic_listener_unix(udp_socket: std::os::unix::net::UnixDatagram, config: Arc<IncomingConfig>, server_config: ServerConfig) -> JoinHandle<Result<()>> {
    let udp_socket = crate::quic::unix_datagram::wrap_unix_udp_socket(udp_socket).die("cannot wrap unix udp socket");
    // todo: fake local_addr
    let local_addr = udp_socket.local_addr().die("cannot get local_addr for quic socket");
    let incoming = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(server_config), udp_socket, Arc::new(TokioRuntime)).die("cannot listen on port/interface");
    internal_spawn_quic_listener(incoming, local_addr, config)
}

pub fn spawn_quic_listener(udp_socket: UdpSocket, config: Arc<IncomingConfig>, server_config: ServerConfig) -> JoinHandle<Result<()>> {
    let local_addr = udp_socket.local_addr().die("cannot get local_addr for quic socket");
    let incoming = Endpoint::new(EndpointConfig::default(), Some(server_config), udp_socket, Arc::new(TokioRuntime)).die("cannot listen on port/interface");
    internal_spawn_quic_listener(incoming, local_addr, config)
}

fn internal_spawn_quic_listener(incoming: Endpoint, local_addr: SocketAddr, config: Arc<IncomingConfig>) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        // when could this return None, do we quit?
        while let Some(incoming_conn) = incoming.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(new_conn) = incoming_conn.await {
                    let client_addr = Context::new("quic-in", new_conn.remote_address());
                    info!("{} connected new connection", client_addr.log_from());

                    #[cfg(any(feature = "s2s-incoming", feature = "webtransport"))]
                    let server_certs = {
                        let server_certs = ServerCerts::from(&new_conn);
                        #[cfg(feature = "webtransport")]
                        if server_certs.alpn().map(|a| a == webtransport_quinn::ALPN).unwrap_or(false) {
                            return crate::webtransport::incoming::handle_webtransport_session(new_conn, config, server_certs, local_addr, client_addr).await;
                        }
                        server_certs
                    };
                    #[cfg(not(any(feature = "s2s-incoming", feature = "webtransport")))]
                    let server_certs = ();

                    handle_quic_session(new_conn, config, server_certs, local_addr, client_addr).await
                }
            });
        }
        error!("quic listener shutting down, should never happen????");
        Ok(())
    })
}

pub async fn handle_quic_session(conn: quinn::Connection, config: Arc<IncomingConfig>, server_certs: ServerCerts, local_addr: SocketAddr, client_addr: Context<'static>) {
    while let Ok((wrt, rd)) = conn.accept_bi().await {
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

pub fn quic_server_config(mut server_config: rustls::ServerConfig) -> ServerConfig {
    #[cfg(feature = "webtransport")]
    server_config.alpn_protocols.push(webtransport_quinn::ALPN.to_vec());
    let transport_config = quinn::TransportConfig::default();
    // todo: configure transport_config here if needed
    let mut server_config = ServerConfig::with_crypto(Arc::new(server_config));
    server_config.transport = Arc::new(transport_config);

    server_config
}
