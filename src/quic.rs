use crate::*;
use futures::StreamExt;
use quinn::{ServerConfig, TransportConfig};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use anyhow::Result;

#[cfg(feature = "outgoing")]
pub async fn quic_connect(target: SocketAddr, server_name: &str, is_c2s: bool, config: OutgoingConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let client_cfg = config.client_cfg_alpn(is_c2s);

    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(client_cfg));

    // connect to server
    let quinn::NewConnection { connection, .. } = endpoint.connect(target, server_name)?.await?;
    trace!("quic connected: addr={}", connection.remote_address());

    let (wrt, rd) = connection.open_bi().await?;
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}

impl Config {
    #[cfg(feature = "incoming")]
    pub fn quic_server_config(&self) -> Result<ServerConfig> {
        let transport_config = TransportConfig::default();
        // todo: configure transport_config here if needed
        let mut server_config = self.server_config()?;
        // todo: will connecting without alpn work then?
        server_config.alpn_protocols.push(ALPN_XMPP_CLIENT.to_vec());
        server_config.alpn_protocols.push(ALPN_XMPP_SERVER.to_vec());
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_config));
        server_config.transport = Arc::new(transport_config);

        Ok(server_config)
    }
}

struct NoopIo;

use core::pin::Pin;
use core::task::{Context, Poll};

// todo: could change this to return Error and kill the stream instead, after all, s2s *should* not be receiving any bytes back
impl AsyncWrite for NoopIo {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for NoopIo {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

pub fn spawn_quic_listener(local_addr: SocketAddr, config: CloneableConfig, server_config: ServerConfig) -> JoinHandle<Result<()>> {
    let (_endpoint, mut incoming) = quinn::Endpoint::server(server_config, local_addr).die("cannot listen on port/interface");
    tokio::spawn(async move {
        // when could this return None, do we quit?
        while let Some(incoming_conn) = incoming.next().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(mut new_conn) = incoming_conn.await {
                    let client_addr = crate::Context::new("quic-in", new_conn.connection.remote_address());
                    info!("{} connected new connection", client_addr.log_from());

                    while let Some(Ok((wrt, rd))) = new_conn.bi_streams.next().await {
                        let config = config.clone();
                        let mut client_addr = client_addr.clone();
                        info!("{} connected new stream", client_addr.log_from());
                        tokio::spawn(async move {
                            if let Err(e) = shuffle_rd_wr(StanzaRead::new(rd), StanzaWrite::new(wrt), config, local_addr, &mut client_addr).await {
                                error!("{} {}", client_addr.log_from(), e);
                            }
                        });
                    }
                }
            });
        }
        error!("quic listener shutting down, should never happen????");
        #[allow(unreachable_code)]
        Ok(())
    })
}
