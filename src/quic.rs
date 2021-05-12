use crate::*;
use futures::StreamExt;
use quinn::{ClientConfigBuilder, Endpoint, ServerConfig, ServerConfigBuilder, TransportConfig};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use anyhow::Result;

pub async fn quic_connect(target: SocketAddr, server_name: &str, is_c2s: bool) -> Result<(Box<dyn AsyncWrite + Unpin + Send>, Box<dyn AsyncRead + Unpin + Send>)> {
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let mut client_cfg = ClientConfigBuilder::default();
    client_cfg.protocols(if is_c2s { ALPN_XMPP_CLIENT } else { ALPN_XMPP_SERVER });
    let client_cfg = client_cfg.build();
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);
    let (endpoint, _incoming) = endpoint_builder.bind(&bind_addr)?;
    // connect to server
    let quinn::NewConnection { connection, .. } = endpoint.connect(&target, server_name).unwrap().await?;
    debug!("[client] connected: addr={}", connection.remote_address());

    if is_c2s {
        let (wrt, rd) = connection.open_bi().await?;
        Ok((Box::new(wrt), Box::new(rd)))
    } else {
        let wrt = connection.open_uni().await?;
        Ok((Box::new(wrt), Box::new(NoopIo)))
    }
}

impl Config {
    pub fn quic_server_config(&self) -> Result<ServerConfig> {
        let pem = std::fs::read(&self.tls_key).expect("error reading key");
        let tls_key = quinn::PrivateKey::from_pem(&pem).expect("error parsing key");

        let pem = std::fs::read(&self.tls_cert).expect("error reading certificates");
        let cert_chain = quinn::CertificateChain::from_pem(&pem).expect("error parsing certificates");

        let transport_config = TransportConfig::default();
        // todo: configure transport_config here if needed
        let mut server_config = ServerConfig::default();
        server_config.transport = Arc::new(transport_config);
        let mut cfg_builder = ServerConfigBuilder::new(server_config);
        cfg_builder.certificate(cert_chain, tls_key)?;

        Ok(cfg_builder.build())
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
    //let (mut incoming, server_cert) = make_server_endpoint(local_addr).die("cannot listen on port/interface");
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (_endpoint, mut incoming) = endpoint_builder.bind(&local_addr).die("cannot listen on port/interface");
    // accept a single connection
    tokio::spawn(async move {
        let incoming_conn = incoming.next().await.unwrap();
        let mut new_conn = incoming_conn.await.unwrap();
        let client_addr = new_conn.connection.remote_address();
        let config = config.clone();
        tokio::spawn(async move {
            println!("INFO: {} quic connected", client_addr);

            loop {
                tokio::select! {
                Some(Ok((wrt, rd))) = new_conn.bi_streams.next() => {
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = shuffle_rd_wr(rd, wrt, config, local_addr, client_addr, AllowedType::ClientOnly).await {
                            eprintln!("ERROR: {} {}", client_addr, e);
                        }
                    });
                },
                Some(Ok(rd)) = new_conn.uni_streams.next() => {
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = shuffle_rd_wr(rd, NoopIo, config, local_addr, client_addr, AllowedType::ServerOnly).await {
                            eprintln!("ERROR: {} {}", client_addr, e);
                        }
                    });
                },
                }
            }
        });
        #[allow(unreachable_code)]
        Ok(())
    })
}
