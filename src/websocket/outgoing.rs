use crate::{
    common::outgoing::OutgoingVerifierConfig,
    in_out::{StanzaRead, StanzaWrite},
    websocket::{ws_cfg, AsyncReadAndWrite},
};
use anyhow::Result;
use futures_util::StreamExt;
use rustls::ServerName;
use std::{convert::TryFrom, net::SocketAddr};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::{
        header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL},
        Uri,
    },
};

pub async fn websocket_connect(target: SocketAddr, server_name: &str, url: &Uri, origin: &str, config: &OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let mut request = url.into_client_request()?;
    request.headers_mut().append(SEC_WEBSOCKET_PROTOCOL, "xmpp".parse()?);
    request.headers_mut().append(ORIGIN, origin.parse()?);

    let dnsname = ServerName::try_from(server_name)?;
    let stream = tokio::net::TcpStream::connect(target).await?;
    let stream = config.connector.connect(dnsname, stream).await?;

    //let stream: tokio_rustls::TlsStream<tokio::net::TcpStream> = stream.into();
    // todo: tokio_tungstenite seems to have a bug, if the write buffer is non-zero, it'll hang forever, even though we always flush, investigate
    //let stream = BufStream::with_capacity(crate::IN_BUFFER_SIZE, 0, stream);
    let stream: Box<dyn AsyncReadAndWrite + Unpin + Send> = Box::new(stream);

    let (stream, _) = tokio_tungstenite::client_async_with_config(request, stream, ws_cfg(config.max_stanza_size_bytes)).await?;

    let (wrt, rd) = stream.split();

    Ok((StanzaWrite::WebSocketClientWrite(wrt), StanzaRead::WebSocketRead(rd)))
}
