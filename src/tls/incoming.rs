use crate::{
    common::{
        first_bytes_match_buf_timeout,
        incoming::{shuffle_rd_wr_filter, IncomingConfig, ServerCerts},
        stream_listener::StreamListener,
        to_str, AsyncReadWritePeekSplit, Split, IN_BUFFER_SIZE,
    },
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::{StanzaFilter, StanzaReader},
};
use anyhow::{bail, Result};
use log::{error, info, trace};
use rustls::{ServerConfig, ServerConnection};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncWriteExt, BufStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

pub fn tls_acceptor(server_config: ServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(server_config))
}

pub fn spawn_tls_listener(listener: impl StreamListener, config: Arc<IncomingConfig>, acceptor: TlsAcceptor) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let local_addr = listener.local_addr()?;
        loop {
            let (stream, client_addr) = listener.accept().await?;
            let config = config.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut client_addr = Context::new("tcp-in", client_addr);
                if let Err(e) = handle_tls_connection(stream, &mut client_addr, local_addr, config, acceptor).await {
                    error!("{} {}", client_addr.log_from(), e);
                }
            });
        }
    })
}

pub async fn handle_tls_connection<S: AsyncReadWritePeekSplit>(mut stream: S, client_addr: &mut Context<'_>, local_addr: SocketAddr, config: Arc<IncomingConfig>, acceptor: TlsAcceptor) -> Result<()> {
    info!("{} connected", client_addr.log_from());

    let mut in_filter = StanzaFilter::new(config.max_stanza_size_bytes);

    /* TLS packet starts with a record "Hello" (0x16), followed by version
     * (0x03 0x00-0x03) (RFC6101 A.1)
     * This means we reject SSLv2 and lower, which is actually a good thing (RFC6176)
     *
     * could just check the leading 0x16 is TLS, it would *probably* be ok ?
     */
    let direct_tls = stream.first_bytes_match(&mut in_filter.buf[0..3], |p| p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x03).await?;

    client_addr.set_proto(if direct_tls { "directtls-in" } else { "starttls-in" });
    info!("{} direct_tls sniffed", client_addr.log_from());

    // starttls
    let stream = if !direct_tls {
        let mut proceed_sent = false;

        let (in_rd, mut in_wr) = stream.split();

        // we naively read 1 byte at a time, which buffering significantly speeds up
        // todo: I don't think we can buffer here, because then we throw away the data left in the buffer? yet it's been working... am I losing my mind?
        //let in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);
        let mut in_rd = StanzaReader(in_rd);

        while let Ok(Some(buf)) = in_rd.next(&mut in_filter).await {
            trace!("{} received pre-tls stanza: '{}'", client_addr.log_from(), to_str(buf));
            if buf.starts_with(b"<?xml ") {
                trace!("{} '{}'", client_addr.log_to(), to_str(buf));
                in_wr.write_all(buf).await?;
                in_wr.flush().await?;
            } else if buf.starts_with(b"<stream:stream ") {
                // gajim seems to REQUIRE an id here...
                let buf = if buf.contains_seq(b"id=") {
                    buf.replace_first(b" id='", b" id='xmpp-proxy")
                        .replace_first(br#" id=""#, br#" id="xmpp-proxy"#)
                        .replace_first(b" to=", br#" bla toblala="#)
                        .replace_first(b" from=", b" to=")
                        .replace_first(br#" bla toblala="#, br#" from="#)
                } else {
                    buf.replace_first(b" to=", br#" bla toblala="#)
                        .replace_first(b" from=", b" to=")
                        .replace_first(br#" bla toblala="#, br#" id='xmpp-proxy' from="#)
                };

                trace!("{} '{}'", client_addr.log_to(), to_str(&buf));
                in_wr.write_all(&buf).await?;

                // ejabberd never sends <starttls/> with the first, only the second?
                //let buf = br###"<features xmlns="http://etherx.jabber.org/streams"><starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"><required/></starttls></features>"###;
                let buf = br###"<stream:features><starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"><required/></starttls></stream:features>"###;
                trace!("{} '{}'", client_addr.log_to(), to_str(buf));
                in_wr.write_all(buf).await?;
                in_wr.flush().await?;
            } else if buf.starts_with(b"<starttls ") {
                let buf = br###"<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls" />"###;
                trace!("{} '{}'", client_addr.log_to(), to_str(buf));
                in_wr.write_all(buf).await?;
                in_wr.flush().await?;
                proceed_sent = true;
                break;
            } else {
                bail!("bad pre-tls stanza: {}", to_str(buf));
            }
        }
        if !proceed_sent {
            bail!("stream ended before open");
        }
        <S as Split>::combine(in_rd.0, in_wr)?
    } else {
        stream
    };

    let stream = acceptor.accept(stream).await?;
    let (_, server_connection) = stream.get_ref();

    // todo: find better way to do this, might require different tokio_rustls API, the problem is I can't hold this
    // past stream.into() below, and I can't get it back out after, now I *could* read sni+alpn+peer_certs
    // *here* instead and pass them on, but since I haven't read anything from the stream yet, I'm
    // not guaranteed that the handshake is complete and these are available, yes I can call is_handshaking()
    // but there is no async API to complete the handshake, so I really need to pass it down to under
    // where we read the first stanza, where we are guaranteed the handshake is complete, but I can't
    // do that without ignoring the lifetime and just pulling a C programmer and pinky promising to be
    // *very careful* that this reference doesn't outlive stream...
    #[cfg(any(feature = "s2s-incoming", feature = "webtransport"))]
    let server_certs = {
        let server_connection: &'static ServerConnection = unsafe { std::mem::transmute(server_connection) };
        ServerCerts::Tls(server_connection)
    };
    #[cfg(not(any(feature = "s2s-incoming", feature = "webtransport")))]
    let server_certs = ();

    #[cfg(not(feature = "websocket"))]
    {
        let (in_rd, in_wr) = stream.split();
        shuffle_rd_wr_filter(StanzaRead::new(in_rd), StanzaWrite::new(in_wr), config, server_certs, local_addr, client_addr, in_filter).await
    }

    #[cfg(feature = "websocket")]
    {
        let mut stream = BufStream::with_capacity(IN_BUFFER_SIZE, 0, stream);
        let websocket = first_bytes_match_buf_timeout(&mut stream, 3, |p| p == b"GET").await?;

        if websocket {
            crate::websocket::incoming::handle_websocket_connection(Box::new(stream), config, server_certs, local_addr, client_addr, in_filter).await
        } else {
            let (in_rd, in_wr) = stream.split();
            shuffle_rd_wr_filter(StanzaRead::already_buffered(in_rd), StanzaWrite::new(in_wr), config, server_certs, local_addr, client_addr, in_filter).await
        }
    }
}
