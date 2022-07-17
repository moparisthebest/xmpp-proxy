use crate::common::incoming::{shuffle_rd_wr_filter, CloneableConfig, ServerCerts};
use std::net::SocketAddr;

use crate::{
    common::{first_bytes_match, to_str, IN_BUFFER_SIZE},
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::{StanzaFilter, StanzaReader},
};
use anyhow::{bail, Result};
use die::Die;
use log::{error, info, trace};
use rustls::{ServerConfig, ServerConnection};

use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

pub fn tls_acceptor(server_config: ServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(server_config))
}

pub fn spawn_tls_listener(local_addr: SocketAddr, config: CloneableConfig, acceptor: TlsAcceptor) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&local_addr).await.die("cannot listen on port/interface");
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

async fn handle_tls_connection(mut stream: tokio::net::TcpStream, client_addr: &mut Context<'_>, local_addr: SocketAddr, config: CloneableConfig, acceptor: TlsAcceptor) -> Result<()> {
    info!("{} connected", client_addr.log_from());

    let mut in_filter = StanzaFilter::new(config.max_stanza_size_bytes);

    /* TLS packet starts with a record "Hello" (0x16), followed by version
     * (0x03 0x00-0x03) (RFC6101 A.1)
     * This means we reject SSLv2 and lower, which is actually a good thing (RFC6176)
     *
     * could just check the leading 0x16 is TLS, it would *probably* be ok ?
     */
    let direct_tls = first_bytes_match(&stream, &mut in_filter.buf[0..3], |p| p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x03).await?;

    client_addr.set_proto(if direct_tls { "directtls-in" } else { "starttls-in" });
    info!("{} direct_tls sniffed", client_addr.log_from());

    // starttls
    if !direct_tls {
        let mut proceed_sent = false;

        let (in_rd, mut in_wr) = stream.split();
        // we naively read 1 byte at a time, which buffering significantly speeds up
        let in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);
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
    }

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
    #[cfg(feature = "s2s-incoming")]
    let server_certs = {
        let server_connection: &'static ServerConnection = unsafe { std::mem::transmute(server_connection) };
        ServerCerts::Tls(server_connection)
    };
    #[cfg(not(feature = "s2s-incoming"))]
    let server_certs = ();

    #[cfg(not(feature = "websocket"))]
    {
        let (in_rd, in_wr) = tokio::io::split(stream);
        shuffle_rd_wr_filter(StanzaRead::new(in_rd), StanzaWrite::new(in_wr), config, server_certs, local_addr, client_addr, in_filter).await
    }

    #[cfg(feature = "websocket")]
    {
        let stream: tokio_rustls::TlsStream<tokio::net::TcpStream> = stream.into();

        let mut stream = BufStream::with_capacity(IN_BUFFER_SIZE, 0, stream);
        let websocket = {
            // wait up to 10 seconds until 3 bytes have been read
            use std::time::{Duration, Instant};
            let duration = Duration::from_secs(10);
            let now = Instant::now();
            let mut buf = stream.fill_buf().await?;
            loop {
                if buf.len() >= 3 {
                    break; // success
                }
                if buf.is_empty() {
                    bail!("not enough bytes");
                }
                if Instant::now() - now > duration {
                    bail!("less than 3 bytes in 10 seconds, closed connection?");
                }
                buf = stream.fill_buf().await?;
            }

            buf[..3] == b"GET"[..]
        };

        if websocket {
            crate::websocket::incoming::handle_websocket_connection(Box::new(stream), config, server_certs, local_addr, client_addr, in_filter).await
        } else {
            let (in_rd, in_wr) = tokio::io::split(stream);
            shuffle_rd_wr_filter(StanzaRead::already_buffered(in_rd), StanzaWrite::new(in_wr), config, server_certs, local_addr, client_addr, in_filter).await
        }
    }
}
