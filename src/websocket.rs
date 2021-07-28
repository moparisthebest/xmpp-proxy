use crate::*;
use futures::{SinkExt, StreamExt, TryStreamExt};

use tokio_tungstenite::tungstenite::protocol::Message::*;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

// https://datatracker.ietf.org/doc/html/rfc7395

pub fn spawn_websocket_listener(local_addr: SocketAddr, config: CloneableConfig, acceptor: TlsAcceptor) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&local_addr).await.die("cannot listen on port/interface");
        loop {
            let (stream, client_addr) = listener.accept().await?;
            let config = config.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut client_addr = Context::new("websocket-in", client_addr);
                if let Err(e) = handle_websocket_connection(stream, &mut client_addr, local_addr, config, acceptor).await {
                    error!("{} {}", client_addr.log_from(), e);
                }
            });
        }
        #[allow(unreachable_code)]
        Ok(())
    })
}

async fn handle_websocket_connection(stream: tokio::net::TcpStream, client_addr: &mut Context<'_>, local_addr: SocketAddr, config: CloneableConfig, acceptor: TlsAcceptor) -> Result<()> {
    info!("{} connected", client_addr.log_from());

    // start TLS
    let stream = acceptor.accept(stream).await?;

    // accept the websocket
    let stream = tokio_tungstenite::accept_async_with_config(
        stream,
        Some(WebSocketConfig {
            max_send_queue: None,                                     // unlimited
            max_frame_size: Some(config.max_stanza_size_bytes),       // this is exactly the stanza size
            max_message_size: Some(config.max_stanza_size_bytes * 4), // this is the message size, default is 4x frame size, so I guess we'll do the same here
            accept_unmasked_frames: true,
        }),
    )
    .await?;

    let (mut in_wr, mut in_rd) = stream.split();

    // https://docs.rs/tungstenite/0.14.0/tungstenite/protocol/enum.Message.html
    // https://datatracker.ietf.org/doc/html/rfc7395#section-3.2 Data frame messages in the XMPP subprotocol MUST be of the text type and contain UTF-8 encoded data.
    let (stanza, is_c2s) = match in_rd.try_next().await? {
        // todo: c2s is xmlns="urn:ietf:params:xml:ns:xmpp-framing", let's make up s2s ? xmlns="urn:ietf:params:xml:ns:xmpp-framing-server" sounds good to me
        Some(Text(stanza)) => {
            let is_c2s = stanza.contains(r#" xmlns="urn:ietf:params:xml:ns:xmpp-framing""#) || stanza.contains(r#" xmlns='urn:ietf:params:xml:ns:xmpp-framing'"#);
            (stanza, is_c2s)
        }
        _ => bail!("expected first websocket frame to be open"),
    };

    let stanza = from_ws(stanza);
    let stream_open = stanza.as_bytes();

    // websocket frame size filters incoming stanza size from client, this is used to split the
    // stanzas from the servers up so we can send them across websocket frames
    let mut in_filter = StanzaFilter::new(config.max_stanza_size_bytes);

    let (out_rd, mut out_wr) = open_incoming(config, local_addr, client_addr, &stream_open, is_c2s, &mut in_filter).await?;

    let mut out_rd = StanzaReader(out_rd);

    loop {
        tokio::select! {
            // server to client
            Ok(buf) = out_rd.next_eoft(&mut in_filter) => {
                match buf {
                    None => break,
                    Some((buf, end_of_first_tag)) => {
                        // ignore this
                        if buf.starts_with(b"<?xml ") {
                            continue;
                        }
                        let stanza = to_ws_new(buf, end_of_first_tag, is_c2s)?;
                        trace!("{} '{}'", client_addr.log_to(), stanza);
                        in_wr.feed(Text(stanza)).await?;
                        in_wr.flush().await?;
                    }
                }
            },
            Ok(Some(msg)) = in_rd.try_next() => {
                match msg {
                    // actual XMPP stanzas
                    Text(stanza) => {
                        let stanza = from_ws(stanza);
                        trace!("{} '{}'", client_addr.log_from(), stanza);
                        out_wr.write_all(stanza.as_bytes()).await?;
                        out_wr.flush().await?;
                    }
                    // websocket ping/pong
                    Ping(msg) => {
                        in_wr.feed(Pong(msg)).await?;
                        in_wr.flush().await?;
                    },
                    // handle Close, just break from loop, hopefully client sent <close/> before
                    Close(_) => break,
                    _ => bail!("invalid websocket message: {}", msg) // Binary or Pong
                }
            },
            // todo: should we also send pings to the client ourselves on a schedule? StanzaFilter strips out whitespace pings if the server uses them...
        }
    }

    info!("{} disconnected", client_addr.log_from());
    Ok(())
}

pub fn from_ws(stanza: String) -> String {
    if stanza.starts_with("<open ") {
        return stanza
            .replace("<open ", r#"<?xml version='1.0'?><stream:stream xmlns:stream="http://etherx.jabber.org/streams" "#)
            .replace("urn:ietf:params:xml:ns:xmpp-framing-server", "jabber:server")
            .replace("urn:ietf:params:xml:ns:xmpp-framing", "jabber:client")
            .replace("/>", ">");
    } else if stanza.starts_with("<close ") {
        return "</stream:stream>".to_string();
    }
    stanza
}

pub fn to_ws_new(buf: &[u8], mut end_of_first_tag: usize, is_c2s: bool) -> Result<String> {
    if end_of_first_tag == 0 {
        return Ok(String::from_utf8(buf.to_vec())?);
    }
    if buf.starts_with(b"<stream:stream ") {
        let buf = String::from_utf8(buf.to_vec())?;
        return Ok(buf
            .replace("<stream:stream ", "<open ")
            .replace("jabber:server", "urn:ietf:params:xml:ns:xmpp-framing-server")
            .replace("jabber:client", "urn:ietf:params:xml:ns:xmpp-framing")
            .replace(">", "/>"));
    }
    if buf.starts_with(b"</stream:stream") {
        return Ok(r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#.to_string());
    }
    if buf[end_of_first_tag - 1] == b'/' {
        end_of_first_tag -= 1;
    }
    let first_tag_bytes = &buf[0..end_of_first_tag];
    if first_tag_bytes.first_index_of(b" xmlns='").is_ok() || first_tag_bytes.first_index_of(br#" xmlns=""#).is_ok() {
        // already set, do nothing
        return Ok(String::from_utf8(buf.to_vec())?);
    }
    // otherwise add proper xmlns before end of tag
    let mut ret = String::with_capacity(buf.len() + 22);
    ret.push_str(std::str::from_utf8(&first_tag_bytes)?);
    ret.push_str(if is_c2s { " xmlns='jabber:client'" } else { " xmlns='jabber:server'" });
    ret.push_str(std::str::from_utf8(&buf[end_of_first_tag..])?);
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use crate::websocket::*;
    use std::io::Cursor;

    #[test]
    fn test_from_ws() {
        assert_eq!(
            from_ws(r#"<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" version="1.0" to="test.moparisthe.best" xml:lang="en" />"#.to_string()),
            r#"<?xml version='1.0'?><stream:stream xmlns:stream="http://etherx.jabber.org/streams" xmlns="jabber:client" version="1.0" to="test.moparisthe.best" xml:lang="en" >"#.to_string()
        );
        assert_eq!(from_ws(r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#.to_string()), r#"</stream:stream>"#.to_string());
    }

    async fn to_vec_eoft<'a, T: tokio::io::AsyncRead + Unpin>(mut stanza_reader: StanzaReader<T>, filter: &'a mut StanzaFilter) -> Result<Vec<String>> {
        let mut ret = Vec::new();
        while let Some((buf, end_of_first_tag)) = stanza_reader.next_eoft(filter).await? {
            ret.push(to_ws_new(buf, end_of_first_tag, true)?);
        }
        return Ok(ret);
    }

    #[tokio::test]
    async fn test_to_ws() -> Result<()> {
        let mut filter = StanzaFilter::new(262_144);

        assert_eq!(
            to_vec_eoft(
                StanzaReader(Cursor::new(
                    br###"
            <stream:stream xmlns="jabber:client" version="1.0" to="test.moparisthe.best" xml:lang="en">
            </stream:stream>
            <iq type='result' id='6ef4a4b7-7f2b-462b-9176-83ec706c625e' to='test1@test.moparisthe.best/gajim.12S9XM42'/>
            <stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>
            <iq type='result' id='7b0d57bb-6446-4701-92e5-8b9354bbfabe'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>test1@test.moparisthe.best/gajim.12S9XM42</jid></bind></iq>
            <iq type='result' id='7b0d57bb-6446-4701-92e5-8b9354bb>fabe'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>test1@test.moparisthe.best/gajim.12S9XM42</jid></bind></iq>
            "###,
                )),
                &mut filter
            )
            .await?,
            vec![
                r#"<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" version="1.0" to="test.moparisthe.best" xml:lang="en"/>"#,
                r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#,
                r#"<iq type='result' id='6ef4a4b7-7f2b-462b-9176-83ec706c625e' to='test1@test.moparisthe.best/gajim.12S9XM42' xmlns='jabber:client'/>"#,
                r#"<stream:features xmlns='jabber:client'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>"#,
                r#"<iq type='result' id='7b0d57bb-6446-4701-92e5-8b9354bbfabe' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>test1@test.moparisthe.best/gajim.12S9XM42</jid></bind></iq>"#,
                r#"<iq type='result' id='7b0d57bb-6446-4701-92e5-8b9354bb>fabe' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>test1@test.moparisthe.best/gajim.12S9XM42</jid></bind></iq>"#,
            ]
        );

        Ok(())
    }
}
