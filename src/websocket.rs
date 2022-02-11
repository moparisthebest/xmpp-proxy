use crate::*;
use anyhow::Result;
use futures::StreamExt;

use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

// https://datatracker.ietf.org/doc/html/rfc7395

pub async fn handle_websocket_connection(
    stream: BufStream<tokio_rustls::TlsStream<tokio::net::TcpStream>>,
    client_addr: &mut Context<'_>,
    local_addr: SocketAddr,
    config: CloneableConfig,
) -> Result<()> {
    info!("{} connected", client_addr.log_from());

    // accept the websocket
    // todo: check SEC_WEBSOCKET_PROTOCOL or ORIGIN ?
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

    let (in_wr, in_rd) = stream.split();

    let in_filter = StanzaFilter::new(config.max_stanza_size_bytes);

    shuffle_rd_wr_filter(StanzaRead::WebSocketRead(in_rd), StanzaWrite::WebSocketClientWrite(in_wr), config, local_addr, client_addr, in_filter).await
}

pub fn from_ws(stanza: String) -> String {
    if stanza.starts_with("<open ") {
        let stanza = stanza
            // todo: hmm what to do here, xml needed? breaks srv pre-tls detection because it's really 2 "stanzas"....
            //.replace("<open ", r#"<?xml version='1.0'?><stream:stream "#)
            .replace("<open ", r#"<stream:stream "#)
            .replace("urn:ietf:params:xml:ns:xmpp-framing-server", "jabber:server")
            .replace("urn:ietf:params:xml:ns:xmpp-framing", "jabber:client");
        if !stanza.contains("xmlns:stream=") {
            stanza.replace("/>", r#" xmlns:stream="http://etherx.jabber.org/streams">"#)
        } else {
            stanza.replace("/>", ">")
        }
    } else if stanza.starts_with("<close ") {
        "</stream:stream>".to_string()
    } else {
        stanza
    }
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
    ret.push_str(std::str::from_utf8(first_tag_bytes)?);
    ret.push_str(if is_c2s { " xmlns='jabber:client'" } else { " xmlns='jabber:server'" });
    ret.push_str(std::str::from_utf8(&buf[end_of_first_tag..])?);
    Ok(ret)
}

use rustls::ServerName;
use std::convert::TryFrom;
use tokio::io::BufStream;

use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::http::Uri;

pub async fn websocket_connect(target: SocketAddr, server_name: &str, url: &Uri, origin: &str, _is_c2s: bool) -> Result<(StanzaWrite, StanzaRead)> {
    // todo: WebSocketConfig
    // todo: static ? alpn? client cert auth for server
    let connector = rustls::ClientConfig::builder().with_safe_defaults().with_root_certificates(root_cert_store()).with_no_client_auth();

    let mut request = url.into_client_request()?;
    request.headers_mut().append(SEC_WEBSOCKET_PROTOCOL, "xmpp".parse()?);
    request.headers_mut().append(ORIGIN, origin.parse()?);

    let dnsname = ServerName::try_from(server_name)?;
    let stream = tokio::net::TcpStream::connect(target).await?;
    let connector = TlsConnector::from(Arc::new(connector));
    let stream = connector.connect(dnsname, stream).await?;

    let stream: tokio_rustls::TlsStream<tokio::net::TcpStream> = stream.into();
    // todo: tokio_tungstenite seems to have a bug, if the write buffer is non-zero, it'll hang forever, even though we always flush, investigate
    let stream = BufStream::with_capacity(crate::IN_BUFFER_SIZE, 0, stream);

    let (stream, _) = tokio_tungstenite::client_async_with_config(request, stream, None).await?;

    let (wrt, rd) = stream.split();

    Ok((StanzaWrite::WebSocketClientWrite(wrt), StanzaRead::WebSocketRead(rd)))
}

#[cfg(test)]
mod tests {
    use crate::websocket::*;
    use std::io::Cursor;

    #[test]
    fn test_from_ws() {
        assert_eq!(
            from_ws(r#"<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" version="1.0" to="test.moparisthe.best" xml:lang="en" />"#.to_string()),
            r#"<?xml version='1.0'?><stream:stream xmlns="jabber:client" version="1.0" to="test.moparisthe.best" xml:lang="en"  xmlns:stream="http://etherx.jabber.org/streams">"#.to_string()
        );
        assert_eq!(from_ws(r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#.to_string()), r#"</stream:stream>"#.to_string());

        assert_eq!(
            from_ws(r#"<open to='one.example.org' xmlns='urn:ietf:params:xml:ns:xmpp-framing' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'/>"#.to_string()),
            r#"<?xml version='1.0'?><stream:stream to='one.example.org' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"#.to_string()
        );
    }

    async fn to_vec_eoft<T: tokio::io::AsyncRead + Unpin>(mut stanza_reader: StanzaReader<T>, filter: &mut StanzaFilter) -> Result<Vec<String>> {
        let mut ret = Vec::new();
        while let Some((buf, end_of_first_tag)) = stanza_reader.next_eoft(filter).await? {
            ret.push(to_ws_new(buf, end_of_first_tag, true)?);
        }
        Ok(ret)
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
