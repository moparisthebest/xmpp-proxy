use anyhow::Result;
use futures::StreamExt;
use futures_util::stream::{SplitSink, SplitStream};
use tokio_tungstenite::{
    tungstenite::{
        handshake::server::{Request, Response},
        http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        protocol::WebSocketConfig,
    },
    WebSocketStream,
};

#[cfg(feature = "incoming")]
pub mod incoming;

#[cfg(feature = "outgoing")]
pub mod outgoing;

pub type WsWr = SplitSink<WebSocketStream<BoxAsyncReadWrite>, tokio_tungstenite::tungstenite::Message>;
pub type WsRd = SplitStream<WebSocketStream<BoxAsyncReadWrite>>;

// https://datatracker.ietf.org/doc/html/rfc7395

fn ws_cfg(max_stanza_size_bytes: usize) -> Option<WebSocketConfig> {
    Some(WebSocketConfig {
        max_frame_size: Some(max_stanza_size_bytes),       // this is exactly the stanza size
        max_message_size: Some(max_stanza_size_bytes * 4), // this is the message size, default is 4x frame size, so I guess we'll do the same here
        accept_unmasked_frames: true,
        ..Default::default()
    })
}

pub async fn incoming_websocket_connection(stream: BoxAsyncReadWrite, max_stanza_size_bytes: usize) -> Result<(StanzaRead, StanzaWrite)> {
    // accept the websocket
    let stream = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        |_request: &Request, mut response: Response| {
            // todo: check SEC_WEBSOCKET_PROTOCOL or ORIGIN ?
            response.headers_mut().append(ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().expect("known to be good value"));
            Ok(response)
        },
        ws_cfg(max_stanza_size_bytes),
    )
    .await?;

    let (in_wr, in_rd) = stream.split();

    Ok((StanzaRead::WebSocketRead(in_rd), StanzaWrite::WebSocketClientWrite(in_wr)))
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
    if buf.starts_with(b"<stream:stream ") {
        let buf = String::from_utf8(buf.to_vec())?;
        return Ok(buf
            .replace("<stream:stream ", "<open ")
            .replace("jabber:server", "urn:ietf:params:xml:ns:xmpp-framing-server")
            .replace("jabber:client", "urn:ietf:params:xml:ns:xmpp-framing")
            .replace('>', "/>"));
    }
    if end_of_first_tag == 0 {
        return Ok(String::from_utf8(buf.to_vec())?);
    }
    if buf.starts_with(b"</stream:stream") {
        return Ok(r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#.to_string());
    }
    if buf[end_of_first_tag - 1] == b'/' {
        end_of_first_tag -= 1;
    }
    let first_tag_bytes = &buf[0..end_of_first_tag];
    let has_xmlns = first_tag_bytes.first_index_of(b" xmlns='").is_ok() || first_tag_bytes.first_index_of(br#" xmlns=""#).is_ok();
    let has_xmlns_stream = !first_tag_bytes.contains_seq(b"stream:") || (first_tag_bytes.first_index_of(b" xmlns:stream='").is_ok() || first_tag_bytes.first_index_of(br#" xmlns:stream=""#).is_ok());
    if has_xmlns && has_xmlns_stream {
        // already set, do nothing
        return Ok(String::from_utf8(buf.to_vec())?);
    }
    // otherwise add proper xmlns before end of tag
    let mut capacity = 0;
    if !has_xmlns {
        capacity += 22;
    }
    if !has_xmlns_stream {
        capacity += 48;
    }
    let mut ret = String::with_capacity(buf.len() + capacity);
    ret.push_str(std::str::from_utf8(first_tag_bytes)?);
    if !has_xmlns {
        ret.push_str(if is_c2s { " xmlns='jabber:client'" } else { " xmlns='jabber:server'" });
    }
    if !has_xmlns_stream {
        ret.push_str(" xmlns:stream='http://etherx.jabber.org/streams'");
    }
    ret.push_str(std::str::from_utf8(&buf[end_of_first_tag..])?);
    Ok(ret)
}

use crate::{
    common::BoxAsyncReadWrite,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
};

#[cfg(test)]
mod tests {
    use crate::{
        stanzafilter::{StanzaFilter, StanzaReader},
        websocket::*,
    };
    use std::io::Cursor;

    #[test]
    fn test_from_ws() {
        assert_eq!(
            from_ws(r#"<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" version="1.0" to="test.moparisthe.best" xml:lang="en" />"#.to_string()),
            r#"<stream:stream xmlns="jabber:client" version="1.0" to="test.moparisthe.best" xml:lang="en"  xmlns:stream="http://etherx.jabber.org/streams">"#.to_string()
        );
        assert_eq!(from_ws(r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#.to_string()), r#"</stream:stream>"#.to_string());

        assert_eq!(
            from_ws(r#"<open to='one.example.org' xmlns='urn:ietf:params:xml:ns:xmpp-framing' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'/>"#.to_string()),
            r#"<stream:stream to='one.example.org' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"#.to_string()
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
            <stream:stream id='719668c2-f5ba-4243-8042-ce6b2cece11b' xmlns='jabber:client' version='1.0' xml:lang='en' from='test.moparisthe.best' xmlns:stream='http://etherx.jabber.org/streams'>
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
                r#"<open id='719668c2-f5ba-4243-8042-ce6b2cece11b' xmlns='urn:ietf:params:xml:ns:xmpp-framing' version='1.0' xml:lang='en' from='test.moparisthe.best' xmlns:stream='http://etherx.jabber.org/streams'/>"#,
                r#"<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" version="1.0" to="test.moparisthe.best" xml:lang="en"/>"#,
                r#"<close xmlns="urn:ietf:params:xml:ns:xmpp-framing" />"#,
                r#"<iq type='result' id='6ef4a4b7-7f2b-462b-9176-83ec706c625e' to='test1@test.moparisthe.best/gajim.12S9XM42' xmlns='jabber:client'/>"#,
                r#"<stream:features xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>"#,
                r#"<iq type='result' id='7b0d57bb-6446-4701-92e5-8b9354bbfabe' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>test1@test.moparisthe.best/gajim.12S9XM42</jid></bind></iq>"#,
                r#"<iq type='result' id='7b0d57bb-6446-4701-92e5-8b9354bb>fabe' xmlns='jabber:client'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>test1@test.moparisthe.best/gajim.12S9XM42</jid></bind></iq>"#,
            ]
        );

        Ok(())
    }
}
