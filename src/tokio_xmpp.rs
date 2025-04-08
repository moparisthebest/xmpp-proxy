use std::{fmt::Display, sync::Arc};

use futures_util::StreamExt;
use tokio_util::codec::Framed;
pub use tokio_xmpp::*;
use xmpp_stream::XMPPStream;

use crate::in_out::StanzaStream;

#[derive(Clone, Debug)]
pub struct XmppProxyServerConnectorError(Arc<anyhow::Error>);

impl Display for XmppProxyServerConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<anyhow::Error> for XmppProxyServerConnectorError {
    fn from(value: anyhow::Error) -> Self {
        Self(value.into())
    }
}

impl From<tokio_xmpp::Error> for XmppProxyServerConnectorError {
    fn from(value: tokio_xmpp::Error) -> Self {
        Self(anyhow::Error::from(value).into())
    }
}

impl std::error::Error for XmppProxyServerConnectorError {}

impl connect::ServerConnectorError for XmppProxyServerConnectorError {}

#[derive(Clone, Debug)]
pub struct XmppProxyServerConnector;

impl connect::ServerConnector for XmppProxyServerConnector {
    type Stream = StanzaStream;
    type Error = XmppProxyServerConnectorError;

    async fn connect(&self, jid: &jid::Jid, ns: &str) -> Result<XMPPStream<Self::Stream>, Self::Error> {
        let domain = jid.domain();
        let is_c2s = ns == "jabber:client";
        let stanza_stream = StanzaStream::connect(domain, is_c2s).await?;
        let mut stanza_stream = Framed::new(stanza_stream, XmppCodec::new());
        let stream_attrs;
        loop {
            match stanza_stream.next().await {
                Some(Ok(Packet::StreamStart(attrs))) => {
                    stream_attrs = attrs;
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => return Err(Error::Disconnected.into()),
            }
        }

        let stream_id = stream_attrs.get("id").ok_or(ProtocolError::NoStreamId).unwrap().clone();
        let stream_features;
        loop {
            match stanza_stream.next().await {
                Some(Ok(Packet::Stanza(stanza))) if stanza.is("features", tokio_xmpp::parsers::ns::STREAM) => {
                    stream_features = stanza;
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
                None => return Err(Error::Disconnected.into()),
            }
        }
        let xmpp_stream = XMPPStream::new(jid.clone(), stanza_stream, ns.to_string(), stream_id, stream_features);

        Ok(xmpp_stream)
    }
}
