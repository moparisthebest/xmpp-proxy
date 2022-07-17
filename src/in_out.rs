#[cfg(feature = "websocket")]
use crate::websocket::{from_ws, to_ws_new, WsRd, WsWr};
use crate::{
    common::IN_BUFFER_SIZE,
    in_out::{StanzaRead::*, StanzaWrite::*},
    slicesubsequence::SliceSubsequence,
    stanzafilter::{StanzaFilter, StanzaReader},
};
use anyhow::{bail, Result};
#[cfg(feature = "websocket")]
use futures_util::{SinkExt, TryStreamExt};
use log::trace;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::Message::{Close, Ping, Pong, Text};

pub enum StanzaWrite {
    AsyncWrite(Box<dyn AsyncWrite + Unpin + Send>),
    #[cfg(feature = "websocket")]
    WebSocketClientWrite(WsWr),
}

pub enum StanzaRead {
    AsyncRead(StanzaReader<Box<dyn AsyncRead + Unpin + Send>>),
    #[cfg(feature = "websocket")]
    WebSocketRead(WsRd),
}

impl StanzaWrite {
    #[inline(always)]
    pub fn new<T: 'static + AsyncWrite + Unpin + Send>(wr: T) -> Self {
        AsyncWrite(Box::new(wr))
        // todo: investigate buffering this, but don't double buffer
        //AsyncWrite(Box::new(tokio::io::BufWriter::with_capacity(8192, wr)))
    }

    pub async fn write_all<'a>(&'a mut self, is_c2s: bool, buf: &'a [u8], end_of_first_tag: usize, client_addr: &'a str) -> Result<()> {
        match self {
            AsyncWrite(wr) => Ok(wr.write_all(buf).await?),
            #[cfg(feature = "websocket")]
            WebSocketClientWrite(in_wr) => {
                let mut buf = buf;
                // ignore this
                if buf.starts_with(b"<?xml ") {
                    // we might want to skip this if it's stand-alone, otherwise we want to skip it
                    buf = &buf[b"<?xml ".len()..];
                    if let Ok(idx) = buf.first_index_of(b"<") {
                        buf = &buf[idx..];
                    } else {
                        trace!("code: skipping '{}'", String::from_utf8(buf.to_vec())?);
                        return Ok(());
                    }
                }
                let stanza = to_ws_new(buf, end_of_first_tag, is_c2s)?;
                trace!("{} (after ws conversion) '{}'", client_addr, stanza);
                Ok(in_wr.feed(Text(stanza)).await?)
            }
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        match self {
            AsyncWrite(wr) => Ok(wr.flush().await?),
            #[cfg(feature = "websocket")]
            WebSocketClientWrite(ws) => Ok(ws.flush().await?),
        }
    }
}

impl StanzaRead {
    #[inline(always)]
    pub fn new<T: 'static + AsyncRead + Unpin + Send>(rd: T) -> Self {
        // we naively read 1 byte at a time, which buffering significantly speeds up
        AsyncRead(StanzaReader(Box::new(BufReader::with_capacity(IN_BUFFER_SIZE, rd))))
    }

    #[inline(always)]
    pub fn already_buffered<T: 'static + AsyncRead + Unpin + Send>(rd: T) -> Self {
        // we naively read 1 byte at a time, which buffering significantly speeds up
        AsyncRead(StanzaReader(Box::new(rd)))
    }

    pub async fn next<'a>(&'a mut self, filter: &'a mut StanzaFilter, client_addr: &'a str, wrt: &mut StanzaWrite) -> Result<Option<(&'a [u8], usize)>> {
        match self {
            AsyncRead(rd) => rd.next_eoft(filter).await,
            #[cfg(feature = "websocket")]
            WebSocketRead(rd) => {
                loop {
                    if let Some(msg) = rd.try_next().await? {
                        match msg {
                            // actual XMPP stanzas
                            Text(stanza) => {
                                trace!("{} (before ws conversion) '{}'", client_addr, stanza);
                                let stanza = from_ws(stanza);
                                let stanza = stanza.as_bytes();
                                // todo: set up websocket connection so max size cannot be bigger than filter.buf.len()
                                let buf = &mut filter.buf[0..stanza.len()];
                                buf.copy_from_slice(stanza);
                                return Ok(Some((buf, 0))); // todo: 0 or None...
                            }
                            // websocket ping/pong
                            Ping(msg) => {
                                match wrt {
                                    AsyncWrite(_) => bail!("programming error! should always send matching write pair into read, so websocket for websocket..."),
                                    WebSocketClientWrite(ws) => {
                                        ws.feed(Pong(msg)).await?;
                                        ws.flush().await?;
                                    }
                                }
                                continue;
                            }
                            // handle Close, just break from loop, hopefully client sent <close/> before
                            Close(cf) => bail!("websocket close: {:?}", cf),
                            _ => bail!("invalid websocket message: {}", msg), // Binary or Pong
                        }
                    } else {
                        bail!("websocket stream ended")
                    }
                }
            }
        }
    }
}
