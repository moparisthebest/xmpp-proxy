use std::io::{Cursor, Error as IoError};
use std::{pin::Pin, task::Poll};

#[cfg(feature = "websocket")]
use crate::websocket::{from_ws, to_ws_new, WsRd, WsWr};
use crate::{
    common::IN_BUFFER_SIZE,
    in_out::{StanzaRead::*, StanzaWrite::*},
    slicesubsequence::SliceSubsequence,
    stanzafilter::{StanzaFilter, StanzaReader},
};
use anyhow::{bail, Result};
use futures_util::Future;
use futures_util::Stream;
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

    pub async fn write_all(&mut self, is_c2s: bool, buf: &[u8], end_of_first_tag: usize, client_addr: &str) -> Result<()> {
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

    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            AsyncWrite(wr) => Ok(wr.shutdown().await?),
            #[cfg(feature = "websocket")]
            WebSocketClientWrite(ws) => Ok(ws.close().await?),
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
                        return Ok(None);
                    }
                }
            }
        }
    }
}

pub struct StanzaStream {
    wr: StanzaWrite,
    rd: StanzaRead,

    fut_next_stanza: Option<u64>,

    send_stream_open: bool,
    stream_open: Vec<u8>,

    client_addr: String,
    is_c2s: bool,

    filter: StanzaFilter,
    wr_filter: Option<StanzaFilter>,
}

impl StanzaStream {
    #[cfg(feature = "outgoing")]
    pub async fn connect(domain: &str, is_c2s: bool) -> Result<Self> {
        let ns = if is_c2s { "jabber:client" } else { "jabber:server" };
        let stream_open = format!("<stream:stream to='{domain}' version='1.0' xmlns='{ns}' xmlns:stream='http://etherx.jabber.org/streams'>");
        Self::connect_open(domain, is_c2s, stream_open.as_bytes()).await
    }

    #[cfg(feature = "outgoing")]
    pub async fn connect_open(domain: &str, is_c2s: bool, stream_open: &[u8]) -> Result<Self> {
        use crate::{
            common::{certs_key::CertsKey, outgoing::OutgoingConfig, DEFAULT_MAX_STANZA_SIZE_BYTES},
            context::Context,
            srv::srv_connect,
        };
        const ADDR: &str = "127.0.0.1";
        let mut context = Context::new("StanzaStream", ADDR.parse().expect("valid"));

        let mut in_filter = StanzaFilter::new(DEFAULT_MAX_STANZA_SIZE_BYTES);
        let config = OutgoingConfig {
            max_stanza_size_bytes: DEFAULT_MAX_STANZA_SIZE_BYTES,
            certs_key: CertsKey::new(Err(anyhow::anyhow!("StanzaStream doesn't support client certs yet"))).into(),
        };
        let (wr, rd, stream_open) = srv_connect(domain, is_c2s, stream_open, &mut in_filter, &mut context, config).await?;
        Ok(StanzaStream::new(wr, rd, stream_open, ADDR.to_string(), is_c2s, in_filter))
    }

    pub fn new(wr: StanzaWrite, rd: StanzaRead, stream_open: Vec<u8>, client_addr: String, is_c2s: bool, filter: StanzaFilter) -> Self {
        let async_write = matches!(wr, StanzaWrite::AsyncWrite(_));
        let wr_filter = if async_write { None } else { Some(filter.clone()) };
        Self {
            wr,
            rd,
            send_stream_open: !stream_open.is_empty(),
            stream_open,
            client_addr,
            is_c2s,
            filter,
            wr_filter,
            fut_next_stanza: None,
        }
    }

    pub async fn next_stanza<'a>(&'a mut self) -> Result<Option<(&'a [u8], usize)>> {
        if self.send_stream_open {
            self.send_stream_open = false;
            return Ok(Some((self.stream_open.as_slice(), 0)));
        }
        self.rd.next(&mut self.filter, self.client_addr.as_str(), &mut self.wr).await
    }

    pub async fn write_stanzas(&mut self, buf: &[u8]) -> Result<usize> {
        match self.wr_filter.as_mut() {
            None => {
                // we don't care about how many stanzas or anything
                self.wr.write_all(self.is_c2s, buf, 0, self.client_addr.as_str()).await?;
                Ok(buf.len())
            }
            Some(wr_filter) => {
                let mut rd = StanzaReader(Cursor::new(buf));
                let mut wrote = 0;
                while let Some((buf, eoft)) = rd.next_eoft(wr_filter).await? {
                    self.wr.write_all(self.is_c2s, buf, eoft, self.client_addr.as_str()).await?;
                    wrote += buf.len();
                }
                Ok(wrote)
            }
        }
    }
}

// todo: using Arc<StanzaFilter> and .make_mut() and a wrapping struct can still return slices safely, and clone will only happen if someone keeps a reference, which is ideal
impl Stream for StanzaStream {
    type Item = Result<(Vec<u8>, usize)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        if self.send_stream_open {
            self.send_stream_open = false;
            // swap in an empty vec and send ours
            let stream_open = std::mem::replace(&mut self.stream_open, Vec::new());
            return std::task::Poll::Ready(Some(Ok((stream_open, 0))));
        }
        let future = self.next_stanza();
        let future = std::pin::pin!(future);
        match future.poll(cx) {
            std::task::Poll::Ready(res) => std::task::Poll::Ready(res.map(|r| r.map(|r| (r.0.to_vec(), r.1))).transpose()),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncRead for StanzaStream {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        // todo: instead of waiting for a whole stanza, if self is AsyncRead, we could go directly to that and skip stanzafilter, problem is this would break Stream::poll_next and XmppStream::next_stanza, so maybe we need a different struct to do that?
        // todo: instead of using our StanzaFilter and copying bytes from it, we could make one out of the buf?
        let future = self.next_stanza();
        // self.fut_next_stanza = Some(future);
        let future = std::pin::pin!(future);
        match future.poll(cx) {
            std::task::Poll::Ready(res) => {
                if let Some((stanza, _)) = res.map_err(|e| IoError::other(e))? {
                    if stanza.len() >= buf.remaining() {
                        return std::task::Poll::Ready(Err(IoError::other(format!("stanza of length {} read but buffer of only {} supplied", stanza.len(), buf.remaining()))));
                    }
                    buf.put_slice(stanza);
                }
                return Poll::Ready(Ok(()));
            }
            std::task::Poll::Pending => {
                // self.fut_next_stanza = Some(future);
                std::task::Poll::Pending
            }
        }
    }
}

impl AsyncWrite for StanzaStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<std::result::Result<usize, std::io::Error>> {
        let future = self.write_stanzas(buf);
        let future = std::pin::pin!(future);
        match future.poll(cx) {
            Poll::Ready(r) => r.map_err(|e| IoError::other(e)).into(),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::result::Result<(), std::io::Error>> {
        let future = self.wr.flush();
        let future = std::pin::pin!(future);
        match future.poll(cx) {
            Poll::Ready(r) => r.map_err(|e| IoError::other(e)).into(),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::result::Result<(), std::io::Error>> {
        let future = self.wr.shutdown();
        let future = std::pin::pin!(future);
        match future.poll(cx) {
            Poll::Ready(r) => r.map_err(|e| IoError::other(e)).into(),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use std::{
        any::{Any, TypeId},
        io::Cursor,
    };
    use tokio::io::AsyncReadExt;

    use crate::{common::to_str, stanzafilter::StanzaFilter};

    use super::*;

    #[tokio::test]
    async fn async_read() -> Result<()> {
        let stream_open = br###"
            <stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' version='1.0' to='example.org' from='example.com' xml:lang='en'>"###;
        let orig = br###"<a/><b>woo</b>"###;
        let rd = Cursor::new(orig.clone());
        // let wr = Cursor::new(&mut written[..]);
        let mut wr = Cursor::new(Vec::new());

        let mut stream = StanzaStream::new(
            StanzaWrite::new(wr.clone()),
            StanzaRead::new(rd),
            stream_open.to_vec(),
            "client-addr".to_string(),
            true,
            StanzaFilter::new(262_144),
        );

        let mut buf = [0u8; 262_144];
        let mut _total_size = 0;
        while let Ok(n) = stream.read(&mut buf[..]).await {
            if n == 0 {
                break;
            }
            wr.write(&buf[0..n]).await?;
        }
        // match stream.wr {
        //     StanzaWrite::AsyncWrite(a) => {
        //         // let a = &a.as_ref() as &dyn Any;
        //         // let a = Box::leak(a);
        //         let a = &a as &dyn Any;
        //         println!("woo");
        //         println!("typeid: '{:?}', cursor: '{:?}", a.type_id(), TypeId::of::<Cursor<Vec<u8>>>());
        //         let out = a.downcast_ref::<Cursor<Vec<u8>>>().expect("must be Cursor<Vec<u8>>");
        //         assert_eq!(out.get_ref(), orig);
        //     }
        //     WebSocketClientWrite(_) => panic!("impossible"),
        // };
        drop(stream);

        let mut expected = stream_open.to_vec();
        expected.extend_from_slice(orig);
        // assert_eq!(&wr.get_ref()[..], &expected[..]);
        assert_eq!(to_str(&wr.get_ref()[..]), to_str(&expected[..]));

        Ok(())
    }
}
