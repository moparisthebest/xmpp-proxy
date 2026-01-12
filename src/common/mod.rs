use crate::{
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::StanzaFilter,
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use log::{info, trace};
use serde::{Deserialize, Deserializer};
use std::{
    fmt::{Display, Formatter},
    io,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    time::Duration,
};
#[cfg(not(target_os = "windows"))]
use tokio::net::UnixStream;
use tokio::{
    io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, BufStream},
    net::{TcpListener, TcpStream},
};

#[cfg(feature = "incoming")]
pub mod incoming;

#[cfg(feature = "outgoing")]
pub mod outgoing;

#[cfg(any(feature = "rustls-native-certs", feature = "webpki-roots"))]
pub mod ca_roots;

#[cfg(feature = "rustls")]
pub mod certs_key;
pub mod stream_listener;

pub const IN_BUFFER_SIZE: usize = 8192;
pub const ALPN_XMPP_CLIENT: &[u8] = b"xmpp-client";
pub const ALPN_XMPP_SERVER: &[u8] = b"xmpp-server";

pub trait AsyncReadAndWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadAndWrite for T {}

pub trait AsyncReadWritePeekSplit: tokio::io::AsyncRead + tokio::io::AsyncWrite + Peek + Send + 'static + Unpin + Split {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Peek + Send + 'static + Unpin + Split> AsyncReadWritePeekSplit for T {}

pub type BoxAsyncReadWrite = Box<dyn AsyncReadAndWrite>;
pub type BufAsyncReadWrite = BufStream<BoxAsyncReadWrite>;

pub fn buf_stream(stream: BoxAsyncReadWrite) -> BufAsyncReadWrite {
    // todo: do we *want* a non-zero writer_capacity ?
    BufStream::with_capacity(IN_BUFFER_SIZE, 0, stream)
}

pub fn to_str(buf: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(buf)
}

pub fn c2s(is_c2s: bool) -> &'static str {
    if is_c2s {
        "c2s"
    } else {
        "s2s"
    }
}

#[derive(Clone)]
pub enum SocketAddrPath {
    SocketAddr(SocketAddr),
    #[cfg(not(target_os = "windows"))]
    Path(PathBuf),
}

impl SocketAddrPath {
    pub async fn connect(&self) -> Result<(Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>)> {
        Ok(match self {
            SocketAddrPath::SocketAddr(sa) => TcpStream::connect(sa).await?.split_boxed(),
            #[cfg(not(target_os = "windows"))]
            SocketAddrPath::Path(path) => tokio::net::UnixStream::connect(path).await?.split_boxed(),
        })
    }

    pub async fn bind(&self) -> Result<Listener> {
        Ok(match self {
            SocketAddrPath::SocketAddr(sa) => Listener::Tcp(TcpListener::bind(sa).await?),
            #[cfg(not(target_os = "windows"))]
            SocketAddrPath::Path(path) => Listener::Unix(tokio::net::UnixListener::bind(path)?),
        })
    }

    pub async fn bind_udp(&self) -> Result<UdpListener> {
        Ok(match self {
            SocketAddrPath::SocketAddr(sa) => UdpListener::Udp(UdpSocket::bind(sa)?),
            #[cfg(not(target_os = "windows"))]
            SocketAddrPath::Path(path) => UdpListener::Unix(std::os::unix::net::UnixDatagram::bind(path)?),
        })
    }
}

impl Display for SocketAddrPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketAddrPath::SocketAddr(x) => x.fmt(f),
            #[cfg(not(target_os = "windows"))]
            SocketAddrPath::Path(x) => x.display().fmt(f),
        }
    }
}

impl<'de> Deserialize<'de> for SocketAddrPath {
    fn deserialize<D>(deserializer: D) -> Result<SocketAddrPath, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[cfg(not(target_os = "windows"))]
        {
            let str = String::deserialize(deserializer)?;
            // seems good enough, possibly could improve
            Ok(if str.contains('/') {
                SocketAddrPath::Path(PathBuf::from(str))
            } else {
                SocketAddrPath::SocketAddr(str.parse().map_err(serde::de::Error::custom)?)
            })
        }
        #[cfg(target_os = "windows")]
        {
            Ok(SocketAddrPath::SocketAddr(SocketAddr::deserialize(deserializer)?))
        }
    }
}

pub enum Listener {
    Tcp(TcpListener),
    #[cfg(not(target_os = "windows"))]
    Unix(tokio::net::UnixListener),
}

pub enum UdpListener {
    Udp(UdpSocket),
    #[cfg(not(target_os = "windows"))]
    Unix(std::os::unix::net::UnixDatagram),
}

pub trait Split: Sized {
    type ReadHalf: AsyncRead + Unpin + Send + 'static;
    type WriteHalf: AsyncWrite + Unpin + Send + 'static;

    fn combine(read_half: Self::ReadHalf, write_half: Self::WriteHalf) -> Result<Self>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf);

    fn stanza_rw(self) -> (StanzaRead, StanzaWrite);

    fn split_boxed(self) -> (Box<dyn AsyncRead + Unpin + Send>, Box<dyn AsyncWrite + Unpin + Send>) {
        let (rd, wr) = self.split();
        (Box::new(rd), Box::new(wr))
    }
}

impl Split for TcpStream {
    type ReadHalf = tokio::net::tcp::OwnedReadHalf;
    type WriteHalf = tokio::net::tcp::OwnedWriteHalf;

    fn combine(read_half: Self::ReadHalf, write_half: Self::WriteHalf) -> Result<Self> {
        Ok(read_half.reunite(write_half)?)
    }

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.into_split()
    }

    fn stanza_rw(self) -> (StanzaRead, StanzaWrite) {
        let (in_rd, in_wr) = self.into_split();
        (StanzaRead::new(in_rd), StanzaWrite::new(in_wr))
    }
}

#[cfg(feature = "tokio-rustls")]
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Split for tokio_rustls::server::TlsStream<T> {
    type ReadHalf = tokio::io::ReadHalf<tokio_rustls::server::TlsStream<T>>;
    type WriteHalf = tokio::io::WriteHalf<tokio_rustls::server::TlsStream<T>>;

    fn combine(read_half: Self::ReadHalf, write_half: Self::WriteHalf) -> Result<Self> {
        if read_half.is_pair_of(&write_half) {
            Ok(read_half.unsplit(write_half))
        } else {
            bail!("non-matching read/write half")
        }
    }

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }

    fn stanza_rw(self) -> (StanzaRead, StanzaWrite) {
        let (in_rd, in_wr) = tokio::io::split(self);
        (StanzaRead::new(in_rd), StanzaWrite::new(in_wr))
    }
}

#[cfg(not(target_os = "windows"))]
impl Split for UnixStream {
    type ReadHalf = tokio::net::unix::OwnedReadHalf;
    type WriteHalf = tokio::net::unix::OwnedWriteHalf;

    fn combine(read_half: Self::ReadHalf, write_half: Self::WriteHalf) -> Result<Self> {
        Ok(read_half.reunite(write_half)?)
    }

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        self.into_split()
    }

    fn stanza_rw(self) -> (StanzaRead, StanzaWrite) {
        let (in_rd, in_wr) = self.into_split();
        (StanzaRead::new(in_rd), StanzaWrite::new(in_wr))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Split for BufStream<T> {
    type ReadHalf = tokio::io::ReadHalf<BufStream<T>>;
    type WriteHalf = tokio::io::WriteHalf<BufStream<T>>;

    fn combine(read_half: Self::ReadHalf, write_half: Self::WriteHalf) -> Result<Self> {
        if read_half.is_pair_of(&write_half) {
            Ok(read_half.unsplit(write_half))
        } else {
            bail!("non-matching read/write half")
        }
    }

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        tokio::io::split(self)
    }

    fn stanza_rw(self) -> (StanzaRead, StanzaWrite) {
        let (in_rd, in_wr) = tokio::io::split(self);
        (StanzaRead::already_buffered(in_rd), StanzaWrite::new(in_wr))
    }
}

#[async_trait]
pub trait Peek {
    async fn peek_bytes<'a>(&mut self, p: &'a mut [u8]) -> anyhow::Result<&'a [u8]>;

    async fn first_bytes_match<'a>(&mut self, p: &'a mut [u8], matcher: fn(&'a [u8]) -> bool) -> Result<bool> {
        Ok(matcher(self.peek_bytes(p).await?))
    }
}

#[async_trait]
impl Peek for TcpStream {
    async fn peek_bytes<'a>(&mut self, p: &'a mut [u8]) -> anyhow::Result<&'a [u8]> {
        // sooo... I don't think peek here can be used for > 1 byte without this timer craziness... can it?
        let len = p.len();
        // wait up to 10 seconds until len bytes have been read
        use std::time::{Duration, Instant};
        let duration = Duration::from_secs(10);
        let now = Instant::now();
        loop {
            let n = self.peek(p).await?;
            if n == len {
                return Ok(p); // success
            }
            if n == 0 {
                bail!("not enough bytes");
            }
            if Instant::now() - now > duration {
                bail!("less than {} bytes in 10 seconds, closed connection?", len);
            }
        }
    }
}

#[async_trait]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Peek for BufStream<T> {
    async fn peek_bytes<'a>(&mut self, p: &'a mut [u8]) -> anyhow::Result<&'a [u8]> {
        // sooo... I don't think peek here can be used for > 1 byte without this timer craziness... can it?
        let len = p.len();
        // wait up to 10 seconds until len bytes have been read
        use std::time::{Duration, Instant};
        use tokio::io::AsyncBufReadExt;
        let duration = Duration::from_secs(10);
        let now = Instant::now();
        loop {
            let buf = self.fill_buf().await?;
            if buf.len() >= len {
                p.copy_from_slice(&buf[0..len]);
                return Ok(p); // success
            }
            if buf.is_empty() {
                bail!("not enough bytes");
            }
            if Instant::now() - now > duration {
                bail!("less than {} bytes in 10 seconds, closed connection?", len);
            }
        }
    }
}

#[async_trait]
impl<T: AsyncRead + Unpin + Send> Peek for BufReader<T> {
    async fn peek_bytes<'a>(&mut self, p: &'a mut [u8]) -> anyhow::Result<&'a [u8]> {
        // sooo... I don't think peek here can be used for > 1 byte without this timer craziness... can it?
        let len = p.len();
        // wait up to 10 seconds until len bytes have been read
        use std::time::{Duration, Instant};
        use tokio::io::AsyncBufReadExt;
        let duration = Duration::from_secs(10);
        let now = Instant::now();
        loop {
            let buf = self.fill_buf().await?;
            if buf.len() >= len {
                p.copy_from_slice(&buf[0..len]);
                return Ok(p); // success
            }
            if buf.is_empty() {
                bail!("not enough bytes");
            }
            if Instant::now() - now > duration {
                bail!("less than {} bytes in 10 seconds, closed connection?", len);
            }
        }
    }
}

/// Caution: this will loop forever, call timeout variant `first_bytes_match_buf_timeout`
async fn first_bytes_match_buf(duration: Duration, stream: &mut (dyn AsyncBufRead + Send + Unpin), len: usize, matcher: fn(&[u8]) -> bool) -> Result<bool> {
    use tokio::io::AsyncBufReadExt;
    let start = std::time::Instant::now();
    loop {
        let buf = tokio::time::timeout(duration, stream.fill_buf()).await??;
        if buf.len() >= len {
            return Ok(matcher(&buf[0..len]));
        }
        let elapsed = start.elapsed();
        if elapsed >= duration {
            // should never happen since this is 2x as long as timeout wrapping it
            bail!("first_bytes_match_buf elapsed {:?} wtf????", elapsed);
        }
    }
}

pub async fn first_bytes_match_buf_timeout(stream: &mut (dyn AsyncBufRead + Send + Unpin), len: usize, matcher: fn(&[u8]) -> bool) -> Result<bool> {
    // wait up to 10 seconds until 3 bytes have been read
    tokio::time::timeout(Duration::from_secs(10), first_bytes_match_buf(Duration::from_secs(20), stream, len, matcher)).await?
}

pub async fn stream_preamble(in_rd: &mut StanzaRead, in_wr: &mut StanzaWrite, client_addr: &'_ str, in_filter: &mut StanzaFilter) -> Result<(Vec<u8>, bool)> {
    let mut stream_open = Vec::new();
    while let Ok(Some((buf, _))) = in_rd.next(in_filter, client_addr, in_wr).await {
        trace!("{} received pre-<stream:stream> stanza: '{}'", client_addr, to_str(buf));
        if buf.starts_with(b"<?xml ") {
            stream_open.extend_from_slice(buf);
        } else if buf.starts_with(b"<stream:stream ") {
            stream_open.extend_from_slice(buf);
            return Ok((stream_open, buf.contains_seq(br#" xmlns="jabber:client""#) || buf.contains_seq(br#" xmlns='jabber:client'"#)));
        } else {
            bail!("bad pre-<stream:stream> stanza: {}", to_str(buf));
        }
    }
    bail!("stream ended before open")
}

#[allow(clippy::too_many_arguments)]
pub async fn shuffle_rd_wr_filter_only(
    mut in_rd: StanzaRead,
    mut in_wr: StanzaWrite,
    mut out_rd: StanzaRead,
    mut out_wr: StanzaWrite,
    is_c2s: bool,
    max_stanza_size_bytes: usize,
    client_addr: &mut Context<'_>,
    mut in_filter: StanzaFilter,
) -> Result<()> {
    let mut out_filter = StanzaFilter::new(max_stanza_size_bytes);

    loop {
        tokio::select! {
            Ok(ret) = in_rd.next(&mut in_filter, client_addr.log_to(), &mut in_wr) => {
                match ret {
                    None => break,
                    Some((buf, eoft)) => {
                        trace!("{} '{}'", client_addr.log_from(), to_str(buf));
                        out_wr.write_all(is_c2s, buf, eoft, client_addr.log_from()).await?;
                        out_wr.flush().await?;
                    }
                }
            },
            Ok(ret) = out_rd.next(&mut out_filter, client_addr.log_from(), &mut out_wr) => {
                match ret {
                    None => break,
                    Some((buf, eoft)) => {
                        trace!("{} '{}'", client_addr.log_to(), to_str(buf));
                        in_wr.write_all(is_c2s, buf, eoft, client_addr.log_to()).await?;
                        in_wr.flush().await?;
                    }
                }
            },
            else => break,
        }
    }

    info!("{} disconnected", client_addr.log_from());
    Ok(())
}

#[cfg(feature = "rustls-pemfile")]
pub fn read_certified_key(tls_key: &str, tls_cert: &str) -> Result<rustls::sign::CertifiedKey> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    let key = rustls::crypto::CryptoProvider::get_default().expect("no crypto provider set").key_provider;

    let tls_key = PrivateKeyDer::pem_file_iter(tls_key)?
        .flat_map(|item| match item {
            Ok(pk) => key.load_private_key(pk).ok(),
            Err(_) => None,
        })
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;

    let mut tls_certs = Vec::with_capacity(2);
    for cert in CertificateDer::pem_file_iter(tls_cert)? {
        tls_certs.push(cert?);
    }

    Ok(rustls::sign::CertifiedKey::new(tls_certs, tls_key))
}
