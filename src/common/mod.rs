use crate::{
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::StanzaFilter,
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use log::{info, trace};
#[cfg(feature = "rustls")]
use rustls::{
    sign::{RsaSigningKey, SigningKey},
    Certificate, PrivateKey,
};
use std::{fs::File, io, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, BufStream},
    net::TcpStream,
};

#[cfg(feature = "incoming")]
pub mod incoming;

#[cfg(feature = "outgoing")]
pub mod outgoing;

#[cfg(any(feature = "rustls-native-certs", feature = "webpki-roots"))]
pub mod ca_roots;

#[cfg(feature = "rustls")]
pub mod certs_key;

pub const IN_BUFFER_SIZE: usize = 8192;
pub const ALPN_XMPP_CLIENT: &[u8] = b"xmpp-client";
pub const ALPN_XMPP_SERVER: &[u8] = b"xmpp-server";

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

pub trait Split: Sized {
    type ReadHalf: AsyncRead + Unpin;
    type WriteHalf: AsyncWrite + Unpin;

    fn combine(read_half: Self::ReadHalf, write_half: Self::WriteHalf) -> Result<Self>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf);
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
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Split for BufStream<T> {
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
}

#[async_trait]
pub trait Peek {
    async fn peek_bytes<'a>(&mut self, p: &'a mut [u8]) -> anyhow::Result<&'a [u8]>;

    async fn first_bytes_match<'a>(&mut self, p: &'a mut [u8], matcher: fn(&'a [u8]) -> bool) -> anyhow::Result<bool> {
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
        }
    }

    info!("{} disconnected", client_addr.log_from());
    Ok(())
}

#[cfg(feature = "rustls-pemfile")]
pub fn read_certified_key(tls_key: &str, tls_cert: &str) -> Result<rustls::sign::CertifiedKey> {
    use rustls_pemfile::{certs, read_all, Item};

    let tls_key = read_all(&mut io::BufReader::new(File::open(tls_key)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?
        .into_iter()
        .flat_map(|item| match item {
            Item::RSAKey(der) => RsaSigningKey::new(&PrivateKey(der)).ok().map(Arc::new).map(|r| r as Arc<dyn SigningKey>),
            Item::PKCS8Key(der) => rustls::sign::any_supported_type(&PrivateKey(der)).ok(),
            Item::ECKey(der) => rustls::sign::any_supported_type(&PrivateKey(der)).ok(),
            _ => None,
        })
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;

    let tls_certs = certs(&mut io::BufReader::new(File::open(tls_cert)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())?;

    Ok(rustls::sign::CertifiedKey::new(tls_certs, tls_key))
}
