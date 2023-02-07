use crate::{
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::StanzaFilter,
};
use anyhow::{bail, Result};
use log::{info, trace};
#[cfg(feature = "rustls")]
use rustls::{
    sign::{RsaSigningKey, SigningKey},
    Certificate, PrivateKey,
};
use std::{fs::File, io, io::BufReader, sync::Arc};

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

pub async fn first_bytes_match(stream: &tokio::net::TcpStream, p: &mut [u8], matcher: fn(&[u8]) -> bool) -> anyhow::Result<bool> {
    // sooo... I don't think peek here can be used for > 1 byte without this timer craziness... can it?
    let len = p.len();
    // wait up to 10 seconds until len bytes have been read
    use std::time::{Duration, Instant};
    let duration = Duration::from_secs(10);
    let now = Instant::now();
    loop {
        let n = stream.peek(p).await?;
        if n == len {
            break; // success
        }
        if n == 0 {
            bail!("not enough bytes");
        }
        if Instant::now() - now > duration {
            bail!("less than {} bytes in 10 seconds, closed connection?", len);
        }
    }

    Ok(matcher(p))
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

    let tls_key = read_all(&mut BufReader::new(File::open(tls_key)?))
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

    let tls_certs = certs(&mut BufReader::new(File::open(tls_cert)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())?;

    Ok(rustls::sign::CertifiedKey::new(tls_certs, tls_key))
}
