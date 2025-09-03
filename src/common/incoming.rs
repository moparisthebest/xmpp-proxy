use crate::{
    common::{c2s, certs_key::CertsKey, shuffle_rd_wr_filter_only, stream_preamble, to_str, SocketAddrPath, ALPN_XMPP_CLIENT, ALPN_XMPP_SERVER},
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::StanzaFilter,
};
use anyhow::{anyhow, bail, Result};
use log::trace;
use rustls::{ServerConfig, ServerConnection};

use rustls::pki_types::{CertificateDer, UnixTime};
use std::{io::Write, net::SocketAddr, sync::Arc};
use tokio::io::AsyncWriteExt;

pub struct IncomingConfig {
    pub max_stanza_size_bytes: usize,
    #[cfg(feature = "s2s-incoming")]
    pub s2s_target: Option<SocketAddrPath>,
    #[cfg(feature = "c2s-incoming")]
    pub c2s_target: Option<SocketAddrPath>,
    pub proxy: bool,
}

pub fn server_config(certs_key: Arc<CertsKey>) -> Result<ServerConfig> {
    if let Err(e) = &certs_key.inner {
        bail!("invalid cert/key: {}", e);
    }

    let config = ServerConfig::builder();
    #[cfg(feature = "s2s")]
    let config = config.with_client_cert_verifier(Arc::new(crate::verify::AllowAnonymousOrAnyCert));
    #[cfg(not(feature = "s2s"))]
    let config = config.with_no_client_auth();
    let mut config = config.with_cert_resolver(certs_key);
    // todo: will connecting without alpn work then?
    config.alpn_protocols.push(ALPN_XMPP_CLIENT.to_vec());
    config.alpn_protocols.push(ALPN_XMPP_SERVER.to_vec());

    Ok(config)
}

#[cfg(not(any(feature = "s2s-incoming", feature = "webtransport")))]
pub type ServerCerts = ();

#[cfg(any(feature = "s2s-incoming", feature = "webtransport"))]
#[derive(Clone)]
pub struct ServerCerts {
    inner: Arc<InnerServerCerts>,
    is_tls: bool,
}

#[cfg(any(feature = "s2s-incoming", feature = "webtransport"))]
struct InnerServerCerts {
    peer_certificates: Option<Vec<CertificateDer<'static>>>,
    sni: Option<String>,
    alpn: Option<Vec<u8>>,
}

#[cfg(any(feature = "s2s-incoming", feature = "webtransport"))]
impl From<&ServerConnection> for ServerCerts {
    fn from(conn: &ServerConnection) -> Self {
        let peer_certificates = conn.peer_certificates().map(|c| c.to_vec());
        let sni = conn.server_name().map(|s| s.to_string());
        let alpn = conn.alpn_protocol().map(|s| s.to_vec());
        Self {
            inner: InnerServerCerts { peer_certificates, sni, alpn }.into(),
            is_tls: true,
        }
    }
}

#[cfg(all(feature = "quic", any(feature = "s2s-incoming", feature = "webtransport")))]
impl From<&quinn::Connection> for ServerCerts {
    fn from(conn: &quinn::Connection) -> Self {
        let peer_certificates = conn.peer_identity().and_then(|v| v.downcast::<Vec<CertificateDer<'static>>>().ok()).map(|v| v.to_vec());
        let (sni, alpn) = conn
            .handshake_data()
            .and_then(|v| v.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .map(|h| (h.server_name, h.protocol))
            .unwrap_or_default();
        Self {
            inner: InnerServerCerts { peer_certificates, sni, alpn }.into(),
            is_tls: false,
        }
    }
}

#[cfg(any(feature = "s2s-incoming", feature = "webtransport"))]
impl ServerCerts {
    pub fn peer_certificates(&self) -> Option<&Vec<CertificateDer<'static>>> {
        self.inner.peer_certificates.as_ref()
    }

    pub fn sni(&self) -> Option<&str> {
        self.inner.sni.as_deref()
    }

    pub fn alpn(&self) -> Option<&Vec<u8>> {
        self.inner.alpn.as_ref()
    }

    pub fn is_tls(&self) -> bool {
        self.is_tls
    }
}

pub async fn shuffle_rd_wr(in_rd: StanzaRead, in_wr: StanzaWrite, config: Arc<IncomingConfig>, server_certs: ServerCerts, local_addr: SocketAddr, client_addr: &mut Context<'_>) -> Result<()> {
    let filter = StanzaFilter::new(config.max_stanza_size_bytes);
    shuffle_rd_wr_filter(in_rd, in_wr, config, server_certs, local_addr, client_addr, filter).await
}

pub async fn shuffle_rd_wr_filter(
    mut in_rd: StanzaRead,
    mut in_wr: StanzaWrite,
    config: Arc<IncomingConfig>,
    server_certs: ServerCerts,
    local_addr: SocketAddr,
    client_addr: &mut Context<'_>,
    mut in_filter: StanzaFilter,
) -> Result<()> {
    // now read to figure out client vs server
    let (stream_open, is_c2s) = stream_preamble(&mut in_rd, &mut in_wr, client_addr.log_from(), &mut in_filter).await?;
    client_addr.set_c2s_stream_open(is_c2s, &stream_open);

    #[cfg(feature = "s2s-incoming")]
    {
        trace!(
            "{} connected: sni: {:?}, alpn: {:?}, tls-not-quic: {}",
            client_addr.log_from(),
            server_certs.sni(),
            server_certs.alpn().map(|a| String::from_utf8_lossy(a).to_string()),
            server_certs.is_tls(),
        );

        if !is_c2s {
            // for s2s we need this
            let domain = stream_open
                .extract_between(b" from='", b"'")
                .or_else(|_| stream_open.extract_between(b" from=\"", b"\""))
                .and_then(|b| Ok(std::str::from_utf8(b)?))?;
            let (_, cert_verifier) = crate::srv::get_xmpp_connections(domain, is_c2s).await?;
            let certs = server_certs.peer_certificates().ok_or_else(|| anyhow!("no client cert auth for s2s incoming from {}", domain))?;
            // todo: send stream error saying cert is invalid
            cert_verifier.verify_cert(&certs[0], &certs[1..], UnixTime::now())?;
        }
        drop(server_certs);
    }

    let (out_rd, out_wr) = open_incoming(&config, local_addr, client_addr, &stream_open, is_c2s, &mut in_filter).await?;
    drop(stream_open);

    shuffle_rd_wr_filter_only(in_rd, in_wr, out_rd, out_wr, is_c2s, config.max_stanza_size_bytes, client_addr, in_filter).await
}

async fn open_incoming(
    config: &IncomingConfig,
    local_addr: SocketAddr,
    client_addr: &mut Context<'_>,
    stream_open: &[u8],
    is_c2s: bool,
    in_filter: &mut StanzaFilter,
) -> Result<(StanzaRead, StanzaWrite)> {
    let target: &Option<SocketAddrPath> = if is_c2s {
        #[cfg(not(feature = "c2s-incoming"))]
        bail!("incoming c2s connection but lacking compile-time support");
        #[cfg(feature = "c2s-incoming")]
        &config.c2s_target
    } else {
        #[cfg(not(feature = "s2s-incoming"))]
        bail!("incoming s2s connection but lacking compile-time support");
        #[cfg(feature = "s2s-incoming")]
        &config.s2s_target
    };
    let target = target.as_ref().ok_or_else(|| anyhow!("incoming connection but `{}_target` not defined", c2s(is_c2s)))?;
    client_addr.set_to_addr(target.to_string());

    let (out_rd, mut out_wr) = target.connect().await?;
    let out_rd = StanzaRead::new(out_rd);

    if config.proxy {
        /*
        https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
        PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n
        PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n
        PROXY TCP6 SOURCE_IP DEST_IP SOURCE_PORT DEST_PORT\r\n
         */
        // tokio AsyncWrite doesn't have write_fmt so have to go through this buffer for some crazy reason
        //write!(out_wr, "PROXY TCP{} {} {} {} {}\r\n", if client_addr.is_ipv4() { '4' } else {'6' }, client_addr.ip(), local_addr.ip(), client_addr.port(), local_addr.port())?;
        write!(
            &mut in_filter.buf[0..],
            "PROXY TCP{} {} {} {} {}\r\n",
            if client_addr.client_addr().is_ipv4() { '4' } else { '6' },
            client_addr.client_addr().ip(),
            local_addr.ip(),
            client_addr.client_addr().port(),
            local_addr.port()
        )?;
        let end_idx = &(&in_filter.buf[0..]).first_index_of(b"\n")? + 1;
        trace!("{} '{}'", client_addr.log_from(), to_str(&in_filter.buf[0..end_idx]));
        out_wr.write_all(&in_filter.buf[0..end_idx]).await?;
    }
    trace!("{} '{}'", client_addr.log_from(), to_str(stream_open));
    out_wr.write_all(stream_open).await?;
    out_wr.flush().await?;
    Ok((out_rd, StanzaWrite::AsyncWrite(out_wr)))
}
