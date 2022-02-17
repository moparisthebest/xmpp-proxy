#![deny(clippy::all)]

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read, Write};
use std::iter::Iterator;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use die::Die;

use serde_derive::Deserialize;

use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[cfg(feature = "rustls")]
use rustls::{Certificate, ClientConfig, PrivateKey, ServerConfig};
#[cfg(feature = "rustls-pemfile")]
use rustls_pemfile::{certs, pkcs8_private_keys};
#[cfg(feature = "tokio-rustls")]
use tokio_rustls::{TlsAcceptor, TlsConnector};

use anyhow::{bail, Result};

mod slicesubsequence;
use slicesubsequence::*;

pub use xmpp_proxy::*;

#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
use crate::quic::*;

mod tls;
use crate::tls::*;

#[cfg(feature = "outgoing")]
mod outgoing;
#[cfg(feature = "outgoing")]
use crate::outgoing::*;

#[cfg(feature = "outgoing")]
mod srv;
#[cfg(feature = "outgoing")]
use crate::srv::*;

#[cfg(feature = "websocket")]
mod websocket;
#[cfg(feature = "websocket")]
use crate::websocket::*;

mod in_out;
pub use crate::in_out::*;

const IN_BUFFER_SIZE: usize = 8192;

// todo: split these out to outgoing module

const ALPN_XMPP_CLIENT: &[u8] = b"xmpp-client";
const ALPN_XMPP_SERVER: &[u8] = b"xmpp-server";

#[cfg(all(feature = "webpki-roots", not(feature = "rustls-native-certs")))]
pub fn root_cert_store() -> rustls::RootCertStore {
    use rustls::{OwnedTrustAnchor, RootCertStore};
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)),
    );
    root_cert_store
}

#[cfg(all(feature = "rustls-native-certs", not(feature = "webpki-roots")))]
pub fn root_cert_store() -> rustls::RootCertStore {
    use rustls::RootCertStore;
    let mut root_cert_store = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
        root_cert_store.add(&rustls::Certificate(cert.0)).unwrap();
    }
    root_cert_store
}

#[derive(Deserialize)]
struct Config {
    tls_key: String,
    tls_cert: String,
    incoming_listen: Option<Vec<String>>,
    quic_listen: Option<Vec<String>>,
    outgoing_listen: Option<Vec<String>>,
    max_stanza_size_bytes: usize,
    s2s_target: SocketAddr,
    c2s_target: SocketAddr,
    proxy: bool,
    #[cfg(feature = "logging")]
    log_level: Option<String>,
    #[cfg(feature = "logging")]
    log_style: Option<String>,
}

#[derive(Clone)]
pub struct CloneableConfig {
    max_stanza_size_bytes: usize,
    s2s_target: SocketAddr,
    c2s_target: SocketAddr,
    proxy: bool,
}

impl Config {
    fn parse<P: AsRef<Path>>(path: P) -> Result<Config> {
        let mut f = File::open(path)?;
        let mut input = String::new();
        f.read_to_string(&mut input)?;
        Ok(toml::from_str(&input)?)
    }

    fn get_cloneable_cfg(&self) -> CloneableConfig {
        CloneableConfig {
            max_stanza_size_bytes: self.max_stanza_size_bytes,
            s2s_target: self.s2s_target,
            c2s_target: self.c2s_target,
            proxy: self.proxy,
        }
    }

    #[cfg(feature = "outgoing")]
    fn get_outgoing_cfg(&self) -> OutgoingConfig {
        let c2s_config = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_cert_store()).with_no_client_auth();
        let s2s_config = match self.certs_key().and_then(|(tls_certs, tls_key)| {
            Ok(ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_cert_store())
                .with_single_cert(tls_certs, tls_key)?)
        }) {
            Ok(s) => s,
            Err(e) => {
                debug!("invalid key/cert for s2s client auth: {}", e);
                c2s_config.clone()
            }
        };
        // uncomment to disable cert auth/sasl external
        //let s2s_config = c2s_config.clone();

        let mut c2s_config_alpn = c2s_config.clone();
        let mut s2s_config_alpn = s2s_config.clone();
        c2s_config_alpn.alpn_protocols.push(ALPN_XMPP_CLIENT.to_vec());
        s2s_config_alpn.alpn_protocols.push(ALPN_XMPP_SERVER.to_vec());

        let c2s_config_alpn = Arc::new(c2s_config_alpn);
        let s2s_config_alpn = Arc::new(s2s_config_alpn);

        let c2s_connector_alpn: TlsConnector = c2s_config_alpn.clone().into();
        let s2s_connector_alpn: TlsConnector = s2s_config_alpn.clone().into();

        let c2s_connector: TlsConnector = Arc::new(c2s_config).into();
        let s2s_connector: TlsConnector = Arc::new(s2s_config).into();

        OutgoingConfig {
            max_stanza_size_bytes: self.max_stanza_size_bytes,
            c2s_config_alpn,
            s2s_config_alpn,
            c2s_connector_alpn,
            s2s_connector_alpn,
            c2s_connector,
            s2s_connector,
        }
    }

    #[cfg(any(feature = "outgoing", feature = "incoming"))]
    fn certs_key(&self) -> Result<(Vec<Certificate>, PrivateKey)> {
        let mut tls_key: Vec<PrivateKey> = pkcs8_private_keys(&mut BufReader::new(File::open(&self.tls_key)?))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect())?;
        if tls_key.is_empty() {
            bail!("invalid key");
        }
        let tls_key = tls_key.remove(0);

        let tls_certs = certs(&mut BufReader::new(File::open(&self.tls_cert)?))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
            .map(|mut certs| certs.drain(..).map(Certificate).collect())?;

        Ok((tls_certs, tls_key))
    }

    #[cfg(feature = "incoming")]
    fn server_config(&self) -> Result<ServerConfig> {
        let (tls_certs, tls_key) = self.certs_key()?;

        // todo: request client auth here
        let mut config = ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(tls_certs, tls_key)?;
        config.alpn_protocols.push(ALPN_XMPP_CLIENT.to_vec());
        config.alpn_protocols.push(ALPN_XMPP_SERVER.to_vec());

        Ok(config)
    }

    #[cfg(feature = "incoming")]
    fn tls_acceptor(&self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(Arc::new(self.server_config()?)))
    }
}

#[derive(Clone)]
#[cfg(feature = "outgoing")]
pub struct OutgoingConfig {
    max_stanza_size_bytes: usize,

    c2s_config_alpn: Arc<ClientConfig>,
    s2s_config_alpn: Arc<ClientConfig>,
    c2s_connector_alpn: TlsConnector,
    s2s_connector_alpn: TlsConnector,

    c2s_connector: TlsConnector,
    s2s_connector: TlsConnector,
}

#[cfg(feature = "outgoing")]
impl OutgoingConfig {
    pub fn client_cfg_alpn(&self, is_c2s: bool) -> Arc<ClientConfig> {
        if is_c2s {
            self.c2s_config_alpn.clone()
        } else {
            self.s2s_config_alpn.clone()
        }
    }

    pub fn connector_alpn(&self, is_c2s: bool) -> TlsConnector {
        if is_c2s {
            self.c2s_connector_alpn.clone()
        } else {
            self.s2s_connector_alpn.clone()
        }
    }

    pub fn connector(&self, is_c2s: bool) -> TlsConnector {
        if is_c2s {
            self.c2s_connector.clone()
        } else {
            self.s2s_connector.clone()
        }
    }
}

async fn shuffle_rd_wr(in_rd: StanzaRead, in_wr: StanzaWrite, config: CloneableConfig, local_addr: SocketAddr, client_addr: &mut Context<'_>) -> Result<()> {
    let filter = StanzaFilter::new(config.max_stanza_size_bytes);
    shuffle_rd_wr_filter(in_rd, in_wr, config, local_addr, client_addr, filter).await
}

async fn shuffle_rd_wr_filter(
    mut in_rd: StanzaRead,
    mut in_wr: StanzaWrite,
    config: CloneableConfig,
    local_addr: SocketAddr,
    client_addr: &mut Context<'_>,
    mut in_filter: StanzaFilter,
) -> Result<()> {
    // now read to figure out client vs server
    let (stream_open, is_c2s) = stream_preamble(&mut in_rd, &mut in_wr, client_addr.log_from(), &mut in_filter).await?;

    let (out_rd, out_wr) = open_incoming(&config, local_addr, client_addr, &stream_open, is_c2s, &mut in_filter).await?;
    drop(stream_open);

    shuffle_rd_wr_filter_only(
        in_rd,
        in_wr,
        StanzaRead::new(out_rd),
        StanzaWrite::new(out_wr),
        is_c2s,
        config.max_stanza_size_bytes,
        client_addr,
        in_filter,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn shuffle_rd_wr_filter_only(
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

async fn open_incoming(
    config: &CloneableConfig,
    local_addr: SocketAddr,
    client_addr: &mut Context<'_>,
    stream_open: &[u8],
    is_c2s: bool,
    in_filter: &mut StanzaFilter,
) -> Result<(ReadHalf<tokio::net::TcpStream>, WriteHalf<tokio::net::TcpStream>)> {
    let target = if is_c2s { config.c2s_target } else { config.s2s_target };
    client_addr.set_to_addr(target);
    client_addr.set_c2s_stream_open(is_c2s, stream_open);

    let out_stream = tokio::net::TcpStream::connect(target).await?;
    let (out_rd, mut out_wr) = tokio::io::split(out_stream);

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
    Ok((out_rd, out_wr))
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

#[tokio::main]
//#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let main_config = Config::parse(std::env::args_os().nth(1).unwrap_or_else(|| OsString::from("/etc/xmpp-proxy/xmpp-proxy.toml"))).die("invalid config file");

    #[cfg(feature = "logging")]
    {
        use env_logger::{Builder, Env, Target};
        let env = Env::default().filter_or("XMPP_PROXY_LOG_LEVEL", "info").write_style_or("XMPP_PROXY_LOG_STYLE", "never");
        let mut builder = Builder::from_env(env);
        builder.target(Target::Stdout);
        if let Some(ref log_level) = main_config.log_level {
            builder.parse_filters(log_level);
        }
        if let Some(ref log_style) = main_config.log_style {
            builder.parse_write_style(log_style);
        }
        // todo: config for this: builder.format_timestamp(None);
        builder.init();
    }

    let config = main_config.get_cloneable_cfg();

    let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();
    #[cfg(feature = "incoming")]
    if let Some(ref listeners) = main_config.incoming_listen {
        let acceptor = main_config.tls_acceptor().die("invalid cert/key ?");
        for listener in listeners {
            handles.push(spawn_tls_listener(listener.parse().die("invalid listener address"), config.clone(), acceptor.clone()));
        }
    }
    #[cfg(all(feature = "quic", feature = "incoming"))]
    if let Some(ref listeners) = main_config.quic_listen {
        let quic_config = main_config.quic_server_config().die("invalid cert/key ?");
        for listener in listeners {
            handles.push(spawn_quic_listener(listener.parse().die("invalid listener address"), config.clone(), quic_config.clone()));
        }
    }
    #[cfg(feature = "outgoing")]
    if let Some(ref listeners) = main_config.outgoing_listen {
        let outgoing_cfg = main_config.get_outgoing_cfg();
        for listener in listeners {
            handles.push(spawn_outgoing_listener(listener.parse().die("invalid listener address"), outgoing_cfg.clone()));
        }
    }
    info!("xmpp-proxy started");
    futures::future::join_all(handles).await;
    info!("xmpp-proxy terminated");
}
