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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[cfg(feature = "incoming")]
use tokio_rustls::{
    rustls::internal::pemfile::{certs, pkcs8_private_keys},
    rustls::{NoClientAuth, ServerConfig},
    TlsAcceptor,
};

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

const IN_BUFFER_SIZE: usize = 8192;
const OUT_BUFFER_SIZE: usize = 8192;

const ALPN_XMPP_CLIENT: &[&[u8]] = &[b"xmpp-client"];
const ALPN_XMPP_SERVER: &[&[u8]] = &[b"xmpp-server"];

#[derive(Deserialize)]
struct Config {
    tls_key: String,
    tls_cert: String,
    incoming_listen: Option<Vec<String>>,
    quic_listen: Option<Vec<String>>,
    outgoing_listen: Option<Vec<String>>,
    max_stanza_size_bytes: usize,
    s2s_target: String,
    c2s_target: String,
    proxy: bool,
    #[cfg(feature = "env_logger")]
    log_level: Option<String>,
    #[cfg(feature = "env_logger")]
    log_style: Option<String>,
}

#[derive(Clone)]
pub struct CloneableConfig {
    max_stanza_size_bytes: usize,
    s2s_target: String,
    c2s_target: String,
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
            s2s_target: self.s2s_target.clone(),
            c2s_target: self.c2s_target.clone(),
            proxy: self.proxy,
        }
    }

    #[cfg(feature = "incoming")]
    fn tls_acceptor(&self) -> Result<TlsAcceptor> {
        let mut tls_key = pkcs8_private_keys(&mut BufReader::new(File::open(&self.tls_key)?)).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;
        if tls_key.is_empty() {
            bail!("invalid key");
        }
        let tls_key = tls_key.remove(0);

        let tls_cert = certs(&mut BufReader::new(File::open(&self.tls_cert)?)).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;

        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_single_cert(tls_cert, tls_key)?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

async fn shuffle_rd_wr<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(in_rd: R, in_wr: W, config: CloneableConfig, local_addr: SocketAddr, client_addr: SocketAddr) -> Result<()> {
    let filter = StanzaFilter::new(config.max_stanza_size_bytes);
    shuffle_rd_wr_filter(in_rd, in_wr, config, local_addr, client_addr, filter).await
}

async fn shuffle_rd_wr_filter<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    in_rd: R,
    mut in_wr: W,
    config: CloneableConfig,
    local_addr: SocketAddr,
    client_addr: SocketAddr,
    in_filter: StanzaFilter,
) -> Result<()> {
    // we naively read 1 byte at a time, which buffering significantly speeds up
    let in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);

    // now read to figure out client vs server
    let (stream_open, is_c2s, mut in_rd, mut in_filter) = stream_preamble(StanzaReader(in_rd), client_addr, in_filter).await?;

    let target = if is_c2s { config.c2s_target } else { config.s2s_target };

    info!("{} is_c2s: {}, target: {}", client_addr, is_c2s, target);

    let out_stream = tokio::net::TcpStream::connect(target).await?;
    let (mut out_rd, mut out_wr) = tokio::io::split(out_stream);

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
            if client_addr.is_ipv4() { '4' } else { '6' },
            client_addr.ip(),
            local_addr.ip(),
            client_addr.port(),
            local_addr.port()
        )?;
        let end_idx = &(&in_filter.buf[0..]).first_index_of(b"\n")? + 1;
        trace!("< {} {} '{}'", client_addr, c2s(is_c2s), to_str(&in_filter.buf[0..end_idx]));
        out_wr.write_all(&in_filter.buf[0..end_idx]).await?;
    }
    trace!("< {} {} '{}'", client_addr, c2s(is_c2s), to_str(&stream_open));
    out_wr.write_all(&stream_open).await?;
    out_wr.flush().await?;
    drop(stream_open);

    let mut out_buf = [0u8; OUT_BUFFER_SIZE];

    loop {
        tokio::select! {
        Ok(buf) = in_rd.next(&mut in_filter) => {
            match buf {
                None => break,
                Some(buf) => {
                    trace!("< {} {} '{}'", client_addr, c2s(is_c2s), to_str(buf));
                    out_wr.write_all(buf).await?;
                    out_wr.flush().await?;
                }
            }
        },
        // we could filter outgoing from-server stanzas by size here too by doing same as above
        // but instead, we'll just send whatever the server sends as it sends it...
        Ok(n) = out_rd.read(&mut out_buf) => {
            if n == 0 {
                break;
            }
            trace!("> {} {} '{}'", client_addr, c2s(is_c2s), to_str(&out_buf[0..n]));
            in_wr.write_all(&out_buf[0..n]).await?;
            in_wr.flush().await?;
        },
        }
    }

    info!("{} disconnected", client_addr);
    Ok(())
}

async fn stream_preamble<R: AsyncRead + Unpin>(mut in_rd: StanzaReader<R>, client_addr: SocketAddr, mut in_filter: StanzaFilter) -> Result<(Vec<u8>, bool, StanzaReader<R>, StanzaFilter)> {
    let mut stream_open = Vec::new();
    while let Ok(Some(buf)) = in_rd.next(&mut in_filter).await {
        trace!("received pre-<stream:stream> stanza: {} '{}'", client_addr, to_str(&buf));
        if buf.starts_with(b"<?xml ") {
            stream_open.extend_from_slice(buf);
        } else if buf.starts_with(b"<stream:stream ") {
            stream_open.extend_from_slice(buf);
            return Ok((
                stream_open,
                buf.contains_seq(br#" xmlns="jabber:client""#) || buf.contains_seq(br#" xmlns='jabber:client'"#),
                in_rd,
                in_filter,
            ));
        } else {
            bail!("bad pre-<stream:stream> stanza: {}", to_str(&buf));
        }
    }
    bail!("stream ended before open");
}

#[tokio::main]
//#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let main_config = Config::parse(std::env::args_os().skip(1).next().unwrap_or(OsString::from("/etc/xmpp-proxy/xmpp-proxy.toml"))).die("invalid config file");

    #[cfg(feature = "env_logger")]
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
    #[cfg(feature = "quic")]
    if let Some(ref listeners) = main_config.quic_listen {
        let quic_config = main_config.quic_server_config().die("invalid cert/key ?");
        for listener in listeners {
            handles.push(spawn_quic_listener(listener.parse().die("invalid listener address"), config.clone(), quic_config.clone()));
        }
    }
    #[cfg(feature = "outgoing")]
    if let Some(ref listeners) = main_config.outgoing_listen {
        for listener in listeners {
            handles.push(spawn_outgoing_listener(listener.parse().die("invalid listener address"), config.max_stanza_size_bytes));
        }
    }
    futures::future::join_all(handles).await;
}
