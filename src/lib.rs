mod stanzafilter;
pub use stanzafilter::*;

mod slicesubsequence;
use slicesubsequence::*;

use anyhow::bail;
use std::net::SocketAddr;

pub use log::{debug, error, info, log_enabled, trace};

#[cfg(feature = "s2s-incoming")]
use rustls::{Certificate, ServerConnection};

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

#[derive(Clone)]
pub struct Context<'a> {
    conn_id: String,
    log_from: String,
    log_to: String,
    proto: &'a str,
    is_c2s: Option<bool>,
    to: Option<String>,
    to_addr: Option<SocketAddr>,
    from: Option<String>,
    client_addr: SocketAddr,
}

impl<'a> Context<'a> {
    pub fn new(proto: &'static str, client_addr: SocketAddr) -> Context {
        let (log_to, log_from, conn_id) = if log_enabled!(log::Level::Info) {
            #[cfg(feature = "logging")]
            let conn_id = {
                use rand::distributions::Alphanumeric;
                use rand::{thread_rng, Rng};
                thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect()
            };
            #[cfg(not(feature = "logging"))]
            let conn_id = "".to_string();
            (
                format!("{}: ({} <- ({}-unk)):", conn_id, client_addr, proto),
                format!("{}: ({} -> ({}-unk)):", conn_id, client_addr, proto),
                conn_id,
            )
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        };

        Context {
            conn_id,
            log_from,
            log_to,
            proto,
            client_addr,
            is_c2s: None,
            to: None,
            to_addr: None,
            from: None,
        }
    }

    fn re_calc(&mut self) {
        // todo: make this good
        self.log_from = format!(
            "{}: ({} ({}) -> ({}-{}) -> {} ({})):",
            self.conn_id,
            self.client_addr,
            if self.from.is_some() { self.from.as_ref().unwrap() } else { "unk" },
            self.proto,
            if self.is_c2s.is_some() { c2s(self.is_c2s.unwrap()) } else { "unk" },
            if self.to_addr.is_some() { self.to_addr.as_ref().unwrap().to_string() } else { "unk".to_string() },
            if self.to.is_some() { self.to.as_ref().unwrap() } else { "unk" },
        );
        self.log_to = self.log_from.replace(" -> ", " <- ");
    }

    pub fn log_from(&self) -> &str {
        &self.log_from
    }

    pub fn log_to(&self) -> &str {
        &self.log_to
    }

    pub fn client_addr(&self) -> &SocketAddr {
        &self.client_addr
    }

    pub fn set_proto(&mut self, proto: &'static str) {
        if log_enabled!(log::Level::Info) {
            self.proto = proto;
            self.to_addr = None;
            self.re_calc();
        }
    }

    pub fn set_c2s_stream_open(&mut self, is_c2s: bool, stream_open: &[u8]) {
        if log_enabled!(log::Level::Info) {
            self.is_c2s = Some(is_c2s);
            self.from = stream_open
                .extract_between(b" from='", b"'")
                .or_else(|_| stream_open.extract_between(b" from=\"", b"\""))
                .map(|b| to_str(b).to_string())
                .ok();
            self.to = stream_open
                .extract_between(b" to='", b"'")
                .or_else(|_| stream_open.extract_between(b" to=\"", b"\""))
                .map(|b| to_str(b).to_string())
                .ok();
            self.re_calc();
            info!("{} stream data set", &self.log_from());
        }
    }

    pub fn set_to_addr(&mut self, to_addr: SocketAddr) {
        if log_enabled!(log::Level::Info) {
            self.to_addr = Some(to_addr);
            self.re_calc();
        }
    }
}

#[cfg(not(feature = "s2s-incoming"))]
pub type ServerCerts = ();

#[cfg(feature = "s2s-incoming")]
#[derive(Clone)]
pub enum ServerCerts {
    Tls(&'static ServerConnection),
    #[cfg(feature = "quic")]
    Quic(quinn::Connection),
}

#[cfg(feature = "s2s-incoming")]
impl ServerCerts {
    pub fn peer_certificates(&self) -> Option<Vec<Certificate>> {
        match self {
            ServerCerts::Tls(c) => c.peer_certificates().map(|c| c.to_vec()),
            #[cfg(feature = "quic")]
            ServerCerts::Quic(c) => c.peer_identity().and_then(|v| v.downcast::<Vec<Certificate>>().ok()).map(|v| v.to_vec()),
        }
    }

    pub fn sni(&self) -> Option<String> {
        match self {
            ServerCerts::Tls(c) => c.sni_hostname().map(|s| s.to_string()),
            #[cfg(feature = "quic")]
            ServerCerts::Quic(c) => c.handshake_data().and_then(|v| v.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|h| h.server_name),
        }
    }

    pub fn alpn(&self) -> Option<Vec<u8>> {
        match self {
            ServerCerts::Tls(c) => c.alpn_protocol().map(|s| s.to_vec()),
            #[cfg(feature = "quic")]
            ServerCerts::Quic(c) => c.handshake_data().and_then(|v| v.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|h| h.protocol),
        }
    }

    pub fn is_tls(&self) -> bool {
        match self {
            ServerCerts::Tls(_) => true,
            #[cfg(feature = "quic")]
            ServerCerts::Quic(_) => false,
        }
    }
}
