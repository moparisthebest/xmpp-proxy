use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::{BufReader, Read};
use std::iter::Iterator;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use die::Die;

use serde_derive::Deserialize;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::rustls::{NoClientAuth, ServerConfig};
use tokio_rustls::TlsAcceptor;

use anyhow::{bail, Result};

mod slicesubsequence;
use slicesubsequence::*;

const IN_BUFFER_SIZE: usize = 8192;
const OUT_BUFFER_SIZE: usize = 8192;

const WHITESPACE: &[u8] = b" \t\n\r";

#[cfg(debug_assertions)]
fn c2s(is_c2s: bool) -> &'static str {
    if is_c2s {
        "c2s"
    } else {
        "s2s"
    }
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! debug {
    ($($y:expr),+) => (println!($($y),+));
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! debug {
    ($($y:expr),+) => {};
}

#[derive(Deserialize)]
struct Config {
    tls_key: String,
    tls_cert: String,
    listen: Vec<String>,
    max_stanza_size_bytes: usize,
    s2s_target: String,
    c2s_target: String,
    proxy: bool,
}

#[derive(Clone)]
struct CloneableConfig {
    max_stanza_size_bytes: usize,
    s2s_target: String,
    c2s_target: String,
    proxy: bool,
    acceptor: TlsAcceptor,
}

impl Config {
    fn parse<P: AsRef<Path>>(path: P) -> Result<Config> {
        let mut f = File::open(path)?;
        let mut input = String::new();
        f.read_to_string(&mut input)?;
        Ok(toml::from_str(&input)?)
    }

    fn get_cloneable_cfg(&self) -> Result<CloneableConfig> {
        Ok(CloneableConfig {
            max_stanza_size_bytes: self.max_stanza_size_bytes,
            s2s_target: self.s2s_target.clone(),
            c2s_target: self.c2s_target.clone(),
            proxy: self.proxy,
            acceptor: self.tls_acceptor()?,
        })
    }

    fn tls_acceptor(&self) -> Result<TlsAcceptor> {
        let mut tls_key = pkcs8_private_keys(&mut BufReader::new(File::open(&self.tls_key)?)).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?;
        if tls_key.is_empty() {
            bail!("invalid key");
        }
        let tls_key = tls_key.remove(0);

        let tls_cert = certs(&mut BufReader::new(File::open(&self.tls_cert)?)).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;

        let mut config = ServerConfig::new(NoClientAuth::new());
        config.set_single_cert(tls_cert, tls_key).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

fn to_str(buf: &[u8]) -> std::borrow::Cow<'_, str> {
    //&str {
    //std::str::from_utf8(buf).unwrap_or("[invalid utf-8]")
    String::from_utf8_lossy(buf)
}

async fn handle_connection(mut stream: tokio::net::TcpStream, client_addr: SocketAddr, local_addr: SocketAddr, config: CloneableConfig) -> Result<()> {
    println!("INFO: {} connected", client_addr);

    let mut in_filter = StanzaFilter::new(config.max_stanza_size_bytes);

    let direct_tls = {
        // sooo... I don't think peek here can be used for > 1 byte without this timer
        // craziness... can it? this could be switched to only peek 1 byte and assume
        // a leading 0x16 is TLS, it would *probably* be ok ?
        //let mut p = [0u8; 3];
        let mut p = &mut in_filter.buf[0..3];
        // wait up to 10 seconds until 3 bytes have been read
        use std::time::{Duration, Instant};
        let duration = Duration::from_secs(10);
        let now = Instant::now();
        loop {
            let n = stream.peek(&mut p).await?;
            if n == 3 {
                break; // success
            }
            if n == 0 {
                bail!("not enough bytes");
            }
            if Instant::now() - now > duration {
                bail!("less than 3 bytes in 10 seconds, closed connection?");
            }
        }

        /* TLS packet starts with a record "Hello" (0x16), followed by version
         * (0x03 0x00-0x03) (RFC6101 A.1)
         * This means we reject SSLv2 and lower, which is actually a good thing (RFC6176)
         */
        p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x03
    };

    println!("INFO: {} direct_tls: {}", client_addr, direct_tls);

    // starttls
    if !direct_tls {
        let mut stream_open = Vec::new();

        let (in_rd, mut in_wr) = stream.split();
        // we naively read 1 byte at a time, which buffering significantly speeds up
        let mut in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);

        while let Ok(n) = in_rd.read(in_filter.current_buf()).await {
            if n == 0 {
                bail!("stream ended before open");
            }
            if let Some(buf) = in_filter.process_next_byte()? {
                debug!("received pre-tls stanza: {} '{}'", client_addr, to_str(&buf));
                let buf = buf.trim_start(WHITESPACE);
                if buf.starts_with(b"<?xml ") {
                    stream_open.extend_from_slice(buf);
                    continue;
                } else if buf.starts_with(b"<stream:stream ") {
                    debug!("> {} '{}'", client_addr, to_str(&stream_open));
                    in_wr.write_all(&stream_open).await?;
                    stream_open.clear();

                    // gajim seems to REQUIRE an id here...
                    let buf = if buf.contains_seq(b"id=") {
                        buf.replace_first(b" id='", b" id='xmpp-proxy")
                            .replace_first(br#" id=""#, br#" id="xmpp-proxy"#)
                            .replace_first(b" to=", br#" bla toblala="#)
                            .replace_first(b" from=", b" to=")
                            .replace_first(br#" bla toblala="#, br#" from="#)
                    } else {
                        buf.replace_first(b" to=", br#" bla toblala="#)
                            .replace_first(b" from=", b" to=")
                            .replace_first(br#" bla toblala="#, br#" id='xmpp-proxy' from="#)
                    };

                    debug!("> {} '{}'", client_addr, to_str(&buf));
                    in_wr.write_all(&buf).await?;

                    // ejabberd never sends <starttls/> with the first, only the second?
                    //let buf = br###"<features xmlns="http://etherx.jabber.org/streams"><starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"><required/></starttls></features>"###;
                    let buf = br###"<stream:features><starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"><required/></starttls></stream:features>"###;
                    debug!("> {} '{}'", client_addr, to_str(buf));
                    in_wr.write_all(buf).await?;
                    in_wr.flush().await?;
                } else if buf.starts_with(b"<starttls ") {
                    let buf = br###"<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls" />"###;
                    debug!("> {} '{}'", client_addr, to_str(buf));
                    in_wr.write_all(buf).await?;
                    in_wr.flush().await?;
                    break;
                } else {
                    bail!("bad pre-tls stanza: {}", to_str(&buf));
                }
            }
        }
    }

    let stream = config.acceptor.accept(stream).await?;

    let (in_rd, mut in_wr) = tokio::io::split(stream);
    // we naively read 1 byte at a time, which buffering significantly speeds up
    let mut in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);

    // now read to figure out client vs server
    let (stream_open, is_c2s) = {
        let mut stream_open = Vec::new();
        let mut ret = None;

        while let Ok(n) = in_rd.read(in_filter.current_buf()).await {
            if n == 0 {
                bail!("stream ended before open");
            }
            if let Some(buf) = in_filter.process_next_byte()? {
                debug!("received pre-<stream:stream> stanza: {} '{}'", client_addr, to_str(&buf));
                let buf = buf.trim_start(WHITESPACE);
                if buf.starts_with(b"<?xml ") {
                    stream_open.extend_from_slice(buf);
                    continue;
                } else if buf.starts_with(b"<stream:stream ") {
                    stream_open.extend_from_slice(buf);
                    //return (stream_open, stanza.contains(r#" xmlns="jabber:client""#) || stanza.contains(r#" xmlns='jabber:client'"#));
                    ret = Some((stream_open, buf.contains_seq(br#" xmlns="jabber:client""#) || buf.contains_seq(br#" xmlns='jabber:client'"#)));
                    break;
                } else {
                    bail!("bad pre-<stream:stream> stanza: {}", to_str(&buf));
                }
            }
        }
        if ret.is_some() {
            ret.unwrap()
        } else {
            bail!("stream ended before open");
        }
    };

    let target = if is_c2s { config.c2s_target } else { config.s2s_target };

    println!("INFO: {} is_c2s: {}, target: {}", client_addr, is_c2s, target);

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
        use std::io::Write;
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
        debug!("< {} {} '{}'", client_addr, c2s(is_c2s), to_str(&in_filter.buf[0..end_idx]));
        out_wr.write_all(&in_filter.buf[0..end_idx]).await?;
    }
    debug!("< {} {} '{}'", client_addr, c2s(is_c2s), to_str(&stream_open));
    out_wr.write_all(&stream_open).await?;
    out_wr.flush().await?;
    drop(stream_open);

    let mut out_buf = [0u8; OUT_BUFFER_SIZE];

    loop {
        tokio::select! {
        Ok(n) = in_rd.read(in_filter.current_buf()) => {
            if n == 0 {
                break;
            }
            if let Some(buf) = in_filter.process_next_byte()? {
                debug!("< {} {} '{}'", client_addr, c2s(is_c2s), to_str(buf));
                out_wr.write_all(buf).await?;
                out_wr.flush().await?;
            }
        },
        // we could filter outgoing from-server stanzas by size here too by doing same as above
        // but instead, we'll just send whatever the server sends as it sends it...
        Ok(n) = out_rd.read(&mut out_buf) => {
            if n == 0 {
                break;
            }
            debug!("> {} {} '{}'", client_addr, c2s(is_c2s), to_str(&out_buf[0..n]));
            in_wr.write_all(&out_buf[0..n]).await?;
            in_wr.flush().await?;
        },
        }
    }

    println!("INFO: {} disconnected", client_addr);
    Ok(())
}

fn spawn_listener(listener: TcpListener, config: CloneableConfig) -> JoinHandle<Result<()>> {
    let local_addr = listener.local_addr().die("could not get local_addr?");
    tokio::spawn(async move {
        loop {
            let (stream, client_addr) = listener.accept().await?;
            let config = config.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, client_addr, local_addr, config).await {
                    eprintln!("ERROR: {} {}", client_addr, e);
                }
            });
        }
        #[allow(unreachable_code)]
        Ok(())
    })
}

#[tokio::main]
//#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let main_config = Config::parse(std::env::args_os().skip(1).next().unwrap_or(OsString::from("/etc/xmpp-proxy/xmpp-proxy.toml"))).die("invalid config file");

    let config = main_config.get_cloneable_cfg().die("invalid cert/key ?");

    let mut handles = Vec::with_capacity(main_config.listen.len());
    for listener in main_config.listen {
        let listener = TcpListener::bind(&listener).await.die("cannot listen on port/interface");
        handles.push(spawn_listener(listener, config.clone()));
    }
    futures::future::join_all(handles).await;
}

struct StanzaFilter {
    buf_size: usize,
    buf: Vec<u8>,
    cnt: usize,
    tag_cnt: usize,
    last_char_was_lt: bool,
    last_char_was_backslash: bool,
}

impl StanzaFilter {
    pub fn new(buf_size: usize) -> StanzaFilter {
        StanzaFilter {
            buf_size,
            buf: vec![0u8; buf_size],
            cnt: 0,
            tag_cnt: 0,
            last_char_was_lt: false,
            last_char_was_backslash: false,
        }
    }

    #[inline(always)]
    pub fn current_buf(&mut self) -> &mut [u8] {
        &mut self.buf[self.cnt..(self.cnt + 1)]
    }

    pub fn process_next_byte(&mut self) -> Result<Option<&[u8]>> {
        //println!("n: {}", n);
        let b = self.buf[self.cnt];
        if b == b'<' {
            self.tag_cnt += 1;
            self.last_char_was_lt = true;
        } else {
            if b == b'/' {
                // if last_char_was_lt but tag_cnt < 2, should only be </stream:stream>
                if self.last_char_was_lt && self.tag_cnt >= 2 {
                    // non-self-closing tag
                    self.tag_cnt -= 2;
                }
                self.last_char_was_backslash = true;
            } else {
                if b == b'>' {
                    if self.last_char_was_backslash {
                        // self-closing tag
                        self.tag_cnt -= 1;
                    }
                    // now special case some tags we want to send stand-alone:
                    if self.tag_cnt == 1 && self.cnt >= 15 && (b"<?xml" == &self.buf[0..5] || b"<stream:stream" == &self.buf[0..14] || b"</stream:stream" == &self.buf[0..15]) {
                        self.tag_cnt = 0; // to fall through to next logic
                    }
                    if self.tag_cnt == 0 {
                        let ret = Ok(Some(&self.buf[0..(self.cnt + 1)]));
                        self.cnt = 0;
                        self.last_char_was_backslash = false;
                        self.last_char_was_lt = false;
                        return ret;
                    }
                }
                self.last_char_was_backslash = false;
            }
            self.last_char_was_lt = false;
        }
        //println!("b: '{}', cnt: {}, tag_cnt: {}, self.buf.len(): {}", b as char, self.cnt, self.tag_cnt, self.buf.len());
        self.cnt += 1;
        if self.cnt == self.buf_size {
            bail!("stanza too big: {}", to_str(&self.buf));
        }
        Ok(None)
    }
}
