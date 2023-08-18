#![deny(clippy::all)]
use anyhow::Result;
use die::{die, Die};
use log::{debug, info};
use serde_derive::Deserialize;
use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    iter::Iterator,
    net::{SocketAddr, UdpSocket},
    path::Path,
    sync::Arc,
};
use tokio::{net::TcpListener, task::JoinHandle};
use xmpp_proxy::common::certs_key::CertsKey;
#[cfg(feature = "outgoing")]
use xmpp_proxy::{common::outgoing::OutgoingConfig, outgoing::spawn_outgoing_listener};

#[derive(Deserialize, Default)]
struct Config {
    tls_key: String,
    tls_cert: String,
    incoming_listen: Vec<String>,
    quic_listen: Vec<String>,
    outgoing_listen: Vec<String>,
    max_stanza_size_bytes: usize,
    s2s_target: Option<SocketAddr>,
    c2s_target: Option<SocketAddr>,
    proxy: bool,
    log_level: Option<String>,
    log_style: Option<String>,
}

impl Config {
    fn parse<P: AsRef<Path>>(path: P) -> Result<Config> {
        let mut f = File::open(path)?;
        let mut input = String::new();
        f.read_to_string(&mut input)?;
        Ok(toml::from_str(&input)?)
    }

    #[cfg(feature = "incoming")]
    fn get_cloneable_cfg(&self) -> xmpp_proxy::common::incoming::CloneableConfig {
        xmpp_proxy::common::incoming::CloneableConfig {
            max_stanza_size_bytes: self.max_stanza_size_bytes,
            #[cfg(feature = "s2s-incoming")]
            s2s_target: self.s2s_target,
            #[cfg(feature = "c2s-incoming")]
            c2s_target: self.c2s_target,
            proxy: self.proxy,
        }
    }

    #[cfg(feature = "outgoing")]
    fn get_outgoing_cfg(&self, certs_key: Arc<CertsKey>) -> OutgoingConfig {
        #[cfg(feature = "rustls-pemfile")]
        if let Err(e) = &certs_key.inner {
            debug!("invalid key/cert for s2s client auth: {}", e);
        }

        OutgoingConfig {
            max_stanza_size_bytes: self.max_stanza_size_bytes,
            certs_key,
        }
    }

    #[cfg(feature = "rustls-pemfile")]
    fn certs_key(&self) -> Result<rustls::sign::CertifiedKey> {
        xmpp_proxy::common::read_certified_key(&self.tls_key, &self.tls_cert)
    }

    #[cfg(not(feature = "rustls-pemfile"))]
    fn certs_key(&self) -> Result<rustls::sign::CertifiedKey> {
        anyhow::bail!("rustls-pemfile disabled at compile time")
    }
}

#[cfg(all(unix, any(feature = "incoming", feature = "s2s-outgoing")))]
fn spawn_refresh_task(certs_key: &'static CertsKey, cfg_path: OsString) -> Option<JoinHandle<Result<()>>> {
    if certs_key.inner.is_err() {
        None
    } else {
        Some(tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut stream = signal(SignalKind::hangup())?;
            loop {
                stream.recv().await;
                info!("got SIGHUP");
                match Config::parse(&cfg_path).and_then(|c| c.certs_key()) {
                    Ok(cert_key) => {
                        if let Ok(rwl) = certs_key.inner.as_ref() {
                            let cert_key = Arc::new(cert_key);
                            let mut certs_key = rwl.write().expect("CertKey poisoned?");
                            *certs_key = cert_key;
                            drop(certs_key);
                            info!("reloaded cert/key successfully!");
                        }
                    }
                    Err(e) => log::error!("invalid config/cert/key on SIGHUP: {}", e),
                };
            }
        }))
    }
}

#[tokio::main]
//#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let cfg_path = std::env::args_os().nth(1);
    if cfg_path == Some(OsString::from("-v")) {
        include!(concat!(env!("OUT_DIR"), "/version.rs"));
        die!(0);
    }
    let cfg_path = cfg_path.unwrap_or_else(|| OsString::from("/etc/xmpp-proxy/xmpp-proxy.toml"));
    let main_config = Config::parse(&cfg_path).die("invalid config file");

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
    #[cfg(not(feature = "logging"))]
    if main_config.log_level.is_some() || main_config.log_style.is_some() {
        die!("log_level or log_style defined in config but logging disabled at compile-time");
    }

    let mut incoming_listen = Vec::new();
    for a in main_config.incoming_listen.iter() {
        incoming_listen.push(TcpListener::bind(a).await.die("cannot listen on port/interface"));
    }
    let mut quic_listen = Vec::new();
    for a in main_config.quic_listen.iter() {
        quic_listen.push(UdpSocket::bind(a).die("cannot listen on port/interface"));
    }
    let mut outgoing_listen = Vec::new();
    for a in main_config.outgoing_listen.iter() {
        outgoing_listen.push(TcpListener::bind(a).await.die("cannot listen on port/interface"));
    }

    #[cfg(all(feature = "nix", not(target_os = "windows")))]
    if let Ok(fds) = xmpp_proxy::systemd::receive_descriptors_with_names(true) {
        use xmpp_proxy::systemd::Listener;
        for fd in fds {
            match fd.listener() {
                Listener::Tcp(tcp_listener) => {
                    let tcp_listener = TcpListener::from_std(tcp_listener()).die("cannot open systemd TcpListener");
                    if let Some(name) = fd.name().map(|n| n.to_ascii_lowercase()) {
                        if name.starts_with("in") {
                            incoming_listen.push(tcp_listener);
                        } else if name.starts_with("out") {
                            outgoing_listen.push(tcp_listener);
                        } else {
                            die!("systemd socket name must start with 'in' or 'out' but is '{}'", name);
                        }
                    } else {
                        // what to do here... for now we will require names
                        // todo: possibly in future if local_addr is localhost or private ranges assume outgoing, otherwise incoming?
                        die!("systemd TCP socket activation requires name that starts with 'in' or 'out'");
                    }
                }
                Listener::Udp(udp_socket) => quic_listen.push(udp_socket()),
                _ => continue,
            }
        }
    }

    #[cfg(feature = "incoming")]
    let config = main_config.get_cloneable_cfg();

    let certs_key = Arc::new(CertsKey::new(main_config.certs_key()));

    let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();
    if !incoming_listen.is_empty() {
        #[cfg(all(any(feature = "tls", feature = "websocket"), feature = "incoming"))]
        {
            use xmpp_proxy::{
                common::incoming::server_config,
                tls::incoming::{spawn_tls_listener, tls_acceptor},
            };
            if main_config.c2s_target.is_none() && main_config.s2s_target.is_none() {
                die!("one of c2s_target/s2s_target must be defined if incoming_listen is non-empty");
            }
            let acceptor = tls_acceptor(server_config(certs_key.clone()).die("invalid cert/key ?"));
            for listener in incoming_listen {
                handles.push(spawn_tls_listener(listener, config.clone(), acceptor.clone()));
            }
        }
        #[cfg(not(all(any(feature = "tls", feature = "websocket"), feature = "incoming")))]
        die!("incoming_listen non-empty but (tls or websocket) or (s2s-incoming and c2s-incoming) disabled at compile-time");
    }
    if !quic_listen.is_empty() {
        #[cfg(all(feature = "quic", feature = "incoming"))]
        {
            use xmpp_proxy::{
                common::incoming::server_config,
                quic::incoming::{quic_server_config, spawn_quic_listener},
            };
            if main_config.c2s_target.is_none() && main_config.s2s_target.is_none() {
                die!("one of c2s_target/s2s_target must be defined if quic_listen is non-empty");
            }
            let quic_config = quic_server_config(server_config(certs_key.clone()).die("invalid cert/key ?"));
            for listener in quic_listen {
                handles.push(spawn_quic_listener(listener, config.clone(), quic_config.clone()));
            }
        }
        #[cfg(not(all(feature = "quic", feature = "incoming")))]
        die!("quic_listen non-empty but quic or (s2s-incoming and c2s-incoming) disabled at compile-time");
    }
    if !outgoing_listen.is_empty() {
        #[cfg(feature = "outgoing")]
        {
            let outgoing_cfg = main_config.get_outgoing_cfg(certs_key.clone());
            for listener in outgoing_listen {
                handles.push(spawn_outgoing_listener(listener, outgoing_cfg.clone()));
            }
        }
        #[cfg(not(feature = "outgoing"))]
        die!("outgoing_listen non-empty but c2s-outgoing and s2s-outgoing disabled at compile-time");
    }
    if handles.is_empty() {
        die!("all of incoming_listen, quic_listen, outgoing_listen empty, nothing to do, exiting...");
    }
    #[cfg(all(unix, any(feature = "incoming", feature = "s2s-outgoing")))]
    {
        let certs_key = Box::leak(Box::new(certs_key.clone()));
        if let Some(refresh_task) = spawn_refresh_task(certs_key, cfg_path) {
            handles.push(refresh_task);
        }
    }

    info!("xmpp-proxy started");
    futures::future::join_all(handles).await;
    info!("xmpp-proxy terminated");
}
