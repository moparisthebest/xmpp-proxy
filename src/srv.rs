#![allow(clippy::upper_case_acronyms)]

#[cfg(feature = "outgoing")]
use crate::common::outgoing::{OutgoingConfig, OutgoingVerifierConfig};
use crate::{
    common::{stream_preamble, to_str},
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
    slicesubsequence::SliceSubsequence,
    stanzafilter::{StanzaFilter, StanzaReader},
    verify::XmppServerCertVerifier,
};
use anyhow::{bail, Result};
use data_encoding::BASE64;
use log::{debug, error, trace};
use reqwest::{Client, Url};
use ring::digest::{Algorithm, Context as DigestContext, SHA256, SHA512};
use serde::Deserialize;
use std::{
    cmp::Ordering,
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::http::Uri;
use trust_dns_resolver::{
    error::ResolveError,
    lookup::{SrvLookup, TxtLookup},
    IntoName, TokioAsyncResolver,
};
use webpki::{DnsName, DnsNameRef};

lazy_static::lazy_static! {
    static ref RESOLVER: TokioAsyncResolver = make_resolver();
    static ref HTTPS_CLIENT: Client = make_https_client();
}

fn make_resolver() -> TokioAsyncResolver {
    let (config, mut options) = trust_dns_resolver::system_conf::read_system_conf().unwrap();
    options.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    TokioAsyncResolver::tokio(config, options)
}

fn make_https_client() -> Client {
    // todo: configure our root certs here
    Client::builder().https_only(true).build().expect("failed to make https client?")
}

async fn https_get<T: reqwest::IntoUrl>(url: T) -> reqwest::Result<reqwest::Response> {
    HTTPS_CLIENT.get(url).send().await
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum XmppConnectionType {
    #[cfg(feature = "tls")]
    StartTLS,
    #[cfg(feature = "tls")]
    DirectTLS,
    #[cfg(feature = "quic")]
    QUIC,
    #[cfg(feature = "websocket")]
    //        uri, origin
    WebSocket(Uri, String),
    #[cfg(feature = "webtransport")]
    WebTransport(Url),
}

impl XmppConnectionType {
    fn idx(&self) -> u8 {
        match self {
            #[cfg(feature = "quic")]
            XmppConnectionType::QUIC => 0,
            #[cfg(feature = "tls")]
            XmppConnectionType::DirectTLS => 2,
            #[cfg(feature = "tls")]
            XmppConnectionType::StartTLS => 3,
            #[cfg(feature = "websocket")]
            XmppConnectionType::WebSocket(_, _) => 4,
            #[cfg(feature = "webtransport")]
            XmppConnectionType::WebTransport(_) => 1,
        }
    }
}

impl Ord for XmppConnectionType {
    fn cmp(&self, other: &Self) -> Ordering {
        let cmp = self.idx().cmp(&other.idx());
        if cmp != Ordering::Equal {
            return cmp;
        }
        // so they are the same type, but WebSocket and WebTransport is a special case...
        match (self, other) {
            #[cfg(feature = "websocket")]
            (XmppConnectionType::WebSocket(self_uri, self_origin), XmppConnectionType::WebSocket(other_uri, other_origin)) => {
                let cmp = self_uri.to_string().cmp(&other_uri.to_string());
                if cmp != Ordering::Equal {
                    return cmp;
                }
                self_origin.cmp(other_origin)
            }
            #[cfg(feature = "webtransport")]
            (XmppConnectionType::WebTransport(self_url), XmppConnectionType::WebTransport(other_url)) => self_url.cmp(other_url),
            (_, _) => Ordering::Equal,
        }
    }
}

impl PartialOrd for XmppConnectionType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct XmppConnection {
    conn_type: XmppConnectionType,
    priority: u16,
    weight: u16, // todo: use weight
    port: u16,
    target: String,
    secure: bool,
    ips: Vec<IpAddr>,
    #[allow(dead_code)]
    ech: Option<String>,
}

impl PartialEq for XmppConnection {
    fn eq(&self, other: &Self) -> bool {
        self.conn_type == other.conn_type && self.port == other.port && self.target == other.target
    }
}

impl Ord for XmppConnection {
    fn cmp(&self, other: &Self) -> Ordering {
        // this should put equal things next to each other, but things we want to keep further to the left
        let cmp = self.conn_type.cmp(&other.conn_type);
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = self.port.cmp(&other.port);
        if cmp != Ordering::Equal {
            return cmp;
        }
        let cmp = self.target.cmp(&other.target);
        if cmp != Ordering::Equal {
            return cmp;
        }
        // end of equality checks, now preferences:
        // backwards on purpose, so secure is earlier in the list
        let cmp = other.secure.cmp(&self.secure);
        if cmp != Ordering::Equal {
            return cmp;
        }
        // lowest priority preferred
        let cmp = self.priority.cmp(&other.priority);
        if cmp != Ordering::Equal {
            return cmp;
        }
        // highest weight preferred
        other.weight.cmp(&self.priority)
    }
}

impl Eq for XmppConnection {}

impl PartialOrd for XmppConnection {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn sort_dedup(ret: &mut Vec<XmppConnection>) {
    ret.sort();
    ret.dedup();
    // now sort by priority
    ret.sort_by(|a, b| {
        let cmp = a.priority.cmp(&b.priority);
        if cmp != Ordering::Equal {
            return cmp;
        }
        // prioritize "better" protocols todo: we *could* prioritize these first before priority...
        let cmp = a.conn_type.idx().cmp(&b.conn_type.idx());
        if cmp != Ordering::Equal {
            return cmp;
        }
        // higher weight first todo: still not ideal
        b.weight.cmp(&a.weight)
    });
}

impl XmppConnection {
    #[cfg(feature = "outgoing")]
    pub async fn connect(
        &self,
        domain: &str,
        stream_open: &[u8],
        in_filter: &mut StanzaFilter,
        client_addr: &mut Context<'_>,
        config: &OutgoingVerifierConfig,
    ) -> Result<(StanzaWrite, StanzaRead, SocketAddr, &'static str)> {
        debug!("{} attempting connection to SRV: {:?}", client_addr.log_from(), self);
        // todo: for DNSSEC we need to optionally allow target in addition to domain, but what for SNI
        let orig_domain = domain;
        let domain = if self.secure { &self.target } else { domain };
        //let ips = RESOLVER.lookup_ip(self.target.clone()).await?;
        let ips = if self.ips.is_empty() {
            RESOLVER.lookup_ip(self.target.clone()).await?.iter().collect()
        } else {
            self.ips.clone() // todo: avoid clone?
        };
        for ip in ips.iter() {
            let to_addr = SocketAddr::new(*ip, self.port);
            debug!("{} trying ip {}", client_addr.log_from(), to_addr);
            match self.conn_type {
                #[cfg(feature = "tls")]
                XmppConnectionType::StartTLS => match crate::tls::outgoing::starttls_connect(to_addr, domain, stream_open, in_filter, config).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "starttls-out")),
                    Err(e) => error!("starttls connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "tls")]
                XmppConnectionType::DirectTLS => match crate::tls::outgoing::tls_connect(to_addr, domain, config).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "directtls-out")),
                    Err(e) => error!("direct tls connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "quic")]
                XmppConnectionType::QUIC => match crate::quic::outgoing::quic_connect(to_addr, domain, config).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "quic-out")),
                    Err(e) => error!("quic connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "websocket")]
                // todo: when websocket is found via DNS, we need to validate cert against domain, *not* target, this is a security problem with XEP-0156, we are doing it the secure but likely unexpected way here for now
                XmppConnectionType::WebSocket(ref url, ref origin) => match crate::websocket::outgoing::websocket_connect(to_addr, domain, url, origin, config).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "websocket-out")),
                    Err(e) => {
                        if self.secure && self.target != orig_domain {
                            // https is a special case, as target is sent in the Host: header, so we have to literally try twice in case this is set for the other on the server
                            match crate::websocket::outgoing::websocket_connect(to_addr, orig_domain, url, origin, config).await {
                                Ok((wr, rd)) => return Ok((wr, rd, to_addr, "websocket-out")),
                                Err(e2) => error!("websocket connection failed to IP {} from TXT {}, error try 1: {}, error try 2: {}", to_addr, url, e, e2),
                            }
                        } else {
                            error!("websocket connection failed to IP {} from TXT {}, error: {}", to_addr, url, e)
                        }
                    }
                },
                #[cfg(feature = "webtransport")]
                XmppConnectionType::WebTransport(ref url) => match crate::webtransport::outgoing::webtransport_connect(to_addr, domain, url, config).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "webtransport-out")),
                    Err(e) => {
                        if self.secure && self.target != orig_domain {
                            match crate::webtransport::outgoing::webtransport_connect(to_addr, orig_domain, url, config).await {
                                Ok((wr, rd)) => return Ok((wr, rd, to_addr, "webtransport-out")),
                                Err(e2) => error!("webtransport connection failed to IP {} from URL {}, error try 1: {}, error try 2: {}", to_addr, url, e, e2),
                            }
                        } else {
                            error!("websocket connection failed to IP {} from URL {}, error: {}", to_addr, url, e)
                        }
                    }
                },
            }
        }
        bail!("cannot connect to any IPs for SRV: {}", self.target)
    }
}

fn collect_srvs(ret: &mut Vec<XmppConnection>, srv_records: std::result::Result<SrvLookup, ResolveError>, conn_type: XmppConnectionType) {
    if let Ok(srv_records) = srv_records {
        for srv in srv_records.iter() {
            if !srv.target().is_root() {
                ret.push(XmppConnection {
                    conn_type: conn_type.clone(),
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    target: srv.target().to_ascii(),
                    secure: false, // todo: support dnssec here, and if true, look up TLSA
                    ips: Vec::new(),
                    ech: None,
                });
            }
        }
    }
}

#[cfg(feature = "websocket")]
fn wss_to_srv(url: &str, secure: bool) -> Option<XmppConnection> {
    let url = match Uri::try_from(url) {
        Ok(url) => url,
        Err(e) => {
            debug!("invalid URL record '{}': {}", url, e);
            return None;
        }
    };
    let server_name = match url.host() {
        Some(server_name) => server_name.to_string(),
        None => {
            debug!("invalid URL record '{}'", url);
            return None;
        }
    };
    let target = server_name.to_string();

    let mut origin = "https://".to_string();
    origin.push_str(&server_name);
    let port = if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(port.as_str());
        port.as_u16()
    } else {
        443
    };
    Some(XmppConnection {
        conn_type: XmppConnectionType::WebSocket(url, origin),
        priority: u16::MAX,
        weight: 0,
        port,
        target,
        secure,
        ips: Vec::new(),
        ech: None,
    })
}

#[cfg(feature = "webtransport")]
fn wt_to_srv(url: &str) -> Option<(XmppConnectionType, u16)> {
    let url = match Url::parse(url) {
        Ok(url) => url,
        Err(e) => {
            debug!("invalid URL record '{}': {}", url, e);
            return None;
        }
    };

    let port = url.port().unwrap_or(443);

    Some((XmppConnectionType::WebTransport(url), port))
}

#[cfg(feature = "websocket")]
fn collect_txts(ret: &mut Vec<XmppConnection>, txt_records: std::result::Result<TxtLookup, ResolveError>, is_c2s: bool) {
    if let Ok(txt_records) = txt_records {
        for txt in txt_records.iter() {
            for txt in txt.iter() {
                // we only support wss and not ws (insecure) on purpose
                if txt.starts_with(if is_c2s { b"_xmpp-client-websocket=wss://" } else { b"_xmpp-server-websocket=wss://" }) {
                    // 23 is the length of "_xmpp-client-websocket=" and "_xmpp-server-websocket="
                    if let Ok(url) = String::from_utf8(txt[23..].to_vec()) {
                        if let Some(srv) = wss_to_srv(&url, false) {
                            if !ret.contains(&srv) {
                                ret.push(srv);
                            }
                        }
                    } else {
                        debug!("invalid TXT record '{}'", to_str(txt));
                    }
                }
            }
        }
    }
}

pub async fn get_xmpp_connections(domain: &str, is_c2s: bool) -> Result<(Vec<XmppConnection>, XmppServerCertVerifier)> {
    let mut valid_tls_cert_server_names: Vec<DnsName> = vec![DnsNameRef::try_from_ascii_str(domain)?.to_owned()];
    let mut sha256_pinnedpubkeys = Vec::new();
    let (starttls, direct_tls, quic, websocket_txt) = if is_c2s {
        ("_xmpp-client._tcp", "_xmpps-client._tcp", "_xmppq-client._udp", "_xmppconnect")
    } else {
        ("_xmpp-server._tcp", "_xmpps-server._tcp", "_xmppq-server._udp", "_xmppconnect-server")
    };

    let starttls = format!("{}.{}.", starttls, domain).into_name()?;
    let direct_tls = format!("{}.{}.", direct_tls, domain).into_name()?;
    #[cfg(feature = "quic")]
    let quic = format!("{}.{}.", quic, domain).into_name()?;
    #[cfg(feature = "websocket")]
    let websocket_txt = format!("{}.{}.", websocket_txt, domain).into_name()?;

    let mut ret = Vec::new();

    // this lets them run concurrently but not in parallel, could spawn parallel tasks but... worth it ?
    // todo: don't look up websocket or quic records when they are disabled
    let (
        starttls,
        direct_tls,
        //#[cfg(feature = "quic")]
        quic,
        //#[cfg(feature = "websocket")]
        websocket_txt,
        websocket_host,
        posh,
    ) = tokio::join!(
        RESOLVER.srv_lookup(starttls),
        RESOLVER.srv_lookup(direct_tls),
        //#[cfg(feature = "quic")]
        RESOLVER.srv_lookup(quic),
        //#[cfg(feature = "websocket")]
        RESOLVER.txt_lookup(websocket_txt),
        collect_host_meta(&mut ret, &mut sha256_pinnedpubkeys, domain, is_c2s),
        collect_posh(domain),
    );
    if let Ok(Some(_ttl)) = websocket_host {
        // todo: cache for ttl
    } else {
        // ignore everything else if new host-meta format
        #[cfg(feature = "websocket")]
        collect_txts(&mut ret, websocket_txt, is_c2s);
        #[cfg(feature = "tls")]
        collect_srvs(&mut ret, starttls, XmppConnectionType::StartTLS);
        #[cfg(feature = "tls")]
        collect_srvs(&mut ret, direct_tls, XmppConnectionType::DirectTLS);
        #[cfg(feature = "quic")]
        collect_srvs(&mut ret, quic, XmppConnectionType::QUIC);
    }

    sort_dedup(&mut ret);

    for srv in &ret {
        if srv.secure {
            if let Ok(target) = DnsNameRef::try_from_ascii_str(srv.target.as_str()) {
                let target = target.to_owned();
                if !valid_tls_cert_server_names.contains(&target) {
                    valid_tls_cert_server_names.push(target);
                }
            }
        }
    }
    let cert_verifier = XmppServerCertVerifier::new(valid_tls_cert_server_names, posh.ok(), sha256_pinnedpubkeys);

    if ret.is_empty() {
        // default starttls ports
        #[cfg(feature = "tls")]
        ret.push(XmppConnection {
            priority: 0,
            weight: 0,
            target: domain.to_string(),
            conn_type: XmppConnectionType::StartTLS,
            port: if is_c2s { 5222 } else { 5269 },
            secure: false,
            ips: Vec::new(),
            ech: None,
        });
        // by spec there are no default direct/quic ports, but we are going 443
        #[cfg(feature = "tls")]
        ret.push(XmppConnection {
            priority: 0,
            weight: 0,
            target: domain.to_string(),
            conn_type: XmppConnectionType::DirectTLS,
            port: 443,
            secure: false,
            ips: Vec::new(),
            ech: None,
        });
        #[cfg(feature = "quic")]
        ret.push(XmppConnection {
            priority: 0,
            weight: 0,
            target: domain.to_string(),
            conn_type: XmppConnectionType::QUIC,
            port: 443,
            secure: false,
            ips: Vec::new(),
            ech: None,
        });
    }

    /*
    // manual target for testing
    ret.clear();
    ret.push(XmppConnection {
        priority: 0,
        weight: 0,
        target: "127.0.0.1".to_string(),
        conn_type: XmppConnectionType::QUIC,
        port: 4443,
    });
    */

    debug!("{} records for {}: {:?}", ret.len(), domain, ret);

    Ok((ret, cert_verifier))
}

#[cfg(feature = "outgoing")]
pub async fn srv_connect(
    domain: &str,
    is_c2s: bool,
    stream_open: &[u8],
    in_filter: &mut StanzaFilter,
    client_addr: &mut Context<'_>,
    config: OutgoingConfig,
) -> Result<(StanzaWrite, StanzaRead, Vec<u8>)> {
    #[cfg(not(feature = "c2s-outgoing"))]
    if is_c2s {
        bail!("outgoing c2s connection but c2s-outgoing disabled at compile-time");
    }
    #[cfg(not(feature = "s2s-outgoing"))]
    if !is_c2s {
        bail!("outgoing s2s connection but s2s-outgoing disabled at compile-time");
    }
    let (srvs, cert_verifier) = get_xmpp_connections(domain, is_c2s).await?;
    let config = config.with_custom_certificate_verifier(is_c2s, Arc::new(cert_verifier));
    for srv in srvs {
        let connect = srv.connect(domain, stream_open, in_filter, client_addr, &config).await;
        if connect.is_err() {
            continue;
        }
        let (mut out_wr, mut out_rd, to_addr, proto) = connect.unwrap();
        // if any of these ? returns early with an Err, these will stay set, I think that's ok though, the connection will be closed
        client_addr.set_proto(proto);
        client_addr.set_to_addr(to_addr.to_string());
        debug!("{} connected", client_addr.log_from());

        trace!("{} '{}'", client_addr.log_from(), to_str(stream_open));
        out_wr.write_all(is_c2s, stream_open, stream_open.len(), client_addr.log_from()).await?;
        out_wr.flush().await?;

        match stream_preamble(&mut out_rd, &mut out_wr, client_addr.log_to(), in_filter).await {
            Ok((server_response, _)) => return Ok((out_wr, out_rd, server_response)),
            Err(e) => {
                debug!("{} bad server response, going to next record, error: {}", client_addr.log_to(), e);
                client_addr.set_proto("unk-out");
                continue;
            }
        }
    }
    bail!("all connection attempts failed")
}

#[cfg(not(feature = "websocket"))]
async fn collect_host_meta(ret: &mut Vec<XmppConnection>, sha256_pinnedpubkeys: &mut Vec<String>, domain: &str, is_c2s: bool) -> Result<Option<u16>> {
    collect_host_meta_json(ret, sha256_pinnedpubkeys, domain, is_c2s).await
}

#[cfg(feature = "websocket")]
async fn collect_host_meta(ret: &mut Vec<XmppConnection>, sha256_pinnedpubkeys: &mut Vec<String>, domain: &str, is_c2s: bool) -> Result<Option<u16>> {
    let mut xml = Vec::new();
    match tokio::join!(collect_host_meta_json(ret, sha256_pinnedpubkeys, domain, is_c2s), collect_host_meta_xml(&mut xml, domain, is_c2s)) {
        (Ok(Some(ttl)), _) => Ok(Some(ttl)), // if ttl is returned, ignore host-meta.xml
        (_, Ok(_)) => {
            ret.append(&mut xml);
            Ok(None)
        }
        (json, _) => json,
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct HostMeta {
    xmpp: Option<HostMetaXmpp>,
    links: Vec<Link>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct HostMetaXmpp {
    ttl: u16,
    #[serde(default)]
    public_key_pins_sha_256: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "rel", rename_all = "kebab-case")]
enum Link {
    #[serde(rename = "urn:xmpp:alt-connections:websocket")]
    WebSocket {
        href: String,
        #[serde(flatten)]
        link: Option<LinkCommon>,
    },
    #[serde(rename = "urn:xmpp:alt-connections:webtransport")]
    WebTransport {
        href: String,
        #[serde(flatten)]
        link: LinkCommon,
    },
    #[serde(rename = "urn:xmpp:alt-connections:tls")]
    DirectTLS {
        #[serde(flatten)]
        link: LinkCommon,
        port: u16,
    },
    #[serde(rename = "urn:xmpp:alt-connections:quic")]
    Quic {
        #[serde(flatten)]
        link: LinkCommon,
        port: u16,
    },
    #[serde(rename = "urn:xmpp:alt-connections:s2s-webtransport")]
    S2SWebTransport {
        href: String,
        #[serde(flatten)]
        link: LinkCommon,
    },
    #[serde(rename = "urn:xmpp:alt-connections:s2s-websocket")]
    S2SWebSocket {
        href: String,
        #[serde(flatten)]
        link: LinkCommon,
    },
    #[serde(rename = "urn:xmpp:alt-connections:s2s-tls")]
    S2SDirectTLS {
        #[serde(flatten)]
        link: LinkCommon,
        port: u16,
    },
    #[serde(rename = "urn:xmpp:alt-connections:s2s-quic")]
    S2SQuic {
        #[serde(flatten)]
        link: LinkCommon,
        port: u16,
    },
    #[serde(other)]
    Unknown,
}
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
struct LinkCommon {
    ips: Vec<IpAddr>,
    priority: u16,
    weight: u16,
    sni: String,
    ech: Option<String>,
}

impl LinkCommon {
    fn into_xmpp_connection(self, conn_type: XmppConnectionType, port: u16) -> Option<XmppConnection> {
        if self.ips.is_empty() {
            error!("invalid empty ips");
            return None;
        }
        Some(XmppConnection {
            conn_type,
            port,
            priority: self.priority,
            weight: self.weight,
            target: self.sni,
            ips: self.ips,
            ech: self.ech,
            secure: true,
        })
    }
}

impl Link {
    fn into_xmpp_connection(self, is_c2s: bool) -> Option<XmppConnection> {
        use XmppConnectionType::*;
        let (srv_is_c2s, port, link, conn_type) = match self {
            #[cfg(feature = "tls")]
            Link::DirectTLS { port, link } => (true, port, link, DirectTLS),
            #[cfg(feature = "quic")]
            Link::Quic { port, link } => (true, port, link, QUIC),
            #[cfg(feature = "tls")]
            Link::S2SDirectTLS { port, link } => (false, port, link, DirectTLS),
            #[cfg(feature = "quic")]
            Link::S2SQuic { port, link } => (false, port, link, QUIC),
            #[cfg(feature = "websocket")]
            Link::WebSocket { href, link } => {
                return if is_c2s {
                    let srv = wss_to_srv(&href, true)?;
                    if let Some(link) = link {
                        link.into_xmpp_connection(srv.conn_type, srv.port)
                    } else {
                        Some(srv)
                    }
                } else {
                    None
                };
            }
            #[cfg(feature = "websocket")]
            Link::S2SWebSocket { href, link } => {
                return if !is_c2s {
                    let srv = wss_to_srv(&href, true)?;
                    link.into_xmpp_connection(srv.conn_type, srv.port)
                } else {
                    None
                };
            }
            #[cfg(feature = "webtransport")]
            Link::WebTransport { href, link } => {
                return if is_c2s {
                    let (conn_type, port) = wt_to_srv(&href)?;
                    link.into_xmpp_connection(conn_type, port)
                } else {
                    None
                };
            }
            #[cfg(feature = "webtransport")]
            Link::S2SWebTransport { href, link } => {
                return if !is_c2s {
                    let (conn_type, port) = wt_to_srv(&href)?;
                    link.into_xmpp_connection(conn_type, port)
                } else {
                    None
                };
            }

            _ => return None,
        };

        if srv_is_c2s == is_c2s {
            link.into_xmpp_connection(conn_type, port)
        } else {
            None
        }
    }
}

impl HostMeta {
    fn collect(self, ret: &mut Vec<XmppConnection>, sha256_pinnedpubkeys: &mut Vec<String>, is_c2s: bool) -> Option<u16> {
        for link in self.links {
            if let Some(srv) = link.into_xmpp_connection(is_c2s) {
                ret.push(srv);
            }
        }
        if let Some(xmpp) = self.xmpp {
            sha256_pinnedpubkeys.extend(xmpp.public_key_pins_sha_256);
            Some(xmpp.ttl)
        } else {
            None
        }
    }
}

async fn collect_host_meta_json(ret: &mut Vec<XmppConnection>, sha256_pinnedpubkeys: &mut Vec<String>, domain: &str, is_c2s: bool) -> Result<Option<u16>> {
    let url = format!("https://{}/.well-known/host-meta.json", domain);
    let resp = https_get(&url).await?;
    if resp.status().is_success() {
        let resp = resp.json::<HostMeta>().await?;
        Ok(resp.collect(ret, sha256_pinnedpubkeys, is_c2s))
    } else {
        bail!("failed with status code {} for url {}", resp.status(), url)
    }
}

#[cfg(feature = "websocket")]
async fn parse_host_meta_xml(rel: &str, bytes: &[u8]) -> Result<Vec<String>> {
    let mut vec = Vec::new();
    let mut stanza_reader = StanzaReader(bytes);
    let mut filter = StanzaFilter::new(8192);
    while let Some((stanza, eoft)) = stanza_reader.next_eoft(&mut filter).await? {
        if stanza.starts_with(b"<XRD") || stanza.starts_with(b"<xrd") {
            // now we are to the Links
            let stanza = &stanza[eoft..];
            let mut stanza_reader = StanzaReader(stanza);
            let mut filter = StanzaFilter::new(4096);
            while let Ok(Some(stanza)) = stanza_reader.next(&mut filter).await {
                if stanza.contains_seq(rel.as_bytes()) {
                    for needle in [b"='wss://", b"=\"wss://"] {
                        if let Ok(idx) = stanza.first_index_of(needle) {
                            let stanza = &stanza[idx + 2..];
                            if let Ok(idx) = stanza.first_index_of(&needle[1..2]) {
                                vec.push(String::from_utf8(stanza[..idx].to_vec())?);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(vec)
}

#[cfg(feature = "websocket")]
async fn collect_host_meta_xml(ret: &mut Vec<XmppConnection>, domain: &str, is_c2s: bool) -> Result<()> {
    if !is_c2s {
        bail!("host-meta XML unsupported for S2s");
    }
    let url = format!("https://{}/.well-known/host-meta", domain);
    let resp = https_get(&url).await?;
    if resp.status().is_success() {
        let rel = "urn:xmpp:alt-connections:websocket";
        let hosts = parse_host_meta_xml(rel, resp.bytes().await?.as_ref()).await?;
        for host in hosts {
            if let Some(srv) = wss_to_srv(&host, true) {
                ret.push(srv);
            }
        }
        Ok(())
    } else {
        bail!("failed with status code {} for url {}", resp.status(), url)
    }
}

// https://datatracker.ietf.org/doc/html/rfc7711
// https://www.iana.org/assignments/posh-service-names/posh-service-names.xhtml
async fn collect_posh(domain: &str) -> Result<Posh> {
    match tokio::join!(collect_posh_service(domain, "xmpp-client"), collect_posh_service(domain, "xmpp-server")) {
        (Ok(client), Ok(server)) => Ok(client.append(server)),
        (_, Ok(server)) => Ok(server),
        (client, _) => client,
    }
}

async fn collect_posh_service(domain: &str, service_name: &str) -> Result<Posh> {
    let url = format!("https://{}/.well-known/posh/{}.json", domain, service_name);
    let resp = https_get(&url).await?;
    if resp.status().is_success() {
        match resp.json::<PoshJson>().await? {
            PoshJson::PoshFingerprints { fingerprints, expires } => Posh::new(fingerprints, expires),
            PoshJson::PoshRedirect { url, expires } => {
                let resp = https_get(&url).await?;
                match resp.json::<PoshJson>().await? {
                    PoshJson::PoshRedirect { .. } => bail!("posh illegal url redirect to another url"),
                    PoshJson::PoshFingerprints { fingerprints, expires: expires2 } => Posh::new(
                        fingerprints,
                        // expires is supposed to be the least of these two
                        min(expires, expires2),
                    ),
                }
            }
        }
    } else {
        bail!("failed with status code {} for url {}", resp.status(), url)
    }
}

fn combine_uniq(target: &mut Vec<String>, mut other: Vec<String>) {
    target.append(&mut other);
    target.sort();
    target.dedup();
}

fn min(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum PoshJson {
    PoshFingerprints { fingerprints: Vec<Fingerprint>, expires: u64 },
    PoshRedirect { url: String, expires: u64 },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct Fingerprint {
    // todo: support more algorithms or no?
    sha_256: Option<String>,
    sha_512: Option<String>,
}

#[derive(Debug)]
pub struct Posh {
    sha_256_fingerprints: Vec<String>,
    sha_512_fingerprints: Vec<String>,
    expires: u64,
}

impl Posh {
    fn new(fingerprints: Vec<Fingerprint>, expires: u64) -> Result<Self> {
        if expires == 0 {
            bail!("posh expires is 0, ignoring");
        }
        let mut sha_256_fingerprints = Vec::with_capacity(fingerprints.len());
        let mut sha_512_fingerprints = Vec::with_capacity(fingerprints.len());
        for f in fingerprints {
            if let Some(h) = f.sha_256 {
                sha_256_fingerprints.push(h);
            }
            if let Some(h) = f.sha_512 {
                sha_512_fingerprints.push(h);
            }
        }
        Ok(Posh {
            sha_256_fingerprints,
            sha_512_fingerprints,
            expires,
        })
    }

    fn append(mut self, other: Self) -> Self {
        combine_uniq(&mut self.sha_256_fingerprints, other.sha_256_fingerprints);
        combine_uniq(&mut self.sha_512_fingerprints, other.sha_512_fingerprints);
        self.expires = min(self.expires, other.expires);
        self
    }

    pub fn valid_cert(&self, cert: &[u8]) -> bool {
        (!self.sha_256_fingerprints.is_empty() && self.sha_256_fingerprints.contains(&digest(&SHA256, cert)))
            || (!self.sha_512_fingerprints.is_empty() && self.sha_512_fingerprints.contains(&digest(&SHA512, cert)))
    }
}

pub fn digest(algorithm: &'static Algorithm, buf: &[u8]) -> String {
    let mut context = DigestContext::new(algorithm);
    context.update(buf);
    let digest = context.finish();
    BASE64.encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use crate::srv::*;
    use std::{fs::File, io::Read, path::PathBuf};

    fn valid_posh(posh: &[u8], cert: &[u8]) -> bool {
        let posh: PoshJson = serde_json::from_slice(posh).unwrap();
        let cert = BASE64.decode(cert).unwrap();
        println!("posh: {:?}", posh);
        if let PoshJson::PoshFingerprints { fingerprints, expires } = posh {
            let posh = Posh::new(fingerprints, expires).unwrap();
            println!("posh: {:?}", posh);
            posh.valid_cert(&cert)
        } else {
            false
        }
    }

    fn read_file(file: &str) -> Result<Vec<u8>> {
        let mut f = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        f.push(file);
        let mut file = File::open(f)?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        Ok(data)
    }

    #[test]
    fn posh_deserialize() {
        assert!(valid_posh(
            br###"{"expires":86400,"fingerprints":[{"sha-256":"6sKZUeE0LBwbCXqeoHJsGCjpFLNrL9QF2W6NhDYnV4I="}]}"###,
            br###"MIICHDCCAaGgAwIBAgIUQCykdom3fbgtYxbVzk12uY13FqUwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MB4XDTIxMTAxNTE0NDkzMloXDTIyMTAxNTE0NDkzMlowGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUeyvxJeBihodBTIATT5szGfsgeNE1nNIEjOU+PSDBpfCFEAKw5oIxB35TGyPvOe1MBSBXcaRFXBSKBZ4AkVRPsKsGjEmUa9GpIbEwcsUvw+NTx8OT81tuTEbpjs0QGy0o4GnMIGkMAwGA1UdEwQFMAMBAf8wgZMGA1UdEQSBizCBiKAqBggrBgEFBQcIB6AeFhxfeG1wcC1jbGllbnQucG9zaC5iYWR4bXBwLmV1oCoGCCsGAQUFBwgHoB4WHF94bXBwLXNlcnZlci5wb3NoLmJhZHhtcHAuZXWgHQYIKwYBBQUHCAWgEQwPcG9zaC5iYWR4bXBwLmV1gg9wb3NoLmJhZHhtcHAuZXUwCgYIKoZIzj0EAwIDaQAwZgIxAKLvjCkY9OV9dX7emghbroYgbqqWWBaQuIHLqtOEKpS+R88fOfEJbokViKNinY3ugwIxAPJ/oiK8ekF0gfa4aWmoCscbNv2Ns7HD+iSLm4GcSc/tza9r+uXVsV+0uqJ3UleTFA=="###
        ));
        assert!(valid_posh(
            br###"{"expires":86400,"fingerprints":[{"sha-512":"7S7zdev/QvRxHYguWHhD5Thlolj+H4aHo9Qy3Y1R6p7WGKnNBNPxk+tnHRSIs5CJIHIR3M7a6wNkgAC5uLWL/g=="}]}"###,
            br###"MIICHDCCAaGgAwIBAgIUQCykdom3fbgtYxbVzk12uY13FqUwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MB4XDTIxMTAxNTE0NDkzMloXDTIyMTAxNTE0NDkzMlowGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUeyvxJeBihodBTIATT5szGfsgeNE1nNIEjOU+PSDBpfCFEAKw5oIxB35TGyPvOe1MBSBXcaRFXBSKBZ4AkVRPsKsGjEmUa9GpIbEwcsUvw+NTx8OT81tuTEbpjs0QGy0o4GnMIGkMAwGA1UdEwQFMAMBAf8wgZMGA1UdEQSBizCBiKAqBggrBgEFBQcIB6AeFhxfeG1wcC1jbGllbnQucG9zaC5iYWR4bXBwLmV1oCoGCCsGAQUFBwgHoB4WHF94bXBwLXNlcnZlci5wb3NoLmJhZHhtcHAuZXWgHQYIKwYBBQUHCAWgEQwPcG9zaC5iYWR4bXBwLmV1gg9wb3NoLmJhZHhtcHAuZXUwCgYIKoZIzj0EAwIDaQAwZgIxAKLvjCkY9OV9dX7emghbroYgbqqWWBaQuIHLqtOEKpS+R88fOfEJbokViKNinY3ugwIxAPJ/oiK8ekF0gfa4aWmoCscbNv2Ns7HD+iSLm4GcSc/tza9r+uXVsV+0uqJ3UleTFA=="###
        ));
        assert!(!valid_posh(
            br###"{"expires":86400,"fingerprints":[{"sha-256":"Dp8REwxYw0vFt2tRAGIAT4nNtXD2wwqL0eF5QdN4Zm4="}]}"###,
            br###"MIICHDCCAaGgAwIBAgIUQCykdom3fbgtYxbVzk12uY13FqUwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MB4XDTIxMTAxNTE0NDkzMloXDTIyMTAxNTE0NDkzMlowGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUeyvxJeBihodBTIATT5szGfsgeNE1nNIEjOU+PSDBpfCFEAKw5oIxB35TGyPvOe1MBSBXcaRFXBSKBZ4AkVRPsKsGjEmUa9GpIbEwcsUvw+NTx8OT81tuTEbpjs0QGy0o4GnMIGkMAwGA1UdEwQFMAMBAf8wgZMGA1UdEQSBizCBiKAqBggrBgEFBQcIB6AeFhxfeG1wcC1jbGllbnQucG9zaC5iYWR4bXBwLmV1oCoGCCsGAQUFBwgHoB4WHF94bXBwLXNlcnZlci5wb3NoLmJhZHhtcHAuZXWgHQYIKwYBBQUHCAWgEQwPcG9zaC5iYWR4bXBwLmV1gg9wb3NoLmJhZHhtcHAuZXUwCgYIKoZIzj0EAwIDaQAwZgIxAKLvjCkY9OV9dX7emghbroYgbqqWWBaQuIHLqtOEKpS+R88fOfEJbokViKNinY3ugwIxAPJ/oiK8ekF0gfa4aWmoCscbNv2Ns7HD+iSLm4GcSc/tza9r+uXVsV+0uqJ3UleTFA=="###
        ));
        assert!(!valid_posh(
            br###"{"expires":86400,"fingerprints":[{"sha-512":"GwfqWa8hIYCGt9V9EgdDHg6npGeGhpAwryUJkU1FuP6CNiF2Auv1s1Tp9gSWSlCTbClSmzz+sorNVOfaDW6m3Q=="}]}"###,
            br###"MIICHDCCAaGgAwIBAgIUQCykdom3fbgtYxbVzk12uY13FqUwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MB4XDTIxMTAxNTE0NDkzMloXDTIyMTAxNTE0NDkzMlowGjEYMBYGA1UEAwwPcG9zaC5iYWR4bXBwLmV1MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUeyvxJeBihodBTIATT5szGfsgeNE1nNIEjOU+PSDBpfCFEAKw5oIxB35TGyPvOe1MBSBXcaRFXBSKBZ4AkVRPsKsGjEmUa9GpIbEwcsUvw+NTx8OT81tuTEbpjs0QGy0o4GnMIGkMAwGA1UdEwQFMAMBAf8wgZMGA1UdEQSBizCBiKAqBggrBgEFBQcIB6AeFhxfeG1wcC1jbGllbnQucG9zaC5iYWR4bXBwLmV1oCoGCCsGAQUFBwgHoB4WHF94bXBwLXNlcnZlci5wb3NoLmJhZHhtcHAuZXWgHQYIKwYBBQUHCAWgEQwPcG9zaC5iYWR4bXBwLmV1gg9wb3NoLmJhZHhtcHAuZXUwCgYIKoZIzj0EAwIDaQAwZgIxAKLvjCkY9OV9dX7emghbroYgbqqWWBaQuIHLqtOEKpS+R88fOfEJbokViKNinY3ugwIxAPJ/oiK8ekF0gfa4aWmoCscbNv2Ns7HD+iSLm4GcSc/tza9r+uXVsV+0uqJ3UleTFA=="###
        ));

        let posh = br###"
        {
         "fingerprints": [
           {
             "sha-256": "4/mggdlVx8A3pvHAWW5sD+qJyMtUHgiRuPjVC48N0XQ=",
             "sha-512": "25N+1hB2Vo42l9lSGqw+n3BKFhDHsyork8ou+D9B43TXeJ1J81mdQEDqm39oR/EHkPBDDG1y5+AG94Kec0xVqA==",
             "bla": "woo"             
           }
         ],
         "expires": 604800
        }
        "###;
        let posh: PoshJson = serde_json::from_slice(&posh[..]).unwrap();
        println!("posh: {:?}", posh);
        if let PoshJson::PoshFingerprints { fingerprints, expires } = posh {
            let posh = Posh::new(fingerprints, expires);
            println!("posh: {:?}", posh);
        }

        let posh = br###"
        {
         "url":"https://hosting.example.net/.well-known/posh/spice.json",
         "expires": 604800
        }
        "###;
        let posh: PoshJson = serde_json::from_slice(&posh[..]).unwrap();
        println!("posh: {:?}", posh);
    }

    #[cfg(feature = "net-test")]
    #[tokio::test]
    async fn posh() -> Result<()> {
        let domain = "posh.badxmpp.eu";
        let posh = collect_posh(domain).await.unwrap();
        println!("posh for domain {}: {:?}", domain, posh);
        Ok(())
    }

    #[cfg(feature = "net-test")]
    #[tokio::test]
    async fn srv() -> Result<()> {
        let domain = "burtrum.org";
        let is_c2s = true;
        let (srvs, cert_verifier) = get_xmpp_connections(domain, is_c2s).await?;
        println!("cert_verifier: {:?}", cert_verifier);
        for srv in srvs {
            println!("trying 1 domain {}, SRV: {:?}", domain, srv);
            let ips = RESOLVER.lookup_ip(srv.target.clone()).await?;
            for ip in ips.iter() {
                println!("trying domain {}, ip {}, is_c2s: {}, SRV: {:?}", domain, ip, is_c2s, srv);
            }
        }
        Ok(())
    }

    #[cfg(feature = "net-test")]
    #[tokio::test]
    async fn http() -> Result<()> {
        let mut hosts = Vec::new();
        let mut sha256_pinnedpubkeys = Vec::new();
        let res = collect_host_meta(&mut hosts, &mut sha256_pinnedpubkeys, "burtrum.org", true).await;
        println!("burtrum.org res: {:?}", res);
        println!("burtrum.org hosts: {:?}", hosts);
        println!("burtrum.org hosts: {:?}", sha256_pinnedpubkeys);
        Ok(())
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn test_parse_host_meta() -> Result<()> {
        let xrd = br#"<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'><Link rel='urn:xmpp:alt-connections:xbosh' href='https://burtrum.org/http-bind'/><Link rel='urn:xmpp:alt-connections:websocket' href='wss://burtrum.org/xmpp-websocket'/></XRD>"#;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:websocket", xrd).await?, vec!["wss://burtrum.org/xmpp-websocket"]);

        let xrd = br#"<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0"><Link rel="urn:xmpp:alt-connections:xbosh" href="https://burtrum.org/http-bind"/><Link rel="urn:xmpp:alt-connections:websocket" href="wss://burtrum.org/xmpp-websocket"/></XRD>"#;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:websocket", xrd).await?, vec!["wss://burtrum.org/xmpp-websocket"]);

        let xrd = br#"<xrd xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'><link rel='urn:xmpp:alt-connections:xbosh' href='https://burtrum.org/http-bind'/><link rel='urn:xmpp:alt-connections:websocket' href='wss://burtrum.org/xmpp-websocket'/></xrd>"#;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:websocket", xrd).await?, vec!["wss://burtrum.org/xmpp-websocket"]);

        let xrd = br#"<xrd xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0"><link rel="urn:xmpp:alt-connections:xbosh" href="https://burtrum.org/http-bind"/><link rel="urn:xmpp:alt-connections:websocket" href="wss://burtrum.org/xmpp-websocket"/></xrd>"#;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:websocket", xrd).await?, vec!["wss://burtrum.org/xmpp-websocket"]);

        let xrd = br#"<xrd xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0"><link rel="urn:xmpp:alt-connections:xbosh" href="https://burtrum.org/http-bind"/><link rel="urn:xmpp:alt-connections:websocket" href="wss://burtrum.org/xmpp-websocket"/><link rel="urn:xmpp:alt-connections:s2s-websocket" href="wss://burtrum.org/xmpp-websocket-s2s"/></xrd>"#;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:s2s-websocket", xrd).await?, vec!["wss://burtrum.org/xmpp-websocket-s2s"]);

        let xrd = br#"<xrd xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0"><link rel="urn:xmpp:alt-connections:xbosh" href="https://burtrum.org/http-bind"/><link rel="urn:xmpp:alt-connections:websocket" href="wss://burtrum.org/xmpp-websocket"/><link rel="urn:xmpp:alt-connections:s2s-websocket" href="wss://burtrum.org/xmpp-websocket-s2s"/></xrd>"#;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:websocket", xrd).await?, vec!["wss://burtrum.org/xmpp-websocket"]);

        let xrd = read_file("contrib/host-meta/xep-0156-current.xml")?;
        assert_eq!(parse_host_meta_xml("urn:xmpp:alt-connections:websocket", &xrd).await?, vec!["wss://example.org/xmpp-websocket"]);
        Ok(())
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn test_parse_host_meta_json() -> Result<()> {
        let xrd = read_file("contrib/host-meta/xep-0156-minimal.json")?;
        let host_meta: HostMeta = serde_json::from_slice(&xrd)?;
        println!("host_meta: {:?}", host_meta);
        //assert_eq!(host_meta.links("urn:xmpp:alt-connections:websocket"), vec!["wss://example.org/xmpp-websocket"]);

        let xrd = read_file("contrib/host-meta/xep-0156-current.json")?;
        let host_meta: HostMeta = serde_json::from_slice(&xrd)?;
        println!("host_meta: {:?}", host_meta);
        //assert_eq!(host_meta.links("urn:xmpp:alt-connections:websocket"), vec!["wss://example.org/xmpp-websocket"]);

        let xrd = read_file("contrib/host-meta/xep-0156-proposed.json")?;
        let host_meta: HostMeta = serde_json::from_slice(&xrd)?;
        println!("host_meta: {:?}", host_meta);
        //assert_eq!(host_meta.links("urn:xmpp:alt-connections:websocket"), vec!["wss://example.org/xmpp-websocket"]);
        Ok(())
    }

    #[test]
    fn test_dedup() {
        let domain = "example.org";
        let mut ret = vec![
            XmppConnection {
                priority: 10,
                weight: 0,
                target: domain.to_string(),
                conn_type: XmppConnectionType::DirectTLS,
                port: 443,
                secure: false,
                ips: Vec::new(),
                ech: None,
            },
            XmppConnection {
                priority: 0,
                weight: 0,
                target: domain.to_string(),
                conn_type: XmppConnectionType::StartTLS,
                port: 5222,
                secure: false,
                ips: Vec::new(),
                ech: None,
            },
            XmppConnection {
                priority: 15,
                weight: 0,
                target: domain.to_string(),
                conn_type: XmppConnectionType::DirectTLS,
                port: 443,
                secure: true,
                ips: Vec::new(),
                ech: None,
            },
            XmppConnection {
                priority: 10,
                weight: 0,
                target: domain.to_string(),
                conn_type: XmppConnectionType::DirectTLS,
                port: 443,
                secure: true,
                ips: Vec::new(),
                ech: None,
            },
            XmppConnection {
                priority: 10,
                weight: 50,
                target: domain.to_string(),
                conn_type: XmppConnectionType::DirectTLS,
                port: 443,
                secure: true,
                ips: Vec::new(),
                ech: None,
            },
            XmppConnection {
                priority: 10,
                weight: 100,
                target: "example.com".to_string(),
                conn_type: XmppConnectionType::DirectTLS,
                port: 443,
                secure: true,
                ips: Vec::new(),
                ech: None,
            },
            XmppConnection {
                priority: 0,
                weight: 100,
                target: "example.com".to_string(),
                conn_type: XmppConnectionType::DirectTLS,
                port: 443,
                secure: true,
                ips: Vec::new(),
                ech: None,
            },
        ];
        sort_dedup(&mut ret);
        println!("ret dedup: {:?}", ret);
    }
}
