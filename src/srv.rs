#![allow(clippy::upper_case_acronyms)]

use std::convert::TryFrom;
use std::net::SocketAddr;

use data_encoding::BASE64;
use ring::digest::{Algorithm, Context as DigestContext, SHA256, SHA512};

use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::{SrvLookup, TxtLookup};
use trust_dns_resolver::{IntoName, TokioAsyncResolver};

use anyhow::{bail, Result};
use tokio_rustls::webpki::DnsName;
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::http::Uri;

use crate::*;

lazy_static::lazy_static! {
    static ref RESOLVER: TokioAsyncResolver = make_resolver();
}

fn make_resolver() -> TokioAsyncResolver {
    let (config, mut options) = trust_dns_resolver::system_conf::read_system_conf().unwrap();
    options.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    TokioAsyncResolver::tokio(config, options).unwrap()
}

#[derive(Clone, Debug, PartialEq)]
pub enum XmppConnectionType {
    StartTLS,
    DirectTLS,
    #[cfg(feature = "quic")]
    QUIC,
    #[cfg(feature = "websocket")]
    WebSocket(Uri, String, bool),
}

#[derive(Debug)]
pub struct XmppConnection {
    conn_type: XmppConnectionType,
    priority: u16,
    #[allow(dead_code)]
    weight: u16, // todo: use weight
    port: u16,
    target: String,
}

impl XmppConnection {
    pub async fn connect(
        &self,
        domain: &str,
        stream_open: &[u8],
        in_filter: &mut crate::StanzaFilter,
        client_addr: &mut Context<'_>,
        config: OutgoingVerifierConfig,
    ) -> Result<(StanzaWrite, StanzaRead, SocketAddr, &'static str)> {
        debug!("{} attempting connection to SRV: {:?}", client_addr.log_from(), self);
        // todo: need to set options to Ipv4AndIpv6
        let ips = RESOLVER.lookup_ip(self.target.clone()).await?;
        for ip in ips.iter() {
            let to_addr = SocketAddr::new(ip, self.port);
            debug!("{} trying ip {}", client_addr.log_from(), to_addr);
            // todo: for DNSSEC we need to optionally allow target in addition to domain, but what for SNI
            match self.conn_type {
                XmppConnectionType::StartTLS => match crate::starttls_connect(to_addr, domain, stream_open, in_filter, config.clone()).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "starttls-out")),
                    Err(e) => error!("starttls connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                XmppConnectionType::DirectTLS => match crate::tls_connect(to_addr, domain, config.clone()).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "directtls-out")),
                    Err(e) => error!("direct tls connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "quic")]
                XmppConnectionType::QUIC => match crate::quic_connect(to_addr, domain, config.clone()).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "quic-out")),
                    Err(e) => error!("quic connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "websocket")]
                // todo: when websocket is found via DNS, we need to validate cert against domain, *not* target, this is a security problem with XEP-0156, we are doing it the secure but likely unexpected way here for now
                XmppConnectionType::WebSocket(ref url, ref origin, ref secure) => {
                    match crate::websocket_connect(to_addr, if *secure { &self.target } else { domain }, url, origin, config.clone()).await {
                        Ok((wr, rd)) => return Ok((wr, rd, to_addr, "websocket-out")),
                        Err(e) => error!("websocket connection failed to IP {} from TXT {}, error: {}", to_addr, url, e),
                    }
                }
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
        conn_type: XmppConnectionType::WebSocket(url, origin, secure),
        priority: u16::MAX,
        weight: 0,
        port,
        target,
    })
}

#[cfg(feature = "websocket")]
fn collect_txts(ret: &mut Vec<XmppConnection>, secure_urls: Vec<String>, txt_records: std::result::Result<TxtLookup, ResolveError>, is_c2s: bool) {
    if let Ok(txt_records) = txt_records {
        for txt in txt_records.iter() {
            for txt in txt.iter() {
                // we only support wss and not ws (insecure) on purpose
                if txt.starts_with(if is_c2s { b"_xmpp-client-websocket=wss://" } else { b"_xmpp-server-websocket=wss://" }) {
                    // 23 is the length of "_xmpp-client-websocket=" and "_xmpp-server-websocket="
                    if let Ok(url) = String::from_utf8(txt[23..].to_vec()) {
                        if !secure_urls.contains(&url) {
                            if let Some(srv) = wss_to_srv(&url, false) {
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
    let (starttls, direct_tls, quic, websocket_txt, websocket_rel) = if is_c2s {
        ("_xmpp-client._tcp", "_xmpps-client._tcp", "_xmppq-client._udp", "_xmppconnect", "urn:xmpp:alt-connections:websocket")
    } else {
        (
            "_xmpp-server._tcp",
            "_xmpps-server._tcp",
            "_xmppq-server._udp",
            "_xmppconnect-server",
            "urn:xmpp:alt-connections:s2s-websocket",
        )
    };

    let starttls = format!("{}.{}.", starttls, domain).into_name()?;
    let direct_tls = format!("{}.{}.", direct_tls, domain).into_name()?;
    #[cfg(feature = "quic")]
    let quic = format!("{}.{}.", quic, domain).into_name()?;
    #[cfg(feature = "websocket")]
    let websocket_txt = format!("{}.{}.", websocket_txt, domain).into_name()?;

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
        collect_host_meta(domain, websocket_rel),
        collect_posh(domain),
    );

    let mut ret = Vec::new();
    collect_srvs(&mut ret, starttls, XmppConnectionType::StartTLS);
    collect_srvs(&mut ret, direct_tls, XmppConnectionType::DirectTLS);
    #[cfg(feature = "quic")]
    collect_srvs(&mut ret, quic, XmppConnectionType::QUIC);
    #[cfg(feature = "websocket")]
    {
        let urls = websocket_host.unwrap_or_default();
        for url in &urls {
            if let Some(url) = wss_to_srv(url, true) {
                ret.push(url);
            }
        }
        collect_txts(&mut ret, urls, websocket_txt, is_c2s);
    }
    ret.sort_by(|a, b| a.priority.cmp(&b.priority));
    // todo: do something with weight

    #[allow(clippy::single_match)]
    for srv in &ret {
        match srv.conn_type {
            #[cfg(feature = "websocket")]
            XmppConnectionType::WebSocket(_, _, ref secure) => {
                if *secure {
                    if let Ok(target) = DnsNameRef::try_from_ascii_str(srv.target.as_str()) {
                        let target = target.to_owned();
                        if !valid_tls_cert_server_names.contains(&target) {
                            valid_tls_cert_server_names.push(target);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let cert_verifier = XmppServerCertVerifier::new(valid_tls_cert_server_names, posh.ok());

    if ret.is_empty() {
        // default starttls ports
        ret.push(XmppConnection {
            priority: 0,
            weight: 0,
            target: domain.to_string(),
            conn_type: XmppConnectionType::StartTLS,
            port: if is_c2s { 5222 } else { 5269 },
        });
        // by spec there are no default direct/quic ports, but we are going 443
        ret.push(XmppConnection {
            priority: 0,
            weight: 0,
            target: domain.to_string(),
            conn_type: XmppConnectionType::DirectTLS,
            port: 443,
        });
        #[cfg(feature = "quic")]
        ret.push(XmppConnection {
            priority: 0,
            weight: 0,
            target: domain.to_string(),
            conn_type: XmppConnectionType::QUIC,
            port: 443,
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

pub async fn srv_connect(
    domain: &str,
    is_c2s: bool,
    stream_open: &[u8],
    in_filter: &mut crate::StanzaFilter,
    client_addr: &mut Context<'_>,
    config: OutgoingConfig,
) -> Result<(StanzaWrite, StanzaRead, Vec<u8>)> {
    let (srvs, cert_verifier) = get_xmpp_connections(domain, is_c2s).await?;
    let config = config.with_custom_certificate_verifier(is_c2s, cert_verifier);
    for srv in srvs {
        let connect = srv.connect(domain, stream_open, in_filter, client_addr, config.clone()).await;
        if connect.is_err() {
            continue;
        }
        let (mut out_wr, mut out_rd, to_addr, proto) = connect.unwrap();
        // if any of these ? returns early with an Err, these will stay set, I think that's ok though, the connection will be closed
        client_addr.set_proto(proto);
        client_addr.set_to_addr(to_addr);
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
async fn collect_host_meta(domain: &str, rel: &str) -> Result<Vec<String>> {
    bail!("websocket disabled")
}

#[cfg(feature = "websocket")]
async fn collect_host_meta(domain: &str, rel: &str) -> Result<Vec<String>> {
    match tokio::join!(collect_host_meta_xml(domain, rel), collect_host_meta_json(domain, rel)) {
        (Ok(mut xml), Ok(json)) => {
            combine_uniq(&mut xml, json);
            Ok(xml)
        }
        (_, Ok(json)) => Ok(json),
        (xml, _) => xml,
    }
}

#[cfg(feature = "websocket")]
async fn collect_host_meta_json(domain: &str, rel: &str) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct HostMeta {
        links: Vec<Link>,
    }
    #[derive(Deserialize)]
    struct Link {
        rel: String,
        href: String,
    }

    let url = format!("https://{}/.well-known/host-meta.json", domain);
    let resp = https_get(&url).await?;
    if resp.status().is_success() {
        let resp = resp.json::<HostMeta>().await?;
        // we will only support wss:// (TLS) not ws:// (plain text)
        Ok(resp.links.iter().filter(|l| l.rel == rel && l.href.starts_with("wss://")).map(|l| l.href.clone()).collect())
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
async fn collect_host_meta_xml(domain: &str, rel: &str) -> Result<Vec<String>> {
    let url = format!("https://{}/.well-known/host-meta", domain);
    let resp = https_get(&url).await?;
    if resp.status().is_success() {
        parse_host_meta_xml(rel, resp.bytes().await?.as_ref()).await
    } else {
        bail!("failed with status code {} for url {}", resp.status(), url)
    }
}

pub async fn https_get<T: reqwest::IntoUrl>(url: T) -> reqwest::Result<reqwest::Response> {
    // todo: resolve URL with our resolver
    reqwest::Client::builder().https_only(true).build()?.get(url).send().await
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

fn digest(algorithm: &'static Algorithm, buf: &[u8]) -> String {
    let mut context = DigestContext::new(algorithm);
    context.update(buf);
    let digest = context.finish();
    BASE64.encode(digest.as_ref())
}

#[cfg(test)]
mod tests {
    use crate::srv::*;

    fn valid_posh(posh: &[u8], cert: &[u8]) -> bool {
        let posh: PoshJson = serde_json::from_slice(&posh[..]).unwrap();
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

    //#[tokio::test]
    async fn posh() -> Result<()> {
        let domain = "posh.badxmpp.eu";
        let posh = collect_posh(domain).await.unwrap();
        println!("posh for domain {}: {:?}", domain, posh);
        Ok(())
    }

    //#[tokio::test]
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

    #[cfg(feature = "websocket")]
    //#[tokio::test]
    async fn http() -> Result<()> {
        let hosts = collect_host_meta_json("burtrum.org", "urn:xmpp:alt-connections:websocket").await?;
        println!("{:?}", hosts);
        let hosts = collect_host_meta_xml("burtrum.org", "urn:xmpp:alt-connections:websocket").await?;
        println!("{:?}", hosts);
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

        Ok(())
    }
}
