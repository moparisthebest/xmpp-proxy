#![allow(clippy::upper_case_acronyms)]

use std::convert::TryFrom;
use std::net::SocketAddr;

use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::{SrvLookup, TxtLookup};
use trust_dns_resolver::{IntoName, TokioAsyncResolver};

use anyhow::{bail, Result};
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
    WebSocket(Uri, String),
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
        is_c2s: bool,
        stream_open: &[u8],
        in_filter: &mut crate::StanzaFilter,
        client_addr: &mut Context<'_>,
    ) -> Result<(StanzaWrite, StanzaRead, SocketAddr, &'static str)> {
        debug!("{} attempting connection to SRV: {:?}", client_addr.log_from(), self);
        // todo: need to set options to Ipv4AndIpv6
        let ips = RESOLVER.lookup_ip(self.target.clone()).await?;
        for ip in ips.iter() {
            let to_addr = SocketAddr::new(ip, self.port);
            debug!("{} trying ip {}", client_addr.log_from(), to_addr);
            // todo: for DNSSEC we need to optionally allow target in addition to domain, but what for SNI
            match self.conn_type {
                XmppConnectionType::StartTLS => match crate::starttls_connect(to_addr, domain, is_c2s, stream_open, in_filter).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "starttls-out")),
                    Err(e) => error!("starttls connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                XmppConnectionType::DirectTLS => match crate::tls_connect(to_addr, domain, is_c2s).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "directtls-out")),
                    Err(e) => error!("direct tls connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "quic")]
                XmppConnectionType::QUIC => match crate::quic_connect(to_addr, domain, is_c2s).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "quic-out")),
                    Err(e) => error!("quic connection failed to IP {} from SRV {}, error: {}", to_addr, self.target, e),
                },
                #[cfg(feature = "websocket")]
                // todo: when websocket is found via DNS, we need to validate cert against domain, *not* target, this is a security problem with XEP-0156, we are doing it the secure but likely unexpected way here for now
                XmppConnectionType::WebSocket(ref url, ref origin) => match crate::websocket_connect(to_addr, domain, url, origin, is_c2s).await {
                    Ok((wr, rd)) => return Ok((wr, rd, to_addr, "websocket-out")),
                    Err(e) => error!("websocket connection failed to IP {} from TXT {}, error: {}", to_addr, url, e),
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
                });
            }
        }
    }
}

#[cfg(feature = "websocket")]
fn collect_txts(ret: &mut Vec<XmppConnection>, txt_records: std::result::Result<TxtLookup, ResolveError>, is_c2s: bool) {
    if let Ok(txt_records) = txt_records {
        for txt in txt_records.iter() {
            for txt in txt.iter() {
                // we only support wss and not ws (insecure) on purpose
                if txt.starts_with(if is_c2s { b"_xmpp-client-websocket=wss://" } else { b"_xmpp-server-websocket=wss://" }) {
                    // 23 is the length of "_xmpp-client-websocket=" and "_xmpp-server-websocket="
                    let url = &txt[23..];
                    let url = match Uri::try_from(url) {
                        Ok(url) => url,
                        Err(e) => {
                            debug!("invalid TXT record '{}', {}", to_str(txt), e);
                            continue;
                        }
                    };
                    let server_name = match url.host() {
                        Some(server_name) => server_name.to_string(),
                        None => {
                            debug!("invalid TXT record '{}'", to_str(txt));
                            continue;
                        }
                    };
                    let target = server_name.clone().to_string();

                    let mut origin = "https://".to_string();
                    origin.push_str(&server_name);
                    let port = if let Some(port) = url.port() {
                        origin.push(':');
                        origin.push_str(port.as_str());
                        port.as_u16()
                    } else {
                        443
                    };
                    ret.push(XmppConnection {
                        conn_type: XmppConnectionType::WebSocket(url, origin),
                        priority: u16::MAX,
                        weight: 0,
                        port,
                        target,
                    });
                }
            }
        }
    }
}

pub async fn get_xmpp_connections(domain: &str, is_c2s: bool) -> Result<Vec<XmppConnection>> {
    let (starttls, direct_tls, quic, websocket) = if is_c2s {
        ("_xmpp-client._tcp", "_xmpps-client._tcp", "_xmppq-client._udp", "_xmppconnect")
    } else {
        ("_xmpp-server._tcp", "_xmpps-server._tcp", "_xmppq-server._udp", "_xmppconnect-server")
    };

    let starttls = format!("{}.{}.", starttls, domain).into_name()?;
    let direct_tls = format!("{}.{}.", direct_tls, domain).into_name()?;
    #[cfg(feature = "quic")]
    let quic = format!("{}.{}.", quic, domain).into_name()?;
    #[cfg(feature = "websocket")]
    let websocket = format!("{}.{}.", websocket, domain).into_name()?;

    // this lets them run concurrently but not in parallel, could spawn parallel tasks but... worth it ?
    // todo: don't look up websocket or quic records when they are disabled
    let (
        starttls,
        direct_tls,
        //#[cfg(feature = "quic")]
        quic,
        //#[cfg(feature = "websocket")]
        websocket,
    ) = tokio::join!(
        RESOLVER.srv_lookup(starttls),
        RESOLVER.srv_lookup(direct_tls),
        //#[cfg(feature = "quic")]
        RESOLVER.srv_lookup(quic),
        //#[cfg(feature = "websocket")]
        RESOLVER.txt_lookup(websocket),
    );

    let mut ret = Vec::new();
    collect_srvs(&mut ret, starttls, XmppConnectionType::StartTLS);
    collect_srvs(&mut ret, direct_tls, XmppConnectionType::DirectTLS);
    #[cfg(feature = "quic")]
    collect_srvs(&mut ret, quic, XmppConnectionType::QUIC);
    #[cfg(feature = "websocket")]
    collect_txts(&mut ret, websocket, is_c2s);
    ret.sort_by(|a, b| a.priority.cmp(&b.priority));
    // todo: do something with weight

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

    Ok(ret)
}

pub async fn srv_connect(domain: &str, is_c2s: bool, stream_open: &[u8], in_filter: &mut crate::StanzaFilter, client_addr: &mut Context<'_>) -> Result<(StanzaWrite, StanzaRead, Vec<u8>)> {
    for srv in get_xmpp_connections(domain, is_c2s).await? {
        let connect = srv.connect(domain, is_c2s, stream_open, in_filter, client_addr).await;
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

#[cfg(test)]
mod tests {
    use crate::srv::*;

    #[tokio::test]
    async fn srv() -> Result<()> {
        let domain = "burtrum.org";
        let is_c2s = true;
        for srv in get_xmpp_connections(domain, is_c2s).await? {
            println!("trying 1 domain {}, SRV: {:?}", domain, srv);
            #[cfg(feature = "websocket")]
            if srv.conn_type == XmppConnectionType::WebSocket {
                continue;
            }
            let ips = RESOLVER.lookup_ip(srv.target.clone()).await?;
            for ip in ips.iter() {
                println!("trying domain {}, ip {}, is_c2s: {}, SRV: {:?}", domain, ip, is_c2s, srv);
            }
        }
        Ok(())
    }
}
