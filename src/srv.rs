use std::net::SocketAddr;

use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup::SrvLookup;
use trust_dns_resolver::{IntoName, TokioAsyncResolver};

use anyhow::{bail, Result};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::stanzafilter::StanzaReader;
use crate::*;

lazy_static::lazy_static! {
    static ref RESOLVER: TokioAsyncResolver = make_resolver();
}

fn make_resolver() -> TokioAsyncResolver {
    let (config, mut options) = trust_dns_resolver::system_conf::read_system_conf().unwrap();
    options.ip_strategy = trust_dns_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    TokioAsyncResolver::tokio(config, options).unwrap()
}

#[derive(Copy, Clone, Debug)]
pub enum XmppConnectionType {
    StartTLS,
    DirectTLS,
    #[cfg(feature = "quic")]
    QUIC,
}

#[derive(Debug)]
pub struct XmppConnection {
    conn_type: XmppConnectionType,
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

impl XmppConnection {
    pub async fn connect(
        &self,
        domain: &str,
        is_c2s: bool,
        stream_open: &[u8],
        mut in_filter: &mut crate::StanzaFilter,
    ) -> Result<(Box<dyn AsyncWrite + Unpin + Send>, Box<dyn AsyncRead + Unpin + Send>)> {
        // todo: need to set options to Ipv4AndIpv6
        let ips = RESOLVER.lookup_ip(self.target.clone()).await?;
        debug!("trying 1 domain {}, SRV: {:?}", domain, self);
        for ip in ips.iter() {
            debug!("trying domain {}, ip {}, is_c2s: {}, SRV: {:?}", domain, ip, is_c2s, self);
            match self.conn_type {
                XmppConnectionType::StartTLS => match crate::starttls_connect(SocketAddr::new(ip, self.port), domain, is_c2s, &stream_open, &mut in_filter).await {
                    Ok((wr, rd)) => return Ok((wr, rd)),
                    Err(e) => println!("ERROR: starttls connection failed to IP {} from SRV {}, error: {}", ip, self.target, e),
                },
                XmppConnectionType::DirectTLS => match crate::tls_connect(SocketAddr::new(ip, self.port), domain, is_c2s).await {
                    Ok((wr, rd)) => return Ok((wr, rd)),
                    Err(e) => println!("ERROR: direct tls connection failed to IP {} from SRV {}, error: {}", ip, self.target, e),
                },
                #[cfg(feature = "quic")]
                XmppConnectionType::QUIC => match crate::quic_connect(SocketAddr::new(ip, self.port), domain, is_c2s).await {
                    Ok((wr, rd)) => return Ok((wr, rd)),
                    Err(e) => println!("ERROR: quic connection failed to IP {} from SRV {}, error: {}", ip, self.target, e),
                },
            }
        }
        debug!("trying 2 domain {}, SRV: {:?}", domain, self);
        bail!("cannot connect to any IPs for SRV: {}", self.target)
    }
}

fn collect_srvs(ret: &mut Vec<XmppConnection>, srv_records: std::result::Result<SrvLookup, ResolveError>, conn_type: XmppConnectionType) {
    if let Ok(srv_records) = srv_records {
        for srv in srv_records.iter() {
            if !srv.target().is_root() {
                ret.push(XmppConnection {
                    conn_type,
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    target: srv.target().to_ascii(),
                });
            }
        }
    }
}

pub async fn get_xmpp_connections(domain: &str, is_c2s: bool) -> Result<Vec<XmppConnection>> {
    let (starttls, direct_tls, quic) = if is_c2s {
        ("_xmpp-client._tcp", "_xmpps-client._tcp", "_xmppq-client._udp")
    } else {
        ("_xmpp-server._tcp", "_xmpps-server._tcp", "_xmppq-server._udp")
    };

    let starttls = format!("{}.{}.", starttls, domain).into_name()?;
    let direct_tls = format!("{}.{}.", direct_tls, domain).into_name()?;
    let quic = format!("{}.{}.", quic, domain).into_name()?;

    // this lets them run concurrently but not in parallel, could spawn parallel tasks but... worth it ?
    let (starttls, direct_tls, quic) = tokio::join!(RESOLVER.srv_lookup(starttls), RESOLVER.srv_lookup(direct_tls), RESOLVER.srv_lookup(quic),);

    let mut ret = Vec::new();
    collect_srvs(&mut ret, starttls, XmppConnectionType::StartTLS);
    collect_srvs(&mut ret, direct_tls, XmppConnectionType::DirectTLS);
    #[cfg(feature = "quic")]
    collect_srvs(&mut ret, quic, XmppConnectionType::QUIC);
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

pub async fn srv_connect(
    domain: &str,
    is_c2s: bool,
    stream_open: &[u8],
    mut in_filter: &mut crate::StanzaFilter,
) -> Result<(Box<dyn AsyncWrite + Unpin + Send>, StanzaReader<tokio::io::BufReader<Box<dyn AsyncRead + Unpin + Send>>>, Vec<u8>)> {
    for srv in get_xmpp_connections(&domain, is_c2s).await? {
        debug!("main srv: {:?}", srv);
        let connect = srv.connect(&domain, is_c2s, &stream_open, &mut in_filter).await;
        if connect.is_err() {
            continue;
        }
        let (mut out_wr, out_rd) = connect.unwrap();
        debug!("main srv out: {:?}", srv);

        // we naively read 1 byte at a time, which buffering significantly speeds up
        let mut out_rd = StanzaReader(tokio::io::BufReader::with_capacity(crate::IN_BUFFER_SIZE, out_rd));

        out_wr.write_all(&stream_open).await?;
        out_wr.flush().await?;

        let mut server_response = Vec::new();
        // let's read to first <stream:stream to make sure we are successfully connected to a real XMPP server
        let mut stream_received = false;
        while let Ok(Some(buf)) = out_rd.next(&mut in_filter).await {
            debug!("received pre-tls stanza: {} '{}'", domain, to_str(&buf));
            if buf.starts_with(b"<?xml ") {
                server_response.extend_from_slice(&buf);
            } else if buf.starts_with(b"<stream:stream ") {
                server_response.extend_from_slice(&buf);
                stream_received = true;
                break;
            } else {
                debug!("bad pre-tls stanza: {}", to_str(&buf));
                break;
            }
        }
        if !stream_received {
            debug!("bad server response, going to next record");
            continue;
        }

        return Ok((Box::new(out_wr), out_rd, server_response));
    }
    bail!("all connection attempts failed")
}

#[cfg(test)]
mod tests {
    use crate::srv::*;
    #[tokio::test]
    async fn srv() -> Result<()> {
        let domain = "moparisthebest.com";
        let is_c2s = true;
        for srv in get_xmpp_connections(domain, is_c2s).await? {
            let ips = RESOLVER.lookup_ip(srv.target.clone()).await?;
            debug!("trying 1 domain {}, SRV: {:?}", domain, srv);
            for ip in ips.iter() {
                debug!("trying domain {}, ip {}, is_c2s: {}, SRV: {:?}", domain, ip, is_c2s, srv);
            }
        }
        Ok(())
    }
}
