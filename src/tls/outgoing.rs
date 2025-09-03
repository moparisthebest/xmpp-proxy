use crate::{
    common::{outgoing::OutgoingVerifierConfig, to_str, IN_BUFFER_SIZE},
    in_out::{StanzaRead, StanzaWrite},
    stanzafilter::{StanzaFilter, StanzaReader},
};
use anyhow::{bail, Result};
use log::{debug, trace};
use rustls::pki_types::ServerName;
use std::{convert::TryFrom, net::SocketAddr};
use tokio::io::AsyncWriteExt;

pub async fn tls_connect(target: SocketAddr, server_name: &str, config: &OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let dnsname = ServerName::try_from(server_name)?.to_owned();
    let stream = tokio::net::TcpStream::connect(target).await?;
    let stream = config.connector_alpn.connect(dnsname, stream).await?;
    let (rd, wrt) = tokio::io::split(stream);
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}

pub async fn starttls_connect(target: SocketAddr, server_name: &str, stream_open: &[u8], in_filter: &mut StanzaFilter, config: &OutgoingVerifierConfig) -> Result<(StanzaWrite, StanzaRead)> {
    let dnsname = ServerName::try_from(server_name)?.to_owned();
    let mut stream = tokio::net::TcpStream::connect(target).await?;
    let (in_rd, mut in_wr) = stream.split();

    // send the stream_open
    trace!("starttls sending: {} '{}'", server_name, to_str(stream_open));
    in_wr.write_all(stream_open).await?;
    in_wr.flush().await?;

    // we naively read 1 byte at a time, which buffering significantly speeds up
    let in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);
    let mut in_rd = StanzaReader(in_rd);
    let mut proceed_received = false;

    trace!("starttls reading stream open {}", server_name);
    while let Ok(Some(buf)) = in_rd.next(in_filter).await {
        trace!("received pre-tls stanza: {} '{}'", server_name, to_str(buf));
        if buf.starts_with(b"<?xml ") || buf.starts_with(b"<stream:stream ") {
            // ignore this
        } else if buf.starts_with(b"<stream:features") {
            // we send starttls regardless, it could have been stripped out, we don't do plaintext
            let buf = br###"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"###;
            trace!("> {} '{}'", server_name, to_str(buf));
            in_wr.write_all(buf).await?;
            in_wr.flush().await?;
        } else if buf.starts_with(b"<proceed ") {
            proceed_received = true;
            break;
        } else {
            bail!("bad pre-tls stanza: {}", to_str(buf));
        }
    }
    if !proceed_received {
        bail!("stream ended before proceed");
    }

    debug!("starttls starting TLS {}", server_name);
    let stream = config.connector.connect(dnsname, stream).await?;
    let (rd, wrt) = tokio::io::split(stream);
    Ok((StanzaWrite::new(wrt), StanzaRead::new(rd)))
}
