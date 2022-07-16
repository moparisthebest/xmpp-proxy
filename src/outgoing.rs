use crate::*;

async fn handle_outgoing_connection(stream: tokio::net::TcpStream, client_addr: &mut Context<'_>, config: OutgoingConfig) -> Result<()> {
    info!("{} connected", client_addr.log_from());

    let mut in_filter = StanzaFilter::new(config.max_stanza_size_bytes);

    #[cfg(feature = "websocket")]
    let (mut in_rd, mut in_wr) = if first_bytes_match(&stream, &mut in_filter.buf[0..3], |p| p == b"GET").await? {
        incoming_websocket_connection(Box::new(stream), config.max_stanza_size_bytes).await?
    } else {
        let (in_rd, in_wr) = tokio::io::split(stream);
        (StanzaRead::new(in_rd), StanzaWrite::new(in_wr))
    };

    #[cfg(not(feature = "websocket"))]
    let (mut in_rd, mut in_wr) = {
        let (in_rd, in_wr) = tokio::io::split(stream);
        (StanzaRead::new(in_rd), StanzaWrite::new(in_wr))
    };

    // now read to figure out client vs server
    let (stream_open, is_c2s) = stream_preamble(&mut in_rd, &mut in_wr, client_addr.log_to(), &mut in_filter).await?;
    client_addr.set_c2s_stream_open(is_c2s, &stream_open);

    // we require a valid to= here or we fail
    let to = std::str::from_utf8(stream_open.extract_between(b" to='", b"'").or_else(|_| stream_open.extract_between(b" to=\"", b"\""))?)?;

    let max_stanza_size_bytes = config.max_stanza_size_bytes;
    let (out_wr, out_rd, stream_open) = srv_connect(to, is_c2s, &stream_open, &mut in_filter, client_addr, config).await?;
    // send server response to client
    in_wr.write_all(is_c2s, &stream_open, 0, client_addr.log_from()).await?;
    in_wr.flush().await?;
    drop(stream_open);

    shuffle_rd_wr_filter_only(in_rd, in_wr, out_rd, out_wr, is_c2s, max_stanza_size_bytes, client_addr, in_filter).await
}

pub fn spawn_outgoing_listener(local_addr: SocketAddr, config: OutgoingConfig) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&local_addr).await.die("cannot listen on port/interface");
        loop {
            let (stream, client_addr) = listener.accept().await?;
            let config = config.clone();
            tokio::spawn(async move {
                let mut client_addr = Context::new("unk-out", client_addr);
                if let Err(e) = handle_outgoing_connection(stream, &mut client_addr, config).await {
                    error!("{} {}", client_addr.log_from(), e);
                }
            });
        }
    })
}
