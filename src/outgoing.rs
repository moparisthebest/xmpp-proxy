use crate::*;

async fn handle_outgoing_connection(stream: tokio::net::TcpStream, client_addr: &mut Context<'_>, max_stanza_size_bytes: usize) -> Result<()> {
    info!("{} connected", client_addr.log_from());

    let in_filter = StanzaFilter::new(max_stanza_size_bytes);

    let (in_rd, mut in_wr) = tokio::io::split(stream);

    // we naively read 1 byte at a time, which buffering significantly speeds up
    //let in_rd = tokio::io::BufReader::with_capacity(IN_BUFFER_SIZE, in_rd);

    // now read to figure out client vs server
    let (stream_open, is_c2s, in_rd, mut in_filter) = stream_preamble(StanzaReader(in_rd), client_addr, in_filter).await?;
    client_addr.set_c2s_stream_open(is_c2s, &stream_open);
    // pull raw reader back out of StanzaReader
    let mut in_rd = in_rd.0;

    // we require a valid to= here or we fail
    let to = std::str::from_utf8(stream_open.extract_between(b" to='", b"'").or_else(|_| stream_open.extract_between(b" to=\"", b"\""))?)?;

    let (mut out_wr, mut out_rd, stream_open) = srv_connect(to, is_c2s, &stream_open, &mut in_filter, client_addr).await?;
    // send server response to client
    in_wr.write_all(&stream_open).await?;
    in_wr.flush().await?;
    drop(stream_open);

    let mut out_buf = [0u8; OUT_BUFFER_SIZE];

    loop {
        tokio::select! {
        Ok(buf) = out_rd.next(&mut in_filter) => {
            match buf {
                None => break,
                Some(buf) => {
                    trace!("{} '{}'", client_addr.log_to(), to_str(buf));
                    in_wr.write_all(buf).await?;
                    in_wr.flush().await?;
                }
            }
        },
        // we could filter outgoing from-client stanzas by size here too by doing same as above
        // but instead, we'll just send whatever the client sends as it sends it...
        Ok(n) = in_rd.read(&mut out_buf) => {
            if n == 0 {
                break;
            }
            trace!("{} '{}'", client_addr.log_from(), to_str(&out_buf[0..n]));
            out_wr.write_all(&out_buf[0..n]).await?;
            out_wr.flush().await?;
        },
        }
    }

    info!("{} disconnected", client_addr.log_from());
    Ok(())
}

pub fn spawn_outgoing_listener(local_addr: SocketAddr, max_stanza_size_bytes: usize) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(&local_addr).await.die("cannot listen on port/interface");
        loop {
            let (stream, client_addr) = listener.accept().await?;
            tokio::spawn(async move {
                let mut client_addr = Context::new("unk-out", client_addr);
                if let Err(e) = handle_outgoing_connection(stream, &mut client_addr, max_stanza_size_bytes).await {
                    error!("{} {}", client_addr.log_from(), e);
                }
            });
        }
        #[allow(unreachable_code)]
        Ok(())
    })
}
