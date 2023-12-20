use crate::{
    common::incoming::{shuffle_rd_wr, IncomingConfig, ServerCerts},
    context::Context,
    in_out::{StanzaRead, StanzaWrite},
};

use log::{error, info};
use std::{net::SocketAddr, sync::Arc};

pub async fn handle_webtransport_session(conn: quinn::Connection, config: Arc<IncomingConfig>, server_certs: ServerCerts, local_addr: SocketAddr, mut client_addr: Context<'static>) {
    client_addr.set_proto("webtransport-in");

    // Perform the WebTransport handshake.
    let request = match webtransport_quinn::accept(conn).await {
        Ok(r) => r,
        Err(e) => {
            error!("{} {}", client_addr.log_from(), e);
            return;
        }
    };
    info!("{} received request URL: {}", client_addr.log_from(), request.url());

    // Accept the session.
    let session = match request.ok().await {
        Ok(r) => r,
        Err(e) => {
            error!("{} {}", client_addr.log_from(), e);
            return;
        }
    };
    info!("{} connected new session", client_addr.log_from());

    while let Ok((wrt, rd)) = session.accept_bi().await {
        let config = config.clone();
        let mut client_addr = client_addr.clone();
        let server_certs = server_certs.clone();
        info!("{} connected new stream", client_addr.log_from());
        tokio::spawn(async move {
            if let Err(e) = shuffle_rd_wr(StanzaRead::new(rd), StanzaWrite::new(wrt), config, server_certs, local_addr, &mut client_addr).await {
                error!("{} {}", client_addr.log_from(), e);
            }
        });
    }
}
