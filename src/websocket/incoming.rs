use crate::{
    common::{
        incoming::{shuffle_rd_wr_filter, IncomingConfig, ServerCerts},
        BoxAsyncReadWrite,
    },
    context::Context,
    stanzafilter::StanzaFilter,
    websocket::incoming_websocket_connection,
};
use anyhow::Result;
use log::info;
use std::{net::SocketAddr, sync::Arc};

pub async fn handle_websocket_connection(
    stream: BoxAsyncReadWrite,
    config: Arc<IncomingConfig>,
    server_certs: ServerCerts,
    local_addr: SocketAddr,
    client_addr: &mut Context<'_>,
    in_filter: StanzaFilter,
) -> Result<()> {
    client_addr.set_proto("websocket-in");
    info!("{} connected", client_addr.log_from());

    let (in_rd, in_wr) = incoming_websocket_connection(stream, config.max_stanza_size_bytes).await?;

    shuffle_rd_wr_filter(in_rd, in_wr, config, server_certs, local_addr, client_addr, in_filter).await
}
