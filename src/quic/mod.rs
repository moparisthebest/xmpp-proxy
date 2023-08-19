use crate::{
    common::Split,
    in_out::{StanzaRead, StanzaWrite},
};
use anyhow::bail;
use quinn::{RecvStream, SendStream};
use std::{
    io::Error,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "incoming")]
pub mod incoming;

#[cfg(feature = "outgoing")]
pub mod outgoing;

#[cfg(all(feature = "incoming", not(target_os = "windows")))]
pub mod unix_datagram;

pub struct QuicStream {
    pub send: SendStream,
    pub recv: RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

impl Split for QuicStream {
    type ReadHalf = RecvStream;
    type WriteHalf = SendStream;

    fn combine(recv: Self::ReadHalf, send: Self::WriteHalf) -> anyhow::Result<Self> {
        if recv.id() != send.id() {
            bail!("ids do not match")
        } else {
            Ok(Self { recv, send })
        }
    }

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        (self.recv, self.send)
    }

    fn stanza_rw(self) -> (StanzaRead, StanzaWrite) {
        (StanzaRead::new(self.recv), StanzaWrite::new(self.send))
    }
}
