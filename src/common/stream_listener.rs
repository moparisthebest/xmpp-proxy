use crate::common::AsyncReadWritePeekSplit;
use anyhow::Result;
use async_trait::async_trait;
use std::io::{Error, IoSlice};

use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(not(target_os = "windows"))]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufStream, ReadBuf},
    net::{TcpListener, TcpStream},
};

#[async_trait]
pub trait StreamListener: Send + Sync + 'static {
    type Stream: AsyncReadWritePeekSplit;
    async fn accept(&self) -> Result<(Self::Stream, SocketAddr)>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

#[async_trait]
impl StreamListener for TcpListener {
    type Stream = TcpStream;
    async fn accept(&self) -> Result<(Self::Stream, SocketAddr)> {
        Ok(self.accept().await?)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr()?)
    }
}

#[cfg(not(target_os = "windows"))]
#[async_trait]
impl StreamListener for UnixListener {
    type Stream = BufStream<UnixStream>;
    async fn accept(&self) -> Result<(Self::Stream, SocketAddr)> {
        let (stream, _client_addr) = self.accept().await?;
        // todo: real SocketAddr
        let client_addr: SocketAddr = "127.0.0.1:0".parse()?;
        Ok((BufStream::new(stream), client_addr))
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // todo: real SocketAddr
        Ok("127.0.0.1:0".parse()?)
    }
}

pub enum AllStream {
    Tcp(TcpStream),
    #[cfg(not(target_os = "windows"))]
    Unix(UnixStream),
}

impl AsyncRead for AllStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            AllStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(not(target_os = "windows"))]
            AllStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AllStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::result::Result<usize, Error>> {
        match self.get_mut() {
            AllStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(not(target_os = "windows"))]
            AllStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Error>> {
        match self.get_mut() {
            AllStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(not(target_os = "windows"))]
            AllStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Error>> {
        match self.get_mut() {
            AllStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(not(target_os = "windows"))]
            AllStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<std::result::Result<usize, Error>> {
        match self.get_mut() {
            AllStream::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(not(target_os = "windows"))]
            AllStream::Unix(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            AllStream::Tcp(s) => s.is_write_vectored(),
            #[cfg(not(target_os = "windows"))]
            AllStream::Unix(s) => s.is_write_vectored(),
        }
    }
}
