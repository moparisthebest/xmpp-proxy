use quinn::{udp, AsyncUdpSocket};

use std::{
    io,
    task::{Context, Poll},
};
use tokio::net::UnixDatagram;

use tokio::io::Interest;

macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub fn wrap_unix_udp_socket(sock: std::os::unix::net::UnixDatagram) -> io::Result<UnixUdpSocket> {
    udp::UdpSocketState::configure((&sock).into())?;
    Ok(UnixUdpSocket {
        io: UnixDatagram::from_std(sock)?,
        inner: udp::UdpSocketState::new(),
    })
}

#[derive(Debug)]
pub struct UnixUdpSocket {
    io: UnixDatagram,
    inner: udp::UdpSocketState,
}

impl AsyncUdpSocket for UnixUdpSocket {
    fn poll_send(&self, state: &udp::UdpState, cx: &mut Context, transmits: &[udp::Transmit]) -> Poll<io::Result<usize>> {
        let inner = &self.inner;
        let io = &self.io;
        loop {
            ready!(io.poll_send_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::WRITABLE, || inner.send(io.into(), state, transmits)) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [std::io::IoSliceMut<'_>], meta: &mut [udp::RecvMeta]) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(res) = self.io.try_io(Interest::READABLE, || self.inner.recv((&self.io).into(), bufs, meta)) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        // todo: real SocketAddr
        Ok("127.0.0.1:0".parse().expect("this one is hardcoded and fine"))
    }

    fn may_fragment(&self) -> bool {
        udp::may_fragment()
    }
}
