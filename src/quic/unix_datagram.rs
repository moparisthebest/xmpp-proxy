use quinn::{udp, AsyncUdpSocket, UdpPoller};

use quinn::udp::Transmit;
use std::{
    fmt::Debug,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
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
    Ok(UnixUdpSocket {
        inner: udp::UdpSocketState::new((&sock).into())?,
        io: UnixDatagram::from_std(sock)?,
    })
}

#[derive(Debug)]
pub struct UnixUdpSocket {
    io: UnixDatagram,
    inner: udp::UdpSocketState,
}

impl AsyncUdpSocket for UnixUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(UdpPollHelper::new(move || {
            let socket = self.clone();
            async move { socket.io.writable().await }
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || self.inner.send((&self.io).into(), transmit))
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
}

// This was copy+pasted from quinn/src/runtime.rs to be used above, above maybe should just be upstreamed
pin_project_lite::pin_project! {
    /// Helper adapting a function `MakeFut` that constructs a single-use future `Fut` into a
    /// [`UdpPoller`] that may be reused indefinitely
    struct UdpPollHelper<MakeFut, Fut> {
        make_fut: MakeFut,
        #[pin]
        fut: Option<Fut>,
    }
}

impl<MakeFut, Fut> UdpPollHelper<MakeFut, Fut> {
    /// Construct a [`UdpPoller`] that calls `make_fut` to get the future to poll, storing it until
    /// it yields [`Poll::Ready`], then creating a new one on the next
    /// [`poll_writable`](UdpPoller::poll_writable)
    fn new(make_fut: MakeFut) -> Self {
        Self { make_fut, fut: None }
    }
}

impl<MakeFut, Fut> UdpPoller for UdpPollHelper<MakeFut, Fut>
where
    MakeFut: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = io::Result<()>> + Send + Sync + 'static,
{
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let mut this = self.project();
        if this.fut.is_none() {
            this.fut.set(Some((this.make_fut)()));
        }
        // We're forced to `unwrap` here because `Fut` may be `!Unpin`, which means we can't safely
        // obtain an `&mut Fut` after storing it in `self.fut` when `self` is already behind `Pin`,
        // and if we didn't store it then we wouldn't be able to keep it alive between
        // `poll_writable` calls.
        let result = this.fut.as_mut().as_pin_mut().unwrap().poll(cx);
        if result.is_ready() {
            // Polling an arbitrary `Future` after it becomes ready is a logic error, so arrange for
            // a new `Future` to be created on the next call.
            this.fut.set(None);
        }
        result
    }
}

impl<MakeFut, Fut> Debug for UdpPollHelper<MakeFut, Fut> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPollHelper").finish_non_exhaustive()
    }
}
