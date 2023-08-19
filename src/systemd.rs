use anyhow::{anyhow, bail, Result};
use nix::sys::socket::{getsockname, getsockopt, AddressFamily, SockType, SockaddrLike, SockaddrStorage};
use std::{
    env,
    net::{TcpListener, UdpSocket},
    os::unix::{
        io::{FromRawFd, IntoRawFd, RawFd},
        net::{UnixDatagram, UnixListener},
    },
    process,
};

/// Minimum FD number used by systemd for passing sockets.
const SD_LISTEN_FDS_START: RawFd = 3;

/// File descriptor passed by systemd to socket-activated services.
///
/// See <https://www.freedesktop.org/software/systemd/man/systemd.socket.html>.
#[derive(Debug, Clone)]
pub struct FileDescriptor {
    raw_fd: RawFd,
    tcp_not_udp: bool,
    inet_not_unix: bool,
    pub name: Option<String>,
}

pub enum SystemdListener {
    Tcp(Box<dyn FnOnce() -> TcpListener>),
    Udp(Box<dyn FnOnce() -> UdpSocket>),
    UnixListener(Box<dyn FnOnce() -> UnixListener>),
    UnixDatagram(Box<dyn FnOnce() -> UnixDatagram>),
}

impl FileDescriptor {
    pub fn name(self) -> Option<String> {
        self.name
    }

    pub fn listener(&self) -> SystemdListener {
        let raw_fd = self.raw_fd;
        match (self.tcp_not_udp, self.inet_not_unix) {
            (true, true) => SystemdListener::Tcp(Box::new(move || unsafe { TcpListener::from_raw_fd(raw_fd) })),
            (false, true) => SystemdListener::Udp(Box::new(move || unsafe { UdpSocket::from_raw_fd(raw_fd) })),
            (true, false) => SystemdListener::UnixListener(Box::new(move || unsafe { UnixListener::from_raw_fd(raw_fd) })),
            (false, false) => SystemdListener::UnixDatagram(Box::new(move || unsafe { UnixDatagram::from_raw_fd(raw_fd) })),
        }
    }
}

/// Check for named file descriptors passed by systemd.
///
/// Like `receive_descriptors`, but this will also return a vector of names
/// associated with each file descriptor.
pub fn receive_descriptors_with_names(unset_env: bool) -> Result<Vec<FileDescriptor>> {
    let pid = env::var("LISTEN_PID");
    let fds = env::var("LISTEN_FDS");
    let fdnames = env::var("LISTEN_FDNAMES");
    log::trace!("LISTEN_PID = {:?}; LISTEN_FDS = {:?}; LISTEN_FDNAMES = {:?}", pid, fds, fdnames);

    if unset_env {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
    }

    let pid = pid
        .map_err(|e| anyhow!("failed to get LISTEN_PID: {}", e))?
        .parse::<u32>()
        .map_err(|e| anyhow!("failed to parse LISTEN_PID: {}", e))?;
    let fds = fds
        .map_err(|e| anyhow!("failed to get LISTEN_FDS: {}", e))?
        .parse::<usize>()
        .map_err(|e| anyhow!("failed to parse LISTEN_FDS: {}", e))?;

    if process::id() != pid {
        bail!("PID mismatch");
    }

    let names = fdnames.map(|n| n.split(':').map(String::from).collect()).unwrap_or_else(|_| Vec::new());

    socks_from_fds(fds, names)
}

fn socks_from_fds(num_fds: usize, names: Vec<String>) -> Result<Vec<FileDescriptor>> {
    let mut descriptors = Vec::with_capacity(num_fds);
    let mut names = names.into_iter();
    for fd_offset in 0..num_fds {
        let name = names.next();
        let raw_fd: RawFd = SD_LISTEN_FDS_START
            .checked_add(fd_offset as i32)
            .ok_or_else(|| anyhow!("overlarge file descriptor index: {}", num_fds))?;
        if !sock_listening(raw_fd) {
            continue;
        }
        let tcp_not_udp = match sock_type(raw_fd) {
            Some(SockType::Stream) => true,
            Some(SockType::Datagram) => false,
            _ => continue,
        };
        let inet_not_unix = match address_family(raw_fd) {
            Some(AddressFamily::Inet) | Some(AddressFamily::Inet6) => true,
            Some(AddressFamily::Unix) => false,
            _ => continue,
        };
        descriptors.push(FileDescriptor {
            raw_fd,
            tcp_not_udp,
            inet_not_unix,
            name,
        });
    }

    Ok(descriptors)
}

fn sock_listening(raw_fd: RawFd) -> bool {
    getsockopt(raw_fd, nix::sys::socket::sockopt::AcceptConn).unwrap_or(false)
}

fn sock_type(raw_fd: RawFd) -> Option<SockType> {
    getsockopt(raw_fd, nix::sys::socket::sockopt::SockType).ok()
}

fn address_family(raw_fd: RawFd) -> Option<AddressFamily> {
    getsockname::<SockaddrStorage>(raw_fd).ok().and_then(|addr| addr.family())
}

impl IntoRawFd for FileDescriptor {
    fn into_raw_fd(self) -> RawFd {
        self.raw_fd
    }
}
