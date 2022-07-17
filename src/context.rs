use crate::{
    common::{c2s, to_str},
    slicesubsequence::SliceSubsequence,
};
use log::{info, log_enabled};
use std::net::SocketAddr;

#[derive(Clone)]
pub struct Context<'a> {
    conn_id: String,
    log_from: String,
    log_to: String,
    proto: &'a str,
    is_c2s: Option<bool>,
    to: Option<String>,
    to_addr: Option<SocketAddr>,
    from: Option<String>,
    client_addr: SocketAddr,
}

impl<'a> Context<'a> {
    pub fn new(proto: &'static str, client_addr: SocketAddr) -> Context {
        let (log_to, log_from, conn_id) = if log_enabled!(log::Level::Info) {
            #[cfg(feature = "logging")]
            let conn_id = {
                use rand::{distributions::Alphanumeric, thread_rng, Rng};
                thread_rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect()
            };
            #[cfg(not(feature = "logging"))]
            let conn_id = "".to_string();
            (
                format!("{}: ({} <- ({}-unk)):", conn_id, client_addr, proto),
                format!("{}: ({} -> ({}-unk)):", conn_id, client_addr, proto),
                conn_id,
            )
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        };

        Context {
            conn_id,
            log_from,
            log_to,
            proto,
            client_addr,
            is_c2s: None,
            to: None,
            to_addr: None,
            from: None,
        }
    }

    fn re_calc(&mut self) {
        // todo: make this good
        self.log_from = format!(
            "{}: ({} ({}) -> ({}-{}) -> {} ({})):",
            self.conn_id,
            self.client_addr,
            if self.from.is_some() { self.from.as_ref().unwrap() } else { "unk" },
            self.proto,
            if self.is_c2s.is_some() { c2s(self.is_c2s.unwrap()) } else { "unk" },
            if self.to_addr.is_some() { self.to_addr.as_ref().unwrap().to_string() } else { "unk".to_string() },
            if self.to.is_some() { self.to.as_ref().unwrap() } else { "unk" },
        );
        self.log_to = self.log_from.replace(" -> ", " <- ");
    }

    pub fn log_from(&self) -> &str {
        &self.log_from
    }

    pub fn log_to(&self) -> &str {
        &self.log_to
    }

    pub fn client_addr(&self) -> &SocketAddr {
        &self.client_addr
    }

    pub fn set_proto(&mut self, proto: &'static str) {
        if log_enabled!(log::Level::Info) {
            self.proto = proto;
            self.to_addr = None;
            self.re_calc();
        }
    }

    pub fn set_c2s_stream_open(&mut self, is_c2s: bool, stream_open: &[u8]) {
        if log_enabled!(log::Level::Info) {
            self.is_c2s = Some(is_c2s);
            self.from = stream_open
                .extract_between(b" from='", b"'")
                .or_else(|_| stream_open.extract_between(b" from=\"", b"\""))
                .map(|b| to_str(b).to_string())
                .ok();
            self.to = stream_open
                .extract_between(b" to='", b"'")
                .or_else(|_| stream_open.extract_between(b" to=\"", b"\""))
                .map(|b| to_str(b).to_string())
                .ok();
            self.re_calc();
            info!("{} stream data set", &self.log_from());
        }
    }

    pub fn set_to_addr(&mut self, to_addr: SocketAddr) {
        if log_enabled!(log::Level::Info) {
            self.to_addr = Some(to_addr);
            self.re_calc();
        }
    }
}
