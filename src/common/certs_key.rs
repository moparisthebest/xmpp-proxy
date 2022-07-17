use std::sync::{Arc, RwLock};

use anyhow::Result;
use rustls::{sign::CertifiedKey, SignatureScheme};

pub struct CertsKey {
    #[cfg(feature = "rustls-pemfile")]
    pub inner: Result<RwLock<Arc<CertifiedKey>>>,
}

impl CertsKey {
    pub fn new(certified_key: Result<CertifiedKey>) -> Self {
        CertsKey {
            #[cfg(feature = "rustls-pemfile")]
            inner: certified_key.map(|c| RwLock::new(Arc::new(c))),
        }
    }
}

#[cfg(feature = "rustls-pemfile")]
impl rustls::server::ResolvesServerCert for CertsKey {
    fn resolve(&self, _: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.inner.as_ref().map(|rwl| rwl.read().expect("CertKey poisoned?").clone()).ok()
    }
}

#[cfg(feature = "rustls-pemfile")]
impl rustls::client::ResolvesClientCert for CertsKey {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.inner.as_ref().map(|rwl| rwl.read().expect("CertKey poisoned?").clone()).ok()
    }

    fn has_certs(&self) -> bool {
        self.inner.is_ok()
    }
}

#[cfg(not(feature = "rustls-pemfile"))]
impl rustls::client::ResolvesClientCert for CertsKey {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}
