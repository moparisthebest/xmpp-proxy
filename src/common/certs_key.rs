use std::sync::{Arc, RwLock};

use anyhow::Result;
use rustls::{sign::CertifiedKey, SignatureScheme};

#[cfg_attr(not(feature = "rustls-pemfile"), derive(Debug))]
pub struct CertsKey {
    #[cfg(feature = "rustls-pemfile")]
    pub inner: Result<RwLock<Arc<CertifiedKey>>>,
}

#[cfg(feature = "rustls-pemfile")]
impl std::fmt::Debug for CertsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.inner.is_ok() {
            f.write_str("CertsKey(Some)")
        } else {
            f.write_str("CertsKey(None)")
        }
    }
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
