#[cfg(feature = "tokio-rustls")]
use tokio_rustls::webpki::{TlsServerTrustAnchors, TrustAnchor};

#[cfg(all(feature = "webpki-roots", not(feature = "rustls-native-certs")))]
pub use webpki_roots::TLS_SERVER_ROOTS;

#[cfg(all(feature = "rustls-native-certs", not(feature = "webpki-roots")))]
lazy_static::lazy_static! {
    pub static ref TLS_SERVER_ROOTS: TlsServerTrustAnchors<'static> = {
        // we need these to stick around for 'static, this is only called once so no problem
        let certs = Box::leak(Box::new(rustls_native_certs::load_native_certs().expect("could not load platform certs")));
        let root_cert_store = Box::leak(Box::new(Vec::new()));
        for cert in certs {
            // some system CAs are invalid, ignore those
            if let Ok(ta) = TrustAnchor::try_from_cert_der(&cert.0) {
                root_cert_store.push(ta);
            }
        }
        TlsServerTrustAnchors(root_cert_store)
    };
}

pub fn root_cert_store() -> rustls::RootCertStore {
    use rustls::{OwnedTrustAnchor, RootCertStore};
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(
        TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)),
    );
    root_cert_store
}
