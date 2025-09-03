use rustls::{client::WebPkiServerVerifier, pki_types::TrustAnchor, RootCertStore};
use std::sync::{Arc, LazyLock};

#[cfg(all(feature = "webpki-roots", not(feature = "rustls-native-certs")))]
static ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    roots.into()
});

#[cfg(all(feature = "rustls-native-certs", not(feature = "webpki-roots")))]
static ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots.into()
});

pub static SERVER_VERIFIER: LazyLock<Arc<WebPkiServerVerifier>> = LazyLock::new(|| WebPkiServerVerifier::builder(ROOT_STORE.clone()).build().expect("couldn't create webpki verifier"));

pub static TLS_SERVER_ROOTS: LazyLock<&[TrustAnchor<'static>]> = LazyLock::new(|| &ROOT_STORE.roots);
