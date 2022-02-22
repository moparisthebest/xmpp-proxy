use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{Certificate, DistinguishedNames, Error};
use std::convert::TryFrom;
use std::time::SystemTime;
use tokio_rustls::webpki;

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

pub fn pki_error(error: webpki::Error) -> Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => Error::InvalidCertificateEncoding,
        InvalidSignatureForPublicKey => Error::InvalidCertificateSignature,
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => Error::InvalidCertificateSignatureType,
        e => Error::InvalidCertificateData(format!("invalid peer certificate: {}", e)),
    }
}

pub struct AllowAnyAnonymousOrAuthenticatedServer;

impl ClientCertVerifier for AllowAnyAnonymousOrAuthenticatedServer {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> Option<bool> {
        Some(false)
    }

    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        Some(Vec::new())
    }

    fn verify_client_cert(&self, end_entity: &Certificate, intermediates: &[Certificate], now: SystemTime) -> Result<ClientCertVerified, Error> {
        let (cert, chain) = prepare(end_entity, intermediates)?;
        let now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;
        cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, &crate::TLS_SERVER_ROOTS, &chain, now)
            .map_err(pki_error)
            .map(|_| ClientCertVerified::assertion())
    }
}

type CertChainAndRoots<'a, 'b> = (webpki::EndEntityCert<'a>, Vec<&'a [u8]>);

fn prepare<'a, 'b>(end_entity: &'a Certificate, intermediates: &'a [Certificate]) -> Result<CertChainAndRoots<'a, 'b>, Error> {
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(pki_error)?;

    let intermediates: Vec<&'a [u8]> = intermediates.iter().map(|cert| cert.0.as_ref()).collect();

    Ok((cert, intermediates))
}
