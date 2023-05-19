use crate::{
    common::ca_roots::TLS_SERVER_ROOTS,
    srv::{digest, Posh},
};
use log::{debug, trace};
use ring::digest::SHA256;
use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    server::{ClientCertVerified, ClientCertVerifier},
    Certificate, DistinguishedNames, Error, ServerName,
};
use std::{convert::TryFrom, time::SystemTime};
use tokio_rustls::{webpki, webpki::DnsName};

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

pub fn verify_is_valid_tls_server_cert<'a>(end_entity: &'a Certificate, intermediates: &'a [Certificate], now: SystemTime) -> Result<webpki::EndEntityCert<'a>, Error> {
    // from WebPkiVerifier, validates CA trusted cert
    let (cert, chain) = prepare(end_entity, intermediates)?;
    let webpki_now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

    cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS, &TLS_SERVER_ROOTS, &chain, webpki_now).map_err(pki_error)?;

    Ok(cert)
}

pub struct AllowAnonymousOrAnyCert;

impl ClientCertVerifier for AllowAnonymousOrAnyCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> Option<bool> {
        Some(false)
    }

    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        Some(Vec::new())
    }

    fn verify_client_cert(&self, _: &Certificate, _: &[Certificate], _: SystemTime) -> Result<ClientCertVerified, Error> {
        // this is checked only after the first <stream: stanza so we know the from=
        Ok(ClientCertVerified::assertion())
    }
}

type CertChainAndRoots<'a> = (webpki::EndEntityCert<'a>, Vec<&'a [u8]>);

fn prepare<'a>(end_entity: &'a Certificate, intermediates: &'a [Certificate]) -> Result<CertChainAndRoots<'a>, Error> {
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::try_from(end_entity.0.as_ref()).map_err(pki_error)?;

    let intermediates: Vec<&'a [u8]> = intermediates.iter().map(|cert| cert.0.as_ref()).collect();

    Ok((cert, intermediates))
}

#[derive(Debug)]
pub struct XmppServerCertVerifier {
    names: Vec<DnsName>,
    posh: Option<Posh>,
    sha256_pinnedpubkeys: Vec<String>,
}

impl XmppServerCertVerifier {
    pub fn new(names: Vec<DnsName>, posh: Option<Posh>, sha256_pinnedpubkeys: Vec<String>) -> Self {
        XmppServerCertVerifier { names, posh, sha256_pinnedpubkeys }
    }

    pub fn verify_cert(&self, end_entity: &Certificate, intermediates: &[Certificate], now: SystemTime) -> Result<ServerCertVerified, Error> {
        if !self.sha256_pinnedpubkeys.is_empty() {
            let cert = webpki::TrustAnchor::try_from_cert_der(end_entity.0.as_ref()).map_err(pki_error)?;
            trace!("spki.len(): {}", cert.spki.len());
            trace!("spki: {:?}", cert.spki);
            // todo: what is wrong with webpki? it returns *almost* the right answer but missing these leading bytes:
            // guess I'll open an issue... (I assume this is some type of algorithm identifying header or something)
            let mut pubkey: Vec<u8> = vec![48, 130, 1, 34];
            pubkey.extend(cert.spki);

            if self.sha256_pinnedpubkeys.contains(&digest(&SHA256, &pubkey)) {
                debug!("pinnedpubkey succeeded for {:?}", self.names.first());
                return Ok(ServerCertVerified::assertion());
            }
            // todo: else fail ????
        }

        if let Some(ref posh) = self.posh {
            if posh.valid_cert(end_entity.as_ref()) {
                debug!("posh succeeded for {:?}", self.names.first());
                return Ok(ServerCertVerified::assertion());
            } else {
                // per RFC if POSH fails, continue with other methods
                debug!("posh failed for {:?}", self.names.first());
            }
        }
        // validates CA trusted cert
        let cert = verify_is_valid_tls_server_cert(end_entity, intermediates, now)?;

        for name in &self.names {
            if cert.verify_is_valid_for_dns_name(name.as_ref()).is_ok() {
                return Ok(ServerCertVerified::assertion());
            }
        }

        Err(Error::InvalidCertificateData(format!("invalid peer certificate: all validation attempts failed: {:?}", end_entity)))
    }
}

impl ServerCertVerifier for XmppServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verify_cert(end_entity, intermediates, now)
    }

    fn request_scts(&self) -> bool {
        false
    }
}
