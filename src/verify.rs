use crate::{
    common::ca_roots::{SERVER_VERIFIER, TLS_SERVER_ROOTS},
    srv::{digest, Posh},
};
use log::{debug, trace};
use ring::digest::SHA256;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, SignatureVerificationAlgorithm, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
};
use std::{convert::TryFrom, sync::LazyLock};

/// Which signature verification mechanisms we support.  No particular
/// order.
// this expect panic should not be possible to trigger because it'll trigger earlier in execution before we get to cert verification
static SUPPORTED_SIG_ALGS: LazyLock<&'static [&'static dyn SignatureVerificationAlgorithm]> =
    LazyLock::new(|| rustls::crypto::CryptoProvider::get_default().expect("no crypto provider set").signature_verification_algorithms.all);

#[allow(deprecated)]
pub fn pki_error(error: webpki::Error) -> Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => Error::InvalidCertificate(CertificateError::BadEncoding),
        InvalidSignatureForPublicKey | UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => Error::InvalidCertificate(CertificateError::BadSignature),
        e => Error::General(format!("invalid peer certificate: {}", e)),
    }
}

pub fn verify_is_valid_tls_server_cert<'a>(end_entity: &'a CertificateDer, intermediates: &'a [CertificateDer], now: UnixTime) -> Result<webpki::EndEntityCert<'a>, Error> {
    // from WebPkiVerifier, validates CA trusted cert
    //let (cert, chain) = prepare(end_entity, intermediates)?;
    // EE cert must appear first.
    let cert = webpki::EndEntityCert::try_from(end_entity).map_err(pki_error)?;

    // todo: check revocation ? where to get CRL list ?

    cert.verify_for_usage(*SUPPORTED_SIG_ALGS, &TLS_SERVER_ROOTS, intermediates, now, webpki::KeyUsage::server_auth(), None, None)
        .map_err(pki_error)?;

    Ok(cert)
}

#[derive(Debug)]
pub struct AllowAnonymousOrAnyCert;

impl ClientCertVerifier for AllowAnonymousOrAnyCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn verify_client_cert(&self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>], _now: UnixTime) -> Result<ClientCertVerified, Error> {
        // this is checked only after the first <stream: stanza so we know the from=
        Ok(ClientCertVerified::assertion())
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        SERVER_VERIFIER.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        SERVER_VERIFIER.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SERVER_VERIFIER.supported_verify_schemes()
    }
}

#[derive(Debug)]
pub struct XmppServerCertVerifier {
    names: Vec<ServerName<'static>>,
    posh: Option<Posh>,
    sha256_pinnedpubkeys: Vec<String>,
}

impl XmppServerCertVerifier {
    pub fn new(names: Vec<ServerName<'static>>, posh: Option<Posh>, sha256_pinnedpubkeys: Vec<String>) -> Self {
        XmppServerCertVerifier { names, posh, sha256_pinnedpubkeys }
    }

    pub fn verify_cert(&self, end_entity: &CertificateDer, intermediates: &[CertificateDer], now: UnixTime) -> Result<ServerCertVerified, Error> {
        if !self.sha256_pinnedpubkeys.is_empty() {
            let cert = webpki::anchor_from_trusted_cert(end_entity).map_err(pki_error)?;
            trace!("subject_public_key_info.len(): {}", cert.subject_public_key_info.len());
            trace!("subject_public_key_info: {:?}", cert.subject_public_key_info);
            // todo: what is wrong with webpki? it returns *almost* the right answer but missing these leading bytes:
            // guess I'll open an issue... (I assume this is some type of algorithm identifying header or something)
            let mut pubkey: Vec<u8> = vec![48, 130, 1, 34];
            pubkey.extend(cert.subject_public_key_info.as_ref());

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
            if cert.verify_is_valid_for_subject_name(name).is_ok() {
                return Ok(ServerCertVerified::assertion());
            }
        }

        Err(Error::General(format!("invalid peer certificate: all validation attempts failed: {:?}", end_entity)))
    }
}

impl ServerCertVerifier for XmppServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.verify_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        SERVER_VERIFIER.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        SERVER_VERIFIER.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SERVER_VERIFIER.supported_verify_schemes()
    }
}
