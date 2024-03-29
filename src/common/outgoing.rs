use crate::common::{certs_key::CertsKey, ALPN_XMPP_CLIENT, ALPN_XMPP_SERVER};
use rustls::{client::ServerCertVerifier, ClientConfig};
use std::sync::Arc;
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct OutgoingConfig {
    pub max_stanza_size_bytes: usize,
    pub certs_key: Arc<CertsKey>,
}

impl OutgoingConfig {
    pub fn with_custom_certificate_verifier(&self, is_c2s: bool, cert_verifier: Arc<dyn ServerCertVerifier>) -> OutgoingVerifierConfig {
        let config = match is_c2s {
            false => ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(cert_verifier)
                .with_client_cert_resolver(self.certs_key.clone()),
            _ => ClientConfig::builder().with_safe_defaults().with_custom_certificate_verifier(cert_verifier).with_no_client_auth(),
        };

        #[cfg(feature = "webtransport")]
        let config_webtransport_alpn = {
            let mut config = config.clone();
            config.alpn_protocols.push(webtransport_quinn::ALPN.to_vec());
            Arc::new(config)
        };

        let mut config_alpn = config.clone();
        config_alpn.alpn_protocols.push(if is_c2s { ALPN_XMPP_CLIENT } else { ALPN_XMPP_SERVER }.to_vec());

        let config_alpn = Arc::new(config_alpn);

        let connector_alpn: TlsConnector = config_alpn.clone().into();

        let connector: TlsConnector = Arc::new(config).into();

        OutgoingVerifierConfig {
            max_stanza_size_bytes: self.max_stanza_size_bytes,
            #[cfg(feature = "webtransport")]
            config_webtransport_alpn,
            config_alpn,
            connector_alpn,
            connector,
        }
    }
}

#[derive(Clone)]
pub struct OutgoingVerifierConfig {
    pub max_stanza_size_bytes: usize,

    #[cfg(feature = "webtransport")]
    pub config_webtransport_alpn: Arc<ClientConfig>,

    pub config_alpn: Arc<ClientConfig>,
    pub connector_alpn: TlsConnector,

    pub connector: TlsConnector,
}
