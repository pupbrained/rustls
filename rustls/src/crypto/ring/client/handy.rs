use crate::client::ResolvesClientCert;
use crate::enums::SignatureScheme;
use crate::error::Error;
use crate::key;
use crate::sign;

use std::sync::Arc;

pub(crate) struct AlwaysResolvesClientCert(Arc<sign::CertifiedKey>);

impl AlwaysResolvesClientCert {
    pub(crate) fn new(
        chain: Vec<key::Certificate>,
        priv_key: &key::PrivateKey,
    ) -> Result<Self, Error> {
        let key = crate::crypto::ring::sign::any_supported_type(priv_key)
            .map_err(|_| Error::General("invalid private key".into()))?;
        Ok(Self(Arc::new(sign::CertifiedKey::new(chain, key))))
    }
}

impl ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}
