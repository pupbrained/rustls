use crate::crypto::ring;
use crate::dns_name::DnsNameRef;
use crate::error::Error;
use crate::key;
use crate::server::ClientHello;
use crate::server::ResolvesServerCert;
use crate::sign;

use std::collections;
use std::sync::Arc;

/// Something which always resolves to the same cert chain.
pub(crate) struct AlwaysResolvesChain(Arc<sign::CertifiedKey>);

impl AlwaysResolvesChain {
    /// Creates an `AlwaysResolvesChain`, auto-detecting the underlying private
    /// key type and encoding.
    pub(crate) fn new(
        chain: Vec<key::Certificate>,
        priv_key: &key::PrivateKey,
    ) -> Result<Self, Error> {
        let key = ring::sign::any_supported_type(priv_key)
            .map_err(|_| Error::General("invalid private key".into()))?;
        Ok(Self(Arc::new(sign::CertifiedKey::new(chain, key))))
    }

    /// Creates an `AlwaysResolvesChain`, auto-detecting the underlying private
    /// key type and encoding.
    ///
    /// If non-empty, the given OCSP response is attached.
    pub(crate) fn new_with_extras(
        chain: Vec<key::Certificate>,
        priv_key: &key::PrivateKey,
        ocsp: Vec<u8>,
    ) -> Result<Self, Error> {
        let mut r = Self::new(chain, priv_key)?;

        {
            let cert = Arc::make_mut(&mut r.0);
            if !ocsp.is_empty() {
                cert.ocsp = Some(ocsp);
            }
        }

        Ok(r)
    }
}

impl ResolvesServerCert for AlwaysResolvesChain {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Something that resolves do different cert chains/keys based
/// on client-supplied server name (via SNI).
pub struct ResolvesServerCertUsingSni {
    by_name: collections::HashMap<String, Arc<sign::CertifiedKey>>,
}

impl ResolvesServerCertUsingSni {
    /// Create a new and empty (i.e., knows no certificates) resolver.
    pub fn new() -> Self {
        Self {
            by_name: collections::HashMap::new(),
        }
    }

    /// Add a new `sign::CertifiedKey` to be used for the given SNI `name`.
    ///
    /// This function fails if `name` is not a valid DNS name, or if
    /// it's not valid for the supplied certificate, or if the certificate
    /// chain is syntactically faulty.
    pub fn add(&mut self, name: &str, ck: sign::CertifiedKey) -> Result<(), Error> {
        let checked_name = DnsNameRef::try_from(name)
            .map_err(|_| Error::General("Bad DNS name".into()))
            .map(|dns| dns.to_lowercase_owned())?;

        // Check the certificate chain for validity:
        // - it should be non-empty list
        // - the first certificate should be parsable as a x509v3,
        // - the first certificate should quote the given server name
        //   (if provided)
        //
        // These checks are not security-sensitive.  They are the
        // *server* attempting to detect accidental misconfiguration.

        // Always reject an empty certificate chain.
        let end_entity_cert = ck.end_entity_cert().map_err(|_| {
            Error::General("No end-entity certificate in certificate chain".to_string())
        })?;

        // Reject syntactically-invalid end-entity certificates.
        let end_entity_cert =
            webpki::EndEntityCert::try_from(end_entity_cert.as_ref()).map_err(|_| {
                Error::General(
                    "End-entity certificate in certificate chain is syntactically invalid"
                        .to_string(),
                )
            })?;

        // Note that this doesn't fully validate that the certificate is valid; it only validates that the name is one
        // that the certificate is valid for, if the certificate is
        // valid.
        let general_error =
            || Error::General("The server certificate is not valid for the given name".to_string());

        let name = webpki::DnsNameRef::try_from_ascii(checked_name.as_ref().as_bytes())
            .map_err(|_| general_error())?;

        end_entity_cert
            .verify_is_valid_for_subject_name(webpki::SubjectNameRef::DnsName(name))
            .map_err(|_| general_error())?;

        let as_str: &str = checked_name.as_ref();
        self.by_name
            .insert(as_str.to_string(), Arc::new(ck));
        Ok(())
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingSni {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            self.by_name.get(name).map(Arc::clone)
        } else {
            // This kind of resolver requires SNI
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_resolvesservercertusingsni_requires_sni() {
        let rscsni = ResolvesServerCertUsingSni::new();
        assert!(rscsni
            .resolve(ClientHello::new(&None, &[], None, &[]))
            .is_none());
    }

    #[test]
    fn test_resolvesservercertusingsni_handles_unknown_name() {
        let rscsni = ResolvesServerCertUsingSni::new();
        let name = DnsNameRef::try_from("hello.com")
            .unwrap()
            .to_owned();
        assert!(rscsni
            .resolve(ClientHello::new(&Some(name), &[], None, &[]))
            .is_none());
    }
}
