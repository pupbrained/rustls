use crate::crypto;
use crate::crypto::cipher::{AeadKey, Iv, MessageDecrypter, MessageEncrypter};
#[cfg(feature = "secret_extraction")]
use crate::suites::ConnectionTrafficSecrets;
use crate::suites::{CipherSuiteCommon, SupportedCipherSuite};

use core::fmt;

pub(crate) mod key_schedule;

pub(crate) trait Tls13AeadAlgorithm: Send + Sync {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter>;
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter>;
    fn key_len(&self) -> usize;

    #[cfg(feature = "secret_extraction")]
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets;
}

/// A TLS 1.3 cipher suite supported by rustls.
pub struct Tls13CipherSuite {
    /// Common cipher suite fields.
    pub common: CipherSuiteCommon,

    /// How to compute HMAC with the suite's hash function.
    pub hmac_provider: &'static dyn crypto::hmac::Hmac,

    /// Producing a suitable `MessageDecrypter` or `MessageEncrypter`
    /// from the raw keys.
    pub(crate) aead_alg: &'static dyn Tls13AeadAlgorithm,

    #[cfg(feature = "quic")]
    pub(crate) confidentiality_limit: u64,
    #[cfg(feature = "quic")]
    pub(crate) integrity_limit: u64,
}

impl Tls13CipherSuite {
    /// Can a session using suite self resume from suite prev?
    pub fn can_resume_from(&self, prev: &'static Self) -> Option<&'static Self> {
        (prev.common.hash_provider.algorithm() == self.common.hash_provider.algorithm())
            .then(|| prev)
    }
}

impl From<&'static Tls13CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls13CipherSuite) -> Self {
        Self::Tls13(s)
    }
}

impl PartialEq for Tls13CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for Tls13CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls13CipherSuite")
            .field("suite", &self.common.suite)
            .finish()
    }
}
