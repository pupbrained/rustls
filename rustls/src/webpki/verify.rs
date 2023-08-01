use super::anchors::{OwnedTrustAnchor, RootCertStore};
use crate::client::ServerName;
use crate::enums::SignatureScheme;
use crate::error::{CertRevocationListError, CertificateError, Error, PeerMisbehaved};
use crate::key::Certificate;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::handshake::DistinguishedName;
use crate::tls13::is_sigscheme_supported_in_tls13;
use crate::verify::{
    ClientCertVerified, ClientCertVerifier, DigitallySignedStruct, HandshakeSignatureValid,
    ServerCertVerified, ServerCertVerifier,
};

use std::sync::Arc;
use std::time::SystemTime;

/// Verify that the end-entity certificate `end_entity` is a valid server cert
/// and chains to at least one of the [OwnedTrustAnchor] in the `roots` [RootCertStore].
///
/// `intermediates` contains all certificates other than `end_entity` that
/// were sent as part of the server's [Certificate] message. It is in the
/// same order that the server sent them and may be empty.
#[allow(dead_code)]
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub fn verify_server_cert_signed_by_trust_anchor(
    cert: &ParsedCertificate,
    roots: &RootCertStore,
    intermediates: &[Certificate],
    now: SystemTime,
    supported_algs: &[&dyn webpki::SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    let chain = intermediate_chain(intermediates);
    let trust_roots = trust_roots(roots);
    let webpki_now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

    cert.0
        .verify_for_usage(
            supported_algs,
            &trust_roots,
            &chain,
            webpki_now,
            webpki::KeyUsage::server_auth(),
            &[], // no CRLs
        )
        .map_err(pki_error)
        .map(|_| ())
}

/// Verify that the `end_entity` has a name or alternative name matching the `server_name`
/// note: this only verifies the name and should be used in conjuction with more verification
/// like [verify_server_cert_signed_by_trust_anchor]
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub fn verify_server_name(cert: &ParsedCertificate, server_name: &ServerName) -> Result<(), Error> {
    match server_name {
        ServerName::DnsName(dns_name) => {
            // unlikely error because dns_name::DnsNameRef and webpki::DnsNameRef
            // should have the same encoding rules.
            let dns_name = webpki::DnsNameRef::try_from_ascii_str(dns_name.as_ref())
                .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
            let name = webpki::SubjectNameRef::DnsName(dns_name);
            cert.0
                .verify_is_valid_for_subject_name(name)
                .map_err(pki_error)?;
        }
        ServerName::IpAddress(ip_addr) => {
            let ip_addr = webpki::IpAddr::from(*ip_addr);
            cert.0
                .verify_is_valid_for_subject_name(webpki::SubjectNameRef::IpAddress(
                    webpki::IpAddrRef::from(&ip_addr),
                ))
                .map_err(pki_error)?;
        }
    }
    Ok(())
}

/// wrapper around internal representation of a parsed certificate. This is used in order to avoid parsing twice when specifying custom verification
#[cfg_attr(not(feature = "dangerous_configuration"), allow(unreachable_pub))]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct ParsedCertificate<'a>(pub(crate) webpki::EndEntityCert<'a>);

impl<'a> TryFrom<&'a Certificate> for ParsedCertificate<'a> {
    type Error = Error;
    fn try_from(value: &'a Certificate) -> Result<ParsedCertificate<'a>, Self::Error> {
        webpki::EndEntityCert::try_from(value.0.as_ref())
            .map_err(pki_error)
            .map(ParsedCertificate)
    }
}

impl ServerCertVerifier for WebPkiVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a  trusted `RootCertStore` CA
    /// - Not Expired
    /// - Valid for DNS entry
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported.all,
        )?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// Default `ServerCertVerifier`, see the trait impl for more information.
#[allow(unreachable_pub)]
#[cfg_attr(docsrs, doc(cfg(feature = "dangerous_configuration")))]
pub struct WebPkiVerifier {
    roots: RootCertStore,
    supported: WebPkiSupportedAlgorithms,
}

#[allow(unreachable_pub)]
impl WebPkiVerifier {
    /// Constructs a new `WebPkiVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    pub fn new(roots: RootCertStore) -> Self {
        Self::new_with_algorithms(roots, SUPPORTED_SIG_ALGS)
    }

    /// Constructs a new `WebPkiVerifier`.
    ///
    /// `roots` is the set of trust anchors to trust for issuing server certs.
    /// `supported` is the set of supported algorithms that will be used for
    /// certificate verification and TLS handshake signature verification.
    pub fn new_with_algorithms(roots: RootCertStore, supported: WebPkiSupportedAlgorithms) -> Self {
        Self { roots, supported }
    }

    /// A full implementation of `ServerCertVerifier::verify_tls12_signature` or
    /// `ClientCertVerifier::verify_tls12_signature`.
    pub fn default_verify_tls12_signature(
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    /// A full implementation of `ServerCertVerifier::verify_tls13_signature` or
    /// `ClientCertVerifier::verify_tls13_signature`.
    pub fn default_verify_tls13_signature(
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &SUPPORTED_SIG_ALGS)
    }

    /// A full implementation of `ServerCertVerifier::supported_verify_schemes()` or
    /// `ClientCertVerifier::supported_verify_schemes()`.
    pub fn default_supported_verify_schemes() -> Vec<SignatureScheme> {
        SUPPORTED_SIG_ALGS.supported_schemes()
    }
}

fn intermediate_chain(intermediates: &[Certificate]) -> Vec<&[u8]> {
    intermediates
        .iter()
        .map(|cert| cert.0.as_ref())
        .collect()
}

fn trust_roots(roots: &RootCertStore) -> Vec<webpki::TrustAnchor> {
    roots
        .roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect()
}

/// An unparsed DER encoded Certificate Revocation List (CRL).
pub struct UnparsedCertRevocationList(pub Vec<u8>);

impl UnparsedCertRevocationList {
    /// Parse the CRL DER, yielding a [`webpki::CertRevocationList`] or an error if the CRL
    /// is malformed, or uses unsupported features.
    pub fn parse(&self) -> Result<webpki::OwnedCertRevocationList, CertRevocationListError> {
        webpki::BorrowedCertRevocationList::from_der(&self.0)
            .and_then(|crl| crl.to_owned())
            .map_err(CertRevocationListError::from)
    }
}

/// A `ClientCertVerifier` that will ensure that every client provides a trusted
/// certificate, without any name checking. Optionally, client certificates will
/// have their revocation status checked using the DER encoded CRLs provided.
pub struct AllowAnyAuthenticatedClient {
    roots: RootCertStore,
    subjects: Vec<DistinguishedName>,
    crls: Vec<webpki::OwnedCertRevocationList>,
    supported: WebPkiSupportedAlgorithms,
}

impl AllowAnyAuthenticatedClient {
    /// Construct a new `AllowAnyAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Self {
        Self {
            subjects: roots
                .roots
                .iter()
                .map(|r| r.subject().clone())
                .collect(),
            crls: Vec::new(),
            roots,
            supported: SUPPORTED_SIG_ALGS,
        }
    }

    /// Update the verifier to validate client certificates against the provided DER format
    /// unparsed certificate revocation lists (CRLs).
    pub fn with_crls(
        self,
        crls: impl IntoIterator<Item = UnparsedCertRevocationList>,
    ) -> Result<Self, CertRevocationListError> {
        Ok(Self {
            crls: crls
                .into_iter()
                .map(|der_crl| der_crl.parse())
                .collect::<Result<Vec<_>, CertRevocationListError>>()?,
            ..self
        })
    }

    /// Wrap this verifier in an [`Arc`] and coerce it to `dyn ClientCertVerifier`
    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn ClientCertVerifier> {
        // This function is needed because `ClientCertVerifier` is only reachable if the
        // `dangerous_configuration` feature is enabled, which makes coercing hard to outside users
        Arc::new(self)
    }
}

impl ClientCertVerifier for AllowAnyAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &self.subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        let chain = intermediate_chain(intermediates);
        let trust_roots = trust_roots(&self.roots);
        let now = webpki::Time::try_from(now).map_err(|_| Error::FailedToGetCurrentTime)?;

        #[allow(trivial_casts)] // Cast to &dyn trait is required.
        let crls = self
            .crls
            .iter()
            .map(|crl| crl as &dyn webpki::CertRevocationList)
            .collect::<Vec<_>>();

        cert.0
            .verify_for_usage(
                self.supported.all,
                &trust_roots,
                &chain,
                now,
                webpki::KeyUsage::client_auth(),
                &crls,
            )
            .map_err(pki_error)
            .map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_signed_struct(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// A `ClientCertVerifier` that will allow both anonymous and authenticated
/// clients, without any name checking.
///
/// Client authentication will be requested during the TLS handshake. If the
/// client offers a certificate then this acts like
/// `AllowAnyAuthenticatedClient`, otherwise this acts like `NoClientAuth`.
pub struct AllowAnyAnonymousOrAuthenticatedClient {
    inner: AllowAnyAuthenticatedClient,
}

impl AllowAnyAnonymousOrAuthenticatedClient {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Self {
        Self {
            inner: AllowAnyAuthenticatedClient::new(roots),
        }
    }

    /// Update the verifier to validate client certificates against the provided DER format
    /// unparsed certificate revocation lists (CRLs).
    pub fn with_crls(
        self,
        crls: impl IntoIterator<Item = UnparsedCertRevocationList>,
    ) -> Result<Self, CertRevocationListError> {
        Ok(Self {
            inner: self.inner.with_crls(crls)?,
        })
    }

    /// Wrap this verifier in an [`Arc`] and coerce it to `dyn ClientCertVerifier`
    #[inline(always)]
    pub fn boxed(self) -> Arc<dyn ClientCertVerifier> {
        // This function is needed because `ClientCertVerifier` is only reachable if the
        // `dangerous_configuration` feature is enabled, which makes coercing hard to outside users
        Arc::new(self)
    }
}

impl ClientCertVerifier for AllowAnyAnonymousOrAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn pki_error(error: webpki::Error) -> Error {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime | TrailingData(_) => CertificateError::BadEncoding.into(),
        CertNotValidYet => CertificateError::NotValidYet.into(),
        CertExpired | InvalidCertValidity => CertificateError::Expired.into(),
        UnknownIssuer => CertificateError::UnknownIssuer.into(),
        CertNotValidForName => CertificateError::NotValidForName.into(),
        CertRevoked => CertificateError::Revoked.into(),
        IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),

        InvalidSignatureForPublicKey
        | UnsupportedSignatureAlgorithm
        | UnsupportedSignatureAlgorithmForPublicKey => CertificateError::BadSignature.into(),

        InvalidCrlSignatureForPublicKey
        | UnsupportedCrlSignatureAlgorithm
        | UnsupportedCrlSignatureAlgorithmForPublicKey => {
            CertRevocationListError::BadSignature.into()
        }

        _ => CertificateError::Other(Arc::new(error)).into(),
    }
}

type SignatureAlgorithms = &'static [&'static dyn webpki::SignatureVerificationAlgorithm];

/// Describes which `webpki` signature verification algorithms are supported and
/// how they map to TLS `SignatureScheme`s.
#[derive(Clone, Copy)]
#[allow(unreachable_pub)]
pub struct WebPkiSupportedAlgorithms {
    /// A list of all supported signature verification algorithms.
    ///
    /// Used for verifying certificate chains.
    ///
    /// The order of this list is not significant.
    pub all: SignatureAlgorithms,

    /// A mapping from TLS `SignatureScheme`s to matching webpki signature verification algorithms.
    ///
    /// This is one (`SignatureScheme`) to many (`webpki::SignatureVerificationAlgorithm`) because
    /// (depending on the protocol version) there is not necessary a 1-to-1 mapping.
    ///
    /// For TLS1.2, all `webpki:SignatureVerificationAlgorithm`s are tried in sequence.
    ///
    /// For TLS1.3, only the first is tried.
    ///
    /// The supported schemes in this mapping is communicated to the peer and the order is significant.
    /// The first mapping is our highest preference.
    pub mapping: &'static [(SignatureScheme, SignatureAlgorithms)],
}

impl WebPkiSupportedAlgorithms {
    /// Return all the `scheme` items in `mapping`, maintaining order.
    fn supported_schemes(&self) -> Vec<SignatureScheme> {
        self.mapping
            .iter()
            .map(|item| item.0)
            .collect()
    }

    /// Return the first item in `mapping` that matches `scheme`.
    fn convert_scheme(&self, scheme: SignatureScheme) -> Result<SignatureAlgorithms, Error> {
        self.mapping
            .iter()
            .filter(|item| item.0 == scheme)
            .map(|item| item.1)
            .next()
            .ok_or_else(|| PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into())
    }
}

/// A `WebPkiSupportedAlgorithms` value that reflects webpki's capabilities when
/// compiled against *ring*.
static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki::ECDSA_P256_SHA256,
        webpki::ECDSA_P256_SHA384,
        webpki::ECDSA_P384_SHA256,
        webpki::ECDSA_P384_SHA384,
        webpki::ED25519,
        webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki::RSA_PKCS1_2048_8192_SHA256,
        webpki::RSA_PKCS1_2048_8192_SHA384,
        webpki::RSA_PKCS1_2048_8192_SHA512,
        webpki::RSA_PKCS1_3072_8192_SHA384,
    ],
    mapping: &[
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme. for TLS1.3 it is.
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[webpki::ECDSA_P384_SHA384, webpki::ECDSA_P256_SHA384],
        ),
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[webpki::ECDSA_P256_SHA256, webpki::ECDSA_P384_SHA256],
        ),
        (SignatureScheme::ED25519, &[webpki::ED25519]),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki::RSA_PKCS1_2048_8192_SHA512],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki::RSA_PKCS1_2048_8192_SHA256],
        ),
    ],
};

fn verify_sig_using_any_alg(
    cert: &webpki::EndEntityCert,
    algs: SignatureAlgorithms,
    message: &[u8],
    sig: &[u8],
) -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single webpki::SignatureVerificationAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(*alg, message, sig) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

fn verify_signed_struct(
    message: &[u8],
    cert: &Certificate,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    let possible_algs = supported_schemes.convert_scheme(dss.scheme)?;
    let cert = webpki::EndEntityCert::try_from(cert.0.as_ref()).map_err(pki_error)?;

    verify_sig_using_any_alg(&cert, possible_algs, message, dss.signature())
        .map_err(pki_error)
        .map(|_| HandshakeSignatureValid::assertion())
}

fn verify_tls13(
    msg: &[u8],
    cert: &Certificate,
    dss: &DigitallySignedStruct,
    supported_schemes: &WebPkiSupportedAlgorithms,
) -> Result<HandshakeSignatureValid, Error> {
    if !is_sigscheme_supported_in_tls13(&dss.scheme) {
        return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
    }

    let alg = supported_schemes.convert_scheme(dss.scheme)?[0];

    let cert = webpki::EndEntityCert::try_from(cert.0.as_ref()).map_err(pki_error)?;

    cert.verify_signature(alg, msg, dss.signature())
        .map_err(pki_error)
        .map(|_| HandshakeSignatureValid::assertion())
}

impl From<webpki::Error> for CertRevocationListError {
    fn from(e: webpki::Error) -> Self {
        use webpki::Error::*;
        match e {
            InvalidCrlSignatureForPublicKey
            | UnsupportedCrlSignatureAlgorithm
            | UnsupportedCrlSignatureAlgorithmForPublicKey => Self::BadSignature,
            InvalidCrlNumber => Self::InvalidCrlNumber,
            InvalidSerialNumber => Self::InvalidRevokedCertSerialNumber,
            IssuerNotCrlSigner => Self::IssuerInvalidForCrl,
            MalformedExtensions | BadDer | BadDerTime => Self::ParseError,
            UnsupportedCriticalExtension => Self::UnsupportedCriticalExtension,
            UnsupportedCrlVersion => Self::UnsupportedCrlVersion,
            UnsupportedDeltaCrl => Self::UnsupportedDeltaCrl,
            UnsupportedIndirectCrl => Self::UnsupportedIndirectCrl,
            UnsupportedRevocationReason => Self::UnsupportedRevocationReason,

            _ => Self::Other(Arc::new(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_crl_errors() {
        // CRL signature errors should be turned into BadSignature.
        assert_eq!(
            pki_error(webpki::Error::InvalidCrlSignatureForPublicKey),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        );
        assert_eq!(
            pki_error(webpki::Error::UnsupportedCrlSignatureAlgorithm),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        );
        assert_eq!(
            pki_error(webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey),
            Error::InvalidCertRevocationList(CertRevocationListError::BadSignature),
        );

        // Revoked cert errors should be turned into Revoked.
        assert_eq!(
            pki_error(webpki::Error::CertRevoked),
            Error::InvalidCertificate(CertificateError::Revoked),
        );

        // Issuer not CRL signer errors should be turned into IssuerInvalidForCrl
        assert_eq!(
            pki_error(webpki::Error::IssuerNotCrlSigner),
            Error::InvalidCertRevocationList(CertRevocationListError::IssuerInvalidForCrl)
        );
    }

    #[test]
    fn crl_error_from_webpki() {
        use crate::error::CertRevocationListError::*;
        let testcases = &[
            (webpki::Error::InvalidCrlSignatureForPublicKey, BadSignature),
            (
                webpki::Error::UnsupportedCrlSignatureAlgorithm,
                BadSignature,
            ),
            (
                webpki::Error::UnsupportedCrlSignatureAlgorithmForPublicKey,
                BadSignature,
            ),
            (webpki::Error::InvalidCrlNumber, InvalidCrlNumber),
            (
                webpki::Error::InvalidSerialNumber,
                InvalidRevokedCertSerialNumber,
            ),
            (webpki::Error::IssuerNotCrlSigner, IssuerInvalidForCrl),
            (webpki::Error::MalformedExtensions, ParseError),
            (webpki::Error::BadDer, ParseError),
            (webpki::Error::BadDerTime, ParseError),
            (
                webpki::Error::UnsupportedCriticalExtension,
                UnsupportedCriticalExtension,
            ),
            (webpki::Error::UnsupportedCrlVersion, UnsupportedCrlVersion),
            (webpki::Error::UnsupportedDeltaCrl, UnsupportedDeltaCrl),
            (
                webpki::Error::UnsupportedIndirectCrl,
                UnsupportedIndirectCrl,
            ),
            (
                webpki::Error::UnsupportedRevocationReason,
                UnsupportedRevocationReason,
            ),
        ];
        for t in testcases {
            assert_eq!(
                <webpki::Error as Into<CertRevocationListError>>::into(t.0),
                t.1
            );
        }

        assert!(matches!(
            <webpki::Error as Into<CertRevocationListError>>::into(
                webpki::Error::NameConstraintViolation
            ),
            Other(_)
        ));
    }
}
