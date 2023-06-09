use std::convert::TryFrom;

use chrono::{DateTime, TimeZone};
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl_utils::*;

use serde::{Deserialize, Serialize};

const DOC_COLLABORATOR_KEY_USAGES: [KeyUsage; 1] = [KeyUsage::KeyEncipherment];
const COMMIT_AUTHOR_KEY_USAGES: [KeyUsage; 2] =
    [KeyUsage::DigitalSignature, KeyUsage::NonRepudiation];

/// A document collaborator
///
/// A document collaborator is someone who can perform document operations
/// in a remote, and possesses the private key for their auth certificate.
///
/// [DocCollaborator]s are [KeySealer]s, for sharing the document key with
/// other collaborators securely.
///
/// Decoupled from [CommitSigner] because a 1:1 correspondence is not enforced.
#[derive(Clone)]
pub struct DocCollaborator {
    pub id: Vec<u8>,
    pub name: String,
    pub auth_certificate: ValidCertificate,
    _priv: (),
}

/// A commit author
///
/// A commit author is someone that can author commits, possessing a private
/// signing key which they use to sign them.
///
/// Decoupled from [DocCollaborator] because a 1:1 correspondence is not enforced.
#[derive(Clone)]
pub struct CommitAuthor {
    pub id: Vec<u8>,
    pub name: String,
    pub sign_certificate: ValidCertificate,
    _priv: (),
}

/// The current user.
///
/// The local user of r2 must possess their private authentication and signing key
/// to unseal the document key and author commits.
#[derive(Clone)]
pub struct Me {
    auth_id: Vec<u8>,
    sign_id: Vec<u8>,
    auth_private_key: Rsa<Private>,
    sign_private_key: Rsa<Private>,
    auth_certificate: ValidCertificate,
    sign_certificate: ValidCertificate,
}

/// A [DocCollaborator] whose certificate was not verified against the CA cert.
/// Can be serialized and deserialized.
#[derive(Serialize, Deserialize)]
pub struct UnverifiedDocCollaborator {
    pub auth_certificate_pem: Vec<u8>,
}

/// A [CommitAuthor] whose certificate was not verified against the CA cert.
/// Note:
/// Can be serialized and deserialized.
#[derive(Serialize, Deserialize)]
pub struct UnverifiedCommitAuthor {
    pub sign_certificate_pem: Vec<u8>,
}

impl DocCollaborator {
    pub fn from_certificate(auth_certificate: X509, ca_cert: &X509) -> Result<Self, CryptoErr> {
        let auth_certificate = auth_certificate.validate(ca_cert, &DOC_COLLABORATOR_KEY_USAGES)?;

        // Safety: we did check key usages on the call to validate() ^
        unsafe { Self::from_certificate_unchecked(auth_certificate) }
    }

    /// Assumes certificate was validated for proper key usage
    pub unsafe fn from_certificate_unchecked(
        auth_certificate: ValidCertificate,
    ) -> Result<Self, CryptoErr> {
        let id = auth_certificate.pubkey_fingerprint()?;
        let name = auth_certificate.cert.common_name()?;

        Ok(DocCollaborator {
            id,
            name,
            auth_certificate,
            _priv: (),
        })
    }
}

impl UnverifiedDocCollaborator {
    pub fn verify(self, ca_cert: &X509) -> Result<DocCollaborator, CryptoErr> {
        let auth_certificate = X509::from_pem(&self.auth_certificate_pem)?;

        DocCollaborator::from_certificate(auth_certificate, ca_cert)
    }

    pub unsafe fn verify_unchecked(self) -> Result<DocCollaborator, CryptoErr> {
        let auth_certificate = X509::from_pem(&self.auth_certificate_pem)?.validate_unchecked();
        DocCollaborator::from_certificate_unchecked(auth_certificate)
    }
}

impl CommitAuthor {
    pub fn from_certificate(sign_certificate: X509, ca_cert: &X509) -> Result<Self, CryptoErr> {
        let sign_certificate = sign_certificate.validate(ca_cert, &COMMIT_AUTHOR_KEY_USAGES)?;

        // Safety: we did check key usages on the call to validate() ^
        unsafe { Self::from_certificate_unchecked(sign_certificate) }
    }

    /// Assumes certificate was validated for proper key usage
    pub unsafe fn from_certificate_unchecked(
        sign_certificate: ValidCertificate,
    ) -> Result<Self, CryptoErr> {
        let id = sign_certificate.pubkey_fingerprint()?;
        let name = sign_certificate.cert.common_name()?;

        Ok(CommitAuthor {
            id,
            name,
            sign_certificate,
            _priv: (),
        })
    }
}

impl UnverifiedCommitAuthor {
    pub fn verify(self, ca_cert: &X509) -> Result<CommitAuthor, CryptoErr> {
        let sign_certificate = X509::from_pem(&self.sign_certificate_pem)?;
        CommitAuthor::from_certificate(sign_certificate, ca_cert)
    }

    pub unsafe fn verify_unchecked(self) -> Result<CommitAuthor, CryptoErr> {
        let sign_certificate = X509::from_pem(&self.sign_certificate_pem)?.validate_unchecked();
        CommitAuthor::from_certificate_unchecked(sign_certificate)
    }
}

impl Me {
    pub fn from_certs(
        ca_cert: &X509,
        sign_private_key: Rsa<Private>,
        sign_certificate: X509,
        auth_private_key: Rsa<Private>,
        auth_certificate: X509,
    ) -> Result<Self, CryptoErr> {
        let sign_id = sign_private_key.pubkey_fingerprint()?;
        let auth_id = auth_private_key.pubkey_fingerprint()?;

        let sign_certificate = sign_certificate.validate(ca_cert, &COMMIT_AUTHOR_KEY_USAGES)?;
        let auth_certificate = auth_certificate.validate(ca_cert, &DOC_COLLABORATOR_KEY_USAGES)?;

        // Key IDs must match
        assert_eq!(
            sign_id,
            sign_certificate.pubkey_fingerprint()?,
            "signing private key and certificate mismatch"
        );
        assert_eq!(
            auth_id,
            auth_certificate.pubkey_fingerprint()?,
            "authentication private key and certificate mistach"
        );

        // Ensure keys are properly used
        sign_certificate
            .key_can(&COMMIT_AUTHOR_KEY_USAGES)
            .and(auth_certificate.key_can(&DOC_COLLABORATOR_KEY_USAGES))?;

        // Ensure keys are properly used
        sign_certificate
            .key_can(&COMMIT_AUTHOR_KEY_USAGES)
            .and(auth_certificate.key_can(&DOC_COLLABORATOR_KEY_USAGES))?;

        // Ensure keys are properly used
        sign_certificate
            .key_can(&COMMIT_AUTHOR_KEY_USAGES)
            .and(auth_certificate.key_can(&DOC_COLLABORATOR_KEY_USAGES))?;

        Ok(Me {
            sign_id,
            auth_id,
            sign_private_key,
            auth_private_key,
            sign_certificate,
            auth_certificate,
        })
    }

    pub fn commit_author_id(&self) -> &[u8] {
        &self.sign_id
    }

    pub fn doc_collaborator_id(&self) -> &[u8] {
        &self.auth_id
    }

    pub fn auth_private_key_pem(&self) -> Vec<u8> {
        self.auth_private_key
            .private_key_to_pem()
            .expect("OpenSSL: error converting private key to PEM")
    }

    pub fn auth_certificate_pem(&self) -> Vec<u8> {
        self.auth_certificate
            .cert
            .to_pem()
            .expect("OpenSSL: error converting certificate to PEM")
    }

    pub fn sign_certificate_pem(&self) -> Vec<u8> {
        self.sign_certificate
            .cert
            .to_pem()
            .expect("OpenSSL: error converting certificate to PEM")
    }
}

impl KeySealer for DocCollaborator {
    fn seal_key(&self, key_plaintext: &AeadKey) -> Result<SealedAeadKey, CryptoErr> {
        self.auth_certificate.seal_key(key_plaintext)
    }
}

impl KeySealer for Me {
    fn seal_key(&self, key_plaintext: &AeadKey) -> Result<SealedAeadKey, CryptoErr> {
        self.auth_private_key.seal_key(key_plaintext)
    }
}

impl KeyUnsealer for Me {
    fn unseal_key(&self, key_ciphertext: &SealedAeadKey) -> Result<AeadKey, CryptoErr> {
        self.auth_private_key.unseal_key(key_ciphertext)
    }
}

impl SignatureVerifier for CommitAuthor {
    fn validate_rsa_sig<T: TimeZone>(
        &self,
        signature: &[u8],
        message: &[u8],
        ts: DateTime<T>,
    ) -> Result<(), CryptoErr> {
        self.sign_certificate
            .validate_rsa_sig(signature, message, ts)
    }
}

impl Signer for Me {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        self.sign_private_key.sign(message)
    }
}

impl TryFrom<CommitAuthor> for UnverifiedCommitAuthor {
    type Error = CryptoErr;

    fn try_from(user: CommitAuthor) -> Result<Self, Self::Error> {
        let sign_certificate_pem = user.sign_certificate.cert.to_pem()?;

        Ok(UnverifiedCommitAuthor {
            sign_certificate_pem,
        })
    }
}

impl TryFrom<DocCollaborator> for UnverifiedDocCollaborator {
    type Error = CryptoErr;

    fn try_from(user: DocCollaborator) -> Result<Self, Self::Error> {
        let auth_certificate_pem = user.auth_certificate.cert.to_pem()?;

        Ok(UnverifiedDocCollaborator {
            auth_certificate_pem,
        })
    }
}
