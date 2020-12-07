use std::convert::TryFrom;

use chrono::{DateTime, TimeZone};
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use openssl_utils::*;

use serde::{Deserialize, Serialize};

const COLLABORATOR_KEY_USAGES: [KeyUsage; 1] = [KeyUsage::KeyEncipherment];
const COMMIT_SIGNER_KEY_USAGES: [KeyUsage; 2] =
    [KeyUsage::DigitalSignature, KeyUsage::NonRepudiation];

/// A document collaborator (as viewed by a remote)
///
/// A collaborator can seal/unseal his document key to decrypt data obtained
/// from a remote, and encrypt data before uploading to a remote.
///
/// To be able to represent other collaborators the private key is optional,
/// so decrypting the document key may be impossible.
///
/// Decoupled from [CommitSigner] because a 1:1 correspondence is not enforced.
#[derive(Clone)]
pub struct Collaborator {
    pub id: Vec<u8>,
    pub name: String,
    pub auth_certificate: ValidCertificate,
    pub auth_private_key: Option<Rsa<Private>>,
    _priv: (),
}

/// Someone with a signing key/cert (as viewed by end users while collaborating)
///
/// A commit signer can sign commits and verify their commit signatures.
///
/// To be able to represent other collaborators the private key is optional,
/// so signing a commit may be impossible.
///
/// Decoupled from [Collaborator] because a 1:1 correspondence is not enforced.
pub struct CommitSigner {
    pub id: Vec<u8>,
    pub name: String,
    pub sign_certificate: ValidCertificate,
    pub sign_private_key: Option<Rsa<Private>>,
    _priv: (),
}

/// A [Collaborator] whose certificate was not verified against the CA cert.
/// Can be serialized and deserialized.
#[derive(Serialize, Deserialize)]
pub struct UnverifiedCollaborator {
    pub auth_certificate_pem: Vec<u8>,
    pub auth_private_key_pem: Option<Vec<u8>>,
}

/// A [CommitSigner] whose certificate was not verified against the CA cert.
/// Can be serialized and deserialized.
#[derive(Serialize, Deserialize)]
pub struct UnverifiedCommitSigner {
    pub sign_certificate_pem: Vec<u8>,
    pub sign_private_key_pem: Option<Vec<u8>>,
}

impl Collaborator {
    pub fn from_certificate(
        auth_certificate: ValidCertificate,
        auth_private_key: Option<Rsa<Private>>,
    ) -> Result<Self, CryptoErr> {
        let id = auth_certificate.pubkey_fingerprint()?;
        let name = auth_certificate.cert.common_name()?;

        Ok(Collaborator {
            id,
            name,
            auth_certificate,
            auth_private_key,
            _priv: (),
        })
    }
}

impl UnverifiedCollaborator {
    pub fn verify(self, ca_cert: &X509) -> Result<Collaborator, CryptoErr> {
        let auth_certificate = X509::from_pem(&self.auth_certificate_pem)?
            .validate(ca_cert, &COLLABORATOR_KEY_USAGES)?;

        let auth_private_key = self
            .auth_private_key_pem
            .map(|raw| Rsa::private_key_from_pem(&raw))
            .transpose()?;

        Collaborator::from_certificate(auth_certificate, auth_private_key)
    }

    pub unsafe fn verify_unchecked(self) -> Result<Collaborator, CryptoErr> {
        let auth_certificate = X509::from_pem(&self.auth_certificate_pem)?.validate_unchecked();

        let auth_private_key = self
            .auth_private_key_pem
            .map(|raw| Rsa::private_key_from_pem(&raw))
            .transpose()?;

        Collaborator::from_certificate(auth_certificate, auth_private_key)
    }
}

impl CommitSigner {
    pub fn from_certificate(
        sign_certificate: ValidCertificate,
        sign_private_key: Option<Rsa<Private>>,
    ) -> Result<Self, CryptoErr> {
        let id = sign_certificate.pubkey_fingerprint()?;
        let name = sign_certificate.cert.common_name()?;

        Ok(CommitSigner {
            id,
            name,
            sign_certificate,
            sign_private_key,
            _priv: (),
        })
    }
}

impl UnverifiedCommitSigner {
    pub fn verify(self, ca_cert: &X509) -> Result<CommitSigner, CryptoErr> {
        let sign_certificate = X509::from_pem(&self.sign_certificate_pem)?
            .validate(ca_cert, &COMMIT_SIGNER_KEY_USAGES)?;

        let sign_private_key = self
            .sign_private_key_pem
            .map(|raw| Rsa::private_key_from_pem(&raw))
            .transpose()?;

        CommitSigner::from_certificate(sign_certificate, sign_private_key)
    }

    pub unsafe fn verify_unchecked(self) -> Result<CommitSigner, CryptoErr> {
        let sign_certificate = X509::from_pem(&self.sign_certificate_pem)?.validate_unchecked();

        let sign_private_key = self
            .sign_private_key_pem
            .map(|raw| Rsa::private_key_from_pem(&raw))
            .transpose()?;

        CommitSigner::from_certificate(sign_certificate, sign_private_key)
    }
}

impl KeySealer for Collaborator {
    fn seal_key(&self, key_plaintext: &AeadKey) -> Result<Vec<u8>, CryptoErr> {
        self.auth_certificate.seal_key(key_plaintext)
    }
}

impl KeyUnsealer for Collaborator {
    fn unseal_key(&self, key_ciphertext: &[u8]) -> Result<AeadKey, CryptoErr> {
        if let Some(ref private_key) = self.auth_private_key {
            private_key.unseal_key(key_ciphertext)
        } else {
            Err(CryptoErr::IncompatibleKeyUsage)
        }
    }
}

impl SignatureVerifier for CommitSigner {
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

impl Signer for CommitSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        if let Some(ref private_key) = self.sign_private_key {
            private_key.sign(message)
        } else {
            Err(CryptoErr::IncompatibleKeyUsage)
        }
    }
}

impl TryFrom<Collaborator> for UnverifiedCollaborator {
    type Error = CryptoErr;

    fn try_from(user: Collaborator) -> Result<Self, Self::Error> {
        let auth_certificate_pem = user.auth_certificate.cert.to_pem()?;
        let auth_private_key_pem = user
            .auth_private_key
            .map(|key| key.private_key_to_pem())
            .transpose()?;

        Ok(UnverifiedCollaborator {
            auth_certificate_pem,
            auth_private_key_pem,
        })
    }
}
