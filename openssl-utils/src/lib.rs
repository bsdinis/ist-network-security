use openssl::error::ErrorStack;
use thiserror::Error;

pub mod pubkey_fingerprint;
pub use pubkey_fingerprint::PublicKeyFingerprintExt;

pub mod cert;
pub use cert::{ValidCertificate, X509Ext};

pub mod sign;
pub use sign::{SignatureVerifier, Signer};

pub mod assymetric_secret;
pub use assymetric_secret::{KeySealer, KeyUnsealer, SealedAeadKey};

pub mod aead;
pub use aead::AeadKey;

#[derive(Clone, Copy)]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    NonRepudiation,
}

#[derive(Debug, Error)]
pub enum CryptoErr {
    #[error("OpenSSL Error: {:?}", .0)]
    OpensslError(#[from] ErrorStack),

    #[error("Certificate missing Common Name field")]
    NoCommonName,

    #[error("Certificate has too many common name fields")]
    TooManyCommonNames,

    #[error("Invalid Certificate")]
    InvalidCert,

    #[error("Incompatible key usage")]
    IncompatibleKeyUsage,

    #[error("Certificate expired")]
    Expired,

    #[error("Message too big")]
    MessageTooBig,

    #[error("Bad key size")]
    BadKeySize,

    #[error("Invalid signature")]
    InvalidSignature,
}
