use openssl::error::ErrorStack;
use std::fmt;

mod pubkey_fingerprint;
pub use pubkey_fingerprint::PublicKeyFingerprintExt;

mod cert;
pub use cert::{ValidCertificate, X509Ext};

mod sign;
pub use sign::{SignatureVerifier, Signer};

mod assymetric_secret;
pub use assymetric_secret::{KeySealer, KeyUnsealer};

mod aead;
pub use aead::AeadKey;

#[derive(Clone, Copy)]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    NonRepudiation,
}

#[derive(Debug)]
pub enum CryptoErr {
    OpensslError(ErrorStack),
    NoCommonName,
    TooManyCommonNames,
    InvalidCert,
    IncompatibleKeyUsage,
    Expired,
    MessageTooBig,
    BadKeySize,
    InvalidSignature,
}

impl From<ErrorStack> for CryptoErr {
    fn from(err: ErrorStack) -> Self {
        CryptoErr::OpensslError(err)
    }
}

impl fmt::Display for CryptoErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoErr::Expired => write!(f, "Certificate Expired"),
            CryptoErr::IncompatibleKeyUsage => write!(f, "Incompatible key usage"),
            CryptoErr::InvalidCert => write!(f, "Invalid Certificate"),
            CryptoErr::MessageTooBig => write!(f, "Certificate Expired"),
            CryptoErr::NoCommonName => write!(f, "Certificate missing Common Name field"),
            CryptoErr::TooManyCommonNames => {
                write!(f, "Too many common name fields in certificate")
            }
            CryptoErr::BadKeySize => write!(f, "Bad Key Size"),
            CryptoErr::InvalidSignature => write!(f, "Signature is invalid"),
            CryptoErr::OpensslError(e) => write!(f, "OpenSSL error: {}", e),
        }
    }
}
