use std::fmt::{self, Debug, Display, Formatter};

use ring::error::Unspecified as RingError;
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair, RsaKeyPair, RsaSubjectPublicKey, UnparsedPublicKey};

pub static SIGN_ALGO: &dyn signature::RsaEncoding = &signature::RSA_PSS_SHA512;
pub static SIGN_VERIFY_ALGO: &dyn signature::VerificationAlgorithm =
    &signature::RSA_PSS_2048_8192_SHA512;

pub fn new_unparsed_public_key<B: AsRef<[u8]>>(pubkey: B) -> UnparsedPublicKey<B> {
    UnparsedPublicKey::new(SIGN_VERIFY_ALGO, pubkey)
}

pub fn public_key(keypair: &RsaKeyPair) -> UnparsedPublicKey<RsaSubjectPublicKey> {
    new_unparsed_public_key(keypair.public_key().clone())
}

pub trait SignatureVerifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError>;
}
pub trait MaybeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError>;
}

pub trait SignatureVerifierAndMaybeSigner: SignatureVerifier + MaybeSigner {}
impl<T: SignatureVerifier + MaybeSigner> SignatureVerifierAndMaybeSigner for T {}

pub enum GenericSigningKey<B: AsRef<[u8]>> {
    PublicKeyOnly(UnparsedPublicKey<B>),
    KeyPair(RsaKeyPair),
}

impl GenericSigningKey<&str> {
    pub fn from_pkcs8_keypair(keypair: &[u8]) -> Result<Self, ring::error::KeyRejected> {
        Ok(GenericSigningKey::from_keypair(RsaKeyPair::from_pkcs8(
            keypair,
        )?))
    }

    pub fn from_keypair(keypair: RsaKeyPair) -> Self {
        GenericSigningKey::KeyPair(keypair)
    }
}

impl<B: AsRef<[u8]>> GenericSigningKey<B> {
    pub fn from_pubkey_bytes(pubkey: B) -> Self {
        Self::from_pubkey(new_unparsed_public_key(pubkey))
    }

    pub fn from_pubkey(pubkey: UnparsedPublicKey<B>) -> Self {
        GenericSigningKey::PublicKeyOnly(pubkey)
    }
}

#[derive(Debug, PartialEq)]
pub enum SigningError {
    Unspecified(RingError),
    KeyCannotSign,
}

impl Display for SigningError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        use SigningError::*;

        match self {
            Unspecified(e) => Display::fmt(e, f),
            KeyCannotSign => {
                write!(f, "Supplied key cannot sign messages (need private key)")
            }
        }
    }
}

impl std::error::Error for SigningError {}

impl From<RingError> for SigningError {
    fn from(err: RingError) -> Self {
        SigningError::Unspecified(err)
    }
}

lazy_static! {
    static ref RNG: SystemRandom = SystemRandom::new();
}

impl<B: AsRef<[u8]>> SignatureVerifier for GenericSigningKey<B> {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        use GenericSigningKey::*;

        match self {
            PublicKeyOnly(pubkey) => SignatureVerifier::verify(pubkey, message, signature),
            KeyPair(keypair) => keypair.verify(message, signature),
        }
    }
}

impl<B: AsRef<[u8]>> MaybeSigner for GenericSigningKey<B> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        use GenericSigningKey::*;

        match self {
            KeyPair(keypair) => MaybeSigner::sign(keypair, message),
            PublicKeyOnly(_) => Err(SigningError::KeyCannotSign),
        }
    }
}

impl<B: AsRef<[u8]>> SignatureVerifier for UnparsedPublicKey<B> {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        self.verify(message, signature)?;
        Ok(())
    }
}

impl SignatureVerifier for RsaKeyPair {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        SignatureVerifier::verify(&public_key(self), message, signature)
    }
}

impl MaybeSigner for RsaKeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        let mut sig = vec![0; self.public_modulus_len()];
        self.sign(SIGN_ALGO, &*RNG, message, &mut sig)?;

        Ok(sig)
    }
}

#[cfg(test)]
mod test {
    use super::GenericSigningKey;
    use super::SigningError;
    use super::{MaybeSigner, SignatureVerifier};

    use crate::test_utils::signature_keys::*;

    #[test]
    fn cant_sign_with_pubkey() {
        let message: Vec<u8> = vec![0, 1, 2, 3];
        let pubkey = GenericSigningKey::PublicKeyOnly(RSA_PUBKEY_A.clone());
        let res = pubkey.sign(&message);

        assert!(
            res.is_err(),
            "We did the impossible: we signed data with a public key"
        );
        assert_eq!(res.unwrap_err(), SigningError::KeyCannotSign);
    }

    #[test]
    fn sign_verify_ok() {
        let keypair = GenericSigningKey::from_pkcs8_keypair(RAW_RSA_KEYPAIR_A)
            .expect("RSA keypair parsing broken");

        let pubkey = GenericSigningKey::from_pubkey_bytes(&*RAW_RSA_PUBKEY_A);

        let message: Vec<u8> = vec![42; 4096]; // 4KiB of data, gotta be big enough to require hashing
        let signature = keypair.sign(&message).expect("Signing is broken");

        assert!(
            keypair.verify(&message, &signature).is_ok(),
            "Good signature was considered bad"
        );
        assert!(
            pubkey.verify(&message, &signature).is_ok(),
            "Good signature was considered bad"
        );
    }

    #[test]
    fn sign_verify_fail_different_signer() {
        let keypair_a = GenericSigningKey::from_pkcs8_keypair(RAW_RSA_KEYPAIR_A)
            .expect("RSA keypair parsing broken");
        let keypair_b = GenericSigningKey::from_pkcs8_keypair(RAW_RSA_KEYPAIR_B)
            .expect("RSA keypair parsing broken");

        let pubkey_a = GenericSigningKey::from_pubkey_bytes(&*RAW_RSA_PUBKEY_A);

        let message: Vec<u8> = vec![42; 4096]; // 4KiB of data, gotta be big enough to require hashing
        let signature_b = keypair_b.sign(&message).expect("Signing is broken");

        assert!(
            keypair_a.verify(&message, &signature_b).is_err(),
            "Bad signature was considered ok"
        );
        assert!(
            pubkey_a.verify(&message, &signature_b).is_err(),
            "Bad signature was considered ok"
        );
    }

    #[test]
    fn sign_verify_fail_different_message() {
        let keypair = GenericSigningKey::from_pkcs8_keypair(RAW_RSA_KEYPAIR_A)
            .expect("RSA keypair parsing broken");

        let pubkey = GenericSigningKey::from_pubkey_bytes(&*RAW_RSA_PUBKEY_A);

        let message_a: Vec<u8> = vec![42; 4096]; // 4KiB of data, gotta be big enough to require hashing
        let signature_a = keypair.sign(&message_a).expect("Signing is broken");

        let message_b = vec![3; 4096];
        assert_ne!(message_a, message_b, "fix your test");

        assert!(
            keypair.verify(&message_b, &signature_a).is_err(),
            "Bad signature was considered ok"
        );
        assert!(
            pubkey.verify(&message_b, &signature_a).is_err(),
            "Bad signature was considered ok"
        );
    }
}
