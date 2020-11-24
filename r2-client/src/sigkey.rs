use std::fmt::{self, Debug, Display, Formatter};

use ring::signature::{self, KeyPair, RsaKeyPair, UnparsedPublicKey};
use ring::rand::SystemRandom;
use ring::error::Unspecified as RingError;

static SIGN_ALGO: &dyn signature::RsaEncoding = &signature::RSA_PSS_SHA512;
static SIGN_VERIFY_ALGO: &dyn signature::VerificationAlgorithm =
    &signature::RSA_PSS_2048_8192_SHA512;

lazy_static! {
    static ref RNG: SystemRandom = SystemRandom::new();
}

fn new_unparsed_public_key<B: AsRef<[u8]>>(pubkey: B) -> UnparsedPublicKey<B> {
    UnparsedPublicKey::new(SIGN_VERIFY_ALGO, pubkey)
}

pub trait SignatureVerifier {
	fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError>;
}

impl<B: AsRef<[u8]>> SignatureVerifier for UnparsedPublicKey<B> {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        self.verify(message, signature)?;
        Ok(())
    }
}

impl SignatureVerifier for RsaKeyPair {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        let pubkey = self.public_key().clone();
        let pubkey = new_unparsed_public_key(pubkey);

        SignatureVerifier::verify(&pubkey, message, signature)
    }
}

pub trait MaybeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError>;
}

impl MaybeSigner for RsaKeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        let mut sig = vec![0; self.public_modulus_len()];
        self.sign(SIGN_ALGO, &*RNG, message, &mut sig)?;

        Ok(sig)
    }
}

pub trait SignatureVerifierAndMaybeSigner : SignatureVerifier + MaybeSigner {}

impl SignatureVerifierAndMaybeSigner for RsaKeyPair {}

pub enum GenericSigningKey<B: AsRef<[u8]>> {
    PublicKeyOnly(B),
    KeyPair(RsaKeyPair),
}

impl GenericSigningKey<&str> {
    pub fn from_pkcs8_keypair(keypair: &[u8]) -> Result<Self, ring::error::KeyRejected> {
        Ok(GenericSigningKey::from_keypair(RsaKeyPair::from_pkcs8(keypair)?))
    }

    pub fn from_keypair(keypair: RsaKeyPair) -> Self {
        GenericSigningKey::KeyPair(keypair)
    }
}

impl<B: AsRef<[u8]>> GenericSigningKey<B> {
    pub fn from_pubkey(pubkey: B) -> Self {
        GenericSigningKey::PublicKeyOnly(pubkey)
    }
}

impl<B: AsRef<[u8]>> SignatureVerifier for GenericSigningKey<B> {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        use GenericSigningKey::*;

        match self {
            PublicKeyOnly(pubkey) => {
                let pubkey = new_unparsed_public_key(pubkey);
                SignatureVerifier::verify(&pubkey, message, signature)
            },
            KeyPair(keypair) => keypair.verify(message, signature),
        }
    }
}

impl<B: AsRef<[u8]>> SignatureVerifierAndMaybeSigner for GenericSigningKey<B> {}

impl<B: AsRef<[u8]>> MaybeSigner for GenericSigningKey<B> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        use GenericSigningKey::*;

        match self {
            KeyPair(keypair) => MaybeSigner::sign(keypair, message),
            PublicKeyOnly(_) => Err(SigningError::KeyCannotSign)
        }
    }
}

#[derive(Debug)]
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
