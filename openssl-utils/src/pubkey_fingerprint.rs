use super::CryptoErr;
use lazy_static::lazy_static;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{HasPublic, PKey};
use openssl::rsa::Rsa;

lazy_static! {
    static ref PUBKEY_DIGEST_ALGO: MessageDigest = MessageDigest::sha3_256();
}

pub trait PublicKeyFingerprintExt {
    fn pubkey_fingerprint(&self) -> Result<Vec<u8>, CryptoErr>;
}

fn pubkey_fingerprint(pubkey: &[u8]) -> Result<Vec<u8>, CryptoErr> {
    Ok(hash(PUBKEY_DIGEST_ALGO.to_owned(), pubkey)?.to_vec())
}

impl<T: HasPublic> PublicKeyFingerprintExt for Rsa<T> {
    fn pubkey_fingerprint(&self) -> Result<Vec<u8>, CryptoErr> {
        let pubkey = self.public_key_to_der()?;
        pubkey_fingerprint(&pubkey)
    }
}

impl<T: HasPublic> PublicKeyFingerprintExt for PKey<T> {
    fn pubkey_fingerprint(&self) -> Result<Vec<u8>, CryptoErr> {
        let pubkey = self.public_key_to_der()?;
        pubkey_fingerprint(&pubkey)
    }
}
