use super::CryptoErr;
use lazy_static::lazy_static;
use openssl::rand::rand_bytes;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref CIPHER: Cipher = Cipher::aes_256_gcm();
}

pub const KEY_SIZE: usize = 32; // 256 bit
pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

#[derive(Serialize, Deserialize)]
pub struct AeadKey([u8; KEY_SIZE]);

#[derive(Debug, PartialEq, Clone)]
pub struct UnsealedSecretBox {
    pub nonce: [u8; NONCE_SIZE],
    pub plaintext: Vec<u8>,
    pub aad: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SealedSecretBox {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag: [u8; TAG_SIZE],
}

impl AeadKey {
    pub fn gen_key() -> Result<Self, CryptoErr> {
        let mut key = [0u8; KEY_SIZE];
        rand_bytes(&mut key)?;

        Ok(AeadKey(key))
    }

    pub fn from_existing_key(key: [u8; KEY_SIZE]) -> Self {
        AeadKey(key)
    }

    pub fn seal(&self, unsealed: UnsealedSecretBox) -> Result<SealedSecretBox, CryptoErr> {
        let mut tag = [0u8; TAG_SIZE];
        let ciphertext = encrypt_aead(CIPHER.to_owned(), &self.0, Some(&unsealed.nonce), &unsealed.aad, &unsealed.plaintext, &mut tag)?;

        Ok(SealedSecretBox {
            nonce: unsealed.nonce,
            ciphertext,
            aad: unsealed.aad,
            tag,
        })
    }

    pub fn unseal(&self, sealed: SealedSecretBox) -> Result<UnsealedSecretBox, CryptoErr> {
        let plaintext = decrypt_aead(CIPHER.to_owned(), &self.0, Some(&sealed.nonce), &sealed.aad, &sealed.ciphertext, &sealed.tag)?;
        Ok(UnsealedSecretBox {
            nonce: sealed.nonce,
            plaintext,
            aad: sealed.aad,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encrypt_decrypt_ok() {
        let key = AeadKey::gen_key().unwrap();
        let unsealed = UnsealedSecretBox {
            nonce: [42; NONCE_SIZE],
            plaintext: vec![3, 7, 23],
            aad: vec![1, 2, 4],
        };

        let sealed = key.seal(unsealed.clone()).unwrap();
        let unsealed_2 = key.unseal(sealed).unwrap();

        assert_eq!(unsealed, unsealed_2);
    }

    #[test]
    fn encrypt_decrypt_bad() {
        let key = AeadKey::gen_key().unwrap();
        let unsealed = UnsealedSecretBox {
            nonce: [42; NONCE_SIZE],
            plaintext: vec![3, 7, 23],
            aad: vec![1, 2, 4],
        };

        let mut sealed = key.seal(unsealed.clone()).unwrap();
        sealed.ciphertext.swap(0, 1);

        let unsealed_2 = key.unseal(sealed);
        assert!(unsealed_2.is_err());
    }
}
