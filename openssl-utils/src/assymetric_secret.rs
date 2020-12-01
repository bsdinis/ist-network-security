use super::{CryptoErr, KeyUsage, ValidCertificate, X509Ext};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};

const PADDING: Padding = Padding::PKCS1_PSS;

pub trait KeyUnsealer {
    /// Unseals a key with RSA.
    fn unseal_key(&self, key_ciphertext: &[u8]) -> Result<Vec<u8>, CryptoErr>;
}

pub trait KeySealer {
    /// Seals a key with RSA.
    ///
    /// The key ciphertext can only be unsealed by the holder of the private key.
    fn seal_key(&self, key_plaintext: &[u8]) -> Result<Vec<u8>, CryptoErr>;
}

impl KeyUnsealer for Rsa<Private> {
    fn unseal_key(&self, key_ciphertext: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let mut key_plaintext = vec![0; self.size() as usize];
        let sz = self.private_decrypt(&key_ciphertext, &mut key_plaintext, PADDING)?;
        key_plaintext.truncate(sz);

        Ok(key_plaintext)
    }
}

impl KeySealer for ValidCertificate {
    fn seal_key(&self, key_plaintext: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let pubkey = self.cert.public_key()?.rsa()?;

        if key_plaintext.len() > pubkey.size() as usize {
            return Err(CryptoErr::MessageTooBig);
        }

        self.cert.key_can(&vec![KeyUsage::KeyEncipherment])?;

        let mut key_ciphertext = vec![0; pubkey.size() as usize];
        let sz = pubkey.public_encrypt(key_plaintext, &mut key_ciphertext, PADDING)?;
        key_ciphertext.truncate(sz);

        Ok(key_ciphertext)
    }
}
