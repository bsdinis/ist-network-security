use super::{AeadKey, CryptoErr, KeyUsage, ValidCertificate, X509Ext};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};

const PADDING: Padding = Padding::PKCS1;

pub trait KeyUnsealer {
    /// Unseals a key with RSA.
    fn unseal_key(&self, key_ciphertext: &[u8]) -> Result<AeadKey, CryptoErr>;
}

pub trait KeySealer {
    /// Seals a key with RSA.
    ///
    /// The key ciphertext can only be unsealed by the holder of the private key.
    fn seal_key(&self, key_plaintext: &AeadKey) -> Result<Vec<u8>, CryptoErr>;
}

impl KeyUnsealer for Rsa<Private> {
    fn unseal_key(&self, key_ciphertext: &[u8]) -> Result<AeadKey, CryptoErr> {
        let mut key_plaintext = vec![0; self.size() as usize];
        let sz = self.private_decrypt(&key_ciphertext, &mut key_plaintext, PADDING)?;
        key_plaintext.truncate(sz);

        AeadKey::from_existing_key(&key_plaintext)
    }
}

impl KeySealer for ValidCertificate {
    fn seal_key(&self, key_plaintext: &AeadKey) -> Result<Vec<u8>, CryptoErr> {
        let pubkey = self.cert.public_key()?.rsa()?;

        if key_plaintext.as_ref().len() > pubkey.size() as usize {
            return Err(CryptoErr::MessageTooBig);
        }

        self.cert.key_can(&vec![KeyUsage::KeyEncipherment])?;

        let mut key_ciphertext = vec![0; pubkey.size() as usize];
        let sz = pubkey.public_encrypt(key_plaintext.as_ref(), &mut key_ciphertext, PADDING)?;
        key_ciphertext.truncate(sz);

        Ok(key_ciphertext)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::aead;
    use lazy_static::lazy_static;
    use openssl::x509::X509;

    lazy_static! {
        static ref CA_CERT: X509 =
            X509::from_pem(include_bytes!("test_certs/ca.cert.pem")).unwrap();
        static ref CL_AUTH_CERT: X509 =
            X509::from_pem(include_bytes!("test_certs/client-auth.cert.pem")).unwrap();
        static ref CL_AUTH_KEY: Rsa<Private> =
            Rsa::private_key_from_pem(include_bytes!("test_certs/client-auth.key.pem")).unwrap();
    }

    #[test]
    fn seal_unseal_ok() {
        // cl auth valid cert
        let ca_cert = CA_CERT.to_owned();
        let cl_auth_cert = CL_AUTH_CERT.to_owned();
        let cl_auth_cert_val = cl_auth_cert
            .validate(&ca_cert, &[KeyUsage::KeyEncipherment])
            .unwrap();

        // seal wiht cl auth valid cert
        let key = aead::AeadKey::gen_key().unwrap();
        let sealed_key = cl_auth_cert_val.seal_key(&key).unwrap();

        // unseal with cl auth priv key
        let cl_auth_key = CL_AUTH_KEY.to_owned();
        let unsealed_key = cl_auth_key.unseal_key(&sealed_key).unwrap();

        // assert equal
        assert_eq!(key, unsealed_key);
    }
}