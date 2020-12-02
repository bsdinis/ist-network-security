use super::{CryptoErr, KeyUsage, ValidCertificate, X509Ext};
use chrono::{DateTime, TimeZone};
use openssl::asn1::Asn1Time;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};

const PADDING: Padding = Padding::PKCS1;

pub trait SignatureVerifier {
    /// Validate a message signature (SHA3-512/RSA/PKCS1)
    ///
    /// Signature could only be created by the holder of the private key.
    /// A timestamp must be provided to check certificate expiration.
    fn validate_rsa_sig<T: TimeZone>(
        &self,
        signature: &[u8],
        message: &[u8],
        ts: DateTime<T>,
    ) -> Result<(), CryptoErr>;
}

pub trait Signer {
    /// Sign a message using SHA3-512/RSA/PKCS1
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoErr>;
}

impl SignatureVerifier for ValidCertificate {
    fn validate_rsa_sig<T: TimeZone>(
        &self,
        signature: &[u8],
        message: &[u8],
        ts: DateTime<T>,
    ) -> Result<(), CryptoErr> {
        // check cert expiration
        let not_before = self.cert.not_before();
        let ts = Asn1Time::from_unix(ts.timestamp())?;
        let not_after = self.cert.not_after();
        if ts < not_before || ts > not_after {
            return Err(CryptoErr::Expired);
        }

        // check cert keyusage restrictions
        self.cert.key_can(&vec![KeyUsage::DigitalSignature])?;

        let pubkey = self.cert.public_key()?;
        let pubkey = pubkey.rsa()?;

        let mut decrypted_sig = vec![0; pubkey.size() as usize];
        let sz = pubkey.public_decrypt(&signature, &mut decrypted_sig, PADDING)?;
        decrypted_sig.truncate(sz);

        let hashed_msg = hash_message(message)?;

        if hashed_msg == decrypted_sig {
            Ok(())
        } else {
            Err(CryptoErr::InvalidSignature)
        }
    }
}

impl Signer for Rsa<Private> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let hashed_message = hash_message(message)?;

        let mut signature = vec![0; self.size() as usize];
        let sz = self.private_encrypt(&hashed_message, &mut signature, PADDING)?;
        signature.truncate(sz);

        Ok(signature)
    }
}

fn hash_message(message: &[u8]) -> Result<Vec<u8>, CryptoErr> {
    let hashed = hash(MessageDigest::sha3_512(), message)?.to_vec();

    Ok(hashed)
}

#[cfg(test)]
mod test {
    use super::*;
    use lazy_static::lazy_static;
    use openssl::rsa::Rsa;
    use openssl::x509::X509;

    lazy_static! {
        static ref CA_CERT: X509 =
            X509::from_pem(include_bytes!("test_certs/ca.cert.pem")).unwrap();
        static ref SERV_CERT: X509 =
            X509::from_pem(include_bytes!("test_certs/server.cert.pem")).unwrap();
        static ref SERV_KEY: Rsa<Private> =
            Rsa::private_key_from_pem(include_bytes!("test_certs/server.key.pem")).unwrap();
    }

    #[test]
    fn val_sign_serv() {
        // sign message with server prviate key
        let server_key = SERV_KEY.to_owned();
        let message = &[7, 23, 71];
        let signature = server_key.sign(message).unwrap();

        // get and validate certificate
        let ca_cert = CA_CERT.to_owned();
        let server_key_cert = SERV_CERT.to_owned();
        let serv_key_cert_val = server_key_cert
            .validate(&ca_cert, &[KeyUsage::DigitalSignature])
            .unwrap();

        // validate signature
        serv_key_cert_val
            .validate_rsa_sig(&signature, message, chrono::offset::Local::now())
            .unwrap();
    }

    #[test]
    fn val_sign_serv_err() {
        // sign message with server prviate key
        let server_key = SERV_KEY.to_owned();
        let message = &[7, 23, 71];
        let mut signature = server_key.sign(message).unwrap();

        // get and validate certificate
        let ca_cert = CA_CERT.to_owned();
        let server_key_cert = SERV_CERT.to_owned();
        let serv_key_cert_val = server_key_cert
            .validate(&ca_cert, &[KeyUsage::DigitalSignature])
            .unwrap();

        signature.swap(0, 1);

        // validate signature must fail
        assert!(serv_key_cert_val
            .validate_rsa_sig(&signature, message, chrono::offset::Local::now())
            .is_err());
    }
}
