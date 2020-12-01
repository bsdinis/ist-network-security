use super::{CryptoErr, KeyUsage, ValidCertificate, X509Ext};
use chrono::{DateTime, TimeZone};
use openssl::asn1::Asn1Time;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};

const PADDING: Padding = Padding::PKCS1_PSS;

pub trait SignatureVerifier {
    /// Validate a message signature (SHA3-512/RSA/PKCS1-PSS)
    ///
    /// Signature could only be created by the holder of the private key.
    /// A timestamp must be provided to check certificate expiration.
    fn validate_rsa_sig<T: TimeZone>(
        &self,
        signature: &[u8],
        message: &[u8],
        ts: DateTime<T>,
    ) -> Result<bool, CryptoErr>;
}

pub trait Signer {
    /// Sign a message using SHA3-512/RSA/PKCS1-PSS
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoErr>;
}

impl SignatureVerifier for ValidCertificate {
    fn validate_rsa_sig<T: TimeZone>(
        &self,
        signature: &[u8],
        message: &[u8],
        ts: DateTime<T>,
    ) -> Result<bool, CryptoErr> {
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

        Ok(hashed_msg == decrypted_sig)
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
