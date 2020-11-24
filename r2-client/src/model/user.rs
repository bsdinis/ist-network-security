use crate::sigkey::*;

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

pub struct User {
    pub id: String,
    pub name: String,
    pub key: Box<dyn SignatureVerifierAndMaybeSigner>,
    _priv: (),
}

impl User {
    pub fn new_with_pubkey(id: String, name: String, pubkey: Vec<u8>) -> Self {
        User {
            id,
            name,
            key: Box::from(GenericSigningKey::from_pubkey(pubkey)),
            _priv: (),
        }
    }

    pub fn new_with_pkcs8_keypair(id: String, name: String, keypair: &[u8]) -> Result<Self, Error> {
        Ok(User {
            id,
            name,
            key: Box::from(GenericSigningKey::from_pkcs8_keypair(keypair)?),
            _priv: (),
        })
    }
}

impl SignatureVerifier for User {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), SigningError> {
        self.key.verify(message, signature)
    }
}

impl MaybeSigner for User {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.key.sign(message)
    }
}

impl SignatureVerifierAndMaybeSigner for User {}
