use crate::{
    model::{Commit, Me, UnverifiedCommit},
    DocCollaborator,
};
use openssl_utils::{
    aead::{AeadKey, SealedSecretBox, UnsealedSecretBox},
    assymetric_secret::{KeySealer, SealedAeadKey},
    CryptoErr,
};

pub type CollaboratorId = Vec<u8>;

pub type DocumentKey = AeadKey;
pub type CipheredDocumentKey = SealedAeadKey;

pub enum Vote {
    For,
    Against,
}

pub struct FileMetadata {
    pub head: String,
    pub document_key: CipheredDocumentKey,
}

#[derive(Clone)]
pub struct CipheredCommit {
    pub id: String,
    pub data: SealedSecretBox,
}

#[derive(Clone)]
pub struct RemoteCollaborator {
    pub id: CollaboratorId,
    pub document_key: CipheredDocumentKey,
}

impl RemoteCollaborator {
    pub fn from_doc_collaborator(
        collaborator: &DocCollaborator,
        key: &DocumentKey,
    ) -> Result<Self, CryptoErr> {
        Ok(RemoteCollaborator {
            id: collaborator.id.clone(),
            document_key: collaborator.seal_key(key)?,
        })
    }

    pub fn from_me(me: &Me, key: &DocumentKey) -> Result<Self, CryptoErr> {
        Ok(RemoteCollaborator {
            id: me.doc_collaborator_id().to_vec(),
            document_key: me.seal_key(key)?,
        })
    }
}

type Error = Box<dyn std::error::Error>;

impl CipheredCommit {
    pub fn cipher(
        commit: &Commit,
        key: &DocumentKey,
        nonce: [u8; openssl_utils::aead::NONCE_SIZE],
    ) -> Result<CipheredCommit, Error> {
        let id = commit.id.clone();
        let unsealed = UnsealedSecretBox {
            nonce,
            aad: vec![],
            plaintext: toml::to_string(commit)?.into_bytes(),
        };

        Ok(CipheredCommit {
            id,
            data: key.seal(unsealed)?,
        })
    }

    pub fn decipher(self, key: &DocumentKey) -> Result<UnverifiedCommit, Error> {
        let unsealed = key.unseal(self.data)?;
        let commit: UnverifiedCommit = toml::from_slice(&unsealed.plaintext)?;

        assert_eq!(
            commit.id, self.id,
            "ID mismatch between what you thought you were getting and what the server sent"
        );

        Ok(commit)
    }
}
