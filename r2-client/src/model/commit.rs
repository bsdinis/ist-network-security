use super::user::User;
use chrono::{DateTime, Utc};
use crate::sigkey::{SignatureVerifier, MaybeSigner};
use ring::digest;
use serde::{Serialize, Deserialize};

static ID_DIGEST_ALGO: &digest::Algorithm = &digest::SHA512;

/// Unverified or in progress commit. Can be (de)serialized.
#[derive(Deserialize, Serialize, Clone)]
pub struct CommitData {
    pub id: String,

    pub prev_commit_id: Option<String>,
    pub author_id: String,
    pub ts: DateTime<Utc>,
    pub message: String,
    pub patch: String,

    pub signature: Vec<u8>,
}

/// A verified commit. Can be freely used by the application.
/// For persistence, convert it back to the untrusted `CommitData` struct.
pub struct Commit {
    pub id: String,

    pub prev_commit_id: Option<String>,
    pub author_id: String,
    pub ts: DateTime<Utc>,
    pub message: String,
    pub patch: String,

    pub signature: Vec<u8>,
    _priv: (),
}

// TODO: use more specific types everywhere
type CommitVerifyError = Box<dyn std::error::Error>;
type CommitSignError = Box<dyn std::error::Error>;

impl CommitData {
    /// Finish commit by setting the author and signing it, returning a trustworthy `Commit` struct
    pub fn author(mut self, author: &User) -> Result<Commit, CommitSignError> {
        self.author_id = author.id.to_owned();

        let bytes = self.bytes();
        self.signature = author.sign(&bytes)?;

        Ok(Commit {
            id: self.id,
            prev_commit_id: self.prev_commit_id,
            author_id: self.author_id,
            ts: self.ts,
            message: self.message,
            patch: self.patch,
            signature: self.signature,
            _priv: (),
        })
    }

    /// Verify commit (loaded from outside), returning a trustworthy `Commit` struct
    /// Verification amounts to checking that the ID was properly derived from the data, and that the signature is valid.
    pub fn verify(self, author: &User) -> Result<Commit, CommitVerifyError> {
        let generated_id = self.gen_id();

        if self.id != generated_id {
            return Err(format!("Badly generated commit ID. Expected {}, got {}", generated_id, self.id))?;
        }

        assert_eq!(self.author_id, author.id, "Tried to verify signature with wrong key");

        let bytes = self.bytes();
        author.verify(&bytes, &self.signature)?;

        Ok(Commit {
            id: self.id,
            prev_commit_id: self.prev_commit_id,
            author_id: self.author_id,
            ts: self.ts,
            message: self.message,
            patch: self.patch,
            signature: self.signature,
            _priv: (),
        })
    }

    /// Create byte array with all commit data for signing (or ID generation when the self.id == "")
    fn bytes(&self) -> Vec<u8> {
        self.id.as_bytes().to_owned().iter()
            .chain(self.prev_commit_id.as_ref().unwrap_or(&String::new()).as_bytes())
            .chain(self.author_id.as_bytes())
            .chain(self.ts.to_rfc3339().as_bytes())
            .chain(self.message.as_bytes())
            .chain(self.patch.as_bytes())
            .map(|byteref| *byteref)
            .collect()
    }

    /// Generate ID for current commit (does not change with already present ID or signature)
    fn gen_id(&self) -> String {
        let commit_empty_id = CommitData {id: "".to_owned(), ..self.clone()};

        let bytes = commit_empty_id.bytes();
        let digest = digest::digest(ID_DIGEST_ALGO, &bytes);

        format!("{:x?}", digest)
    }
}

impl From<Commit> for CommitData {
    fn from(c: Commit) -> Self {
        CommitData {
            id: c.id,
            prev_commit_id: c.prev_commit_id,
            author_id: c.author_id,
            ts: c.ts,
            message: c.message,
            patch: c.patch,
            signature: c.signature,
        }
    }
}
