use super::user::User;
use chrono::{DateTime, Utc};
use ring::{digest, signature};
use ring::rand::SystemRandom;
use serde::{Serialize, Deserialize};

const ID_DIGEST_ALGO: &digest::Algorithm = &digest::SHA512;
const COMMIT_SIGN_ALGO: &dyn signature::RsaEncoding = &signature::RSA_PSS_SHA512;
const COMMIT_SIGN_VERIFY_ALGO: &dyn signature::VerificationAlgorithm = &signature::RSA_PSS_2048_8192_SHA512;

/// Unverified or in progress commit. Can be (de)serialized.
#[derive(Deserialize, Serialize)]
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
    pub fn author<B: AsRef<[u8]>>(self, author: &User<B>) -> Result<Commit, CommitSignError> {
        self.author_id = author.id;

        let keypair = author.privkey.ok_or("author has no keypair")?;

        let bytes = self.bytes();
        let rng = SystemRandom::new();
        self.signature = vec![0; keypair.public_modulus_len()];
        keypair.sign(COMMIT_SIGN_ALGO, rng, bytes, &mut self.signature)?;

        Ok(Commit {..self})
    }

    /// Verify commit (loaded from outside), returning a trustworthy `Commit` struct
    /// Verification amounts to checking that the ID was properly derived from the data, and that the signature is valid.
    pub fn verify<B: AsRef<[u8]>>(self, author: &User<B>) -> Result<Commit, CommitVerifyError> {
        let generated_id = self.gen_id();

        if self.id != generated_id {
            return Err(format!("Badly generated commit ID. Expected {}, got {}", generated_id, self.id));
        }

        assert_eq!(self.author_id, author.id, "Tried to verify signature with wrong key");

        let bytes = self.bytes();
        author.pubkey.verify(&bytes, &self.signature)?;

        Ok(Commit {..self})
    }

    /// Create byte array with all commit data for signing (or ID generation when the self.id == "")
    fn bytes(&self) -> Vec<u8> {
        let bytes = Vec::new();

        bytes.push(self.id.as_bytes());
        bytes.push(self.prev_commit_id.unwrap_or(String::new()).as_bytes());
        bytes.push(self.author_id.as_bytes());
        bytes.push(self.ts.to_rfc3339().as_bytes());
        bytes.push(self.message.as_bytes());
        bytes.push(self.patch.as_bytes());

        bytes
    }

    /// Generate ID for current commit (does not change with already present ID or signature)
    fn gen_id(&self) -> String {
        let commit_empty_id = Commit {id: "".to_owned(), ..self};

        let bytes = commit_empty_id.bytes();
        let digest = digest::digest(ID_DIGEST_ALGO, &bytes);

        format!("{:x?}", digest)
    }
}

impl From<Commit> for CommitData {
    fn from(c: Commit) -> Self {
        CommitData {..c}
    }
}
