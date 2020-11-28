use super::snapshot::PatchStr;
use super::storage::{Storage, StorageSharedGuard};
use super::user::User;
use crate::sigkey::{MaybeSigner, SignatureVerifier};
use chrono::{DateTime, Utc};
use ring::digest;
use serde::{Deserialize, Serialize};

static ID_DIGEST_ALGO: &digest::Algorithm = &digest::SHA512;

/// A commit.
///
/// Guaranteed to be well-formed: with a valid ID and signature from a
/// collaborator.
///
/// It cannot be deserialized (because we'd get possibly invalid signatures,
/// authors or IDs), but the serialization format is guaranteed to be compatible
/// with [UnsafeCommit] (which can be deserialized).
#[derive(Clone, Serialize, Debug, PartialEq)]
pub struct Commit {
    pub id: String,

    pub prev_commit_id: Option<String>,
    pub author_id: String,
    pub ts: DateTime<Utc>,
    pub message: String,

    pub patch: PatchStr,

    pub signature: Vec<u8>,

    #[serde(skip)]
    _priv: (),
}

/// Unverified commit (obtained from an outside source).
///
/// It can be converted to a [Commit] object by verifying
/// ([`Self::verify()`]) it.
///
/// It cannot be serialized, to avoid persisting bad data, but
/// the serialization format is guaranteed to be compatible with
/// [Commit] (which can be serialized).
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct UnverifiedCommit {
    pub id: String,

    pub prev_commit_id: Option<String>,
    pub author_id: String,
    pub ts: DateTime<Utc>,
    pub message: String,

    pub patch: PatchStr,

    pub signature: Vec<u8>,

    #[serde(skip)]
    _priv: (),
}

/// Commit builder.
pub struct CommitBuilder {
    prev_commit_id: Option<String>,
    message: String,
    patch: PatchStr,
}

// TODO: use more specific types everywhere
type Error = Box<dyn std::error::Error>;

impl UnverifiedCommit {
    /// Convert to [Commit] after verification, given its author.
    ///
    /// - Passing an [User] which is not the commit's author will panic;
    /// - A commit whose ID does not match the one generated by our
    ///   algorithm is considered invalid;
    /// - A valid commit must have a valid signature from its author.
    pub fn verify(self, author: &User) -> Result<Commit, Error> {
        assert_eq!(
            self.author_id, author.id,
            "Tried to verify signature with wrong key"
        );

        let generated_id = {
            let mut idless_commit = self.clone();
            idless_commit.id = String::new();
            idless_commit.gen_id()
        };

        if self.id != generated_id {
            return Err(format!(
                "Badly generated commit ID. Expected {}, got {:?}",
                generated_id, self.id
            ))?;
        }

        let bytes = self.bytes(true);
        author.verify(&bytes, &self.signature)?;

        // Safety: we did check ^
        unsafe { Ok(self.verify_unchecked()) }
    }

    pub unsafe fn verify_unchecked(self) -> Commit {
        Commit {
            id: self.id,
            prev_commit_id: self.prev_commit_id,
            author_id: self.author_id,
            ts: self.ts,
            message: self.message,
            patch: self.patch,
            signature: self.signature,
            _priv: (),
        }
    }

    /// Create byte array with all commit data (for ID generation or signing)
    /// ID can be included (for signing) or not (for id generation).
    fn bytes(&self, with_id: bool) -> Vec<u8> {
        let empty_string = String::new();
        let prev_commit_id_bytes = self
            .prev_commit_id
            .as_ref()
            .unwrap_or(&empty_string)
            .as_bytes();

        let id_bytes = if with_id {
            self.id.as_bytes()
        } else {
            empty_string.as_bytes()
        };

        id_bytes
            .iter()
            .chain(prev_commit_id_bytes)
            .chain(self.author_id.as_bytes())
            .chain(self.ts.to_rfc3339().as_bytes())
            .chain(self.message.as_bytes())
            .chain(self.patch.as_bytes())
            .cloned()
            .collect()
    }

    /// Generate ID for current commit (does not change with already present ID or signature)
    fn gen_id(&self) -> String {
        let bytes = self.bytes(false);
        let digest = digest::digest(ID_DIGEST_ALGO, &bytes);

        format!("{:x?}", digest)
    }
}

impl CommitBuilder {
    pub fn root_commit(message: String, patch: PatchStr) -> Self {
        let prev_commit_id = None;
        CommitBuilder {
            prev_commit_id,
            message,
            patch,
        }
    }

    pub fn from_commit(prev_commit: &Commit, message: String, patch: PatchStr) -> Self {
        let prev_commit_id = Some(prev_commit.id.clone());
        CommitBuilder {
            prev_commit_id,
            message,
            patch,
        }
    }

    pub async fn from_head<T: Storage<T>>(
        storage: &dyn StorageSharedGuard<T>,
        message: String,
        patch: PatchStr,
    ) -> Result<Self, Error> {
        let prev_commit_id = Some(storage.load_head().await?);
        Ok(CommitBuilder {
            prev_commit_id,
            message,
            patch,
        })
    }

    /// Convert to [Commit], setting the author, generating an ID and signing it.
    ///
    /// Usage with commits that already have a signature, author or ID will panic
    /// in debug builds.
    pub fn author(self, author: &User) -> Result<Commit, Error> {
        let mut commit = UnverifiedCommit {
            id: String::new(),
            prev_commit_id: self.prev_commit_id,
            author_id: author.id.to_owned(),
            ts: Utc::now(),
            message: self.message,
            patch: self.patch,
            signature: Vec::new(),
            _priv: (),
        };

        commit.id = commit.gen_id();

        let bytes = commit.bytes(true);
        commit.signature = author.sign(&bytes)?;

        // Safety: we built a well-formed commit
        unsafe { Ok(commit.verify_unchecked()) }
    }
}

impl From<Commit> for UnverifiedCommit {
    fn from(c: Commit) -> Self {
        UnverifiedCommit {
            id: c.id,
            prev_commit_id: c.prev_commit_id,
            author_id: c.author_id,
            ts: c.ts,
            message: c.message,
            patch: c.patch,
            signature: c.signature,
            _priv: (),
        }
    }
}

#[cfg(test)]
mod test {
    use toml;

    use super::*;
    use crate::test_utils::commit::*;
    use crate::test_utils::user::*;

    #[test]
    fn compatible_serialization() {
        let ucommit0_orig: UnverifiedCommit = COMMIT_0.to_owned().into();
        let ucommit1_orig: UnverifiedCommit = COMMIT_1.to_owned().into();

        let commit0_str = toml::to_string(&*COMMIT_0).unwrap();
        println!("{}", commit0_str);
        let commit1_str = toml::to_string(&*COMMIT_1).unwrap();

        let ucommit0: UnverifiedCommit = toml::from_str(&commit0_str).unwrap();
        let ucommit1: UnverifiedCommit = toml::from_str(&commit1_str).unwrap();

        assert_eq!(
            ucommit0_orig, ucommit0,
            "Incompatible serialization format (prev_commit_id=None)"
        );
        assert_eq!(
            ucommit1_orig, ucommit1,
            "Incompatible serialization format (prev_commit_id!=None)"
        );
    }

    #[test]
    fn verify_unchecked() {
        // de-verify
        let ucommit0: UnverifiedCommit = COMMIT_0.to_owned().into();
        let ucommit1: UnverifiedCommit = COMMIT_1.to_owned().into();

        let commit0 = unsafe { ucommit0.clone().verify_unchecked() };
        assert_eq!(ucommit0.id, commit0.id);
        assert_eq!(ucommit0.author_id, commit0.author_id);
        assert_eq!(ucommit0.ts, commit0.ts);
        assert_eq!(ucommit0.message, commit0.message);
        assert_eq!(ucommit0.patch, commit0.patch);
        assert_eq!(ucommit0.signature, commit0.signature);

        let commit1 = unsafe { ucommit1.clone().verify_unchecked() };
        assert_eq!(ucommit1.id, commit1.id);
        assert_eq!(ucommit1.author_id, commit1.author_id);
        assert_eq!(ucommit1.ts, commit1.ts);
        assert_eq!(ucommit1.message, commit1.message);
        assert_eq!(ucommit1.patch, commit1.patch);
        assert_eq!(ucommit1.signature, commit1.signature);
    }

    #[test]
    fn verify_ok() {
        // de-verify
        let ucommit0: UnverifiedCommit = COMMIT_0.to_owned().into();
        let ucommit1: UnverifiedCommit = COMMIT_1.to_owned().into();

        let commit0 = ucommit0.clone().verify(&*USER_A).unwrap();
        assert_eq!(ucommit0.id, commit0.id);
        assert_eq!(ucommit0.author_id, commit0.author_id);
        assert_eq!(ucommit0.ts, commit0.ts);
        assert_eq!(ucommit0.message, commit0.message);
        assert_eq!(ucommit0.patch, commit0.patch);
        assert_eq!(ucommit0.signature, commit0.signature);

        let commit1 = ucommit1.clone().verify(&*USER_B).unwrap();
        assert_eq!(ucommit1.id, commit1.id);
        assert_eq!(ucommit1.author_id, commit1.author_id);
        assert_eq!(ucommit1.ts, commit1.ts);
        assert_eq!(ucommit1.message, commit1.message);
        assert_eq!(ucommit1.patch, commit1.patch);
        assert_eq!(ucommit1.signature, commit1.signature);
    }

    #[test]
    fn author_ok() {
        let commit0 = CommitBuilder::root_commit(COMMIT_0.message.clone(), COMMIT_0.patch.clone())
            .author(&*USER_B)
            .unwrap();
        assert_eq!(commit0.prev_commit_id, None);
        assert_eq!(commit0.author_id, USER_B.id);
        assert_eq!(commit0.message, COMMIT_0.message);
        assert_eq!(commit0.patch, COMMIT_0.patch);

        let commit1 =
            CommitBuilder::from_commit(&COMMIT_0, COMMIT_1.message.clone(), COMMIT_1.patch.clone())
                .author(&*USER_A)
                .unwrap();
        assert_eq!(commit1.prev_commit_id, Some(COMMIT_0.id.clone()));
        assert_eq!(commit1.author_id, USER_A.id);
        assert_eq!(commit1.message, COMMIT_1.message);
        assert_eq!(commit1.patch, COMMIT_1.patch);
    }

    mod swap_field_fail_sig_tests {
        use crate::model::commit::UnverifiedCommit;
        use crate::test_utils::commit::*;
        use crate::test_utils::user::*;
        use std::mem;

        macro_rules! test {
            ($field:ident) => {
                #[test]
                fn $field() {
                    let mut ucommit0: UnverifiedCommit = COMMIT_0.to_owned().into();
                    let mut ucommit1: UnverifiedCommit = COMMIT_1.to_owned().into();
                    mem::swap(&mut ucommit0.$field, &mut ucommit1.$field);

                    assert!(
                        ucommit0.verify(&*USER_A).is_err(),
                        "verified commit with bad signature"
                    );
                    assert!(
                        ucommit1.verify(&*USER_B).is_err(),
                        "verified commit with bad signature"
                    );
                }
            };
        }

        test!(id);
        test!(prev_commit_id);
        //test!(author_id); // this is an outright panic
        test!(ts);
        test!(message);
        test!(patch);
        test!(signature);
    }

    #[test]
    #[should_panic(expected = "Tried to verify signature with wrong key")]
    fn verify_panic_author_mismatch() {
        let ucommit0: UnverifiedCommit = COMMIT_0.to_owned().into();
        let ucommit1: UnverifiedCommit = COMMIT_1.to_owned().into();

        let _ = ucommit0.verify(&*USER_B); // should be B
        let _ = ucommit1.verify(&*USER_A); // should be A

        panic!("failed for the wrong reason. should have panicked before");
    }

    #[test]
    fn verify_err_empty_signature() {
        let mut ucommit0: UnverifiedCommit = COMMIT_0.to_owned().into();
        let mut ucommit1: UnverifiedCommit = COMMIT_1.to_owned().into();
        ucommit0.signature = vec![];
        ucommit1.signature = vec![];

        assert!(
            ucommit0.verify(&*USER_A).is_err(),
            "verified signature-less commit"
        );
        assert!(
            ucommit1.verify(&*USER_B).is_err(),
            "verified signature-less commit"
        );
    }
}
