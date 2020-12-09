#[macro_use]
extern crate lazy_static;

pub mod model;
pub mod remote;
pub mod storage;
#[cfg(test)]
mod test_utils;

type Error = Box<dyn std::error::Error>;

use model::*;
use storage::*;
use remote::*;
use remote::model::*;
use openssl_utils::AeadKey;

use std::sync::Arc;

/// A File tracked by R2
pub struct File<S: Storage, RF: RemoteFile>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
{
    me: Arc<Me>,
    document_key: AeadKey,
    storage: S,
    remote: RF,
}

/// Identifier of a revision
pub enum RichRevisionId {
    /// Revision at a specific commit
    CommitId(String),

    /// Revision at n commits before the current HEAD
    /// Usually represented as HEAD~n
    RelativeHead(usize),

    /// The current, possibly uncommitted, state
    Uncommitted,
}

/// Reset hardness
pub enum ResetHardness {
    /// Rewind HEAD and overwrite current file to match revision
    Hard,

    /// Rewind HEAD, but leave current file untouched
    Soft,
}

impl<S: Storage, RF: RemoteFile> File<S, RF>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
{
    pub fn new(me: Arc<Me>, document_key: AeadKey, storage: S, remote: RF) -> Self {
        File { me, document_key, storage, remote }
    }

    /// Compute the patch that transforms revision a into revision b
    pub async fn diff(&self, a: RichRevisionId, b: RichRevisionId) -> Result<PatchStr, Error> {
        let storage = self.storage.try_shared()?;
        Ok(storage.diff(a, b).await?)
    }

    /// Commit the current state
    pub async fn commit(&mut self, message: String) -> Result<Commit, Error> {
        let mut storage = self.storage.try_exclusive()?;

        let commit = {
            let patch = storage
                .diff(RichRevisionId::RelativeHead(0), RichRevisionId::Uncommitted)
                .await?;

            let ucommit = storage.build_commit_from_head(message, patch).await?;
            ucommit.author(&self.me)?
        };

        self.remote.commit(self.cipher_commit(&commit)?).await?;
        storage.save_commit(&commit).await?;
        storage.save_head(&commit.id).await?;

        Ok(commit)
    }

    /// Move HEAD
    pub async fn reset(&self, rev: RichRevisionId, softness: ResetHardness) -> Result<(), Error> {
        use RichRevisionId::*;
        let mut storage = self.storage.try_exclusive()?;

        let commit_id = match rev {
            CommitId(id) => {
                // verify that commit id is in the current graph
                let head = storage.load_head().await?;
                let _ = storage.walk_back_from_commit(&head, Some(&id)).await?;

                id
            }
            RelativeHead(n) => storage.head_minus(n).await?,
            Uncommitted => return Ok(()),
        };

        storage.save_head(&commit_id).await?;

        if let ResetHardness::Hard = softness {
            let content = storage.snapshot(CommitId(commit_id)).await?;
            storage.save_current_snapshot(&content).await?;
        }

        Ok(())
    }

    /// Initiate or vote for a rollback
    /// Analogous to a global [`Self::reset()`]
    pub async fn rollback(
        &self,
        _rev: RichRevisionId,
        _softness: ResetHardness,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    /// Initiate or vote for a squash
    pub async fn squash(&self, _from_rev: RichRevisionId) -> Result<(), Error> {
        unimplemented!()
    }

    /// Pull and apply changes from remote
    /// Only supports fast-forwarding.
    pub async fn pull(&self) -> Result<(), Error> {
        // TODO: consider implementing pull with rebase
        unimplemented!()
    }

    fn cipher_commit(&self, _commit: &Commit) -> Result<CipheredCommit, Error> {
        unimplemented!()
        //CipheredCommit::cipher(commit, self.document_key, ?)
    }
}

#[tonic::async_trait]
trait StorageSharedGuardExt: StorageSharedGuard + Sync
where
    Error: From<Self::Error>,
{
    /// Compute the patch that transforms revision a into revision b
    async fn diff(&self, a: RichRevisionId, b: RichRevisionId) -> Result<PatchStr, Error> {
        let snapshot_a = self.snapshot(a).await?;
        let snapshot_b = self.snapshot(b).await?;

        Ok(snapshot_a.diff(&snapshot_b))
    }

    /// Get snapshot of a revision
    async fn snapshot(&self, r: RichRevisionId) -> Result<Snapshot, Error> {
        use RichRevisionId::*;
        let commit_id = match r {
            Uncommitted => return Ok(self.load_current_snapshot().await?),
            CommitId(id) => id,
            RelativeHead(n) => self.head_minus(n).await?,
        };

        // build snapshot from commit history
        let snapshot = self
            .walk_back_from_commit(&commit_id, None)
            .await?
            .drain(..)
            .rev()
            .map(|c| c.patch)
            .try_fold(Snapshot::empty(), |prev, patch| prev.apply(&patch))?;

        Ok(snapshot)
    }

    /// Given a commit ID, return a vector containing it and all
    async fn walk_back_from_commit(
        &self,
        from_id: &str,
        to_id: Option<&str>,
    ) -> Result<Vec<Commit>, Error> {
        let mut res = Vec::new();

        let commit = self
            .load_commit(from_id)
            .await?
            .ok_or(format!("Commit {} not found", from_id))?;
        let mut prev_id = commit.prev_commit_id.clone();
        res.push(commit);

        while let Some(ref id) = prev_id {
            let commit = self
                .load_commit(id)
                .await?
                .ok_or(format!("Commit {} not found", id))?;

            prev_id = match to_id {
                // stop going back when target is reached
                Some(until) if until == id => None,
                _ => commit.prev_commit_id.clone(),
            };
            res.push(commit);
        }

        Ok(res)
    }

    /// Get commit id corresponding to a HEAD~n reference
    async fn head_minus(&self, n: usize) -> Result<String, Error> {
        let mut commit_id = self.load_head().await?;
        for _ in 0..n {
            commit_id = self
                .load_commit(&commit_id)
                .await?
                .ok_or(format!("Commit {} not found", commit_id))?
                .prev_commit_id
                .ok_or(format!("Unknown revision: HEAD~{}", n))?;
        }

        Ok(commit_id)
    }
}

impl<T: StorageSharedGuard + Sync> StorageSharedGuardExt for T where Error: From<T::Error> {}

#[tonic::async_trait]
trait StorageExclusiveGuardExt: StorageExclusiveGuard + Sync
where
    Error: From<Self::Error>,
{
    async fn build_commit_from_head(
        &mut self,
        message: String,
        patch: PatchStr,
    ) -> Result<CommitBuilder, Error> {
        let prev_commit_id = self.load_head().await?;
        let prev_commit = self.load_commit(&prev_commit_id).await?.ok_or(format!(
            "invalid HEAD: commit {} does not exist",
            &prev_commit_id
        ))?;
        Ok(CommitBuilder::from_commit(&prev_commit, message, patch))
    }
}

impl<T: StorageExclusiveGuard + Sync> StorageExclusiveGuardExt for T where Error: From<T::Error> {}

#[cfg(test)]
mod test {
    use openssl_utils::AeadKey;

    use std::sync::Arc;
    use super::File;
    use crate::remote::{DummyRemote, Remote, model::RemoteCollaborator};
    use crate::remote::model::{CipheredCommit, CipheredCommitNonceSource};
    use crate::model::Commit;
    use crate::storage::{Storage, StorageExclusiveGuard};
    use crate::storage::test::TempDirFilesystemStorage;
    use crate::test_utils::{user::*, commit::*};

    struct DummyNonceSource;
    impl CipheredCommitNonceSource for DummyNonceSource {
        type Error = std::convert::Infallible;
        fn nonce_for(&self, _commit: &Commit) -> Result<[u8; openssl_utils::aead::NONCE_SIZE], Self::Error> {
            Ok([42; openssl_utils::aead::NONCE_SIZE])
        }
    }

    #[tokio::test]
    async fn construct() {
        let me = Arc::new(ME_A.clone());
        let mut remote = DummyRemote::new(me.clone());

        let initial_commit = COMMIT_0.to_owned();

        let storage = TempDirFilesystemStorage::new();
        {
            let mut s = storage.try_exclusive().unwrap();
            s.save_head(&initial_commit.id).await.unwrap();
            s.save_commit(&initial_commit).await.unwrap();
        }
    
        let doc_key = AeadKey::gen_key().unwrap();
        let nonce_src = DummyNonceSource;
        let initial_commit = CipheredCommit::cipher(&initial_commit, &doc_key, &nonce_src).unwrap();
        let collaborators = vec![RemoteCollaborator::from_me(&me, &doc_key).unwrap()];
        let remote_file = remote.create(initial_commit, collaborators).await.unwrap();
        
        let _ = File::new(me, doc_key, storage, remote_file);
    }
}
