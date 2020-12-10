#[macro_use]
extern crate lazy_static;

mod collab_fetcher;
pub mod model;
pub mod remote;
pub mod storage;
#[cfg(test)]
mod test_utils;

type Error = Box<dyn std::error::Error>;

pub use collab_fetcher::*;
use model::*;
use openssl_utils::{AeadKey, KeyUnsealer, SealedAeadKey};
use remote::model::*;
use remote::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::borrow::Borrow;
use std::path::PathBuf;
use std::sync::Arc;
use storage::*;

use iterutils::TryCollectExt;
use std::convert::TryInto;

use openssl_utils::aead::NONCE_SIZE as AEAD_NONCE_SIZE;

/// A File tracked by R2
pub struct File<S: Storage, RF: RemoteFile, CF: CollaboratorFetcher>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    CF: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
    RF::Id: Serialize + DeserializeOwned + Send + Sync,
    for<'de> RF::Id: Deserialize<'de>,
{
    me: Arc<Me>,
    config: RepoConfig<RF::Id>,
    storage: S,
    remote: RF,
    collab_fetcher: CF,
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

impl<S: Storage, RF: RemoteFile, CF: CollaboratorFetcher> File<S, RF, CF>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    CF: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
    RF::Id: Serialize + DeserializeOwned + Send + Sync,
    for<'de> RF::Id: Deserialize<'de>,
{
    pub async fn from_existing<R>(
        collab_fetcher: CF,
        me: Arc<Me>,
        storage: S,
        remote: R,
    ) -> Result<Self, Error>
    where
        R: Remote<Id = RF::Id, File = RF>,
        Error: From<R::Error>,
    {
        let config: RepoConfig<RF::Id> = {
            let s = storage.try_exclusive()?;
            s.load(&()).await?
        };

        let remote = remote.open(&config.remote_id).await?;

        Ok(File {
            me,
            config,
            storage,
            remote,
            collab_fetcher,
        })
    }

    pub async fn init<R>(
        collab_fetcher: CF,
        me: Arc<Me>,
        storage: S,
        mut remote: R,
        initial_commit_message: String,
        mut other_collaborators: Vec<DocCollaborator>,
    ) -> Result<Self, Error>
    where
        R: Remote<Id = RF::Id, File = RF>,
        Error: From<R::Error>,
    {
        let mut s = storage.try_exclusive()?;

        let document_key = AeadKey::gen_key()?;
        let initial_commit = {
            let empty = Snapshot::empty();
            let current = s.load_current_snapshot().await?;
            let patch = empty.diff(&current);

            CommitBuilder::root_commit(initial_commit_message, patch).author(&me)?
        };
        s.save_commit(&initial_commit).await?;
        s.save_head(&initial_commit.id).await?;

        // Safety: commit is the first in the repository with this document key and was saved
        // no other commit will have this ID prefix with this document key
        let nonce = unsafe { nonce_for_commit(&initial_commit) };
        let ciphered_commit = CipheredCommit::cipher(&initial_commit, &document_key, nonce)?;

        // might as well cache all collaborators
        for c in &other_collaborators {
            s.save_doc_collaborator(c).await?;
        }

        let collaborators = vec![RemoteCollaborator::from_me(&me, &document_key)]
            .into_iter()
            .chain(
                other_collaborators
                    .drain(..)
                    .map(|c| RemoteCollaborator::from_doc_collaborator(&c, &document_key)),
            )
            .try_collect()?;

        let remote = remote.create(ciphered_commit, collaborators).await?;
        s.save_remote_head(&initial_commit.id).await?;

        let config = RepoConfig {
            document_key,
            remote_id: remote.id().to_owned(),
        };
        s.save(&config).await?;

        Ok(File {
            me,
            config,
            storage,
            remote,
            collab_fetcher,
        })
    }
}

impl<S: Storage, RF: RemoteFile, CF: CollaboratorFetcher> File<S, RF, CF>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    CF: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
    RF::Id: Serialize + DeserializeOwned + Send + Sync,
    for<'de> RF::Id: Deserialize<'de>,
{
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

    /// Fetch changes from remote
    /// Returns last received commit from remote
    pub async fn fetch(&mut self) -> Result<Option<Commit>, Error> {
        let mut s = self.storage.try_exclusive()?;

        let cur_remote_head = s.load_remote_head().await?;

        let metadata = self.remote.load_metadata().await?;
        self.update_document_key(&mut s, &metadata.document_key)
            .await?;
        if cur_remote_head == metadata.head {
            return Ok(None);
        }

        let mut commits_to_apply: Vec<Commit> = vec![];
        let commit = self.remote.load_commit(&metadata.head).await?;
        let commit = self.decipher_commit(&mut s, commit).await?;
        commits_to_apply.push(commit);

        let mut prev_id_opt = commits_to_apply.last().unwrap().prev_commit_id.as_ref();
        while prev_id_opt != Some(&cur_remote_head) && prev_id_opt != None {
            let prev_id = prev_id_opt.unwrap();
            let commit = self.remote.load_commit(&prev_id).await?;
            let commit = self.decipher_commit(&mut s, commit).await?;
            commits_to_apply.push(commit);

            prev_id_opt = commits_to_apply.last().unwrap().prev_commit_id.as_ref();
        }

        for commit in commits_to_apply.iter().rev() {
            s.save_commit(commit).await?;
            s.save_remote_head(&commit.id).await?;
        }

        Ok(Some(commits_to_apply.remove(0)))
    }

    fn cipher_commit(&self, _commit: &Commit) -> Result<CipheredCommit, Error> {
        unimplemented!()
        //CipheredCommit::cipher(commit, self.document_key, ?)
    }

    async fn decipher_commit<SG: StorageExclusiveGuard<Error = S::Error>>(
        &self,
        s: &mut SG,
        commit: CipheredCommit,
    ) -> Result<Commit, Error> {
        let unverified = commit.decipher(&self.config.document_key)?;
        let author = match s.load_commit_author(&unverified.author_id).await? {
            None => {
                let author = self
                    .collab_fetcher
                    .fetch_commit_author(&unverified.author_id)
                    .await?;
                s.save_commit_author(&author).await?;

                author
            }
            Some(a) => a,
        };

        unverified.verify(&author)
    }

    async fn update_document_key(
        &mut self,
        s: &mut S::ExclusiveGuard,
        key: &SealedAeadKey,
    ) -> Result<(), Error> {
        let key = self.me.unseal_key(key)?;
        if key != self.config.document_key {
            self.config.document_key = key;
            s.save(&self.config).await?;
        }

        Ok(())
    }
}

unsafe fn nonce_for_commit(commit: &Commit) -> [u8; AEAD_NONCE_SIZE] {
    let id_bytes = hex::decode(&commit.id).expect("Bad commit ID");

    id_bytes[0..AEAD_NONCE_SIZE].to_owned().try_into().unwrap()
}

#[derive(Serialize, Deserialize)]
struct RepoConfig<ID> {
    remote_id: ID,
    document_key: AeadKey,
}

impl<T> StorageObject for RepoConfig<T>
where
    T: Serialize + DeserializeOwned + Send + Sync,
    for<'de> T: Deserialize<'de>,
{
    type Id = ();

    fn load_path<ID>(root: &PathBuf, _id: &ID) -> PathBuf
    where
        Self::Id: Borrow<ID>,
    {
        root.join("config")
    }
    fn save_path(&self, root: &PathBuf) -> PathBuf {
        root.join("config")
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

        let commit = self.load_commit(from_id).await?;
        let mut prev_id = commit.prev_commit_id.clone();
        res.push(commit);

        while let Some(ref id) = prev_id {
            let commit = self.load_commit(id).await?;

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
        let prev_commit = self.load_commit(&prev_commit_id).await?;
        Ok(CommitBuilder::from_commit(&prev_commit, message, patch))
    }
}

impl<T: StorageExclusiveGuard + Sync> StorageExclusiveGuardExt for T where Error: From<T::Error> {}

#[cfg(test)]
mod test {
    use super::File;
    use crate::collab_fetcher::TestCollaboratorFetcher;
    use crate::remote::DummyRemote;
    use crate::storage::test::TempDirFilesystemStorage;
    use crate::test_utils::user::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn construct() {
        let me = Arc::new(ME_A.clone());
        let remote = DummyRemote::new(me.clone());
        let collab_fetcher = TestCollaboratorFetcher::new();

        let storage = TempDirFilesystemStorage::new();
        let f = File::init(
            collab_fetcher,
            me.clone(),
            storage.clone(),
            remote.clone(),
            "initial commit".to_owned(),
            vec![],
        )
        .await
        .unwrap();
        std::mem::drop(f);

        let collab_fetcher = TestCollaboratorFetcher::new();
        let _f = File::from_existing(collab_fetcher, me, storage, remote)
            .await
            .unwrap();
    }
}
