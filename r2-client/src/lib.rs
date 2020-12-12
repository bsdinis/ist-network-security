#[macro_use]
extern crate lazy_static;

mod collab_fetcher;
pub mod model;
pub mod remote;
pub mod storage;
#[cfg(test)]
mod test_utils;

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

use eyre::Report as Error;
use eyre::{eyre, Result, WrapErr};

/// A File tracked by R2
pub struct File<S: Storage, RF: RemoteFile, CF: CollaboratorFetcher>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    CF: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
    S::Error: Send + Sync + std::error::Error + 'static,
    RF::Error: Send + Sync + std::error::Error + 'static,
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

    /// Revision at n commits before the current remote HEAD
    /// Usually represented as remote/HEAD~n
    RelativeRemoteHead(usize),

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

pub struct FileLog {
    pub commits: Vec<Commit>,
    pub head: String,
    pub remote_head: String,
}

impl<S: Storage, RF: RemoteFile, CF: CollaboratorFetcher> File<S, RF, CF>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    CF: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
    S::Error: Send + Sync + std::error::Error + 'static,
    RF::Error: Send + Sync + std::error::Error + 'static,
    RF::Id: Serialize + DeserializeOwned + Send + Sync + 'static,
    for<'de> RF::Id: Deserialize<'de>,
{
    /// Open existing file repo
    pub async fn open<R>(
        collab_fetcher: CF,
        me: Arc<Me>,
        storage: S,
        remote: R,
    ) -> Result<Self, Error>
    where
        R: Remote<Id = RF::Id, File = RF>,
        Error: From<R::Error>,
        R::Error: Send + Sync + std::error::Error,
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

    /// Create new repo from existing file
    pub async fn create<R>(
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
        R::Error: Send + Sync + std::error::Error + 'static,
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

        let remote = remote
            .create(ciphered_commit, collaborators)
            .await
            .wrap_err("Failed creating file in remote")?;
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

    /// Create local copy of existing repo in remote
    pub async fn from_remote<R: Remote<Id = RF::Id, File = RF>>(
        collab_fetcher: CF,
        me: Arc<Me>,
        storage: S,
        remote: R,
        remote_id: &RF::Id,
    ) -> Result<Self, Error>
    where
        Error: From<R::Error>,
        R::Error: Send + Sync + std::error::Error + 'static,
    {
        let mut remote = remote.open(remote_id).await?;
        let mut s = storage.try_exclusive()?;

        let remote_metadata = remote.load_metadata().await?;
        let config = {
            let remote_id = remote_id.to_owned();
            let document_key = me.unseal_key(&remote_metadata.document_key)?;

            RepoConfig {
                remote_id,
                document_key,
            }
        };
        s.save(&config).await?;

        let mut file = File {
            collab_fetcher,
            me,
            config,
            storage,
            remote,
        };

        // Fetch existing commits
        let mut commits = vec![];
        let mut prev_commit_id = Some(remote_metadata.head.clone());
        while let Some(id) = &prev_commit_id {
            let commit = file.remote.load_commit(id).await?;
            let commit = file.decipher_commit(&mut s, commit).await?;

            prev_commit_id = commit.prev_commit_id.clone();
            s.save_commit(&commit).await?;
            commits.push(commit);
        }
        s.save_remote_head(&remote_metadata.head).await?;

        // Apply existing commits
        let mut snapshot = Snapshot::empty();
        for commit in commits.iter().rev() {
            snapshot = snapshot.apply(&commit.patch)?;
        }
        s.save_current_snapshot(&snapshot).await?;
        s.save_head(&remote_metadata.head).await?;

        Ok(file)
    }
}

impl<S: Storage, RF: RemoteFile, CF: CollaboratorFetcher> File<S, RF, CF>
where
    S::SharedGuard: Sync,
    S::ExclusiveGuard: Sync,
    CF: Sync,
    Error: From<S::Error>,
    Error: From<RF::Error>,
    S::Error: Send + Sync + std::error::Error + 'static,
    RF::Error: Send + Sync + std::error::Error + 'static,
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

        self.remote
            .commit(self.cipher_commit(&storage, &commit).await?)
            .await?;
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
            RelativeRemoteHead(n) => storage.remote_head_minus(n).await?,
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
    pub async fn fetch(&mut self) -> Result<Vec<Commit>, Error> {
        let mut s = self.storage.try_exclusive()?;

        let cur_remote_head = s.load_remote_head().await?;

        let metadata = self.remote.load_metadata().await?;
        self.update_document_key(&mut s, &metadata.document_key)
            .await?;
        if cur_remote_head == metadata.head {
            return Ok(vec![]);
        }

        let mut commits_to_fetch: Vec<Commit> = vec![];
        let commit = self.remote.load_commit(&metadata.head).await?;
        let commit = self.decipher_commit(&mut s, commit).await?;
        commits_to_fetch.push(commit);

        let mut prev_id_opt = commits_to_fetch.last().unwrap().prev_commit_id.as_ref();
        while prev_id_opt != Some(&cur_remote_head) && prev_id_opt != None {
            let prev_id = prev_id_opt.unwrap();
            let commit = self.remote.load_commit(&prev_id).await?;
            let commit = self.decipher_commit(&mut s, commit).await?;
            commits_to_fetch.push(commit);

            prev_id_opt = commits_to_fetch.last().unwrap().prev_commit_id.as_ref();
        }

        for commit in commits_to_fetch.iter().rev() {
            s.save_commit(commit).await?;
            s.save_remote_head(&commit.id).await?;
        }

        Ok(commits_to_fetch)
    }

    /// Merge changes from remote HEAD to current state
    /// Only supports fast forwarding HEAD (but still performs 3-way merge to preserve uncommitted changes)
    pub async fn merge_from_remote(&self, force: bool) -> Result<(), Error> {
        let mut s = self.storage.try_exclusive()?;

        let current_state = s.load_current_snapshot().await?;

        let head = s.load_head().await?;
        let remote_head = s.load_remote_head().await?;

        let commits_to_apply = s.walk_back_from_commit(&remote_head, Some(&head)).await?;

        // early exit if no commits need to be applied
        if commits_to_apply.is_empty() {
            return Ok(());
        }

        let ancestor = if commits_to_apply.last().unwrap().id != head {
            // history rewritten in remote
            if !force {
                return Err(eyre!(
                    "History rewritten in remote. Can't merge without force"
                ));
            }

            Snapshot::empty()
        } else {
            // fast-forwarding, use the current head
            s.snapshot(RichRevisionId::RelativeHead(0)).await?
        };

        let theirs = s
            .snapshot(RichRevisionId::CommitId(remote_head.clone()))
            .await?;
        let ours = current_state;
        let merged = Snapshot::merge3(ancestor, ours, theirs);

        let merged_snapshot = match &merged {
            Ok(a) => a,
            Err(a) => a,
        };
        s.save_current_snapshot(merged_snapshot).await?;
        s.save_head(&remote_head).await?;

        if merged.is_err() {
            Err(eyre!(
                "Merged with conflicts. Please fix them and commit the result."
            ))
        } else {
            Ok(())
        }
    }

    /// Get all commits starting from the HEAD (most recent first)
    pub async fn log(&self) -> Result<FileLog, Error> {
        let s = self.storage.try_shared()?;

        let mut prev_id = Some(s.load_head().await?);
        let mut commits = Vec::new();
        while let Some(id) = prev_id {
            let commit = s.load_commit(&id).await?;

            prev_id = commit.prev_commit_id.clone();
            commits.push(commit);
        }

        let head = s.load_head().await?;
        let remote_head = s.load_remote_head().await?;

        Ok(FileLog {
            commits,
            head,
            remote_head,
        })
    }

    /// Get a commit author by ID
    /// Will not try to fetch commit authors not yet seen.
    pub async fn get_commit_author(&self, id: &[u8]) -> Result<CommitAuthor, Error> {
        let s = self.storage.try_shared()?;
        s.load_commit_author(id)
            .await
            .map_err(|e| e.into())
            .and_then(|o| o.ok_or(eyre!("commit author not found")))
    }

    async fn cipher_commit(
        &self,
        storage: &S::ExclusiveGuard,
        commit: &Commit,
    ) -> Result<CipheredCommit, Error> {
        // Safety: nonce is the prefix of the commit hash
        // we will then check that no other commit exists with the same prefix
        let nonce = unsafe { nonce_for_commit(&commit) };
        let nonce_str = hex::encode(&nonce);

        if storage.count_commits_with_prefix(&nonce_str).await? > 0 {
            return Err(eyre!("Commit hash prefix collision. Try again in a bit."));
        }

        CipheredCommit::cipher(commit, &self.config.document_key, nonce).map_err(|e| e.into())
    }

    async fn decipher_commit(
        &self,
        s: &mut S::ExclusiveGuard,
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

        unverified.verify(&author).map_err(|e| e.into())
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
    // Panic free: Commit objects have valid IDs by definition
    let id_bytes = hex::decode(&commit.id).unwrap();

    // Panic free: a slice &[u8; AEAD_NONCE_SIZE] always converts successfully to [u8; AEAD_NONCE_SIZE]
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
            RelativeRemoteHead(n) => self.remote_head_minus(n).await?,
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

    /// Get vector with all commits from [from_id] to [to_id], in that order.
    /// [from_id] must be after [to_id] in the commit DAG.
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
                .ok_or(eyre!("Unknown revision: HEAD~{}", n))?;
        }

        Ok(commit_id)
    }

    /// Get commit id corresponding to a remote/HEAD~n reference
    async fn remote_head_minus(&self, n: usize) -> Result<String, Error> {
        let mut commit_id = self.load_remote_head().await?;
        for _ in 0..n {
            commit_id = self
                .load_commit(&commit_id)
                .await?
                .prev_commit_id
                .ok_or(eyre!("Unknown revision: HEAD~{}", n))?;
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
        let f = File::create(
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
        let _f = File::open(collab_fetcher, me, storage, remote)
            .await
            .unwrap();
    }
}
