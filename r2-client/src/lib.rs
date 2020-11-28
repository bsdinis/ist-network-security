#[macro_use]
extern crate lazy_static;

mod sigkey;
mod model;
#[cfg(test)] mod test_utils;

pub use model::storage::{Storage, StorageSharedGuard, StorageExclusiveGuard};
pub use model::snapshot::{Snapshot, PatchStr};
pub use model::commit::{Commit, UnsafeCommit};
pub use model::user::User;

pub use model::fs_storage::FilesystemStorage;

type Error = Box<dyn std::error::Error>;

/// A File tracked by R2
pub struct File<S: Storage<S>> {
    storage: S,
}

/// Identifier of a revision
pub enum RichRevisionId {
    /// Revision at a specific commit
    CommitId(String),

    /// Revision at n commits before the current HEAD
    /// Usually represented as HEAD~n
    RelativeHead(usize),

    /// The current, possibly uncommitted, state
    Current,
}

impl<S: Storage<S>> File<S> {
    pub fn new(storage: S) -> Self {
        File {
            storage,
        }
    }

    /// Compute the patch that transforms revision a into revision b
    pub async fn diff(&self, a: RichRevisionId, b: RichRevisionId) -> Result<PatchStr, Error> {
        let storage = self.storage.try_shared()?;
        self.diff_locked(&storage, a, b).await
    }

    /// Commit the current state
    pub async fn commit(&self, message: String) -> Result<Commit, Error> {
        let mut storage = self.storage.try_exclusive()?;

        let commit = {
            let patch = self.diff_locked(&storage, RichRevisionId::RelativeHead(0), RichRevisionId::Current).await?;
            let head = storage.load_head().await?;
            let prev_commit = Some(self.get_commit(&storage, &head).await?);

            let ucommit = UnsafeCommit::new(prev_commit.as_ref(), message, patch);
            let author = self.get_own_user(&storage).await?;
            ucommit.author(&author)?
        };

        storage.save_commit(&commit).await?;
        storage.save_head(&commit.id).await?;

        Ok(commit)
    }

    async fn diff_locked(&self, storage: &dyn StorageSharedGuard<S>, a: RichRevisionId, b: RichRevisionId) -> Result<PatchStr, Error> {
        let snapshot_a = self.snapshot(storage, a).await?;
        let snapshot_b = self.snapshot(storage, b).await?;

        Ok(snapshot_a.diff(&snapshot_b))
    }

    /// Get snapshot of a revision
    async fn snapshot(&self, storage: &dyn StorageSharedGuard<S>, r: RichRevisionId) -> Result<Snapshot, Error> {
        use RichRevisionId::*;
        let commit_id = match r {
            Current => return Ok(storage.load_current_snapshot().await?),
            CommitId(id) => id,
            RelativeHead(i) => self.parse_head_relative_revision(storage, i).await?,
        };

        // build snapshot from commit history
        let snapshot = self.walk_back_from_commit(storage, &commit_id).await?
            .drain(..)
            .rev()
            .map(|c| c.patch)
            .try_fold(Snapshot::empty(), |prev, patch| prev.apply(&patch))?;

        Ok(snapshot)
    }

    /// Given a commit ID, return a vector containing it and all
    async fn walk_back_from_commit(&self, storage: &dyn StorageSharedGuard<S>, commit_id: &str) -> Result<Vec<Commit>, Error> {
        let mut res = Vec::new();

        let commit = self.get_commit(storage, commit_id).await?;
        let mut prev_id = commit.prev_commit_id.clone();
        res.push(commit);

        while let Some(ref id) = prev_id {
            let commit = self.get_commit(storage, id).await?;
            prev_id = commit.prev_commit_id.clone();
            res.push(commit);
        }

        Ok(res)
    }

    /// Get commit id corresponding to a HEAD~n reference
    async fn parse_head_relative_revision(&self, storage: &dyn StorageSharedGuard<S>, i: usize) -> Result<String, Error> {
        let mut commit_id = storage.load_head().await?;
        for _ in 0..i {
            commit_id = self.get_commit(storage, &commit_id).await?
                .prev_commit_id
                .ok_or(format!("Unknown revision: HEAD~{}", i))?;
        }

        Ok(commit_id)
    }

    async fn get_commit(&self, storage: &dyn StorageSharedGuard<S>, commit_id: &str) -> Result<Commit, Error> {
        let unsafe_commit = match storage.load_commit(commit_id).await {
            Ok(Some(v)) => v,
            Ok(None) => return Err(format!("Commit {} not found", commit_id).into()),
            Err(e) => return Err(e.into()),
        };

        let author_id = unsafe_commit.author_id.as_ref()
            .ok_or(format!("Commit {:?} invalid: missing author", unsafe_commit.id))?;

        let author = self.get_collaborator(storage, author_id).await?;

        unsafe_commit.verify(&author)
    }

    async fn get_collaborator(&self, _storage: &dyn StorageSharedGuard<S>, _id: &str) -> Result<User, Error> {
        unimplemented!()
    }

    async fn get_own_user(&self, _storage: &dyn StorageSharedGuard<S>) -> Result<User, Error> {
        unimplemented!()
    }
}
