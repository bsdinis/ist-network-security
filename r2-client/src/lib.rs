#[macro_use]
extern crate lazy_static;

mod model;
mod persistence;
mod sigkey;
#[cfg(test)]
mod test_utils;

pub use model::*;
pub use persistence::*;

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
    Uncommitted,
}

/// Reset hardness
pub enum ResetHardness {
    /// Rewind HEAD and overwrite current file to match revision
    Hard,

    /// Rewind HEAD, but leave current file untouched
    Soft,
}

impl<S: Storage<S>> File<S> {
    pub fn new(storage: S) -> Self {
        File { storage }
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
            let patch = self
                .diff_locked(
                    &storage,
                    RichRevisionId::RelativeHead(0),
                    RichRevisionId::Uncommitted,
                )
                .await?;

            let ucommit = build_commit_from_head(&storage, message, patch).await?;
            let author = self.get_own_user(&storage).await?;
            ucommit.author(&author)?
        };

        storage.save_commit(&commit).await?;
        storage.save_head(&commit.id).await?;

        Ok(commit)
    }

    /// Rewind HEAD
    pub async fn reset(&self, rev: RichRevisionId, softness: ResetHardness) -> Result<(), Error> {
        use RichRevisionId::*;
        let mut storage = self.storage.try_exclusive()?;

        let commit_id = match rev {
            CommitId(id) => {
                // verify that commit id is in the current graph
                let head = storage.load_head().await?;
                let _ = self
                    .walk_back_from_commit(&storage, &head, Some(&id))
                    .await?;

                id
            }
            RelativeHead(n) => self.parse_head_relative_revision(&storage, n).await?,
            Uncommitted => return Ok(()),
        };

        storage.save_head(&commit_id).await?;

        if let ResetHardness::Hard = softness {
            let content = self.snapshot(&storage, CommitId(commit_id)).await?;
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

    /// Push local changes to remote
    pub async fn push(&self) -> Result<(), Error> {
        unimplemented!()
    }

    async fn diff_locked(
        &self,
        storage: &dyn StorageSharedGuard<S>,
        a: RichRevisionId,
        b: RichRevisionId,
    ) -> Result<PatchStr, Error> {
        let snapshot_a = self.snapshot(storage, a).await?;
        let snapshot_b = self.snapshot(storage, b).await?;

        Ok(snapshot_a.diff(&snapshot_b))
    }

    /// Get snapshot of a revision
    async fn snapshot(
        &self,
        storage: &dyn StorageSharedGuard<S>,
        r: RichRevisionId,
    ) -> Result<Snapshot, Error> {
        use RichRevisionId::*;
        let commit_id = match r {
            Uncommitted => return Ok(storage.load_current_snapshot().await?),
            CommitId(id) => id,
            RelativeHead(i) => self.parse_head_relative_revision(storage, i).await?,
        };

        // build snapshot from commit history
        let snapshot = self
            .walk_back_from_commit(storage, &commit_id, None)
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
        storage: &dyn StorageSharedGuard<S>,
        commit_id: &str,
        until: Option<&str>,
    ) -> Result<Vec<Commit>, Error> {
        let mut res = Vec::new();

        let commit = storage
            .load_commit(commit_id)
            .await?
            .ok_or(format!("Commit {} not found", commit_id))?;
        let mut prev_id = commit.prev_commit_id.clone();
        res.push(commit);

        while let Some(ref id) = prev_id {
            let commit = storage
                .load_commit(id)
                .await?
                .ok_or(format!("Commit {} not found", id))?;

            prev_id = match until {
                // stop going back when target is reached
                Some(until) if until == id => None,
                _ => commit.prev_commit_id.clone(),
            };
            res.push(commit);
        }

        Ok(res)
    }

    /// Get commit id corresponding to a HEAD~n reference
    async fn parse_head_relative_revision(
        &self,
        storage: &dyn StorageSharedGuard<S>,
        n: usize,
    ) -> Result<String, Error> {
        let mut commit_id = storage.load_head().await?;
        for _ in 0..n {
            commit_id = storage
                .load_commit(&commit_id)
                .await?
                .ok_or(format!("Commit {} not found", commit_id))?
                .prev_commit_id
                .ok_or(format!("Unknown revision: HEAD~{}", n))?;
        }

        Ok(commit_id)
    }

    async fn get_own_user(&self, _storage: &dyn StorageSharedGuard<S>) -> Result<User, Error> {
        unimplemented!()
    }
}

async fn build_commit_from_head<T: Storage<T>>(
    storage: &dyn StorageSharedGuard<T>,
    message: String,
    patch: PatchStr,
) -> Result<CommitBuilder, Error> {
    let prev_commit_id = Some(storage.load_head().await?);
    let commit_builder = unsafe { CommitBuilder::from_commit_id(prev_commit_id, message, patch) };
    Ok(commit_builder)
}
