use super::commit::{Commit, UnsafeCommit};
use super::snapshot::Snapshot;

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

pub trait RepoStorage<T: RepoStorage<T>> {
    type SharedGuard: RepoStorageSharedGuard<T>;
    type ExclusiveGuard: RepoStorageExclusiveGuard<T>;

    fn try_shared(self) -> Result<Self::SharedGuard, Error>;

    fn try_exclusive(self) -> Result<Self::ExclusiveGuard, Error>;
}

#[tonic::async_trait]
pub trait RepoStorageSharedGuard<T: RepoStorage<T>>: Drop {
    /// Load a persisted commit from repo
    async fn load_commit(&self, commit_id: &str) -> Result<UnsafeCommit, Error>;

    /// Read head reference
    async fn get_head(&self) -> Result<String, Error>;

    /// Read remote head reference
    async fn get_remote_head(&self) -> Result<String, Error>;

    /// Get current file contents
    async fn read_file(&self) -> Result<Snapshot, Error>;

    fn unlock(self) -> T;
}

#[tonic::async_trait]
pub trait RepoStorageExclusiveGuard<T: RepoStorage<T>>: RepoStorageSharedGuard<T> {
    /// Persist a commit
    async fn save_commit(&mut self, c: &Commit) -> Result<(), Error>;

    /// Set head reference
    async fn set_head(&mut self, commit_id: &str) -> Result<(), Error>;

    /// Set remote head reference
    async fn set_remote_head(&mut self, commit_id: &str) -> Result<(), Error>;

    /// Write file contents
    async fn write_file(&mut self, content: &Snapshot) -> Result<(), Error>;
}
