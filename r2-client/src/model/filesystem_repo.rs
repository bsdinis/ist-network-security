use fs2::FileExt;
use std::ffi::OsString;
use std::path::PathBuf;
use tokio::fs;

use super::commit::CommitData;
use super::repo::{RepoStorage, RepoStorageExclusiveGuard, RepoStorageSharedGuard};
use super::snapshot::Snapshot;

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

pub struct FilesystemRepoStorage {
    file_path: PathBuf,
    root: PathBuf,
    lock_file: std::fs::File,
}
pub struct FilesystemRepoStorageSharedGuard(FilesystemRepoStorage);
pub struct FilesystemRepoStorageExclusiveGuard(FilesystemRepoStorage);

fn root_path(file_path: &PathBuf) -> PathBuf {
    let mut file_name = OsString::new();
    file_name.push(".");
    file_name.push(file_path.file_name().unwrap());
    file_name.push(".r2");

    file_path.with_file_name(file_name)
}

fn lockfile_path(root: &PathBuf) -> PathBuf {
    root.join("lockfile")
}

fn commit_path(root: &PathBuf, commit_id: &str) -> PathBuf {
    assert!(commit_id.len() > 2);
    root.join("commits").join(&commit_id[..2]).join(commit_id)
}

fn head_path(root: &PathBuf) -> PathBuf {
    root.join("head")
}

fn remote_head_path(root: &PathBuf) -> PathBuf {
    root.join("remote_head")
}

impl FilesystemRepoStorage {
    pub fn new(file_path: PathBuf) -> Result<Self, Error> {
        let root = root_path(&file_path);

        std::fs::DirBuilder::new()
            .recursive(true) // to not error when dir already exists
            .create(&root)?;

        let lock_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(lockfile_path(&root))?;

        Ok(FilesystemRepoStorage {
            file_path,
            root,
            lock_file,
        })
    }
}

impl RepoStorage<FilesystemRepoStorage> for FilesystemRepoStorage {
    type SharedGuard = FilesystemRepoStorageSharedGuard;
    type ExclusiveGuard = FilesystemRepoStorageExclusiveGuard;

    fn try_shared(self) -> Result<Self::SharedGuard, Error> {
        self.lock_file.try_lock_shared()?;

        Ok(FilesystemRepoStorageSharedGuard(self))
    }
    fn try_exclusive(self) -> Result<Self::ExclusiveGuard, Error> {
        self.lock_file.try_lock_exclusive()?;

        Ok(FilesystemRepoStorageExclusiveGuard(self))
    }
}

impl Drop for FilesystemRepoStorageSharedGuard {
    fn drop(&mut self) {
        self.0
            .lock_file
            .unlock()
            .expect("couldn't unlock repo (previously had shared lock)");
    }
}

impl Drop for FilesystemRepoStorageExclusiveGuard {
    fn drop(&mut self) {
        self.0
            .lock_file
            .unlock()
            .expect("couldn't unlock repo (previously had shared lock)");
    }
}

macro_rules! impl_shared {
    ($typename:ident) => {
        #[tonic::async_trait]
        impl RepoStorageSharedGuard<FilesystemRepoStorage> for $typename {
            async fn load_commit(&self, commit_id: &str) -> Result<CommitData, Error> {
                let commit_file_path = commit_path(&self.0.root, commit_id);
                let commit_file = fs::read_to_string(commit_file_path).await?;
                Ok(toml::from_str(&commit_file)?)
            }

            async fn get_head(&self) -> Result<String, Error> {
                Ok(fs::read_to_string(head_path(&self.0.root)).await?)
            }

            async fn get_remote_head(&self) -> Result<String, Error> {
                Ok(fs::read_to_string(remote_head_path(&self.0.root)).await?)
            }

            async fn read_file(&self) -> Result<Snapshot, Error> {
                Ok(fs::read_to_string(&self.0.file_path).await?.into())
            }

            fn unlock(mut self) -> FilesystemRepoStorage {
                let cloned = FilesystemRepoStorage {
                    file_path: self.0.file_path.clone(),
                    root: self.0.root.clone(),
                    lock_file: self
                        .0
                        .lock_file
                        .try_clone()
                        .expect("File::try_clone shouldn't error really"),
                };

                std::mem::replace(&mut self.0, cloned)
            }
        }
    };
}

impl_shared!(FilesystemRepoStorageSharedGuard);
impl_shared!(FilesystemRepoStorageExclusiveGuard);

#[tonic::async_trait]
impl RepoStorageExclusiveGuard<FilesystemRepoStorage> for FilesystemRepoStorageExclusiveGuard {
    async fn save_commit(&mut self, commit: &CommitData) -> Result<(), Error> {
        let commit_file_path = commit_path(&self.0.root, &commit.id);

        fs::DirBuilder::new()
            .recursive(true)
            .create(commit_file_path.parent().unwrap())
            .await?;

        let contents = toml::to_string(commit)?;
        fs::write(commit_file_path, contents).await?;

        Ok(())
    }

    async fn set_head(&mut self, commit_id: &str) -> Result<(), Error> {
        fs::write(head_path(&self.0.root), commit_id).await?;
        Ok(())
    }

    async fn set_remote_head(&mut self, commit_id: &str) -> Result<(), Error> {
        fs::write(remote_head_path(&self.0.root), commit_id).await?;
        Ok(())
    }

    async fn write_file(&mut self, content: &Snapshot) -> Result<(), Error> {
        fs::write(remote_head_path(&self.0.root), content).await?;
        Ok(())
    }
}
