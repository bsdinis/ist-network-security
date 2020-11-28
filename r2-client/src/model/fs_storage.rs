use fs2::FileExt;
use std::ffi::OsString;
use std::path::PathBuf;
use tokio::fs;

use super::commit::{UnverifiedCommit, Commit};
use super::storage::{Storage, StorageExclusiveGuard, StorageSharedGuard};
use super::snapshot::Snapshot;

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

#[derive(Clone)]
pub struct FilesystemStorage {
    file_path: PathBuf,
    root: PathBuf,
}
pub struct FilesystemStorageSharedGuard {
    file_path: PathBuf,
    root: PathBuf,
    lock_file: std::fs::File,
}

pub struct FilesystemStorageExclusiveGuard {
    file_path: PathBuf,
    root: PathBuf,
    lock_file: std::fs::File,
}

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

impl FilesystemStorage {
    pub fn new(file_path: PathBuf) -> Result<Self, Error> {
        let root = root_path(&file_path);

        std::fs::DirBuilder::new()
            .recursive(true) // to not error when dir already exists
            .create(&root)?;

        Ok(FilesystemStorage {
            file_path,
            root,
        })
    }
}

impl Storage<FilesystemStorage> for FilesystemStorage {
    type SharedGuard = FilesystemStorageSharedGuard;
    type ExclusiveGuard = FilesystemStorageExclusiveGuard;

    fn try_shared(&self) -> Result<Self::SharedGuard, Error> {
        FilesystemStorageSharedGuard::new(&self)
    }

    fn try_exclusive(&self) -> Result<Self::ExclusiveGuard, Error> {
        FilesystemStorageExclusiveGuard::new(&self)
    }
}


fn lock_file(storage: &FilesystemStorage) -> Result<std::fs::File, Error> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(lockfile_path(&storage.root))
        .map_err(|err| err.into())
}

impl FilesystemStorageSharedGuard {
    fn new(storage: &FilesystemStorage) -> Result<Self, Error> {
        let lock_file = lock_file(storage)?;
        lock_file.try_lock_shared()?;

        Ok(FilesystemStorageSharedGuard {
            file_path: storage.file_path.to_owned(),
            root: storage.root.to_owned(),
            lock_file,
        })
    }
}

impl FilesystemStorageExclusiveGuard {
    fn new(storage: &FilesystemStorage) -> Result<Self, Error> {
        let lock_file = lock_file(storage)?;
        lock_file.try_lock_exclusive()?;

        Ok(FilesystemStorageExclusiveGuard {
            file_path: storage.file_path.to_owned(),
            root: storage.root.to_owned(),
            lock_file,
        })
    }
}

impl Drop for FilesystemStorageSharedGuard {
    fn drop(&mut self) {
        self.lock_file
            .unlock()
            .expect("couldn't unlock repo (previously had shared lock)");
    }
}

impl Drop for FilesystemStorageExclusiveGuard {
    fn drop(&mut self) {
        self.lock_file
            .unlock()
            .expect("couldn't unlock repo (previously had shared lock)");
    }
}

macro_rules! impl_shared {
    ($typename:ident) => {
        #[tonic::async_trait]
        impl StorageSharedGuard<FilesystemStorage> for $typename {
            async fn load_commit(&self, commit_id: &str) -> Result<Option<Commit>, Error> {
                use std::io::ErrorKind;

                let commit_file_path = commit_path(&self.root, commit_id);

                match fs::read_to_string(commit_file_path).await {
                    Ok(commit) => {
                        let commit: UnverifiedCommit = toml::from_str(&commit)?;

                        // Safety: only verified commits are persisted
                        unsafe { Ok(Some(commit.verify_unchecked())) }
                    },
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e.into()),
                }
            }

            async fn load_head(&self) -> Result<String, Error> {
                Ok(fs::read_to_string(head_path(&self.root)).await?)
            }

            async fn load_remote_head(&self) -> Result<String, Error> {
                Ok(fs::read_to_string(remote_head_path(&self.root)).await?)
            }

            async fn load_current_snapshot(&self) -> Result<Snapshot, Error> {
                Ok(fs::read_to_string(&self.file_path).await?.into())
            }

            fn unlock(self) {
                // guard is dropped
            }
        }
    };
}

impl_shared!(FilesystemStorageSharedGuard);
impl_shared!(FilesystemStorageExclusiveGuard);

#[tonic::async_trait]
impl StorageExclusiveGuard<FilesystemStorage> for FilesystemStorageExclusiveGuard {
    async fn save_commit(&mut self, commit: &Commit) -> Result<(), Error> {
        let commit_file_path = commit_path(&self.root, &commit.id);

        fs::DirBuilder::new()
            .recursive(true)
            .create(commit_file_path.parent().unwrap())
            .await?;

        let contents = toml::to_string(commit)?;
        fs::write(commit_file_path, contents).await?;

        Ok(())
    }

    async fn save_head(&mut self, commit_id: &str) -> Result<(), Error> {
        fs::write(head_path(&self.root), commit_id).await?;
        Ok(())
    }

    async fn save_remote_head(&mut self, commit_id: &str) -> Result<(), Error> {
        fs::write(remote_head_path(&self.root), commit_id).await?;
        Ok(())
    }

    async fn save_current_snapshot(&mut self, content: &Snapshot) -> Result<(), Error> {
        fs::write(&self.file_path, content).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::FilesystemStorage;
    use tempdir::TempDir;
    use std::future::Future;


    async fn ephemeral_storage<F, Fut>(cb: F)
    where
        F: Fn(FilesystemStorage) -> Fut,
        Fut: Future<Output = ()>,
    {
        let dir = TempDir::new("r2fstor_test")
            .expect("!NOT A TEST PROBLEM! failed to create ephemeral storage directory !NOT A TEST PROBLEM!");

        eprintln!("Test dir is {:?}", dir.path());
        let file_path = dir.path().join("thefile.txt");
        std::fs::write(&file_path, "hey").expect("failed to create test file in storage");

        let storage = FilesystemStorage::new(file_path).expect("failed to create storage");
        cb(storage).await;
    }

    #[tokio::test]
    async fn original_content_not_lost() {
        ephemeral_storage(original_content_not_lost_impl).await
    }

    async fn original_content_not_lost_impl(storage: FilesystemStorage) {
        let s = storage.try_shared().expect("failed to acquire shared storage lock");
        let expected: Snapshot = "hey".to_owned().into();

        assert_eq!(expected, s.load_current_snapshot().await.unwrap(), "storage creation mangled file");
    }

    test_storage_trait_for_impl!(ephemeral_storage);
}
