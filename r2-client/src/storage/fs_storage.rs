use fs2::FileExt;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::ffi::OsString;
use std::path::PathBuf;
use std::str;

use tokio::fs;

use super::{Storage, StorageExclusiveGuard, StorageObject, StorageSharedGuard};
use crate::model::*;

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

fn doc_collaborator_path(root: &PathBuf, doc_collaborator_id: &[u8]) -> PathBuf {
    let doc_collaborator_id = hex::encode(doc_collaborator_id);
    root.join("doc_collaborators").join(doc_collaborator_id)
}

fn commit_author_path(root: &PathBuf, commit_author_id: &[u8]) -> PathBuf {
    let commit_author_id = hex::encode(commit_author_id);
    root.join("commit_authors").join(commit_author_id)
}

impl FilesystemStorage {
    pub fn new(file_path: PathBuf) -> Result<Self, <Self as Storage>::Error> {
        let root = root_path(&file_path);

        std::fs::DirBuilder::new()
            .recursive(true) // to not error when dir already exists
            .create(&root)?;

        Ok(FilesystemStorage { file_path, root })
    }
}

impl Storage for FilesystemStorage {
    type Error = Error;
    type SharedGuard = FilesystemStorageSharedGuard;
    type ExclusiveGuard = FilesystemStorageExclusiveGuard;

    fn try_shared(&self) -> Result<Self::SharedGuard, Self::Error> {
        FilesystemStorageSharedGuard::new(&self)
    }

    fn try_exclusive(&self) -> Result<Self::ExclusiveGuard, Self::Error> {
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
    fn new(storage: &FilesystemStorage) -> Result<Self, <Self as StorageSharedGuard>::Error> {
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
    fn new(storage: &FilesystemStorage) -> Result<Self, <Self as StorageSharedGuard>::Error> {
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
        impl StorageSharedGuard for $typename {
            type Error = Error;

            async fn load_commit(&self, commit_id: &str) -> Result<Commit, Self::Error> {
                let commit_file_path = commit_path(&self.root, commit_id);

                fs::read_to_string(commit_file_path)
                    .await
                    .and_then(|commit| {
                        let commit: UnverifiedCommit = toml::from_str(&commit)?;

                        // Safety: only verified commits are persisted
                        unsafe { Ok(commit.verify_unchecked()) }
                    })
                    .map_err(|e| e.into())
            }

            async fn count_commits_with_prefix(
                &self,
                commit_id_prefix: &str,
            ) -> Result<usize, Self::Error> {
                let commit_file_path = commit_path(&self.root, commit_id_prefix);
                let commit_folder = commit_file_path.parent().unwrap();

                let mut entries = fs::read_dir(commit_folder).await?;
                let mut count = 0usize;

                while let Some(entry) = entries.next_entry().await? {
                    let id = entry.file_name().into_string().unwrap();
                    if id.starts_with(commit_id_prefix) {
                        count += 1;
                    }
                }

                Ok(count)
            }

            async fn load_head(&self) -> Result<String, Self::Error> {
                Ok(fs::read_to_string(head_path(&self.root)).await?)
            }

            async fn load_remote_head(&self) -> Result<String, Self::Error> {
                Ok(fs::read_to_string(remote_head_path(&self.root)).await?)
            }

            async fn load_current_snapshot(&self) -> Result<Snapshot, Self::Error> {
                Ok(fs::read_to_string(&self.file_path).await?.into())
            }

            async fn load_doc_collaborator(
                &self,
                id: &[u8],
            ) -> Result<Option<DocCollaborator>, Self::Error> {
                use std::io::ErrorKind;

                let doc_collaborator_path = doc_collaborator_path(&self.root, id);
                let doc_collaborator = match fs::read_to_string(doc_collaborator_path).await {
                    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e.into()),
                    Ok(c) => c,
                };

                let doc_collaborator: UnverifiedDocCollaborator =
                    toml::from_str(&doc_collaborator)?;
                unsafe { Ok(Some(doc_collaborator.verify_unchecked().unwrap())) }
            }

            async fn load_commit_author(
                &self,
                id: &[u8],
            ) -> Result<Option<CommitAuthor>, Self::Error> {
                use std::io::ErrorKind;

                let commit_author_path = commit_author_path(&self.root, id);
                let commit_author = match fs::read_to_string(commit_author_path).await {
                    Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e.into()),
                    Ok(c) => c,
                };
                let commit_author: UnverifiedCommitAuthor = toml::from_str(&commit_author)?;
                unsafe { Ok(Some(commit_author.verify_unchecked().unwrap())) }
            }

            async fn load<O: StorageObject, ID: Sync>(&self, id: &ID) -> Result<O, Self::Error>
            where
                O::Id: Borrow<ID>,
            {
                let path = O::load_path(&self.root, id);
                let serialized = fs::read_to_string(path).await?;
                let obj: O = toml::from_str(&serialized)?;
                Ok(obj)
            }
        }
    };
}

impl_shared!(FilesystemStorageSharedGuard);
impl_shared!(FilesystemStorageExclusiveGuard);

#[tonic::async_trait]
impl StorageExclusiveGuard for FilesystemStorageExclusiveGuard {
    async fn save_commit(
        &mut self,
        commit: &Commit,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        let commit_file_path = commit_path(&self.root, &commit.id);

        fs::DirBuilder::new()
            .recursive(true)
            .create(commit_file_path.parent().unwrap())
            .await?;

        let contents = toml::to_string(commit)?;
        fs::write(commit_file_path, contents).await?;

        Ok(())
    }

    async fn save_head(
        &mut self,
        commit_id: &str,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        fs::write(head_path(&self.root), commit_id).await?;
        Ok(())
    }

    async fn save_remote_head(
        &mut self,
        commit_id: &str,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        fs::write(remote_head_path(&self.root), commit_id).await?;
        Ok(())
    }

    async fn save_current_snapshot(
        &mut self,
        content: &Snapshot,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        fs::write(&self.file_path, content).await?;
        Ok(())
    }

    async fn save_doc_collaborator(
        &mut self,
        doc_collaborator: &DocCollaborator,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        let doc_collaborator_path = doc_collaborator_path(&self.root, &doc_collaborator.id);

        fs::DirBuilder::new()
            .recursive(true)
            .create(doc_collaborator_path.parent().unwrap())
            .await?;

        let doc_collaborator = doc_collaborator.to_owned();
        let doc_collaborator = UnverifiedDocCollaborator::try_from(doc_collaborator).unwrap(); //maybe use matching

        let contents = toml::to_string(&doc_collaborator)?;
        fs::write(doc_collaborator_path, contents).await?;

        Ok(())
    }

    async fn save_commit_author(
        &mut self,
        commit_author: &CommitAuthor,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        let commit_author_path = commit_author_path(&self.root, &commit_author.id);

        fs::DirBuilder::new()
            .recursive(true)
            .create(commit_author_path.parent().unwrap())
            .await?;

        let commit_author = commit_author.to_owned();
        let commit_author = UnverifiedCommitAuthor::try_from(commit_author).unwrap(); //maybe use matching

        let contents = toml::to_string(&commit_author)?;
        fs::write(commit_author_path, contents).await?;
        Ok(())
    }

    async fn save<O: StorageObject>(
        &mut self,
        obj: &O,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        let serialized = toml::to_string(obj)?;
        fs::write(obj.save_path(&self.root), serialized).await?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::FilesystemStorage;
    use crate::model::Snapshot;
    use crate::storage::{Storage, StorageSharedGuard};
    use std::sync::Arc;
    use tempdir::TempDir;

    /// Wrapper for [FilesystemStorage] that creates a temp dir for storage
    /// Can be cloned for usage with multiple instances.
    #[derive(Clone)]
    pub struct TempDirFilesystemStorage(Arc<TempDir>, FilesystemStorage);
    impl Storage for TempDirFilesystemStorage {
        type Error = <FilesystemStorage as Storage>::Error;
        type SharedGuard = <FilesystemStorage as Storage>::SharedGuard;
        type ExclusiveGuard = <FilesystemStorage as Storage>::ExclusiveGuard;

        fn try_shared(&self) -> Result<Self::SharedGuard, Self::Error> {
            self.1.try_shared()
        }

        fn try_exclusive(&self) -> Result<Self::ExclusiveGuard, Self::Error> {
            self.1.try_exclusive()
        }
    }

    impl TempDirFilesystemStorage {
        pub const FILE_NAME: &'static str = "thefile.txt";
        pub const FILE_INITIAL_CONTENTS: &'static str = "hey";

        pub fn new() -> Self {
            let dir = TempDir::new("r2fstor_test")
                .expect("!NOT A TEST PROBLEM! failed to create ephemeral storage directory !NOT A TEST PROBLEM!");

            eprintln!("Test dir is {:?}", dir.path());
            let file_path = dir.path().join(Self::FILE_NAME);
            std::fs::write(&file_path, Self::FILE_INITIAL_CONTENTS)
                .expect("failed to create test file in storage");

            let storage = FilesystemStorage::new(file_path).expect("failed to create storage");

            TempDirFilesystemStorage(Arc::new(dir), storage)
        }
    }

    #[tokio::test]
    async fn original_content_not_lost() {
        let storage = TempDirFilesystemStorage::new();
        let storage = storage
            .try_shared()
            .expect("failed to acquire shared storage lock");
        let expected: Snapshot = "hey".to_owned().into();

        assert_eq!(
            expected,
            storage.load_current_snapshot().await.unwrap(),
            "storage creation mangled file"
        );
    }

    fn storage_builder() -> TempDirFilesystemStorage {
        TempDirFilesystemStorage::new()
    }
    test_storage_trait_for_impl!(storage_builder);
}
