use fs2::FileExt;
use std::borrow::Borrow;
use std::boxed::Box;
use std::path::PathBuf;
use thiserror::Error;

use tokio::fs;

use super::{Storage, StorageExclusiveGuard, StorageObject, StorageSharedGuard};

#[derive(Debug, Clone)]
pub struct FilesystemStorage {
    root: PathBuf,
}
pub struct FilesystemStorageSharedGuard {
    root: PathBuf,
    lock_file: std::fs::File,
}

pub struct FilesystemStorageExclusiveGuard {
    root: PathBuf,
    lock_file: std::fs::File,
}

#[derive(Debug, Error)]
pub enum FilesystemStorageError {
    #[error("Failed to lock storage")]
    LockFailed(#[source] std::io::Error),

    #[error("Failed to (de)serialize data to store")]
    BadData(#[from] Box<bincode::ErrorKind>),

    #[error("I/O Error: {:?}", .0)]
    IOError(#[from] std::io::Error),
}


fn lockfile_path(root: &PathBuf) -> PathBuf {
    root.join("lockfile")
}

impl FilesystemStorage {
    pub fn new(root: PathBuf) -> Result<Self, FilesystemStorageError> {
        std::fs::DirBuilder::new()
            .recursive(true) // to not error when dir already exists
            .create(&root)?;

        Ok(FilesystemStorage { root })
    }
}

impl Storage for FilesystemStorage {
    type Error = FilesystemStorageError;
    type SharedGuard = FilesystemStorageSharedGuard;
    type ExclusiveGuard = FilesystemStorageExclusiveGuard;

    fn try_shared(&self) -> Result<Self::SharedGuard, Self::Error> {
        FilesystemStorageSharedGuard::new(&self)
    }

    fn try_exclusive(&self) -> Result<Self::ExclusiveGuard, Self::Error> {
        FilesystemStorageExclusiveGuard::new(&self)
    }
}

fn lock_file(storage: &FilesystemStorage) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(lockfile_path(&storage.root))
}

impl FilesystemStorageSharedGuard {
    fn new(storage: &FilesystemStorage) -> Result<Self, FilesystemStorageError> {
        let lock_file = lock_file(storage).map_err(|e| FilesystemStorageError::LockFailed(e))?;
        lock_file
            .try_lock_shared()
            .map_err(|e| FilesystemStorageError::LockFailed(e))?;

        Ok(FilesystemStorageSharedGuard {
            root: storage.root.to_owned(),
            lock_file,
        })
    }
}

impl FilesystemStorageExclusiveGuard {
    fn new(storage: &FilesystemStorage) -> Result<Self, FilesystemStorageError> {
        let lock_file = lock_file(storage).map_err(|e| FilesystemStorageError::LockFailed(e))?;
        lock_file
            .try_lock_exclusive()
            .map_err(|e| FilesystemStorageError::LockFailed(e))?;

        Ok(FilesystemStorageExclusiveGuard {
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
            type Error = FilesystemStorageError;

            async fn load<O: StorageObject, ID: Sync>(&self, id: &ID) -> Result<O, Self::Error>
            where
                O::Id: Borrow<ID>,
            {
                let path = O::load_path(&self.root, id);
                let serialized = fs::read(path).await?;
                let obj: O = bincode::deserialize(&serialized)?;
                Ok(obj)
            }
        }
    };
}

impl_shared!(FilesystemStorageSharedGuard);
impl_shared!(FilesystemStorageExclusiveGuard);

#[tonic::async_trait]
impl StorageExclusiveGuard for FilesystemStorageExclusiveGuard {
    async fn save<O: StorageObject>(
        &mut self,
        obj: &O,
    ) -> Result<(), <Self as StorageSharedGuard>::Error> {
        let serialized = bincode::serialize(obj)?;
        fs::write(obj.save_path(&self.root), serialized).await?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use super::FilesystemStorage;
    use crate::storage::Storage;
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
        pub fn new() -> Self {
            let dir = TempDir::new("r2fstor_test")
                .expect("!NOT A TEST PROBLEM! failed to create ephemeral storage directory !NOT A TEST PROBLEM!");

            let storage = FilesystemStorage::new(dir.path().to_path_buf()).expect("failed to create storage");

            TempDirFilesystemStorage(Arc::new(dir), storage)
        }
    }

    fn storage_builder() -> TempDirFilesystemStorage {
        TempDirFilesystemStorage::new()
    }
    test_storage_trait_for_impl!(storage_builder);
}
