use super::commit::{Commit, UnsafeCommit};
use super::snapshot::Snapshot;

type Error = Box<dyn std::error::Error>; // TODO: use more specific type

pub trait Storage<T: Storage<T>> {
    type SharedGuard: StorageSharedGuard<T>;
    type ExclusiveGuard: StorageExclusiveGuard<T>;

    fn try_shared(&self) -> Result<Self::SharedGuard, Error>;

    fn try_exclusive(&self) -> Result<Self::ExclusiveGuard, Error>;
}

#[tonic::async_trait]
pub trait StorageSharedGuard<T: Storage<T>>: Drop {
    /// Load a persisted commit from repo
    /// Will return None if the commit does not exist in storage.
    async fn load_commit(&self, commit_id: &str) -> Result<Option<UnsafeCommit>, Error>;

    /// Read head reference
    /// Will return an error if the head was not saved before.
    async fn load_head(&self) -> Result<String, Error>;

    /// Read remote head reference
    /// Will return an error if the remote head was not saved before.
    async fn load_remote_head(&self) -> Result<String, Error>;

    /// Read current file contents
    async fn load_current_snapshot(&self) -> Result<Snapshot, Error>;

    /// Drops lock, consuming this guard object
    // no default implementation because the compiler is not smart enough
    fn unlock(self);
}

#[tonic::async_trait]
pub trait StorageExclusiveGuard<T: Storage<T>>: StorageSharedGuard<T> {
    /// Persist a commit
    async fn save_commit(&mut self, c: &Commit) -> Result<(), Error>;

    /// Write head reference
    async fn save_head(&mut self, commit_id: &str) -> Result<(), Error>;

    /// Write remote head reference
    async fn save_remote_head(&mut self, commit_id: &str) -> Result<(), Error>;

    /// Write file contents
    async fn save_current_snapshot(&mut self, content: &Snapshot) -> Result<(), Error>;
}

#[cfg(test)]
#[macro_use]
pub mod test {
    use super::*;
    use crate::test_utils::commit::*;
    use std::mem;

    pub struct StorageTester<T: Storage<T>>(T);

    impl<T: Storage<T>> From<T> for StorageTester<T> {
        fn from(storage: T) -> Self {
            StorageTester(storage)
        }
    }

    impl<T: Storage<T>> StorageTester<T> {
        pub fn new(storage: T) -> Self {
            storage.into()
        }

        pub fn locks(&self) {
            let shared_lock = self.0
                .try_shared()
                .expect("can't lock storage (shared)");
            let shared_lock2 = self.0
                .try_shared()
                .expect("can't lock storage (shared), 2nd lock");

            assert!(self.0.try_exclusive().is_err(), "obtained exclusive lock while shared lock was taken");

            mem::drop(shared_lock);
            shared_lock2.unlock();

            let exclusive_lock = self.0.try_exclusive()
                .expect("can't lock storage (exclusive)");

            assert!(self.0.try_exclusive().is_err(), "obtained exclusive lock while exclusive lock was taken");
            assert!(self.0.try_shared().is_err(), "obtained shared lock while exclusive lock was taken");

            mem::drop(exclusive_lock);

            self.0.try_exclusive()
                .expect("can't lock storage (exclusive) after exiting exclusive lock")
                .unlock();

            self.0.try_shared()
                .expect("can't lock storage (exclusive) after exiting exclusive lock");
        }

        pub async fn save_load_commits(&self) {
            let mut s = self.0.try_exclusive().expect("can't lock storage (exclusive)");
            assert_eq!(None, s.load_commit(&COMMIT_0.id).await.unwrap());
            assert_eq!(None, s.load_commit(&COMMIT_1.id).await.unwrap());

            s.save_commit(&*COMMIT_0).await.expect("can't save commit");
            s.save_commit(&*COMMIT_1).await.expect("can't save commit");

            let ucommit0: UnsafeCommit = COMMIT_0.to_owned().into();
            let ucommit1: UnsafeCommit = COMMIT_1.to_owned().into();

            assert_eq!(ucommit0, s.load_commit(&COMMIT_0.id).await.unwrap().unwrap(), "storage mangled commit");
            assert_eq!(ucommit1, s.load_commit(&COMMIT_1.id).await.unwrap().unwrap(), "storage mangled commit");
        }

        pub async fn save_load_head(&self) {
            let mut s = self.0.try_exclusive().expect("can't lock storage (exclusive)");
            assert!(s.load_head().await.is_err());

            s.save_head(&COMMIT_0.id).await.expect("can't save head");

            assert_eq!(COMMIT_0.id, s.load_head().await.unwrap(), "storage mangled head");
        }

        pub async fn save_load_remote_head(&self) {
            let mut s = self.0.try_exclusive().expect("can't lock storage (exclusive)");
            assert!(s.load_remote_head().await.is_err());

            s.save_remote_head(&COMMIT_0.id).await.expect("can't save remote head");

            assert_eq!(COMMIT_0.id, s.load_remote_head().await.unwrap(), "storage mangled remote head");
        }

        pub async fn save_load_current_snapshot(&self) {
            let mut s = self.0.try_exclusive().expect("can't lock storage (exclusive)");

            let content: Snapshot = "oh my, this is a beautiful file".into();
            s.save_current_snapshot(&content).await.expect("can't save snapshot");

            assert_eq!(content, s.load_current_snapshot().await.unwrap(), "storage didn't write file properly");

            let content: Snapshot = "oh my, this is an even more beautiful file".into();
            s.save_current_snapshot(&content).await.expect("can't save snapshot");

            assert_eq!(content, s.load_current_snapshot().await.unwrap(), "storage didn't write file properly");
        }
    }

    /*
     * To the poor soul that wanders in here, this is just generates that executes each of
     * the tests defined above in StorageTester.
     *
     * It takes as argument the name of a function that creates a fresh storage instance,
     * calls its first argument with it (an async fn (s: <TheStorageImplType>) -> ()), awaiting
     * it and cleans up the created storage.
     *
     * If a test is added to StorageTester, it should be easy enough to add it:
     *  - if the test is async, add a new test_async_method! invocation with its name;
     *  - otherwise, duplicate the locks() implemention and adapt to fit the test name.
     */
    #[macro_export]
    macro_rules! test_storage_trait_for_impl {
        ($ephemeral_storage_provider:ident) => {
            mod autogenerated_storage_trait {
                use super::$ephemeral_storage_provider;
                use crate::model::storage::test::StorageTester;

                #[tokio::test]
                async fn locks() {
                    $ephemeral_storage_provider(move |s| {
                        StorageTester::new(s).locks();
                        std::future::ready(())
                    }).await
                }

                macro_rules! test_async_method {
                    ($test_name:ident) => {
                        mod $test_name {
                            use crate::model::storage::{Storage, test::StorageTester};

                            pub async fn aux<S: Storage<S>>(s: S) {
                                let tester = StorageTester::new(s);
                                tester.$test_name().await;
                                //std::thread::sleep(std::time::Duration::from_millis(60000));
                            }
                        }

                        #[tokio::test]
                        async fn $test_name() {
                            $ephemeral_storage_provider($test_name::aux).await
                        }
                    };
                }

                test_async_method!(save_load_commits);
                test_async_method!(save_load_head);
                test_async_method!(save_load_remote_head);
                test_async_method!(save_load_current_snapshot);
            }
        };
    }
}
