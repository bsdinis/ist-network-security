use std::path::PathBuf;

use serde::{de::DeserializeOwned, Serialize};
use std::borrow::Borrow;

pub trait Storage {
    type Error;
    type SharedGuard: StorageSharedGuard<Error = Self::Error>;
    type ExclusiveGuard: StorageExclusiveGuard<Error = Self::Error>;

    fn try_shared(&self) -> Result<Self::SharedGuard, Self::Error>;

    fn try_exclusive(&self) -> Result<Self::ExclusiveGuard, Self::Error>;
}

#[tonic::async_trait]
pub trait StorageSharedGuard: Drop + Send {
    type Error;

    /// Read [StorageObject] from storage
    async fn load<O: StorageObject, ID: Sync>(&self, id: &ID) -> Result<O, Self::Error>
    where
        O::Id: Borrow<ID>;

    /// Drops lock, consuming this guard object
    fn unlock(self)
    where
        Self: Sized,
    {
    }
}

#[tonic::async_trait]
pub trait StorageExclusiveGuard: StorageSharedGuard {
    /// Write [StorageObject] to storage
    async fn save<O: StorageObject>(&mut self, obj: &O) -> Result<(), Self::Error>;
}

pub trait StorageObject: Serialize + DeserializeOwned + Send + Sync {
    type Id;
    fn save_path(&self, root: &PathBuf) -> PathBuf;
    fn load_path<ID>(root: &PathBuf, id: &ID) -> PathBuf
    where
        Self::Id: Borrow<ID>;
}

#[cfg(test)]
#[macro_use]
pub mod test {
    use super::{Storage, StorageExclusiveGuard, StorageObject, StorageSharedGuard};
    use serde::{Deserialize, Serialize};
    use std::borrow::Borrow;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::mem;
    use std::path::PathBuf;

    pub struct StorageTester<T: Storage>(T)
    where
        T::Error: Debug;

    impl<T: Storage> From<T> for StorageTester<T>
    where
        T::Error: Debug,
    {
        fn from(storage: T) -> Self {
            StorageTester(storage)
        }
    }

    impl<T: Storage> StorageTester<T>
    where
        T::Error: Debug,
    {
        pub fn new(storage: T) -> Self {
            storage.into()
        }

        pub fn locks(&self) {
            let shared_lock = self.0.try_shared().expect("can't lock storage (shared)");
            let shared_lock2 = self
                .0
                .try_shared()
                .expect("can't lock storage (shared), 2nd lock");

            assert!(
                self.0.try_exclusive().is_err(),
                "obtained exclusive lock while shared lock was taken"
            );

            mem::drop(shared_lock);
            shared_lock2.unlock();

            let exclusive_lock = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");

            assert!(
                self.0.try_exclusive().is_err(),
                "obtained exclusive lock while exclusive lock was taken"
            );
            assert!(
                self.0.try_shared().is_err(),
                "obtained shared lock while exclusive lock was taken"
            );

            mem::drop(exclusive_lock);

            self.0
                .try_exclusive()
                .expect("can't lock storage (exclusive) after exiting exclusive lock")
                .unlock();

            self.0
                .try_shared()
                .expect("can't lock storage (exclusive) after exiting exclusive lock");
        }

        pub async fn save_load(&self) {
            let mut s = self.0.try_exclusive().unwrap();

            #[derive(Debug, Serialize, Deserialize, PartialEq)]
            struct X {
                i: i32,
                s: String,

                // server needs this stuff to work (non string keys in maps)
                weird: HashMap<Vec<u8>, ()>,
            }
            impl StorageObject for X {
                type Id = ();
                fn save_path(&self, root: &PathBuf) -> PathBuf {
                    assert_eq!(42, self.i, "self got mangled");
                    assert_eq!("asd", self.s, "self got mangled");
                    root.join("x")
                }
                fn load_path<ID>(root: &PathBuf, _id: &ID) -> PathBuf
                where
                    Self::Id: Borrow<ID>,
                {
                    root.join("x")
                }
            }

            let mut weird = HashMap::new();
            weird.insert(vec![1, 2, 3], ());
            let a = X {
                i: 42,
                s: "asd".to_owned(),
                weird,
            };
            s.save(&a).await.expect("can't save object");

            let b: X = s.load(&()).await.expect("can't save object");
            assert_eq!(a, b, "storage mangled object");
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
        ($ephemeral_storage_builder:ident) => {
            mod autogenerated_storage_trait {
                use super::$ephemeral_storage_builder;
                use crate::storage::storage::test::StorageTester;

                #[test]
                fn locks() {
                    let tester = StorageTester::new($ephemeral_storage_builder());
                    tester.locks();
                }

                #[tokio::test]
                async fn save_load() {
                    let tester = StorageTester::new($ephemeral_storage_builder());
                    tester.save_load().await;
                }
            }
        };
    }
}
