use crate::model::{Commit, CommitAuthor, DocCollaborator, Me, Snapshot};

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

    /// Load a persisted commit from repo
    /// Will return None if the commit does not exist in storage.
    async fn load_commit(&self, commit_id: &str) -> Result<Option<Commit>, Self::Error>;

    /// Read head reference
    /// Will return an error if the head was not saved before.
    async fn load_head(&self) -> Result<String, Self::Error>;

    /// Read remote head reference
    /// Will return an error if the remote head was not saved before.
    async fn load_remote_head(&self) -> Result<String, Self::Error>;

    /// Read current file contents
    async fn load_current_snapshot(&self) -> Result<Snapshot, Self::Error>;

    /// Read a document collaborator
    async fn load_doc_collaborator(&self, id: &str) -> Result<DocCollaborator, Self::Error>;

    /// Read a commit author
    async fn load_commit_author(&self, id: &str) -> Result<CommitAuthor, Self::Error>;

    /// Read local user
    async fn load_me(&self) -> Result<Me, Self::Error>;

    /// Drops lock, consuming this guard object
    // no default implementation because the compiler is not smart enough
    fn unlock(self)
    where
        Self: Sized,
    {
    }
}

#[tonic::async_trait]
pub trait StorageExclusiveGuard: StorageSharedGuard {
    /// Persist a commit
    async fn save_commit(&mut self, c: &Commit) -> Result<(), Self::Error>;

    /// Write head reference
    async fn save_head(&mut self, commit_id: &str) -> Result<(), Self::Error>;

    /// Write remote head reference
    async fn save_remote_head(&mut self, commit_id: &str) -> Result<(), Self::Error>;

    /// Write file contents
    async fn save_current_snapshot(&mut self, content: &Snapshot) -> Result<(), Self::Error>;

    /// Write document collaborator
    async fn save_doc_collaborator(
        &mut self,
        doc_collaborator: &DocCollaborator,
    ) -> Result<(), Self::Error>;

    /// Write commit author
    async fn save_commit_author(&mut self, commit_author: &CommitAuthor)
        -> Result<(), Self::Error>;

    /// Write local user
    async fn save_me(&mut self, me: &Me) -> Result<(), Self::Error>;
}

#[cfg(test)]
#[macro_use]
pub mod test {
    use openssl_utils::{ X509Ext };

    use super::{Storage, StorageExclusiveGuard, StorageSharedGuard};
    use crate::test_utils::commit::*;
    use crate::{model::Snapshot, CommitAuthor, DocCollaborator};
    use openssl::x509::X509;
    use std::fmt::Debug;
    use std::mem;

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

        pub async fn save_load_commits(&self) {
            let mut s = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");
            assert!(s.load_commit(&COMMIT_0.id).await.unwrap().is_none());
            assert!(s.load_commit(&COMMIT_1.id).await.unwrap().is_none());

            s.save_commit(&*COMMIT_0).await.expect("can't save commit");
            s.save_commit(&*COMMIT_1).await.expect("can't save commit");

            assert_eq!(
                COMMIT_0.to_owned(),
                s.load_commit(&COMMIT_0.id).await.unwrap().unwrap(),
                "storage mangled commit"
            );
            assert_eq!(
                COMMIT_1.to_owned(),
                s.load_commit(&COMMIT_1.id).await.unwrap().unwrap(),
                "storage mangled commit"
            );
        }

        pub async fn save_load_head(&self) {
            let mut s = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");
            assert!(s.load_head().await.is_err());

            s.save_head(&COMMIT_0.id).await.expect("can't save head");

            assert_eq!(
                COMMIT_0.id,
                s.load_head().await.unwrap(),
                "storage mangled head"
            );
        }

        pub async fn save_load_remote_head(&self) {
            let mut s = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");
            assert!(s.load_remote_head().await.is_err());

            s.save_remote_head(&COMMIT_0.id)
                .await
                .expect("can't save remote head");

            assert_eq!(
                COMMIT_0.id,
                s.load_remote_head().await.unwrap(),
                "storage mangled remote head"
            );
        }

        pub async fn save_load_current_snapshot(&self) {
            let mut s = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");

            let content: Snapshot = "oh my, this is a beautiful file".into();
            s.save_current_snapshot(&content)
                .await
                .expect("can't save snapshot");

            assert_eq!(
                content,
                s.load_current_snapshot().await.unwrap(),
                "storage didn't write file properly"
            );

            let content: Snapshot = "oh my, this is an even more beautiful file".into();
            s.save_current_snapshot(&content)
                .await
                .expect("can't save snapshot");

            assert_eq!(
                content,
                s.load_current_snapshot().await.unwrap(),
                "storage didn't write file properly"
            );
        }

        pub async fn save_load_doc_collaborator(&self) {
            let mut s = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");

            let auht_cert_pem = include_bytes!("../test_utils/clientA-auth.cert.pem");
            let auth_cert = X509::from_pem(auht_cert_pem).unwrap();

            let auth_cert = unsafe { auth_cert.validate_unchecked() };
            let doc_collaborator = DocCollaborator::from_certificate(auth_cert).unwrap();

            s.save_doc_collaborator(&doc_collaborator)
                .await
                .expect("can't save doc collaborator");

            let loaded_doc_collaborator = s
                .load_doc_collaborator(&hex::encode(&doc_collaborator.id))
                .await
                .unwrap();

            assert_eq!(
                doc_collaborator.id, loaded_doc_collaborator.id,
                "storage didn't write doc collaborator properly"
            );

            assert_eq!(
                doc_collaborator.name, loaded_doc_collaborator.name,
                "storage didn't write doc collaborator properly"
            );

            assert_eq!(
                doc_collaborator.auth_certificate.cert.to_pem().unwrap(),
                loaded_doc_collaborator
                    .auth_certificate
                    .cert
                    .to_pem()
                    .unwrap(),
                "storage didn't write doc collaborator properly"
            );
        }

        pub async fn save_load_commit_author(&self) {
            let mut s = self
                .0
                .try_exclusive()
                .expect("can't lock storage (exclusive)");

            let sign_cert_pem = include_bytes!("../test_utils/clientA-sign.cert.pem");
            let sign_cert = X509::from_pem(sign_cert_pem).unwrap();

            let sign_cert = unsafe { sign_cert.validate_unchecked() };
            let commit_author = CommitAuthor::from_certificate(sign_cert).unwrap();

            s.save_commit_author(&commit_author)
                .await
                .expect("can't save commit author");

            let loaded_commit_author = s
                .load_commit_author(&hex::encode(&commit_author.id))
                .await
                .unwrap();

            assert_eq!(
                commit_author.id, loaded_commit_author.id,
                "storage didn't write commit author properly"
            );

            assert_eq!(
                commit_author.name, loaded_commit_author.name,
                "storage didn't write commit author properly"
            );

            assert_eq!(
                commit_author.sign_certificate.cert.to_pem().unwrap(),
                loaded_commit_author.sign_certificate.cert.to_pem().unwrap(),
                "storage didn't write commit author properly"
            );
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

                macro_rules! test_async_method {
                    ($test_name:ident) => {
                        #[tokio::test]
                        async fn $test_name() {
                            let tester = StorageTester::new($ephemeral_storage_builder());
                            tester.$test_name().await;
                        }
                    };
                }

                test_async_method!(save_load_commits);
                test_async_method!(save_load_head);
                test_async_method!(save_load_remote_head);
                test_async_method!(save_load_current_snapshot);
                test_async_method!(save_load_doc_collaborator);
                test_async_method!(save_load_commit_author);
            }
        };
    }
}
