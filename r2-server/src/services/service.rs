use crate::storage::{FilesystemStorage, FilesystemStorageError};
use crate::storage::{Storage, StorageExclusiveGuard, StorageObject, StorageSharedGuard};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::iter::Iterator;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::{RwLock, RwLockWriteGuard};
use tracing::{event, instrument, Level};
use uuid::Uuid;

type CipheredKey = Vec<u8>;
type UserId = Vec<u8>;
type Collaborator = (UserId, CipheredKey);

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ServerCommit {
    pub id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Could not perform operation {0}: {1}")]
    OperationalError(String, String),

    #[error("Invariant Broken: {0}")]
    InvariantError(String),

    #[error("Access Denied: {0} has no permissions on document {1}")]
    AuthorizationError(String, Uuid),

    #[error("Not Found: document {0}")]
    DocumentNotFound(Uuid),

    #[error("Not Found: document {0}: commit {1}")]
    CommitNotFound(Uuid, String),

    #[error(transparent)]
    StorageError(#[from] FilesystemStorageError),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Document {
    pub id: Uuid,
    pub keys: HashMap<UserId, CipheredKey>,
    pub commits: HashMap<String, ServerCommit>,
    pub owner: UserId,
    pub head: Option<String>,
}

#[derive(Debug, PartialEq)]
pub struct SquashRequest {
    pub document_id: String,
    pub vote: bool,
    pub dropped_commits: Vec<String>,
    pub all_commits: Vec<ServerCommit>,
    pub collaborators: Vec<Collaborator>,
}

#[derive(Debug, PartialEq)]
pub struct RollbackRequest {
    pub document_id: String,
    pub vote: bool,
    pub target_commit: String,
    pub dropped_commits: Vec<String>,
    pub all_commits: Vec<ServerCommit>,
    pub collaborators: Vec<Collaborator>,
}

#[derive(Debug, PartialEq)]
pub struct Metadata {
    pub id: String,
    pub head: Option<String>,
    pub key: CipheredKey,
    pub pending_squash: Option<SquashRequest>,
    pub squash_vote_tally: Option<i64>,
    pub pending_rollback: Option<RollbackRequest>,
    pub rollback_vote_tally: Option<i64>,
}

impl Metadata {
    fn new(id: Uuid, head: Option<String>, key: CipheredKey) -> Metadata {
        Metadata {
            id: id.to_simple().to_string(),
            head,
            key,
            pending_squash: None,
            squash_vote_tally: None,
            pending_rollback: None,
            rollback_vote_tally: None,
        }
    }
}

impl StorageObject for Document {
    type Id = ();
    fn save_path(&self, root: &PathBuf) -> PathBuf {
        root.join("document")
    }
    fn load_path<ID>(root: &PathBuf, _: &ID) -> PathBuf {
        root.join("document")
    }
}

/// check if the owner is a collaborator
fn assert_owner_collaborator<'a>(
    owner: &UserId,
    mut collaborators: impl Iterator<Item = &'a Collaborator>,
) -> Result<(), ServiceError> {
    collaborators
        .find(|(x, _)| x == owner)
        .map(|_| ())
        .ok_or_else(|| ServiceError::InvariantError("owner is not a collaborator".to_string()))
}

/// generate a unique id
fn create_id() -> Uuid {
    Uuid::new_v4()
}

impl Document {
    #[instrument]
    fn create(
        id: Uuid,
        owner: UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<Self, ServiceError> {
        assert_owner_collaborator(&owner, collaborators.iter())?;
        Ok(Document {
            id,
            keys: collaborators.into_iter().collect(),
            commits: HashMap::new(),
            owner,
            head: None,
        })
    }

    #[instrument]
    fn edit_collaborators(
        &mut self,
        owner: &UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<(), ServiceError> {
        assert_owner_collaborator(&owner, collaborators.iter())?;
        self.keys = collaborators.into_iter().collect();
        Ok(())
    }

    #[instrument]
    fn commit(&mut self, commit: ServerCommit) -> Result<(), ServiceError> {
        if self.commits.contains_key(&commit.id) {
            return Err(ServiceError::OperationalError(
                "commit".to_string(),
                format!(
                    "[document {}] commit {} already exists",
                    &self.id, &commit.id
                ),
            ));
        }
        self.head = Some(commit.id.clone());
        self.commits.insert(commit.id.clone(), commit);
        Ok(())
    }

    #[instrument]
    fn has_owner(&self, owner: &UserId) -> bool {
        &self.owner == owner
    }

    #[instrument]
    fn has_collaborator(&self, id: &UserId) -> bool {
        self.keys.iter().find(|&(x, _)| x == id).is_some()
    }

    #[instrument]
    fn get_commit(&self, id: &str) -> Result<ServerCommit, ServiceError> {
        self.commits
            .get(id)
            .cloned()
            .ok_or_else(|| ServiceError::CommitNotFound(self.id.clone(), id.to_string()))
    }
}

type MapType = HashMap<Uuid, (Document, FilesystemStorage)>;
#[derive(Debug)]
pub struct ClientApiService {
    documents: RwLock<MapType>,
}

lazy_static! {
    static ref GLOBAL_DOC_LIST: PathBuf = PathBuf::from(".document_list");
}

impl ClientApiService {
    pub async fn new() -> Result<Self, FilesystemStorageError> {
        let mut docs = HashMap::new();
        if let Ok(file_bytes) = fs::read(&*GLOBAL_DOC_LIST) {
            let doc_list: Vec<Uuid> = bincode::deserialize(&file_bytes)?;

            for id in doc_list {
                let stor = FilesystemStorage::new(PathBuf::from(&id.to_simple().to_string()))?;
                let doc = stor.try_shared()?.load(&()).await?;
                docs.insert(id, (doc, stor));
            }
        }

        Ok(ClientApiService {
            documents: RwLock::new(docs),
        })
    }

    #[instrument]
    fn save_doc_list(
        &self,
        guard: &mut RwLockWriteGuard<'_, MapType>,
    ) -> Result<(), FilesystemStorageError> {
        let keys: Vec<Uuid> = guard.keys().cloned().collect();
        fs::write(&*GLOBAL_DOC_LIST, &bincode::serialize(&keys)?).map_err(|err| err.into())
    }

    #[instrument]
    pub async fn create(
        &self,
        owner: UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<Uuid, ServiceError> {
        let id = create_id();
        let mut docs = self.documents.write().await;

        let doc = Document::create(id.clone(), owner, collaborators)?;
        let stor = FilesystemStorage::new(PathBuf::from(&id.to_simple().to_string()))?;

        stor.try_exclusive()?.save(&doc).await?;
        docs.insert(id.clone(), (doc, stor));
        self.save_doc_list(&mut docs)?;
        Ok(id)
    }

    #[instrument]
    pub async fn edit_collaborators(
        &self,
        id: &Uuid,
        owner: &UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<(), ServiceError> {
        let mut docs = self.documents.write().await;
        let (doc, stor) = docs
            .get_mut(id)
            .ok_or_else(|| ServiceError::DocumentNotFound(id.clone()))?;

        if !doc.has_owner(owner) {
            return Err(ServiceError::AuthorizationError(
                format!("{:?}", owner),
                doc.id,
            ));
        }

        doc.edit_collaborators(owner, collaborators)?;
        stor.try_exclusive()?.save(doc).await?;
        Ok(())
    }

    #[instrument]
    pub async fn get_metadata(&self, id: &Uuid, user: &UserId) -> Option<Metadata> {
        let docs = self.documents.read().await;
        docs.get(id).and_then(|(x, _)| {
            x.keys
                .get(user)
                .map(|key| Metadata::new(x.id.clone(), x.head.clone(), key.clone()))
        })
    }

    #[instrument]
    pub async fn get_collaborators(&self, id: &Uuid) -> Option<Vec<Collaborator>> {
        self.documents
            .read()
            .await
            .get(id)
            .map(|(x, _)| x.keys.clone().into_iter().collect())
    }

    #[instrument]
    pub async fn commit(
        &self,
        doc_id: &Uuid,
        user_id: &UserId,
        commit: ServerCommit,
    ) -> Result<(), ServiceError> {
        let mut docs = self.documents.write().await;
        let (doc, stor) = docs
            .get_mut(doc_id)
            .ok_or_else(|| ServiceError::DocumentNotFound(doc_id.clone()))?;

        if !doc.has_collaborator(user_id) {
            return Err(ServiceError::AuthorizationError(
                format!("{:?}", user_id),
                doc_id.clone(),
            ));
        }

        doc.commit(commit)?;
        stor.try_exclusive()?.save(doc).await?;
        Ok(())
    }

    #[instrument]
    pub async fn get_commit(
        &self,
        doc_id: &Uuid,
        user_id: &UserId,
        commit_id: &str,
    ) -> Result<ServerCommit, ServiceError> {
        let docs = self.documents.read().await;
        let (doc, _) = docs
            .get(doc_id)
            .ok_or_else(|| ServiceError::DocumentNotFound(doc_id.clone()))?;

        if !doc.has_collaborator(user_id) {
            return Err(ServiceError::AuthorizationError(
                format!("{:?}", user_id),
                doc_id.clone(),
            ));
        }

        doc.get_commit(commit_id)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn uvec(id: u64) -> Vec<u8> {
        id.to_be_bytes().iter().cloned().collect()
    }

    #[test]
    fn doc_create() {
        let owner = uvec(42);
        let uuid = Uuid::new_v4();
        assert!(Document::create(uuid.clone(), owner.clone(), vec![(uvec(0), uvec(42))]).is_err());
        let doc = Document::create(
            uuid.clone(),
            owner.clone(),
            vec![(uvec(42), uvec(0)), (uvec(43), uvec(1))],
        )
        .unwrap();
        assert_eq!(
            doc,
            Document {
                id: uuid,
                keys: vec![(uvec(42), uvec(0)), (uvec(43), uvec(1))]
                    .into_iter()
                    .collect(),
                commits: HashMap::new(),
                owner: uvec(42),
                head: None
            }
        );

        assert!(doc.has_owner(&owner));
        assert!(doc.has_collaborator(&owner));
        assert!(doc.has_collaborator(&uvec(43)));
    }

    #[test]
    fn doc_edit_collabs() {
        let owner = uvec(42);
        let collabs = vec![(uvec(42), uvec(0))];
        let mut document =
            Document::create(Uuid::new_v4(), owner.clone(), collabs.clone()).unwrap();

        assert!(document
            .edit_collaborators(&owner, vec![(uvec(0), uvec(42))])
            .is_err());

        let new_collabs = vec![(uvec(42), uvec(0)), (uvec(43), uvec(0))];
        assert!(document
            .edit_collaborators(&owner, new_collabs.clone())
            .is_ok());
        assert_eq!(new_collabs.len(), document.keys.len());
        new_collabs
            .iter()
            .for_each(|(x, y)| assert_eq!(document.keys.get(x).unwrap(), y));
    }

    #[test]
    fn doc_commit() {
        let mut document =
            Document::create(Uuid::new_v4(), uvec(42), vec![(uvec(42), uvec(0))]).unwrap();

        assert_eq!(
            document.get_commit("not_found"),
            Err(ServiceError::CommitNotFound(
                "doc".to_string(),
                "not_found".to_string()
            ))
        );

        assert_eq!(
            document.commit(ServerCommit {
                id: "aaaa".to_string(),
                ciphertext: uvec(151341u64),
                nonce: vec![],
                aad: vec![],
                tag: vec![]
            }),
            Ok(())
        );

        assert_eq!(
            document.get_commit("aaaa"),
            Ok(ServerCommit {
                id: "aaaa".to_string(),
                ciphertext: uvec(151341u64),
                nonce: vec![],
                aad: vec![],
                tag: vec![]
            })
        );

        assert_eq!(
            document.commit(ServerCommit {
                id: "aaaa".to_string(),
                ciphertext: uvec(151341u64),
                nonce: vec![],
                aad: vec![],
                tag: vec![]
            }),
            Err(ServiceError::OperationalError(
                "commit".to_string(),
                "[document doc] commit aaaa already exists".to_string(),
            ))
        );

        assert_eq!(
            document.commit(ServerCommit {
                id: "aaaab".to_string(),
                ciphertext: uvec(151341u64),
                nonce: vec![],
                aad: vec![],
                tag: vec![]
            }),
            Ok(())
        );

        assert_eq!(
            document.get_commit("aaaab"),
            Ok(ServerCommit {
                id: "aaaab".to_string(),
                ciphertext: uvec(151341u64),
                nonce: vec![],
                aad: vec![],
                tag: vec![]
            })
        );
    }

    #[test]
    fn clnt_api() {
        let api = ClientApiService::new();
        let uid = uvec(42);
        let uid2 = uvec(43);
        let commit = ServerCommit {
            id: "aaaa".to_string(),
            ciphertext: uvec(151341u64),
            nonce: vec![],
            aad: vec![],
            tag: vec![],
        };

        let uuid = Uuid::new_v4();
        assert_eq!(api.get_metadata(&uuid, &uid), None);
        assert_eq!(api.get_collaborators(&uuid), None);
        assert_eq!(
            api.get_commit(&uuid, &uid, "abc"),
            Err(ServiceError::DocumentNotFound("doc".to_string()))
        );
        assert_eq!(
            api.edit_collaborators(&uuid, &uid, vec![(uvec(42), uvec(0))]),
            Err(ServiceError::DocumentNotFound("doc".to_string()))
        );
        assert_eq!(
            api.commit(&uuid, &uid, commit.clone()),
            Err(ServiceError::DocumentNotFound("doc".to_string()))
        );

        let res = api.create(uvec(42), vec![(uvec(42), uvec(0))]);
        assert!(res.is_ok());
        let doc_id = res.unwrap();
        assert_eq!(
            api.get_metadata(&doc_id, &uid),
            Some(Metadata::new(doc_id.clone(), None, uvec(0)))
        );
        assert_eq!(
            api.get_collaborators(&doc_id),
            Some(vec![(uvec(42), uvec(0))])
        );
        assert_eq!(
            api.edit_collaborators(
                &doc_id,
                &uid2,
                vec![(uvec(42), uvec(0)), (uvec(48), uvec(44))]
            ),
            Err(ServiceError::AuthorizationError(
                format!("{:?}", &uid2),
                doc_id.clone()
            ))
        );
        assert_eq!(
            api.edit_collaborators(
                &doc_id,
                &uid,
                vec![(uvec(42), uvec(0)), (uvec(48), uvec(44))]
            ),
            Ok(())
        );
        assert_eq!(
            api.get_commit(&doc_id, &uid, "abc"),
            Err(ServiceError::CommitNotFound(
                doc_id.clone(),
                "abc".to_string()
            ))
        );
        assert_eq!(api.commit(&doc_id, &uid, commit.clone()), Ok(()));
        assert_eq!(
            api.commit(&doc_id, &uid2, commit.clone()),
            Err(ServiceError::AuthorizationError(
                format!("{:?}", &uid2),
                doc_id.clone()
            ))
        );
        assert_eq!(
            api.commit(&doc_id, &uid, commit.clone()),
            Err(ServiceError::OperationalError(
                "commit".to_string(),
                format!(
                    "[document {}] commit {} already exists",
                    &doc_id, &commit.id
                )
            ))
        );
        assert_eq!(
            api.get_commit(&doc_id, &uid2, "aaaa"),
            Err(ServiceError::AuthorizationError(
                format!("{:?}", &uid2),
                doc_id.clone()
            ))
        );
    }
}
