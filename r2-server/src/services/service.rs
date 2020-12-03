use eyre::Result;
use std::cell::Cell;
use std::collections::HashMap;
use std::iter::Iterator;
use std::sync::Mutex;
use std::thread;
use thiserror::Error;

type CipheredKey = Vec<u8>;
type UserId = Vec<u8>;
type Collaborator = (UserId, CipheredKey);

#[derive(Debug, PartialEq, Clone)]
pub struct ServerCommit {
    pub id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ServiceError {
    #[error("Could not perform operation {0}: {1}")]
    OperationalError(String, String),

    #[error("Invariant Broken: {0}")]
    InvariantError(String),

    #[error("Access Denied: {0} has no permissions on document {1}")]
    AuthorizationError(String, String),

    #[error("Not Found: document {0}")]
    DocumentNotFound(String),

    #[error("Not Found: document {0}: commit {1}")]
    CommitNotFound(String, String),
}

#[derive(Debug, PartialEq)]
struct Document {
    pub id: String,
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
    fn new(id: String, head: Option<String>, key: CipheredKey) -> Metadata {
        Metadata {
            id,
            head,
            key,
            pending_squash: None,
            squash_vote_tally: None,
            pending_rollback: None,
            rollback_vote_tally: None,
        }
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

thread_local! {
  static ID: Cell<usize> = Cell::new(0);
}

/// generate a unique id
fn create_id() -> String {
    ID.with(|x| x.set(x.get() + 1));
    format!("doc_{:?}_{}", thread::current().id(), ID.with(|x| x.get()))
}

impl Document {
    fn create(
        id: String,
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

    fn edit_collaborators(
        &mut self,
        owner: &UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<(), ServiceError> {
        assert_owner_collaborator(&owner, collaborators.iter())?;
        self.keys = collaborators.into_iter().collect();
        Ok(())
    }

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
        self.commits.insert(commit.id.clone(), commit);
        Ok(())
    }

    fn has_owner(&self, owner: &UserId) -> bool {
        &self.owner == owner
    }

    fn has_collaborator(&self, id: &UserId) -> bool {
        self.keys.iter().find(|&(x, _)| x == id).is_some()
    }

    fn get_commit(&self, id: &str) -> Result<ServerCommit, ServiceError> {
        self.commits
            .get(id)
            .cloned()
            .ok_or_else(|| ServiceError::CommitNotFound(self.id.clone(), id.to_string()))
    }
}

pub struct ClientApiService {
    documents: Mutex<HashMap<String, Document>>,
}

impl ClientApiService {
    pub fn new() -> Self {
        ClientApiService {
            documents: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(
        &self,
        owner: UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<String, ServiceError> {
        let id = create_id();
        self.documents.lock().expect("mutex panicked").insert(
            id.clone(),
            Document::create(id.clone(), owner, collaborators)?,
        );
        Ok(id)
    }

    pub fn edit_collaborators(
        &self,
        id: &str,
        owner: &UserId,
        collaborators: Vec<Collaborator>,
    ) -> Result<(), ServiceError> {
        let mut docs = self.documents.lock().expect("mutex panicked");
        let doc = docs
            .get_mut(id)
            .ok_or_else(|| ServiceError::DocumentNotFound(id.to_string()))?;

        if !doc.has_owner(owner) {
            return Err(ServiceError::AuthorizationError(
                format!("{:?}", owner),
                doc.id.to_string(),
            ));
        }

        doc.edit_collaborators(owner, collaborators)
    }

    pub fn get_metadata(&self, id: &str, user: &UserId) -> Option<Metadata> {
        self.documents
            .lock()
            .expect("mutex panicked")
            .get(id)
            .and_then(|x| {
                x.keys
                    .get(user)
                    .map(|key| Metadata::new(x.id.clone(), x.head.clone(), key.clone()))
            })
    }

    pub fn get_collaborators(&self, id: &str) -> Option<Vec<Collaborator>> {
        self.documents
            .lock()
            .expect("mutex panicked")
            .get(id)
            .map(|x| x.keys.clone().into_iter().collect())
    }

    pub fn commit(
        &self,
        doc_id: &str,
        user_id: &UserId,
        commit: ServerCommit,
    ) -> Result<(), ServiceError> {
        let mut docs = self.documents.lock().expect("mutex panicked");
        let doc = docs
            .get_mut(doc_id)
            .ok_or_else(|| ServiceError::DocumentNotFound(doc_id.to_string()))?;

        if !doc.has_collaborator(user_id) {
            return Err(ServiceError::AuthorizationError(
                format!("{:?}", user_id),
                doc_id.to_string(),
            ));
        }

        doc.commit(commit)
    }
    pub fn get_commit(
        &self,
        doc_id: &str,
        user_id: &UserId,
        commit_id: &str,
    ) -> Result<ServerCommit, ServiceError> {
        let docs = self.documents.lock().expect("mutex panicked");
        let doc = docs
            .get(doc_id)
            .ok_or_else(|| ServiceError::DocumentNotFound(doc_id.to_string()))?;

        if !doc.has_collaborator(user_id) {
            return Err(ServiceError::AuthorizationError(
                format!("{:?}", user_id),
                doc_id.to_string(),
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
        assert!(
            Document::create("doc".to_string(), owner.clone(), vec![(uvec(0), uvec(42))]).is_err()
        );
        let doc = Document::create(
            "doc".to_string(),
            owner.clone(),
            vec![(uvec(42), uvec(0)), (uvec(43), uvec(1))],
        )
        .unwrap();
        assert_eq!(
            doc,
            Document {
                id: "doc".to_string(),
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
            Document::create("doc".to_string(), owner.clone(), collabs.clone()).unwrap();

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
            Document::create("doc".to_string(), uvec(42), vec![(uvec(42), uvec(0))]).unwrap();

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
                tag: vec![]
        };

        assert_eq!(api.get_metadata("doc", &uid), None);
        assert_eq!(api.get_collaborators("doc"), None);
        assert_eq!(api.get_commit("doc", &uid, "abc"), Err(ServiceError::DocumentNotFound("doc".to_string())));
        assert_eq!(
            api.edit_collaborators("doc", &uid, vec![(uvec(42), uvec(0))]),
            Err(ServiceError::DocumentNotFound("doc".to_string()))
        );
        assert_eq!(api.commit("doc", &uid, commit.clone()), Err(ServiceError::DocumentNotFound("doc".to_string())));

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
            Err(ServiceError::AuthorizationError(format!("{:?}", &uid2), doc_id.clone()))
        );
        assert_eq!(
            api.edit_collaborators(
                &doc_id,
                &uid,
                vec![(uvec(42), uvec(0)), (uvec(48), uvec(44))]
            ),
            Ok(())
        );
        assert_eq!(api.get_commit(&doc_id, &uid, "abc"),
                   Err(ServiceError::CommitNotFound(doc_id.clone(), "abc".to_string())));
        assert_eq!(api.commit(&doc_id, &uid, commit.clone()), Ok(()));
        assert_eq!(api.commit(&doc_id, &uid2, commit.clone()),
                   Err(ServiceError::AuthorizationError(format!("{:?}", &uid2), doc_id.clone())));
        assert_eq!(api.commit(&doc_id, &uid, commit.clone()),
                   Err(ServiceError::OperationalError("commit".to_string(), format!(
                    "[document {}] commit {} already exists",
                    &doc_id, &commit.id
                ))));
        assert_eq!(api.get_commit(&doc_id, &uid2, "aaaa"),
                   Err(ServiceError::AuthorizationError(format!("{:?}", &uid2), doc_id.clone())));
    }
}
