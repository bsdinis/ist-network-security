use super::auth_utils::authenticate;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::services::service::{
    create_id, Document, Metadata, ServerCollaborator, ServerCommit, ServiceError, UserId,
};
use crate::storage::{FilesystemStorage, FilesystemStorageError, Storage, StorageSharedGuard};

use lazy_static::lazy_static;
use protos::client_api_server::ClientApi;
use protos::*;
use tokio::sync::{mpsc, RwLock, RwLockWriteGuard};
use tonic::{Request, Response, Status};
use tracing::instrument;
use uuid::Uuid;

fn convert_to_uuid(s: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|err| {
        Status::invalid_argument(format!("failed to parse UUID from `{}`: {:?}", s, err))
    })
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
        collaborators: Vec<ServerCollaborator>,
    ) -> Result<Uuid, ServiceError> {
        let id = create_id();
        let mut docs = self.documents.write().await;

        let doc = Document::create(id.clone(), owner, collaborators)?;
        let stor = FilesystemStorage::new(PathBuf::from(&id.to_simple().to_string()))?;

        doc.save(&stor).await?;
        docs.insert(id.clone(), (doc, stor));
        self.save_doc_list(&mut docs)?;
        Ok(id)
    }

    #[instrument]
    pub async fn edit_collaborators(
        &self,
        id: &Uuid,
        owner: &UserId,
        collaborators: Vec<ServerCollaborator>,
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
        doc.save(stor).await?;
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
    pub async fn get_collaborators(&self, id: &Uuid) -> Option<Vec<ServerCollaborator>> {
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
        doc.save(stor).await?;
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

#[tonic::async_trait]
impl ClientApi for ClientApiService {
    #[instrument]
    async fn create(
        &self,
        request: Request<CreateRequest>,
    ) -> Result<Response<CreateResponse>, Status> {
        let client_id = authenticate(&request).await?;
        let doc_id = self
            .create(
                client_id,
                request
                    .get_ref()
                    .collaborators
                    .iter()
                    .map(|x| (x.auth_fingerprint.clone(), x.ciphered_document_key.clone()))
                    .collect(),
            )
            .await
            .map_err(|err| Status::invalid_argument(format!("error: {:?}", err)))?;
        Ok(Response::new(CreateResponse {
            document_id: doc_id.to_simple().to_string(),
        }))
    }

    #[instrument]
    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> Result<Response<GetMetadataResponse>, Status> {
        let client_id = authenticate(&request).await?;

        let metadata = self
            .get_metadata(
                &convert_to_uuid(&request.get_ref().document_id)?,
                &client_id,
            )
            .await
            .ok_or_else(|| {
                Status::not_found(format!(
                    "document {} was not found",
                    &request.get_ref().document_id
                ))
            })?;

        Ok(Response::new(GetMetadataResponse {
            head: metadata.head.unwrap_or("".to_string()), // TODO: add optional head
            ciphered_document_key: metadata.key,
            pending_squash: metadata.pending_squash.map(|x| SquashRequest {
                document_id: x.document_id,
                vote: x.vote,
                dropped_commit_ids: x.dropped_commits, // TODO fix
                all_commits: x
                    .all_commits
                    .into_iter()
                    .map(|y| Commit {
                        commit_id: y.id,
                        ciphertext: y.ciphertext,
                        nonce: y.nonce,
                        aad: y.aad,
                        tag: y.tag,
                    })
                    .collect(),
                collaborators: x
                    .collaborators
                    .into_iter()
                    .map(|c| Collaborator {
                        auth_fingerprint: c.0,
                        ciphered_document_key: c.1,
                    })
                    .collect(),
            }),
            squash_vote_tally: metadata.squash_vote_tally.unwrap_or(-1),
            pending_rollback: metadata.pending_rollback.map(|x| RollbackRequest {
                document_id: x.document_id,
                vote: x.vote,
                dropped_commit_ids: x.dropped_commits, // TODO fix
                target_commit_id: format!("{:?}", x.target_commit),
                all_commits: x
                    .all_commits
                    .into_iter()
                    .map(|y| Commit {
                        commit_id: y.id,
                        ciphertext: y.ciphertext,
                        nonce: y.nonce,
                        aad: y.aad,
                        tag: y.tag,
                    })
                    .collect(),
                collaborators: x
                    .collaborators
                    .into_iter()
                    .map(|c| Collaborator {
                        auth_fingerprint: c.0,
                        ciphered_document_key: c.1,
                    })
                    .collect(),
            }),
            rollback_vote_tally: metadata.rollback_vote_tally.unwrap_or(-1),
        }))
    }

    #[instrument]
    async fn get_commit(
        &self,
        request: Request<GetCommitRequest>,
    ) -> Result<Response<GetCommitResponse>, Status> {
        let client_id = authenticate(&request).await?;
        self.get_commit(
            &convert_to_uuid(&request.get_ref().document_id)?,
            &client_id,
            &request.get_ref().commit_id,
        )
        .await
        .map(|x| {
            Response::new(GetCommitResponse {
                commit: Some(Commit {
                    commit_id: x.id,
                    ciphertext: x.ciphertext,
                    nonce: x.nonce,
                    aad: x.aad,
                    tag: x.tag,
                }),
            })
        })
        .map_err(|err| match err {
            ServiceError::AuthorizationError(user_id, doc_id) => {
                Status::unauthenticated(format!("{} cannot access {}", user_id, doc_id))
            }
            ServiceError::DocumentNotFound(doc_id) => {
                Status::not_found(format!("document {}", doc_id))
            }
            ServiceError::CommitNotFound(doc_id, commit_id) => {
                Status::not_found(format!("document {}, commit {}", doc_id, commit_id))
            }
            _ => Status::unimplemented(format!("unknown error for commit: {:?}", err)),
        })
    }

    #[instrument]
    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let client_id = authenticate(&request).await?;
        let req_commit = request
            .get_ref()
            .commit
            .clone()
            .expect("need a commit to commit");
        let commit = ServerCommit {
            id: req_commit.commit_id,
            ciphertext: req_commit.ciphertext,
            nonce: req_commit.nonce,
            aad: req_commit.aad,
            tag: req_commit.tag,
        };
        self.commit(
            &convert_to_uuid(&request.get_ref().document_id)?,
            &client_id,
            commit,
        )
        .await
        .map_err(|err| match err {
            ServiceError::AuthorizationError(user_id, doc_id) => {
                Status::unauthenticated(format!("{} cannot access {}", user_id, doc_id))
            }
            ServiceError::DocumentNotFound(doc_id) => {
                Status::not_found(format!("document {}", doc_id))
            }
            _ => Status::unimplemented(format!("unknown error for commit: {:?}", err)),
        })
        .map(|_| Response::new(CommitResponse {}))
    }

    #[instrument]
    async fn edit_collaborators(
        &self,
        request: Request<EditCollaboratorsRequest>,
    ) -> Result<Response<EditCollaboratorsResponse>, Status> {
        let client_id = authenticate(&request).await?;
        self.edit_collaborators(
            &convert_to_uuid(&request.get_ref().document_id)?,
            &client_id,
            request
                .get_ref()
                .collaborators
                .iter()
                .map(|c| (c.auth_fingerprint.clone(), c.ciphered_document_key.clone()))
                .collect(),
        )
        .await
        .map_err(|err| match err {
            ServiceError::AuthorizationError(user_id, doc_id) => {
                Status::unauthenticated(format!("{} cannot access {}", user_id, doc_id))
            }
            ServiceError::DocumentNotFound(doc_id) => {
                Status::not_found(format!("document {}", doc_id))
            }
            _ => Status::unimplemented(format!("unknown error for commit: {:?}", err)),
        })
        .map(|_| Response::new(EditCollaboratorsResponse {}))
    }

    #[instrument]
    async fn get_collaborators(
        &self,
        request: Request<GetCollaboratorsRequest>,
    ) -> Result<Response<GetCollaboratorsResponse>, Status> {
        let doc_id = &convert_to_uuid(&request.get_ref().document_id)?;
        self.get_collaborators(doc_id)
            .await
            .ok_or_else(|| Status::not_found(format!("document {}", doc_id)))
            .map(|collabs| {
                Response::new(GetCollaboratorsResponse {
                    collaborators: collabs
                        .into_iter()
                        .map(|(x, y)| Collaborator {
                            auth_fingerprint: x,
                            ciphered_document_key: y,
                        })
                        .collect(),
                })
            })
    }

    type squashStream = mpsc::Receiver<Result<SquashResponse, Status>>;
    #[instrument]
    async fn squash(
        &self,
        request: Request<SquashRequest>,
    ) -> Result<Response<Self::squashStream>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    type rollbackStream = mpsc::Receiver<Result<RollbackResponse, Status>>;
    #[instrument]
    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<Self::rollbackStream>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn uvec(id: u64) -> Vec<u8> {
        id.to_be_bytes().iter().cloned().collect()
    }

    #[tokio::test]
    async fn clnt_api() {
        let api = ClientApiService::new().await.unwrap();
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
        assert_eq!(api.get_metadata(&uuid, &uid).await, None);
        assert_eq!(api.get_collaborators(&uuid).await, None);
        assert!(api.get_commit(&uuid, &uid, "abc").await.is_err(),);
        assert!(api
            .edit_collaborators(&uuid, &uid, vec![(uvec(42), uvec(0))])
            .await
            .is_err());
        assert!(api.commit(&uuid, &uid, commit.clone()).await.is_err());

        let res = api.create(uvec(42), vec![(uvec(42), uvec(0))]).await;
        assert!(res.is_ok());
        let doc_id = res.unwrap();
        assert_eq!(
            api.get_metadata(&doc_id, &uid).await,
            Some(Metadata::new(doc_id.clone(), None, uvec(0)))
        );
        assert_eq!(
            api.get_collaborators(&doc_id).await,
            Some(vec![(uvec(42), uvec(0))])
        );
        assert!(api
            .edit_collaborators(
                &doc_id,
                &uid2,
                vec![(uvec(42), uvec(0)), (uvec(48), uvec(44))]
            )
            .await
            .is_err());
        assert!(api
            .edit_collaborators(
                &doc_id,
                &uid,
                vec![(uvec(42), uvec(0)), (uvec(48), uvec(44))]
            )
            .await
            .is_ok());
        assert!(api.get_commit(&doc_id, &uid, "abc").await.is_err());
        assert!(api.commit(&doc_id, &uid, commit.clone()).await.is_ok());
        assert!(api.commit(&doc_id, &uid2, commit.clone()).await.is_err(),);
        assert!(api.commit(&doc_id, &uid, commit.clone()).await.is_err(),);
        assert!(api.get_commit(&doc_id, &uid2, "aaaa").await.is_err());
    }
}
