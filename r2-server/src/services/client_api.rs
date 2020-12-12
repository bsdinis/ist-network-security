use super::auth_utils::authenticate;
use crate::services::service::{ClientApiService, ServerCommit, ServiceError};
use protos::client_api_server::ClientApi;
use protos::*;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use tracing::instrument;
use uuid::Uuid;

fn convert_to_uuid(s: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|err| {
        Status::invalid_argument(format!("failed to parse UUID from `{}`: {:?}", s, err))
    })
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
