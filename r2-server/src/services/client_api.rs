use super::auth_utils::authenticate;
use protos::client_api_server::ClientApi;
use protos::*;
use tonic::{Request, Response, Status};

pub struct ClientApiService;

impl ClientApiService {
    pub fn new() -> Self {
        ClientApiService
    }
}

#[tonic::async_trait]
impl ClientApi for ClientApiService {
    async fn create(
        &self,
        request: Request<CreateRequest>,
    ) -> Result<Response<CreateResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> Result<Response<GetMetadataResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn get_commit(
        &self,
        request: Request<GetCommitRequest>,
    ) -> Result<Response<GetCommitResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn edit_collaborators(
        &self,
        request: Request<EditCollaboratorsRequest>,
    ) -> Result<Response<EditCollaboratorsResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn get_collaborators(
        &self,
        request: Request<GetCollaboratorsRequest>,
    ) -> Result<Response<GetCollaboratorsResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn squash(
        &self,
        request: Request<SquashRequest>,
    ) -> Result<Response<SquashResponse>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<RollbackRequest>, Status> {
        let client_id = authenticate(&request).await?;
        eprintln!(
            "not implemented: you are {:x?} request was {:#?}",
            client_id, request
        );
        Err(Status::unimplemented("hold up, not yet"))
    }
}
