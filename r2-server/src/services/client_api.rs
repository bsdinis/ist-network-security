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
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> Result<Response<GetMetadataResponse>, Status> {
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn fetch_commit(
        &self,
        request: Request<FetchCommitRequest>,
    ) -> Result<Response<FetchCommitResponse>, Status> {
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn commit(
        &self,
        request: Request<CommitRequest>,
    ) -> Result<Response<CommitResponse>, Status> {
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn edit_collaborators(
        &self,
        request: Request<EditCollaboratorsRequest>,
    ) -> Result<Response<EditCollaboratorsResponse>, Status> {
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn squash(
        &self,
        request: Request<SquashRequest>,
    ) -> Result<Response<SquashResponse>, Status> {
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }

    async fn rollback(
        &self,
        request: Request<RollbackRequest>,
    ) -> Result<Response<RollbackRequest>, Status> {
        eprintln!("not implemented: request was {:#?}", request);
        Err(Status::unimplemented("hold up, not yet"))
    }
}
