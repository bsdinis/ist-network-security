use protos::identity_server::Identity;
use protos::*;
use std::collections::HashMap;
use tonic::{Request, Response, Status};

pub struct IdentityService {
    map: HashMap<Vec<u8>, Vec<u8>>,
}

impl IdentityService {
    pub fn new(map: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        IdentityService { map }
    }
}

#[tonic::async_trait]
impl Identity for IdentityService {
    async fn get_certificate(
        &self,
        request: Request<GetCertificateRequest>,
    ) -> Result<Response<GetCertificateResponse>, Status> {
        let pubkey = request.into_inner().pubkey;
        let certificate = self
            .map
            .get(&pubkey)
            .ok_or(Status::not_found("Cert not found"))?
            .to_owned();

        Ok(Response::new(GetCertificateResponse { certificate }))
    }
}