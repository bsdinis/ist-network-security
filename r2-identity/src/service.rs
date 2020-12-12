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
        let pubkey_fingerprint = &request.get_ref().pubkey_fingerprint;
        let certificate = self
            .map
            .get(pubkey_fingerprint)
            .ok_or(Status::not_found("Cert not found"))?
            .to_owned();

        Ok(Response::new(GetCertificateResponse { certificate }))
    }
}
