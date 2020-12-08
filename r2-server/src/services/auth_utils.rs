use openssl::x509::X509;
use openssl_utils::X509Ext;
use std::sync::{RwLock, Arc};
use tokio::task;
use tonic::{Request, Status, transport::Certificate};

pub async fn authenticate<T>(req: &Request<T>) -> Result<Vec<u8>, Status> {
    let certs_ref = req.peer_certs_global()
        .ok_or(Status::internal("can't authenticate client: no global certs object (broken implementation)"))?;

    let mut id = try_auth(certs_ref.clone());
    let mut remaining_attempts = 1000i32;
    while let None = id {
        task::yield_now().await;
        id = try_auth(certs_ref.clone());

        remaining_attempts -= 1;
        if remaining_attempts < 0 {
            break;
        }
    }

    id
        .ok_or(Status::internal("can't authenticate client: maximum attempts reached"))?
}

fn try_auth(certs_lock: Arc<RwLock<Option<Vec<Certificate>>>>) -> Option<Result<Vec<u8>, Status>> {
    let certs_guard = certs_lock
        .read()
        .expect("poisoned lock");

    certs_guard
        .as_ref()
        .map(|certs| {
            // the first certificate is the client's certificate (lowest in chain)
            certs.first()
            .ok_or(Status::internal("can't authenticate client: no certs"))
            .and_then(|client_cert| {
                X509::from_der(client_cert.as_ref())
                    .map_err(|err| err.into())
                    .and_then(|c| c.pubkey_fingerprint())
                    .map_err(|_| Status::internal("can't authenticate client: unable to parse cert fingerprint"))
            })
        })

}
