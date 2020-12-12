use eyre::{eyre, Result, WrapErr};
use openssl::x509::X509;
use openssl_utils::PublicKeyFingerprintExt;
use std::sync::{Arc, RwLock};
use tonic::{transport::Certificate, Request, Status};

pub async fn authenticate<T>(req: &Request<T>) -> Result<Vec<u8>, Status> {
    let certs_ref = req.peer_certs_global().ok_or(Status::internal(
        "can't authenticate client: no global certs object (broken implementation)",
    ))?;

    authenticate_cert(certs_ref)
        .await
        .map_err(|e| Status::internal(format!("Failed to authenticate client: {:?}", e)))
}

async fn authenticate_cert(certs_ref: Arc<RwLock<Option<Vec<Certificate>>>>) -> Result<Vec<u8>> {
    let certs_guard = certs_ref.read().expect("poisoned lock");

    let cert = certs_guard
        .as_ref()
        .ok_or(eyre!("certs unavailable"))?
        .first()
        .ok_or(eyre!("no certificates sent by client???"))?;

    let cert = X509::from_der(cert.as_ref()).wrap_err("Failed to parse client cert")?;

    cert.pubkey_fingerprint()
        .wrap_err(eyre!("Failed to compute client cert fingerprint"))
}
