use openssl::x509::X509;
use openssl_utils::PublicKeyFingerprintExt;
use protos::identity_client::IdentityClient;
use protos::GetCertificateRequest;
use thiserror::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Uri};
use tonic::{Request, Status};

use crate::model::{CommitAuthor, DocCollaborator};

#[tonic::async_trait]
pub trait CollaboratorFetcher: Sized {
    async fn fetch_cert(&self, pubkey_fingerprint: &[u8])
        -> Result<X509, CollaboratorFetcherError>;

    fn ca_cert(&self) -> &X509;

    async fn fetch_doc_collaborator(
        &self,
        id: &[u8],
    ) -> Result<DocCollaborator, CollaboratorFetcherError> {
        let cert = self.fetch_cert(id).await?;

        DocCollaborator::from_certificate(cert, self.ca_cert())
            .map_err(|_| CollaboratorFetcherError::BadFetchedCert)
    }

    async fn fetch_commit_author(
        &self,
        id: &[u8],
    ) -> Result<CommitAuthor, CollaboratorFetcherError> {
        let cert = self.fetch_cert(id).await?;

        CommitAuthor::from_certificate(cert, self.ca_cert())
            .map_err(|_| CollaboratorFetcherError::BadFetchedCert)
    }
}

pub struct IdentityCollaboratorFetcher {
    ca_cert: X509,
    channel: Channel,
}

#[derive(Error, Debug)]
pub enum CollaboratorFetcherError {
    #[error("Error parsing CA certificate. Is it really a PEM-formatted cert?")]
    BadCACert,

    #[error("Tonic error: {:?}", .0)]
    TonicError(#[from] tonic::transport::Error),

    #[error("Certificate not found in identity service")]
    NotFound,

    #[error("Identity service yielded bad certificate")]
    BadFetchedCert,

    #[error("Failed to fetch certificate: {:?}", .0)]
    CertFetchFail(Status),
}

impl IdentityCollaboratorFetcher {
    pub fn new(ca_cert_pem: &[u8], uri: Uri) -> Result<Self, CollaboratorFetcherError> {
        let ca_cert =
            X509::from_pem(ca_cert_pem).map_err(|_| CollaboratorFetcherError::BadCACert)?;

        let ca_cert_for_tonic = Certificate::from_pem(ca_cert_pem);
        let tls_config = ClientTlsConfig::new().ca_certificate(ca_cert_for_tonic);
        let channel = Channel::builder(uri)
            .tls_config(tls_config)?
            .connect_lazy()?;

        Ok(IdentityCollaboratorFetcher { ca_cert, channel })
    }
}

#[tonic::async_trait]
impl CollaboratorFetcher for IdentityCollaboratorFetcher {
    async fn fetch_cert(
        &self,
        pubkey_fingerprint: &[u8],
    ) -> Result<X509, CollaboratorFetcherError> {
        let cert = {
            let pubkey_fingerprint = pubkey_fingerprint.to_owned();

            IdentityClient::new(self.channel.clone())
                .get_certificate(Request::new(GetCertificateRequest { pubkey_fingerprint }))
                .await?
                .into_inner()
                .certificate
        };

        let cert = X509::from_pem(&cert).map_err(|_| CollaboratorFetcherError::BadFetchedCert)?;

        let cert_pubk_fp = cert
            .pubkey_fingerprint()
            .map_err(|_| CollaboratorFetcherError::BadFetchedCert)?;

        if cert_pubk_fp != pubkey_fingerprint {
            return Err(CollaboratorFetcherError::BadFetchedCert);
        }

        Ok(cert)
    }

    fn ca_cert(&self) -> &X509 {
        &self.ca_cert
    }
}

impl From<Status> for CollaboratorFetcherError {
    fn from(status: Status) -> Self {
        use tonic::Code;

        match status.code() {
            Code::NotFound => CollaboratorFetcherError::NotFound,
            _ => CollaboratorFetcherError::CertFetchFail(status),
        }
    }
}

#[cfg(test)]
mod test_impl {
    use super::{CollaboratorFetcher, CollaboratorFetcherError};
    use crate::test_utils::certs::*;
    use openssl::x509::X509;
    use openssl_utils::PublicKeyFingerprintExt;
    use std::collections::HashMap;

    pub struct TestCollaboratorFetcher {
        ca_cert: X509,
        store: HashMap<Vec<u8>, X509>,
    }

    impl TestCollaboratorFetcher {
        pub fn new() -> Self {
            let mut self_ = TestCollaboratorFetcher {
                ca_cert: CA_CERT.to_owned(),
                store: HashMap::new(),
            };

            self_.insert(CA_CERT.to_owned());
            self_.insert(CLIENT_A_AUTH_CERT.cert.to_owned());
            self_.insert(CLIENT_B_AUTH_CERT.cert.to_owned());
            self_.insert(CLIENT_A_SIGN_CERT.cert.to_owned());
            self_.insert(CLIENT_B_SIGN_CERT.cert.to_owned());

            self_
        }

        pub fn insert(&mut self, cert: X509) {
            let fingerprint = cert.pubkey_fingerprint().unwrap();
            self.store.insert(fingerprint, cert);
        }
    }

    #[tonic::async_trait]
    impl CollaboratorFetcher for TestCollaboratorFetcher {
        fn ca_cert(&self) -> &X509 {
            &self.ca_cert
        }

        async fn fetch_cert(
            &self,
            pubkey_fingerprint: &[u8],
        ) -> Result<X509, CollaboratorFetcherError> {
            self.store
                .get(pubkey_fingerprint)
                .cloned()
                .ok_or(CollaboratorFetcherError::NotFound)
        }
    }
}

#[cfg(test)]
pub use test_impl::TestCollaboratorFetcher;
