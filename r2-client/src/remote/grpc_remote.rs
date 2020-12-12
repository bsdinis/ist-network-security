use super::model::*;
use super::{Remote, RemoteFile};
use crate::model::Me;
use openssl_utils::{aead::SealedSecretBox, SealedAeadKey};
use protos::client_api_client::ClientApiClient;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri};
use tonic::{Code as StatusCode, Request, Status};

use iterutils::{MapIntoExt, MapTryIntoExt};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

use thiserror::Error;

use chrono::{DateTime, TimeZone, Utc};
use lazy_static::lazy_static;

pub struct GrpcRemote {
    channel: Channel,
}

pub struct GrpcRemoteFile {
    id: String,
    client: ClientApiClient<Channel>,
}

lazy_static! {
    static ref DT: DateTime<Utc> = Utc.ymd(2000, 1, 1).and_hms_nano(0, 0, 1, 444);
}

fn gen_timestamp() -> u64 {
    DT.timestamp_nanos() as u64
}

#[derive(Debug, Error)]
pub enum GrpcRemoteError {
    #[error("Server sent a nonce with the wrong size")]
    BadNonceSize,

    #[error("Server sent a tag with the wrong size")]
    BadTagSize,

    #[error("Server did not send required field {}", .0)]
    MissingField(&'static str),

    #[error("Failed commit precondition. Did you forget to `pull`? {}", .0.message())]
    FailedCommitPrecondition(Status),

    #[error("Server sent unexpected status: {:?}", .0)]
    UnexpectedStatus(#[from] Status),

    #[error("Error creating remote: {:?}", .0)]
    InitializationError(#[source] tonic::transport::Error),
}

impl GrpcRemote {
    pub fn new(uri: Uri, me: Arc<Me>, ca_cert_pem: &[u8]) -> Result<Self, GrpcRemoteError> {
        let tls_config = ClientTlsConfig::new()
            .identity(Identity::from_pem(
                me.auth_certificate_pem(),
                me.auth_private_key_pem(),
            ))
            .ca_certificate(Certificate::from_pem(ca_cert_pem));

        let channel = Channel::builder(uri)
            .tls_config(tls_config)
            .and_then(|e| e.connect_lazy())
            .map_err(|e| GrpcRemoteError::InitializationError(e))?;

        Ok(GrpcRemote { channel })
    }
}

#[tonic::async_trait]
impl Remote for GrpcRemote {
    type Error = GrpcRemoteError;
    type File = GrpcRemoteFile;
    type Id = String;

    async fn create(
        &mut self,
        initial_commit: CipheredCommit,
        collaborators: Vec<RemoteCollaborator>,
    ) -> Result<Self::File, Self::Error> {
        let mut client = ClientApiClient::new(self.channel.clone());

        let collaborators: Vec<protos::Collaborator> = collaborators.map_into();

        let initial_commit: Option<protos::Commit> = Some(initial_commit.into());
        let ts = gen_timestamp();

        let res = client
            .create(Request::new(protos::CreateRequest {
                initial_commit,
                collaborators,
                seqno: 0, // None
                view: 0,  // None
                ts,
            }))
            .await?
            .into_inner();

        let id = res.document_id;
        let file = GrpcRemoteFile { id, client };

        Ok(file)
    }

    async fn open(&self, id: &Self::Id) -> Result<Self::File, Self::Error> {
        Ok(GrpcRemoteFile {
            id: id.clone(),
            client: ClientApiClient::new(self.channel.clone()),
        })
    }
}

#[tonic::async_trait]
impl RemoteFile for GrpcRemoteFile {
    type Error = GrpcRemoteError;
    type Id = String;

    async fn load_metadata(&mut self) -> Result<FileMetadata, Self::Error> {
        let ts = gen_timestamp();
        let req = protos::GetMetadataRequest {
            document_id: self.id.to_owned(),
            seqno: 0,
            view: 0,
            ts,
        };

        let resp = self.client.get_metadata(req).await?.into_inner();

        Ok(resp.into())
    }

    async fn load_commit(&mut self, commit_id: &str) -> Result<CipheredCommit, Self::Error> {
        let ts = gen_timestamp();
        let req = protos::GetCommitRequest {
            document_id: self.id.to_owned(),
            commit_id: commit_id.to_owned(),
            ts,
            seqno: 0,
            view: 0,
        };

        let resp = self.client.get_commit(req).await?.into_inner();

        resp.commit
            .map_try_into()?
            .ok_or(GrpcRemoteError::MissingField("commit"))
            .map_err(|e| e.into())
    }

    async fn commit(&mut self, commit: CipheredCommit) -> Result<(), Self::Error> {
        let ts = gen_timestamp();
        let req = protos::CommitRequest {
            document_id: self.id.to_owned(),
            commit: Some(commit.into()),
            ts,
            seqno: 0,
            view: 0,
        };

        match self.client.commit(req).await {
            Ok(_) => Ok(()),
            Err(s) if s.code() == StatusCode::FailedPrecondition => {
                Err(GrpcRemoteError::FailedCommitPrecondition(s))
            }
            Err(s) => Err(s.into()),
        }
    }

    async fn load_collaborators(&mut self) -> Result<Vec<RemoteCollaborator>, Self::Error> {
        unimplemented!()
    }

    async fn save_collaborators(
        &mut self,
        _collaborators: Vec<RemoteCollaborator>,
        _commits: Option<Vec<CipheredCommit>>,
    ) -> Result<(), Self::Error> {
        unimplemented!()
    }

    async fn vote_rollback(
        &mut self,
        _vote: Vote,
        _target_commit_id: &str,
        _dropped_commit_ids: &[&str],
        _rekeyed_collaborators: Vec<RemoteCollaborator>,
        _rekeyed_commits: Vec<CipheredCommit>,
    ) -> Result<i64, Self::Error> {
        unimplemented!()
    }

    async fn vote_squash(
        &mut self,
        _vote: Vote,
        _dropped_commit_ids: &[&str],
        _rekeyed_collaborators: Vec<RemoteCollaborator>,
        _rekeyed_commits: Vec<CipheredCommit>,
    ) -> Result<i64, Self::Error> {
        unimplemented!()
    }

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl Into<protos::Collaborator> for RemoteCollaborator {
    fn into(self) -> protos::Collaborator {
        protos::Collaborator {
            auth_fingerprint: self.id,
            ciphered_document_key: self.document_key.into(),
        }
    }
}

impl From<protos::Collaborator> for RemoteCollaborator {
    fn from(msg: protos::Collaborator) -> Self {
        RemoteCollaborator {
            id: msg.auth_fingerprint,
            document_key: SealedAeadKey(msg.ciphered_document_key),
        }
    }
}

impl Into<protos::Commit> for CipheredCommit {
    fn into(self) -> protos::Commit {
        protos::Commit {
            commit_id: self.id,
            prev_commit_id: self.prev_commit_id.unwrap_or(String::new()),
            ciphertext: self.data.ciphertext,
            nonce: self.data.nonce.into(),
            aad: self.data.aad,
            tag: self.data.tag.into(),
        }
    }
}

impl TryFrom<protos::Commit> for CipheredCommit {
    type Error = GrpcRemoteError;

    fn try_from(msg: protos::Commit) -> Result<Self, Self::Error> {
        let prev_commit_id = if msg.prev_commit_id == "" {
            None
        } else {
            Some(msg.prev_commit_id)
        };

        Ok(CipheredCommit {
            id: msg.commit_id,
            prev_commit_id,
            data: SealedSecretBox {
                ciphertext: msg.ciphertext,
                nonce: msg
                    .nonce
                    .try_into()
                    .map_err(|_| GrpcRemoteError::BadNonceSize)?,
                aad: msg.aad,
                tag: msg
                    .tag
                    .try_into()
                    .map_err(|_| GrpcRemoteError::BadTagSize)?,
            },
        })
    }
}

impl From<protos::GetMetadataResponse> for FileMetadata {
    fn from(msg: protos::GetMetadataResponse) -> Self {
        FileMetadata {
            head: msg.head,
            document_key: SealedAeadKey(msg.ciphered_document_key),
        }
    }
}
