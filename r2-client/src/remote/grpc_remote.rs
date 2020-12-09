use super::model::*;
use super::{Remote, RemoteFile};
use crate::model::Me;
use openssl_utils::{aead::SealedSecretBox, SealedAeadKey};
use protos::client_api_client::ClientApiClient;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Uri};
use tonic::Request;

use std::convert::{TryFrom, TryInto};
use std::sync::Arc;

type Error = Box<dyn std::error::Error>;

pub struct GrpcRemote {
    channel: Channel,
}

pub struct GrpcRemoteFile {
    id: String,
    client: ClientApiClient<Channel>,
}

impl GrpcRemote {
    pub fn new(uri: Uri, me: Arc<Me>, ca_cert_pem: &[u8]) -> Result<Self, Error> {
        let tls_config = ClientTlsConfig::new()
            .identity(Identity::from_pem(
                me.auth_certificate_pem(),
                me.auth_private_key_pem(),
            ))
            .ca_certificate(Certificate::from_pem(ca_cert_pem));

        let channel = Channel::builder(uri)
            .tls_config(tls_config)?
            .connect_lazy()?;

        Ok(GrpcRemote { channel })
    }
}

#[tonic::async_trait]
impl Remote for GrpcRemote {
    type Error = Error;
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

        let res = client
            .create(Request::new(protos::CreateRequest {
                initial_commit,
                collaborators,
            }))
            .await?
            .into_inner();

        let id = res.document_id;
        let file = GrpcRemoteFile { id: id, client };

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
    type Error = Error;
    type Id = String;

    async fn load_metadata(&mut self) -> Result<FileMetadata, Self::Error> {
        let req = protos::GetMetadataRequest {
            document_id: self.id.to_owned(),
        };

        let resp = self.client.get_metadata(req).await?.into_inner();

        Ok(resp.into())
    }

    async fn load_commit(&mut self, commit_id: &str) -> Result<CipheredCommit, Self::Error> {
        let req = protos::GetCommitRequest {
            document_id: self.id.to_owned(),
            commit_id: commit_id.to_owned(),
        };

        let resp = self.client.get_commit(req).await?.into_inner();

        Ok(resp.commit.try_into()?)
    }

    async fn commit(&mut self, commit: CipheredCommit) -> Result<(), Self::Error> {
        let req = protos::CommitRequest {
            document_id: self.id.to_owned(),
            commit: Some(commit.into()),
        };

        self.client.commit(req).await?;

        Ok(())
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
            ciphertext: self.data.ciphertext,
            nonce: self.data.nonce.into(),
            aad: self.data.aad,
            tag: self.data.tag.into(),
        }
    }
}

#[derive(Debug)]
pub struct BadDataFromServer;

use std::fmt;
impl fmt::Display for BadDataFromServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error: BadDataFromServer")
    }
}

impl std::error::Error for BadDataFromServer {}

impl TryFrom<protos::Commit> for CipheredCommit {
    type Error = BadDataFromServer;

    fn try_from(msg: protos::Commit) -> Result<Self, Self::Error> {
        Ok(CipheredCommit {
            id: msg.commit_id,
            data: SealedSecretBox {
                ciphertext: msg.ciphertext,
                nonce: msg.nonce.try_into().map_err(|_| BadDataFromServer)?,
                aad: msg.aad,
                tag: msg.tag.try_into().map_err(|_| BadDataFromServer)?,
            },
        })
    }
}

impl TryFrom<Option<protos::Commit>> for CipheredCommit {
    type Error = BadDataFromServer;

    fn try_from(maybe_msg: Option<protos::Commit>) -> Result<Self, Self::Error> {
        maybe_msg.map_try_into()?.ok_or(BadDataFromServer)
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

trait MapTryIntoExt<T, E> {
    fn map_try_into(self) -> Result<T, E>;
}
impl<U, T, E> MapTryIntoExt<Option<T>, E> for Option<U>
where
    U: TryInto<T, Error = E>,
{
    fn map_try_into(self) -> Result<Option<T>, E> {
        self.map(|u| u.try_into()).transpose()
    }
}

trait MapIntoExt<T> {
    fn map_into(self) -> T;
}
impl<U, T> MapIntoExt<Option<T>> for Option<U>
where
    U: Into<T>,
{
    fn map_into(self) -> Option<T> {
        self.map(|u| u.into())
    }
}
impl<U, T> MapIntoExt<Vec<T>> for Vec<U>
where
    U: Into<T>,
{
    fn map_into(mut self) -> Vec<T> {
        self.drain(..).map(|u| u.into()).collect()
    }
}

trait TryCollectExt<V, E, B> {
    fn try_collect(self) -> Result<B, E>;
}

impl<I, V, E> TryCollectExt<V, E, Vec<V>> for I
where
    I: Iterator<Item = Result<V, E>>,
{
    fn try_collect(mut self) -> Result<Vec<V>, E> {
        let mut res = Vec::new();

        while let Some(item) = self.next() {
            res.push(item?);
        }

        Ok(res)
    }
}
