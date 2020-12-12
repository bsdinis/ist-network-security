use super::{model::*, Remote, RemoteFile};
use crate::model::Me;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use std::convert::Infallible;
use thiserror::Error;

#[derive(Clone)]
pub struct DummyRemote {
    files: Arc<Mutex<Vec<DummyRemoteFile>>>,
    current_user: Arc<Me>,
}

#[derive(Clone)]
pub struct DummyRemoteFile {
    id: usize,
    data: Arc<Mutex<FileData>>,
    current_user: Arc<Me>,
}

struct FileData {
    commits: HashMap<String, CipheredCommit>,
    collaborators: HashMap<Vec<u8>, RemoteCollaborator>,
    head: String,
}

impl DummyRemote {
    pub fn new(me: Arc<Me>) -> Self {
        DummyRemote {
            files: Arc::new(Mutex::new(vec![])),
            current_user: me,
        }
    }

    pub fn clone_for_user(&self, user: Arc<Me>) -> Self {
        DummyRemote {
            files: self.files.clone(),
            current_user: user,
        }
    }
}

#[tonic::async_trait]
impl Remote for DummyRemote {
    type Error = Infallible;
    type File = DummyRemoteFile;
    type Id = usize;

    async fn create(
        &mut self,
        initial_commit: CipheredCommit,
        mut collaborators: Vec<RemoteCollaborator>,
    ) -> Result<Self::File, Self::Error> {
        let mut files = self.files.lock().await;

        let id = files.len();

        let head = initial_commit.id.clone();

        let mut commits = HashMap::new();
        commits.insert(initial_commit.id.clone(), initial_commit);

        let collaborators = collaborators.drain(..).map(|c| (c.id.clone(), c)).collect();

        let file_data = FileData {
            head,
            commits,
            collaborators,
        };
        let file_data = Arc::new(Mutex::new(file_data));

        let file = DummyRemoteFile {
            id,
            current_user: self.current_user.clone(),
            data: file_data,
        };

        files.push(file.clone());
        Ok(file)
    }

    async fn open(&self, id: &Self::Id) -> Result<Self::File, Self::Error> {
        let files = self.files.lock().await;
        let mut file = files[*id].clone();
        file.current_user = self.current_user.clone();

        Ok(file)
    }
}

#[derive(Error, Debug)]
#[error("Commit '{id}' not found")]
pub struct CommitNotFoundError {
    id: String,
}

#[tonic::async_trait]
impl RemoteFile for DummyRemoteFile {
    type Error = CommitNotFoundError;
    type Id = usize;

    async fn load_metadata(&mut self) -> Result<FileMetadata, Self::Error> {
        let data = self.data.lock().await;

        Ok(FileMetadata {
            head: data.head.clone(),
            document_key: data.collaborators[self.current_user.doc_collaborator_id()]
                .document_key
                .clone(),
            pending_rollback: None,
            pending_squash: None,
            squash_vote_tally: 0,
            rollback_vote_tally: 0,
        })
    }

    async fn load_commit(&mut self, commit_id: &str) -> Result<CipheredCommit, Self::Error> {
        let data = self.data.lock().await;

        data.commits
            .get(commit_id)
            .ok_or(CommitNotFoundError {
                id: commit_id.to_owned(),
            })
            .map(|c| c.to_owned())
            .map_err(|e| e.into())
    }

    async fn commit(&mut self, commit: CipheredCommit) -> Result<(), Self::Error> {
        let mut data = self.data.lock().await;
        data.commits.insert(commit.id.clone(), commit);

        Ok(())
    }

    async fn load_collaborators(&mut self) -> Result<Vec<RemoteCollaborator>, Self::Error> {
        let data = self.data.lock().await;

        Ok(data.collaborators.values().cloned().collect())
    }

    async fn edit_collaborators(
        &mut self,
        _collaborators: Vec<RemoteCollaborator>,
        _commits: Vec<CipheredCommit>,
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
