use super::model::*;

#[tonic::async_trait]
pub trait Remote {
    type Error;
    type File: RemoteFile<Id = Self::Id>;
    type Id: Clone + Send + Sync;

    async fn create(
        &mut self,
        initial_commit: CipheredCommit,
        collaborators: Vec<RemoteCollaborator>,
    ) -> Result<Self::File, Self::Error>;

    async fn open(&self, id: &Self::Id) -> Result<Self::File, Self::Error>;
}

#[tonic::async_trait]
pub trait RemoteFile {
    type Error;
    type Id: Clone + Send + Sync;

    async fn load_metadata(&mut self) -> Result<FileMetadata, Self::Error>;

    async fn load_commit(&mut self, commit_id: &str) -> Result<CipheredCommit, Self::Error>;

    async fn commit(&mut self, commit: CipheredCommit) -> Result<(), Self::Error>;

    async fn load_collaborators(&mut self) -> Result<Vec<RemoteCollaborator>, Self::Error>;

    async fn edit_collaborators(
        &mut self,
        collaborators: Vec<RemoteCollaborator>,
        commits: Vec<CipheredCommit>,
    ) -> Result<(), Self::Error>;

    async fn vote_rollback(
        &mut self,
        vote: Vote,
        target_commit_id: &str,
        dropped_commit_ids: &[&str],
        rekeyed_collaborators: Vec<RemoteCollaborator>,
        rekeyed_commits: Vec<CipheredCommit>,
    ) -> Result<i64, Self::Error>;

    async fn vote_squash(
        &mut self,
        vote: Vote,
        dropped_commit_ids: &[&str],
        rekeyed_collaborators: Vec<RemoteCollaborator>,
        rekeyed_commits: Vec<CipheredCommit>,
    ) -> Result<i64, Self::Error>;

    fn id(&self) -> &Self::Id;
}
