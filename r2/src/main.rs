use eyre::Result;
use lib::parse_ref;
use openssl::rsa::Rsa;
use openssl::x509::X509;
use r2_client::model::{Commit, Me};
use r2_client::remote::{GrpcRemote, Remote};
use r2_client::storage::FilesystemStorage;
use r2_client::{CollaboratorFetcher, IdentityCollaboratorFetcher, ResetHardness, RichRevisionId};
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;
use tonic::transport::Uri;

mod lib;

type RemoteImpl = GrpcRemote;

type File =
    r2_client::File<FilesystemStorage, <RemoteImpl as Remote>::File, IdentityCollaboratorFetcher>;

#[derive(StructOpt)]
#[structopt(name = "r2-store")]
struct Opt {
    /// Command
    #[structopt(subcommand)]
    command: Command,

    /// The file
    file_path: PathBuf,

    /// Identity Server URI
    #[structopt(name = "identity-server", long, env = "R2_IDENTITY_SERVER")]
    identity_server_addr: Uri,

    /// Server URI
    #[structopt(name = "server", long, env = "R2_SERVER")]
    server_addr: Uri,

    /// CA certificate path
    #[structopt(name = "ca-cert", long, env = "R2_CA_CERT")]
    ca_cert_path: PathBuf,

    /// Path to authentication certificate
    #[structopt(name = "auth-cert", long, env = "R2_AUTH_CERT")]
    auth_cert_path: PathBuf,

    /// Path to signing certificate
    #[structopt(name = "sign-cert", long, env = "R2_SIGN_CERT")]
    sign_cert_path: PathBuf,

    ///Path to authentication key
    #[structopt(name = "auth-key", long, env = "R2_AUTH_KEY")]
    auth_key_path: PathBuf,

    /// Path to signing key
    #[structopt(name = "sign-key", long, env = "R2_SIGN_KEY")]
    sign_key_path: PathBuf,
}

#[derive(StructOpt)]
enum Command {
    /// Inits a new repository
    Init {
        message: String,
        collaborators: Vec<String>,
    },
    /// Clone a repository from a remote into a new file
    Clone {
        remote_id: <RemoteImpl as Remote>::Id,
    },
    /// Record changes to the repository
    Commit { message: String },
    /// Download commits and refs from remote
    Fetch,
    /// Fetch and integrate with the remote
    Pull {
        #[structopt(long, short)]
        force: bool,
    },
    /// Show changes between commits
    Diff {
        revision1: String,
        revision2: String,
    },
    /// Locally reset current HEAD to the specified state
    Reset {
        revision: String,
        #[structopt(flatten)]
        hardness: Hardness,
    },
    /// Reset current HEAD to the specified state
    Rollback {
        revision: String,
        #[structopt(flatten)]
        hardness: Hardness,
        #[structopt(long)]
        cancel: bool,
    },
    /// Join commits until specified commit
    Squash { revision: String },
    /// Show commit logs (from specified commit, HEAD if none provided, to the beginning of history)
    Log { revision: Option<String> },
    /// Adds collaborators
    EditCollaborators { collaborators: Vec<String> },
}

#[derive(StructOpt)]
struct Hardness {
    /// Rewinds HEAD to commit and discards local changes
    #[structopt(long, conflicts_with("soft"))]
    hard: bool,
    /// Rewinds HEAD to commit (default if --hard not specified)
    #[structopt(long = "soft", conflicts_with("hard"))]
    _soft: bool,
}

impl From<Hardness> for ResetHardness {
    fn from(hardness: Hardness) -> Self {
        if hardness.hard {
            ResetHardness::Hard
        } else {
            ResetHardness::Soft
        }
    }
}

fn get_me(
    ca_cert: &Vec<u8>,
    auth_cert_path: PathBuf,
    auth_key_path: PathBuf,
    sign_cert_path: PathBuf,
    sign_key_path: PathBuf,
) -> Me {
    let ca_cert = X509::from_pem(ca_cert).expect("Invalid CA certificate");

    let auth_cert = std::fs::read(auth_cert_path).expect("Auth certificate not found");
    let auth_cert = X509::from_pem(&auth_cert).expect("Invalid auth certificate");

    let auth_key = std::fs::read(auth_key_path).expect("Auth key not found");
    let auth_key = Rsa::private_key_from_pem(&auth_key).expect("Invalid auth key");

    let sign_cert = std::fs::read(sign_cert_path).expect("Sign certificate not found");
    let sign_cert = X509::from_pem(&sign_cert).expect("Invalid sign certificate");

    let sign_key = std::fs::read(sign_key_path).expect("Sign key not found");
    let sign_key = Rsa::private_key_from_pem(&sign_key).expect("Invalid sign key");

    Me::from_certs(&ca_cert, sign_key, sign_cert, auth_key, auth_cert)
        .expect("Invalid certificates/keys: couldn't create `Me`")
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let opt = Opt::from_args();
    let ca_cert = std::fs::read(opt.ca_cert_path).expect("CA certificate not found");

    let me = get_me(
        &ca_cert,
        opt.auth_cert_path,
        opt.auth_key_path,
        opt.sign_cert_path,
        opt.sign_key_path,
    );
    let me = Arc::new(me);

    let uri = opt.server_addr;
    let storage =
        FilesystemStorage::new(opt.file_path.clone()).expect("Couldn't create file system storage");

    let collab_fetcher = IdentityCollaboratorFetcher::new(&ca_cert, opt.identity_server_addr)?;

    let remote = GrpcRemote::new(uri, me.clone(), &ca_cert).expect("Couldn't create grpc remote");

    if let Command::Init {
        message,
        collaborators,
    } = &opt.command
    {
        let mut other_collaborators = Vec::with_capacity(collaborators.len());
        for id_str in collaborators {
            let id = hex::decode(&id_str)?;

            other_collaborators.push(collab_fetcher.fetch_doc_collaborator(&id).await?);
        }

        File::create(
            collab_fetcher,
            me,
            storage,
            remote,
            message.to_owned(),
            other_collaborators,
        )
        .await?;
        println!(
            "Initialized new r2 repository for {}",
            opt.file_path.to_string_lossy()
        );
    } else if let Command::Clone { remote_id } = &opt.command {
        File::from_remote(collab_fetcher, me, storage, remote, remote_id).await?;
        println!("Cloned r2 file to {}", opt.file_path.to_string_lossy());
    } else {
        let mut file = File::open(collab_fetcher, me, storage, remote)
            .await
            .expect("Couldn't get file");

        match opt.command {
            Command::Commit { message } => commit(file, message).await?,
            Command::Fetch => fetch(&mut file).await?,
            Command::Pull { force } => pull(file, force).await?,
            Command::Log { revision } => log(file, revision).await?,
            Command::Diff {
                revision1,
                revision2,
            } => diff(file, revision1, revision2).await?,
            Command::Reset { revision, hardness } => reset(file, revision, hardness).await?,
            Command::Rollback {
                revision,
                hardness,
                cancel,
            } => rollback(file, revision, hardness, cancel).await?,
            Command::Squash { revision } => squash(file, revision).await?,
            Command::EditCollaborators { collaborators } => edit_collaborators(file, collaborators).await?,

            Command::Init { .. } => unreachable!(),
            Command::Clone { .. } => unreachable!(),
        };
    }
    Ok(())
}

struct CommitStats {
    insertions: usize,
    deletions: usize,
}
fn commit_stats(commit: &Commit) -> CommitStats {
    let patch = commit.patch.as_patch();
    let deletions = patch
        .hunks()
        .into_iter()
        .map(|h| {
            h.lines()
                .into_iter()
                .filter(|l| {
                    if let diffy::Line::Delete(_) = l {
                        true
                    } else {
                        false
                    }
                })
                .count()
        })
        .fold(0, |acc, x| acc + x);
    let insertions = patch
        .hunks()
        .into_iter()
        .map(|h| {
            h.lines()
                .into_iter()
                .filter(|l| {
                    if let diffy::Line::Insert(_) = l {
                        true
                    } else {
                        false
                    }
                })
                .count()
        })
        .fold(0, |acc, x| acc + x);

    CommitStats {
        insertions,
        deletions,
    }
}

async fn commit(mut file: File, message: String) -> Result<()> {
    let commit = file.commit(message).await?;
    let stats = commit_stats(&commit);

    println!("[{}] {}", commit.id, commit.message);
    println!(
        "\t{} insertions(+), {} deletions (+)",
        stats.insertions, stats.deletions
    );

    Ok(())
}
async fn fetch(file: &mut File) -> Result<()> {
    let fetched_commits: Vec<Commit> = file.fetch().await?;
    if fetched_commits.len() > 0 {
        let last = fetched_commits.first().unwrap();
        let first = fetched_commits.last().unwrap();
        println!(
            "{}..{} (total {})",
            first.id,
            last.id,
            fetched_commits.len()
        );
    }

    Ok(())
}
async fn pull(mut file: File, force: bool) -> Result<()> {
    fetch(&mut file).await?;
    let (merged_commits, is_forced, has_conflicts) = file.merge_from_remote(force).await?;

    if merged_commits.len() > 0 {
        let last = merged_commits.first().unwrap();
        let first = merged_commits.last().unwrap();
        println!("Updated {}..{}", first.id, last.id);
        if is_forced {
            println!("Forced update");
        } else {
            println!("Fast-forward");
        }

        let stats = merged_commits.iter().map(|c| commit_stats(c)).fold(
            CommitStats {
                insertions: 0,
                deletions: 0,
            },
            |acc, x| CommitStats {
                insertions: acc.insertions + x.insertions,
                deletions: acc.deletions + x.deletions,
            },
        );

        println!(
            "\t{} insertions(+), {} deletions (+)",
            stats.insertions, stats.deletions
        );

        if has_conflicts {
            println!("ERROR: conflicts encountered while merging with remote. Please fix them manually and commit them.");
        }
    } else {
        println!("Already up to date.")
    }
    Ok(())
}
async fn log(file: File, revision: Option<String>) -> Result<()> {
    let revision = revision.map(|r| parse_ref(&r)).unwrap_or(Ok(RichRevisionId::RelativeHead(0)))?;
    let log = file.log(revision).await?;

    for commit in log.commits {
        let author = file.get_commit_author(&commit.author_id).await?;

        print!("commit {}", commit.id);
        match get_refs_vec(&commit, &log.head, &log.remote_head) {
            v if v.len() > 0 => {
                print!(" ({})", v.join(&","));
            }
            _ => (),
        }
        println!();

        println!("Author: {}", author.name);
        println!("Date: {}", commit.ts);
        println!();
        println!("\t{}", commit.message.replace("\n", "\n\t"));
        println!();
    }

    Ok(())
}
fn get_refs_vec(commit: &Commit, head: &str, remote_head: &str) -> Vec<&'static str> {
    let mut res = vec![];

    if commit.id == head {
        res.push("HEAD");
    }
    if commit.id == remote_head {
        res.push("remote/HEAD");
    }
    res
}

async fn diff(file: File, revision1: String, revision2: String) -> Result<()> {
    let revision1 = parse_ref(&revision1)?;
    let revision2 = parse_ref(&revision2)?;

    let diff = file.diff(revision1, revision2).await?;
    let patch = diff.as_patch();

    let formatter = diffy::PatchFormatter::new().with_color();
    println!("{}", formatter.fmt_patch(&patch));

    Ok(())
}

async fn reset(file: File, revision: String, hardness: Hardness) -> Result<()> {
    let revision = parse_ref(&revision)?;
    let _reset = file.reset(revision, hardness.into()).await?;
    Ok(())
}

async fn rollback(
    mut file: File,
    revision: String,
    hardness: Hardness,
    cancel: bool,
) -> Result<()> {
    let revision = parse_ref(&revision)?;
    let _rollback = file.rollback(revision, hardness.into(), cancel).await?;
    Ok(())
}

async fn squash(file: File, revision: String) -> Result<()> {
    let revision = parse_ref(&revision)?;
    let _squash = file.squash(revision).await?;
    Ok(())
}

async fn edit_collaborators(mut file: File, collaborator_strs: Vec<String>) -> Result<()> {
    let mut collaborators = Vec::with_capacity(collaborator_strs.len());
    let collab_fetcher = file.collab_fetcher();
    for id_str in collaborator_strs {
        let id = hex::decode(&id_str)?;

        collaborators.push(collab_fetcher.fetch_doc_collaborator(&id).await?);
    }
    file.edit_collaborators(collaborators).await?;
    Ok(())
}
