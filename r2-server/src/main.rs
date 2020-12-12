use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use argh::FromArgs;
use eyre::Result;

use protos::client_api_server::ClientApiServer;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

pub mod services;
mod storage;
use services::service::ClientApiService;
use tracing::{event, Level};

/// Tokio Rustls server example
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// CA cert file (for client authentication)
    #[argh(option, short = 'a')]
    ca_cert: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;

    let cert = tokio::fs::read(options.cert).await?;
    let key = tokio::fs::read(options.key).await?;
    let server_identity = Identity::from_pem(cert, key);

    let ca_cert_file = tokio::fs::read(options.ca_cert).await?;
    let ca_cert = Certificate::from_pem(ca_cert_file);

    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(ca_cert);

    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stderr());
    let subscriber = tracing_subscriber::fmt().with_writer(non_blocking).finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Unable to set global default subscriber");

    let server = Server::builder()
        .tls_config(tls_config)?
        .add_service(ClientApiServer::new(ClientApiService::new().await?))
        .serve_with_shutdown(addr, ctrl_c());

    event!(Level::INFO, "Sever listening on {:?}", addr);
    server.await?;

    println!("Bye!");
    Ok(())
}

async fn ctrl_c() {
    use std::future;

    if let Err(_) = tokio::signal::ctrl_c().await {
        eprintln!("Failed to listen for Ctrl+C/SIGINT. Server will still exit after receiving them, just not gracefully.");
        future::pending().await // never completes
    }
}
