use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use argh::FromArgs;

use tonic::{Request, Response, Status};
use tonic::transport::{Server, Identity, Certificate, ServerTlsConfig};
use protos::client_api_server::{ClientApi, ClientApiServer};
use protos::{HelloWorldResponse, HelloWorldRequest};

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

#[derive(Default)]
struct ClientApiServerImpl;

#[tonic::async_trait]
impl ClientApi for ClientApiServerImpl {
    async fn hello(&self, req: Request<HelloWorldRequest>) -> Result<Response<HelloWorldResponse>, Status> {
        Ok(Response::new(HelloWorldResponse {
            resp: format!("Hello {}!", req.get_ref().name),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    Server::builder()
        .tls_config(tls_config)?
        .add_service(ClientApiServer::new(ClientApiServerImpl::default()))
        .serve(addr)
        .await?;

    Ok(())
}
